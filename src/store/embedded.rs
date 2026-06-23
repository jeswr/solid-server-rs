// AUTHORED-BY Claude Opus 4.8
//! The **embedded** [`SparqClient`] — the SPARQ query engine consumed IN-PROCESS as a library.
//!
//! [`EmbeddedSparqClient`] implements the authoritative-RDF seam by calling the `sparq-engine`
//! query/update entry points DIRECTLY against an in-process [`Graph`] (`sparq-core`), rather than
//! over SPARQ's HTTP service (the [`HttpSparqClient`](super::http::HttpSparqClient) path). It is a
//! THIRD `SparqClient` impl alongside the HTTP client and the [`InMemorySparqClient`] test double,
//! selected at boot by `PSS_SPARQ_BACKEND=embedded` (see `main.rs`). Behind the OPT-IN
//! `embedded-sparq` build feature, so the DEFAULT build/tests/conformance carry NO sparq dependency
//! and are byte-identical. See `decisions/0001-embed-sparq-in-process.md`.
//!
//! ## Why this is a net simplification over the HTTP path
//! - **Same queries, different transport.** Every query/update is built by the SAME injection-safe
//!   builders in [`super::sparql`] that the HTTP client uses — VERBATIM, no new query strings. So the
//!   conformance-equivalence to the HTTP/in-memory impls is trivial: identical SPARQL, identical
//!   named-graph model, only the execution path differs (in-process engine call vs an HTTP POST).
//! - **Named-graph isolation is REAL here (fixes the HTTP path's DEVIATION-1).** The engine's
//!   `query`/`update_in_place` fully support `GRAPH <g> { … }` over a single [`Graph`] that holds the
//!   default graph PLUS named graphs (graph IRI == resource IRI, the WAC-design model). The live
//!   HTTP `sparq-server` today folds named graphs into one default graph; embedding sidesteps that.
//! - **No marker/follow-up-ASK atomicity dance.** The HTTP impl needs per-operation create/delete
//!   markers + follow-up ASKs because a SPARQL UPDATE over HTTP cannot return rows, so the outcome
//!   (`NotFound`/`NotEmpty`/`Deleted`/created-or-not) must be probed afterwards — racing a concurrent
//!   mutation unless a nonce nothing else touches is used. IN-PROCESS, the whole op runs UNDER ONE
//!   HELD LOCK on the [`Graph`], so `create_child`/`delete_meta_if_empty` decide and return their
//!   outcome DIRECTLY (check-then-act with no interleaving) — the simpler, correct semantics.
//!
//! ## The sync↔tokio bridge (no "runtime within a runtime")
//! The [`SparqClient`] trait is `#[async_trait]` and the server is tokio, but the engine is a
//! BLOCKING, CPU-bound library (no async I/O — it computes against in-RAM indexes). Running an engine
//! call directly on a tokio worker would block the reactor. So every engine call here is dispatched
//! to a blocking thread via [`tokio::task::spawn_blocking`], mirroring the in-tree off-reactor
//! precedent ([`crate::redis_replay`]'s dedicated-thread pattern + the verifier's `net.rs`). The
//! [`Graph`] lives behind `Arc<Mutex<Graph>>`; the `Arc` is cloned into the blocking closure, which
//! locks + runs the engine call there. (A dedicated-OS-thread / actor owning the `Graph` and serving
//! ops over an mpsc channel is the production upgrade — see the follow-up — but `spawn_blocking`
//! over an `Arc<Mutex>` is the correct, simplest first slice and is what the task scopes.)
//!
//! ## Persistence
//! Constructed over a FRESH in-memory graph ([`EmbeddedSparqClient::in_memory`]), or over a
//! directory-backed graph loaded with [`Graph::open`] ([`EmbeddedSparqClient::open`]); the optional
//! on-disk snapshot is taken with [`EmbeddedSparqClient::save`]. The first slice keeps the in-memory
//! graph and offers `save`/`open` as the durable seam; a WAL/durable-on-every-write story is the
//! directory-backed `update_in_place` path (a follow-up to wire through).

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sparq_core::Graph;

use super::sparq::{DeleteOutcome, ResourceMeta, SparqClient, SparqError};
use super::sparql;

/// A live [`SparqClient`] backed by an IN-PROCESS SPARQ [`Graph`] + the `sparq-engine` query/update
/// entry points. Cheap to clone (the inner `Arc` is shared); construct once and share.
#[derive(Clone)]
pub struct EmbeddedSparqClient {
    /// The authoritative RDF index (the default graph + one named graph per resource IRI). Behind a
    /// `Mutex` so a write that must check-then-act (`create_child`, `delete_meta_if_empty`) holds the
    /// lock across the whole op (no interleaving), and so the `!Sync`-free `Arc<Mutex<Graph>>` can be
    /// moved into a `spawn_blocking` closure. `Graph` is `Send + Sync` (compile-time asserted in
    /// sparq-core), so this is sound.
    graph: Arc<Mutex<Graph>>,
}

impl EmbeddedSparqClient {
    /// Build a client over a FRESH, empty in-memory [`Graph`].
    ///
    /// The empty graph is an empty N-Triples parse — the cheapest way to mint a zero-triple `Graph`
    /// without depending on a private constructor. A parse of the empty string cannot fail, but we
    /// surface a [`SparqError::Backend`] rather than panicking if the engine ever changes that.
    pub fn in_memory() -> Result<Self, SparqError> {
        let graph = Graph::load_str("", "ntriples")
            .map_err(|e| SparqError::Backend(format!("fatal: empty graph init failed: {e}")))?;
        Ok(Self {
            graph: Arc::new(Mutex::new(graph)),
        })
    }

    /// Build a client over a DIRECTORY-BACKED [`Graph`] loaded from `dir` (a previously-`save`d
    /// snapshot). The on-disk path the persistence option selects.
    pub fn open(dir: &Path) -> Result<Self, SparqError> {
        let graph = Graph::open(dir).map_err(|e| {
            SparqError::Backend(format!("fatal: graph open({}) failed: {e}", dir.display()))
        })?;
        Ok(Self {
            graph: Arc::new(Mutex::new(graph)),
        })
    }

    /// Snapshot the current graph to `dir` (the durable seam for the in-memory path). Runs the
    /// blocking save off the reactor.
    pub async fn save(&self, dir: &Path) -> Result<(), SparqError> {
        let graph = Arc::clone(&self.graph);
        let dir = dir.to_path_buf();
        run_blocking(move || {
            let g = lock(&graph)?;
            g.save(&dir).map_err(|e| {
                SparqError::Backend(format!("fatal: graph save({}) failed: {e}", dir.display()))
            })
        })
        .await
    }
}

/// Lock the shared graph, mapping a poisoned mutex to a fail-closed backend error (never a panic
/// that could take down the worker).
fn lock(graph: &Arc<Mutex<Graph>>) -> Result<std::sync::MutexGuard<'_, Graph>, SparqError> {
    graph
        .lock()
        .map_err(|_| SparqError::Backend("fatal: embedded graph mutex poisoned".into()))
}

/// Dispatch a BLOCKING, CPU-bound engine closure to a tokio blocking thread, so the engine never
/// runs on (and never blocks) a reactor worker. A join failure (the blocking thread panicked) is a
/// fail-closed backend error.
async fn run_blocking<T, F>(f: F) -> Result<T, SparqError>
where
    F: FnOnce() -> Result<T, SparqError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(join_err) => Err(SparqError::Backend(format!(
            "fatal: embedded engine task failed: {join_err}"
        ))),
    }
}

/// Map an engine error string (the `Result<_, String>` the `sparq-engine` entry points return) into
/// the opaque trait [`SparqError::Backend`]. The engine error is a query/update execution failure on
/// a TRUSTED, builder-constructed query — never untrusted input — so it is a fatal backend condition.
fn engine_err(context: &str, e: String) -> SparqError {
    SparqError::Backend(format!("fatal: embedded engine {context}: {e}"))
}

/// Extract the lexical string of a SELECT cell ([`oxrdf::Term`]): a literal's value, or an IRI's
/// string. The data-path SELECTs bind either plain literals (the metadata fields) or IRIs (a
/// `?child`); both are returned as their value string, matching the HTTP impl's
/// SPARQL-results-JSON `value` field. A missing/unexpected term yields `None` (the caller maps that
/// to a malformed-result error or a fail-closed `NotFound`).
fn term_value(term: Option<&oxrdf::Term>) -> Option<String> {
    match term? {
        oxrdf::Term::Literal(l) => Some(l.value().to_string()),
        oxrdf::Term::NamedNode(n) => Some(n.as_str().to_string()),
        oxrdf::Term::BlankNode(b) => Some(b.as_str().to_string()),
        // RDF-1.2 quoted triples never appear in a metadata/containment binding; treat as absent.
        _ => None,
    }
}

/// Find the column index of a SELECT variable by name in the result header. The builders bind known
/// variable names (`ct`/`bk`/`etag`/`child`/`bk`), so a missing column is a malformed result.
fn var_col(result: &sparq_engine::QueryResult, name: &str) -> Option<usize> {
    result.vars.iter().position(|v| v.as_str() == name)
}

#[async_trait]
impl SparqClient for EmbeddedSparqClient {
    async fn get_meta(&self, iri: &str) -> Result<ResourceMeta, SparqError> {
        // SAME query as the HTTP/in-mem paths — the injection-safe `select_meta` builder VERBATIM.
        let q = sparql::select_meta(iri)?;
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let g = lock(&graph)?;
            let result = sparq_engine::query(&g, &q).map_err(|e| engine_err("select_meta", e))?;
            // No row ⇒ the resource is not indexed (fail-closed: never invent metadata).
            let row = result.rows.first().ok_or(SparqError::NotFound)?;
            let ct_col = var_col(&result, "ct").ok_or_else(|| {
                SparqError::Backend("fatal: meta result missing ?ct column".into())
            })?;
            let bk_col = var_col(&result, "bk").ok_or_else(|| {
                SparqError::Backend("fatal: meta result missing ?bk column".into())
            })?;
            let et_col = var_col(&result, "etag").ok_or_else(|| {
                SparqError::Backend("fatal: meta result missing ?etag column".into())
            })?;
            let content_type = term_value(row.get(ct_col).and_then(|c| c.as_ref()))
                .ok_or_else(|| SparqError::Backend("fatal: meta row missing contentType".into()))?;
            let blob_key = term_value(row.get(bk_col).and_then(|c| c.as_ref()))
                .ok_or_else(|| SparqError::Backend("fatal: meta row missing blobKey".into()))?;
            let etag = term_value(row.get(et_col).and_then(|c| c.as_ref()))
                .ok_or_else(|| SparqError::Backend("fatal: meta row missing etag".into()))?;
            Ok(ResourceMeta {
                content_type,
                blob_key,
                etag,
            })
        })
        .await
    }

    async fn put_meta(&self, iri: &str, meta: ResourceMeta) -> Result<(), SparqError> {
        // The SAME `update_put_meta` builder — a single `;`-joined update (3 targeted deletes + one
        // insert). Run it request-ATOMICALLY (`update_in_place_atomic`): the whole request commits
        // all-or-nothing, so a re-write never leaves a half-deleted record (the safe public default
        // for a direct library consumer, per the sparq-engine docs).
        let u = sparql::update_put_meta(iri, &meta.content_type, &meta.blob_key, &meta.etag)?;
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let mut g = lock(&graph)?;
            sparq_engine::update_in_place_atomic(&mut g, &u).map_err(|e| engine_err("put_meta", e))
        })
        .await
    }

    async fn exists(&self, iri: &str) -> Result<bool, SparqError> {
        let q = sparql::ask_exists(iri)?;
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let g = lock(&graph)?;
            sparq_engine::ask(&g, &q).map_err(|e| engine_err("ask_exists", e))
        })
        .await
    }

    async fn delete_meta(&self, iri: &str) -> Result<(), SparqError> {
        // DROP SILENT the resource's whole named graph (idempotent on an absent graph) — the SAME
        // `update_delete_resource` builder. Atomic single-op.
        let u = sparql::update_delete_resource(iri)?;
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let mut g = lock(&graph)?;
            sparq_engine::update_in_place_atomic(&mut g, &u)
                .map_err(|e| engine_err("delete_meta", e))
        })
        .await
    }

    async fn delete_meta_if_empty(
        &self,
        iri: &str,
        parent: Option<&str>,
    ) -> Result<DeleteOutcome, SparqError> {
        // IN-PROCESS atomicity simplification (the documented difference from the HTTP impl): the
        // whole op runs UNDER ONE HELD LOCK, so the existence + empty checks and the delete decide
        // their outcome DIRECTLY with no interleaving — NO marker/follow-up-ASK dance is needed. The
        // HTTP path needs the markers because a SPARQL UPDATE over HTTP cannot return rows AND a
        // concurrent op could mutate state between the update and a separate probe; here the Mutex
        // serialises every access, so check-then-act IS atomic.
        let exists_q = sparql::ask_exists(iri)?;
        let children_q = sparql::select_children(iri)?;
        // Build the conditional-delete update with a nonce the builder requires, even though we do not
        // consult the marker afterwards — the marker INSERT is harmless (it lands in the scratch
        // graph; pruned by the reconciler) and keeps the SAME query string as the HTTP path. The
        // builder's WHERE guard (exists AND empty) still protects the delete; our pre-checks under the
        // lock decide the returned `DeleteOutcome` directly.
        let nonce = next_nonce();
        let delete_u = sparql::update_delete_container_if_empty(iri, parent, &nonce)?;
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let mut g = lock(&graph)?;
            // 1. Exists? (absent ⇒ NotFound, nothing deleted.)
            if !sparq_engine::ask(&g, &exists_q)
                .map_err(|e| engine_err("delete_if_empty/exists", e))?
            {
                return Ok(DeleteOutcome::NotFound);
            }
            // 2. Empty? (any `ldp:contains` member ⇒ NotEmpty, nothing deleted.)
            let children = sparq_engine::query(&g, &children_q)
                .map_err(|e| engine_err("delete_if_empty/children", e))?;
            if !children.rows.is_empty() {
                return Ok(DeleteOutcome::NotEmpty);
            }
            // 3. Exists + empty ⇒ run the guarded atomic delete (container graph + parent edge +
            //    marker). The builder's own WHERE guard re-confirms exists+empty against the same
            //    locked graph (belt-and-braces; it can only AGREE with our check under the held lock),
            //    then deletes atomically.
            sparq_engine::update_in_place_atomic(&mut g, &delete_u)
                .map_err(|e| engine_err("delete_if_empty/delete", e))?;
            Ok(DeleteOutcome::Deleted)
        })
        .await
    }

    async fn create_child(
        &self,
        container: &str,
        child: &str,
        meta: ResourceMeta,
    ) -> Result<(), SparqError> {
        // IN-PROCESS atomicity simplification: under ONE held lock, verify the container exists, then
        // commit the child record + the containment edge atomically. No create-marker/follow-up-ASK
        // is needed (the HTTP path needs them only because an UPDATE over HTTP cannot report whether
        // its container-EXISTS guard matched). The builder's guarded `DELETE/INSERT … WHERE` is still
        // used VERBATIM, so the committed triples are identical to the HTTP path.
        let exists_q = sparql::ask_exists(container)?;
        let nonce = next_nonce();
        let create_u = sparql::update_create_child(
            container,
            child,
            &meta.content_type,
            &meta.blob_key,
            &meta.etag,
            &nonce,
        )?;
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let mut g = lock(&graph)?;
            // Container must exist (else 404). Checked under the lock, so no concurrent delete can
            // race between this check and the insert.
            if !sparq_engine::ask(&g, &exists_q)
                .map_err(|e| engine_err("create_child/exists", e))?
            {
                return Err(SparqError::NotFound);
            }
            sparq_engine::update_in_place_atomic(&mut g, &create_u)
                .map_err(|e| engine_err("create_child/insert", e))
        })
        .await
    }

    async fn remove_child(&self, container: &str, child: &str) -> Result<(), SparqError> {
        let u = sparql::update_remove_child(container, child)?;
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let mut g = lock(&graph)?;
            sparq_engine::update_in_place_atomic(&mut g, &u)
                .map_err(|e| engine_err("remove_child", e))
        })
        .await
    }

    async fn list_children(&self, container: &str) -> Result<Vec<String>, SparqError> {
        let q = sparql::select_children(container)?;
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let g = lock(&graph)?;
            let result = sparq_engine::query(&g, &q).map_err(|e| engine_err("list_children", e))?;
            let child_col = var_col(&result, "child").ok_or_else(|| {
                SparqError::Backend("fatal: select-children result missing ?child column".into())
            })?;
            let mut children = Vec::with_capacity(result.rows.len());
            for row in &result.rows {
                // A `SELECT ?child` row MUST carry a bound `child`. A missing/unbound value is a
                // malformed result, NOT an empty list — surface it as a fatal error (the same
                // fail-closed posture as the HTTP impl), because `list_children` feeds the
                // empty-container DELETE check (a silently-shortened list could wrongly allow a
                // non-empty container's delete).
                let child =
                    term_value(row.get(child_col).and_then(|c| c.as_ref())).ok_or_else(|| {
                        SparqError::Backend(
                            "fatal: select-children row missing the 'child' binding".into(),
                        )
                    })?;
                children.push(child);
            }
            Ok(children)
        })
        .await
    }

    async fn referenced_blob_keys(&self) -> Result<std::collections::HashSet<String>, SparqError> {
        let q = sparql::select_referenced_blob_keys();
        let graph = Arc::clone(&self.graph);
        run_blocking(move || {
            let g = lock(&graph)?;
            let result =
                sparq_engine::query(&g, &q).map_err(|e| engine_err("referenced_blob_keys", e))?;
            let bk_col = var_col(&result, "bk").ok_or_else(|| {
                SparqError::Backend("fatal: referenced-blob-keys result missing ?bk column".into())
            })?;
            let mut keys = std::collections::HashSet::with_capacity(result.rows.len());
            for row in &result.rows {
                // A missing `bk` binding is a malformed result — FATAL, never silently dropped: a
                // shortened referenced set would make the reconciler treat a still-referenced blob as
                // an orphan and DELETE live bytes. Fail-closed (the reconciler aborts the sweep).
                let bk = term_value(row.get(bk_col).and_then(|c| c.as_ref())).ok_or_else(|| {
                    SparqError::Backend(
                        "fatal: referenced-blob-keys row missing the 'bk' binding".into(),
                    )
                })?;
                keys.insert(bk);
            }
            Ok(keys)
        })
        .await
    }
}

/// A process-unique nonce for the marker triples the conditional-delete / create builders require.
/// IN-PROCESS we do not consult the marker (the held lock makes the outcome directly observable), so
/// only uniqueness matters — a monotonic counter combined with the boot-time nanos. Mirrors the HTTP
/// impl's `next_nonce` so the SAME builder is fed an equivalently-unique value.
fn next_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("op-{nanos:x}-{n:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A current-thread runtime so the async `SparqClient` API can be driven from a sync unit test
    /// without the `#[tokio::test]` macro for every case. NB `spawn_blocking` needs a multi-thread
    /// runtime to make progress, so we use the multi-thread builder.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(f)
    }

    fn client() -> EmbeddedSparqClient {
        EmbeddedSparqClient::in_memory().expect("empty in-memory graph")
    }

    fn meta(ct: &str, bk: &str, etag: &str) -> ResourceMeta {
        ResourceMeta {
            content_type: ct.into(),
            blob_key: bk.into(),
            etag: etag.into(),
        }
    }

    #[test]
    fn put_then_get_meta_round_trips() {
        block_on(async {
            let c = client();
            let iri = "http://pod/alice/doc";
            assert!(!c.exists(iri).await.unwrap(), "absent before write");
            assert!(matches!(c.get_meta(iri).await, Err(SparqError::NotFound)));
            c.put_meta(iri, meta("text/turtle", "blob-1", "\"e1\""))
                .await
                .unwrap();
            assert!(c.exists(iri).await.unwrap(), "present after write");
            let got = c.get_meta(iri).await.unwrap();
            assert_eq!(got, meta("text/turtle", "blob-1", "\"e1\""));
        });
    }

    #[test]
    fn put_meta_replaces_not_accumulates() {
        block_on(async {
            let c = client();
            let iri = "http://pod/alice/doc";
            c.put_meta(iri, meta("text/turtle", "blob-1", "\"e1\""))
                .await
                .unwrap();
            c.put_meta(iri, meta("application/ld+json", "blob-2", "\"e2\""))
                .await
                .unwrap();
            // A second put must REPLACE the single-valued record (no duplicate ct/bk/etag), so
            // get_meta is deterministic and returns the latest.
            let got = c.get_meta(iri).await.unwrap();
            assert_eq!(got, meta("application/ld+json", "blob-2", "\"e2\""));
        });
    }

    #[test]
    fn delete_meta_is_idempotent() {
        block_on(async {
            let c = client();
            let iri = "http://pod/alice/doc";
            c.put_meta(iri, meta("text/turtle", "b", "\"e\""))
                .await
                .unwrap();
            c.delete_meta(iri).await.unwrap();
            assert!(!c.exists(iri).await.unwrap());
            // Deleting an absent IRI is Ok (idempotent at the index layer).
            c.delete_meta(iri).await.unwrap();
        });
    }

    #[test]
    fn create_child_records_membership_and_guards_missing_container() {
        block_on(async {
            let c = client();
            let container = "http://pod/alice/c/";
            let child = "http://pod/alice/c/note";
            // A create into a non-indexed container is NotFound.
            assert!(matches!(
                c.create_child(container, child, meta("text/turtle", "bk", "\"e\""))
                    .await,
                Err(SparqError::NotFound)
            ));
            // Index the container, then create — the edge + the child's metadata both land.
            c.put_meta(container, meta("text/turtle", "cbk", "\"ce\""))
                .await
                .unwrap();
            c.create_child(container, child, meta("text/turtle", "bk", "\"e\""))
                .await
                .unwrap();
            assert_eq!(
                c.list_children(container).await.unwrap(),
                vec![child.to_string()]
            );
            assert!(c.exists(child).await.unwrap());
            assert_eq!(
                c.get_meta(child).await.unwrap(),
                meta("text/turtle", "bk", "\"e\"")
            );
        });
    }

    #[test]
    fn delete_meta_if_empty_outcomes() {
        block_on(async {
            let c = client();
            let container = "http://pod/alice/c/";
            let child = "http://pod/alice/c/note";
            // Absent ⇒ NotFound.
            assert_eq!(
                c.delete_meta_if_empty(container, None).await.unwrap(),
                DeleteOutcome::NotFound
            );
            // Indexed + a member ⇒ NotEmpty, nothing deleted.
            c.put_meta(container, meta("text/turtle", "cbk", "\"ce\""))
                .await
                .unwrap();
            c.create_child(container, child, meta("text/turtle", "bk", "\"e\""))
                .await
                .unwrap();
            assert_eq!(
                c.delete_meta_if_empty(container, None).await.unwrap(),
                DeleteOutcome::NotEmpty
            );
            assert!(
                c.exists(container).await.unwrap(),
                "a non-empty container is never deleted"
            );
            // Remove the child (its membership edge + its record — the non-container delete path), so
            // the container becomes empty, then the empty container deletes.
            c.remove_child(container, child).await.unwrap();
            c.delete_meta(child).await.unwrap();
            assert_eq!(
                c.delete_meta_if_empty(container, None).await.unwrap(),
                DeleteOutcome::Deleted
            );
            assert!(!c.exists(container).await.unwrap());
        });
    }

    #[test]
    fn referenced_blob_keys_collects_all_pointers() {
        block_on(async {
            let c = client();
            c.put_meta("http://pod/a", meta("text/turtle", "k1", "\"e\""))
                .await
                .unwrap();
            c.put_meta("http://pod/b", meta("text/turtle", "k2", "\"e\""))
                .await
                .unwrap();
            let keys = c.referenced_blob_keys().await.unwrap();
            assert!(keys.contains("k1") && keys.contains("k2"), "got {keys:?}");
            assert_eq!(keys.len(), 2);
        });
    }
}
