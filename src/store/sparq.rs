// AUTHORED-BY Claude Opus 4.8
//! The SPARQ client seam — the **authoritative** source for RDF data, metadata, and containment.
//!
//! Per the maintainer's directive, SPARQ (queried over its HTTP API) is the system of record for the
//! resource graph and its metadata (existence, content type, the `s3Key` byte-pointer). Read paths
//! consult SPARQ, **not** an S3 LIST/HEAD (the same "QLever/SPARQ is the source of truth" invariant
//! as the production server). This module defines the [`SparqClient`] trait + an in-memory test impl.
//!
//! M2: the live HTTP client (a SPARQL Query/Update client over SPARQ's endpoint, with the bearer
//! gating SPARQ requires for UPDATE) plugs in behind this trait. It needs a running SPARQ instance,
//! so it is exercised by an integration test, not the M1 unit tests.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

/// The authoritative metadata SPARQ holds for a resource (the index record, not the bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMeta {
    /// The RDF content type the resource was stored as (e.g. `text/turtle`).
    pub content_type: String,
    /// The opaque blob-store key the bytes live under (the `pss:s3Key` pointer).
    pub blob_key: String,
    /// An opaque entity tag for conditional requests. M2: derived from the SPARQ index state.
    pub etag: String,
}

/// A SPARQ-client error (opaque — never leaks backend detail to a client).
#[derive(Debug, thiserror::Error)]
pub enum SparqError {
    #[error("resource not indexed")]
    NotFound,
    #[error("sparq backend error: {0}")]
    Backend(String),
}

/// A query-build failure (an IRIREF-invalid untrusted IRI) is a FATAL backend error — fail-closed,
/// never silently escaped/aliased.
impl From<super::sparql::BuildError> for SparqError {
    fn from(e: super::sparql::BuildError) -> Self {
        SparqError::Backend(format!("fatal: {e}"))
    }
}

/// The authoritative RDF index over SPARQ.
///
/// M1 defined only the metadata-record operations needed by GET/HEAD/PUT. M2 adds DELETE
/// ([`SparqClient::delete_meta`]) and containment membership ([`SparqClient::create_child`] /
/// [`remove_child`](SparqClient::remove_child) / [`list_children`](SparqClient::list_children)) —
/// SPARQ is authoritative for containment, so POST (mint a child) + the empty-container DELETE check
/// flow through it, never an S3 LIST. M2-next: the `usage()` quota view + the WAC/ACP ACL-document
/// graphs the (future) access-evaluation step reads.
#[async_trait]
pub trait SparqClient: Send + Sync {
    /// Fetch the authoritative metadata for a resource IRI, or [`SparqError::NotFound`].
    async fn get_meta(&self, iri: &str) -> Result<ResourceMeta, SparqError>;

    /// Upsert the authoritative metadata record for a resource IRI.
    async fn put_meta(&self, iri: &str, meta: ResourceMeta) -> Result<(), SparqError>;

    /// Whether the resource is indexed (the authoritative existence check — never an S3 HEAD).
    async fn exists(&self, iri: &str) -> Result<bool, SparqError>;

    /// Remove a resource's metadata record. Idempotent: deleting an absent IRI is `Ok(())` (the
    /// caller's existence check governs the 404, so this is a no-op-on-absent at the index layer).
    async fn delete_meta(&self, iri: &str) -> Result<(), SparqError>;

    /// ATOMICALLY create a child resource record: in a SINGLE index operation, verify `container` is
    /// indexed (else [`SparqError::NotFound`]) and commit BOTH `child`'s metadata record AND the
    /// `container`→`child` containment edge together.
    ///
    /// Committing the metadata and the membership in one atomic step is what makes the POST path
    /// race-free: there is NO window in which the edge exists without the child's metadata (or vice
    /// versa), so no removal-based compensation is needed and a concurrent same-IRI creator cannot
    /// observe — or have removed — a half-built containment. (The live impl is one SPARQL UPDATE with
    /// a `container`-EXISTS guard that inserts both triples.) The blob bytes are written by the caller
    /// BEFORE this call; if this fails (missing container), those bytes are orphaned and GC'd by the
    /// reconciler — the same crash-consistency model as [`SparqClient::put_meta`].
    async fn create_child(
        &self,
        container: &str,
        child: &str,
        meta: ResourceMeta,
    ) -> Result<(), SparqError>;

    /// Remove `child` from `container`'s membership. Idempotent on an absent edge.
    async fn remove_child(&self, container: &str, child: &str) -> Result<(), SparqError>;

    /// List the IRIs of `container`'s direct children (its `ldp:contains` members).
    async fn list_children(&self, container: &str) -> Result<Vec<String>, SparqError>;
}

/// An in-memory [`SparqClient`] for tests and the M1/M2 boot-without-SPARQ path.
///
/// Holds the metadata records AND the containment edges (container IRI → ordered child IRIs) behind
/// a single lock, so a POST/DELETE that touches both stays internally consistent under the test
/// double's coarse locking.
#[derive(Default)]
pub struct InMemorySparqClient {
    inner: Mutex<Index>,
}

/// The in-memory index state: metadata records + containment membership.
#[derive(Default)]
struct Index {
    meta: HashMap<String, ResourceMeta>,
    /// container IRI → its direct children, kept in insertion order (a `Vec`, de-duplicated).
    children: HashMap<String, Vec<String>>,
}

impl InMemorySparqClient {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SparqClient for InMemorySparqClient {
    async fn get_meta(&self, iri: &str) -> Result<ResourceMeta, SparqError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        guard.meta.get(iri).cloned().ok_or(SparqError::NotFound)
    }

    async fn put_meta(&self, iri: &str, meta: ResourceMeta) -> Result<(), SparqError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        guard.meta.insert(iri.to_string(), meta);
        Ok(())
    }

    async fn exists(&self, iri: &str) -> Result<bool, SparqError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        Ok(guard.meta.contains_key(iri))
    }

    async fn delete_meta(&self, iri: &str) -> Result<(), SparqError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        guard.meta.remove(iri);
        // Parity with the live SPARQ path (`DROP SILENT GRAPH <iri>`): a resource's named graph holds
        // BOTH its index record AND — if it is a container — its `ldp:contains` edges, so dropping the
        // record drops the containment set too. Mirror that here by clearing `iri`'s own children
        // entry, so a delete-then-recreate of a container at the same IRI cannot inherit a stale
        // (empty-or-not) membership list. (The empty-container DELETE check has already run in the
        // handler, so any surviving entry would be a leak, not a live member.)
        guard.children.remove(iri);
        Ok(())
    }

    async fn create_child(
        &self,
        container: &str,
        child: &str,
        meta: ResourceMeta,
    ) -> Result<(), SparqError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        // ONE atomic step under the single lock: verify the container exists, then commit BOTH the
        // child's metadata AND the containment edge together. No window separates them, so there is
        // nothing for a concurrent creator (or a failed-request compensation) to observe half-built.
        if !guard.meta.contains_key(container) {
            return Err(SparqError::NotFound);
        }
        guard.meta.insert(child.to_string(), meta);
        let entry = guard.children.entry(container.to_string()).or_default();
        if !entry.iter().any(|c| c == child) {
            entry.push(child.to_string());
        }
        Ok(())
    }

    async fn remove_child(&self, container: &str, child: &str) -> Result<(), SparqError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        if let Some(entry) = guard.children.get_mut(container) {
            entry.retain(|c| c != child);
        }
        Ok(())
    }

    async fn list_children(&self, container: &str) -> Result<Vec<String>, SparqError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        Ok(guard.children.get(container).cloned().unwrap_or_default())
    }
}
