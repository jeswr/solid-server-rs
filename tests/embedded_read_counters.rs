// AUTHORED-BY Claude Fable 5
//! P1.6 (beyond-50k `docs/design/beyond-50k-throughput.md` §4) — the **embedded-sparq benchmark
//! config that exercises the backend round-trip counters** on the READ path. The seam-level counters
//! (`docs/design/backend-read-path.md` §7, `tests/read_path_counters.rs`) are re-proven here against
//! the REAL in-process `EmbeddedSparqClient` engine — so the deterministic per-operation backend
//! round-trip counts are the observability the NEXT phase (round-trip reduction) targets, and a
//! regression that adds a round-trip on the embedded path fails.
//!
//! Gated on the opt-in `embedded-sparq` feature (the default build carries no sparq dependency); a
//! no-op test binary when the feature is off.
//!
//! ## Two measurements, two truths (both deterministic)
//! 1. **App-view seam counts** (`counted_router`): the full assembled router (auth → WAC → LDP →
//!    store) over `CountingSparqClient<EmbeddedSparqClient>`. This counts how many times the APP layer
//!    invokes each `SparqClient`/`BlobStore` trait method — `read_plan` is ONE seam call regardless of
//!    backend — so the per-op counts match `read_path_counters.rs`. It proves the counters + the
//!    app-layer round-trip model hold over the real engine (not just the in-memory double), and guards
//!    against a regression that adds a store call on the embedded read path.
//! 2. **True engine round-trips** (`embedded_read_plan_fans_out`): the embedded backend has NO
//!    combined-`read_plan` override, so it inherits the trait DEFAULT, which decomposes a read plan
//!    into `1 (target) + N (ACL candidates)` sequential `get_meta` round-trips. A `RawSeamCounter`
//!    (a seam counter WITHOUT the read_plan override, so the default fan-out is visible) pins that
//!    `1 + N`. This is the round-trip cost the collapsed backends (in-memory / the live HTTP client's
//!    one combined SELECT) already avoid — i.e. the exact reduction the next phase buys by
//!    implementing a combined `read_plan` on `EmbeddedSparqClient`. When it lands, this pin DROPS (an
//!    intended, measured win), and the app-view seam counts in (1) stay flat.

#![cfg(feature = "embedded-sparq")]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body, Bytes};
use axum::http::{header, Request, StatusCode};
use common::{jwks_provider, mint_access_token, mint_dpop_proof, KeyKit, BASE_URL};
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::store::embedded::EmbeddedSparqClient;
use solid_server_rs::store::{
    BackendCounters, CompositeStore, CounterSnapshot, CountingBlobStore, CountingSparqClient,
    DeleteOutcome, InMemoryBlobStore, ReadPlan, ResourceMeta, SparqClient, SparqError, Store,
};
use tower::ServiceExt;

const TURTLE: &str =
    "<https://pod.example/alice/c/doc#it> <http://xmlns.com/foaf/0.1/name> \"Doc\" .";

type CountedEmbeddedStore =
    CompositeStore<CountingSparqClient<EmbeddedSparqClient>, CountingBlobStore<InMemoryBlobStore>>;

// ---------------------------------------------------------------------------------------------------
// (1) App-view seam counts — full router over the EMBEDDED engine.
// ---------------------------------------------------------------------------------------------------

/// The counting harness: the assembled router the LDP e2e tests drive, with the counting decorators
/// wrapped around the REAL embedded SPARQ engine + an in-memory blob store, and the shared
/// [`BackendCounters`] exposed.
struct Harness {
    app: axum::Router,
    issuer_key: KeyKit,
    client_key: KeyKit,
    counters: Arc<BackendCounters>,
}

impl Harness {
    async fn new() -> Self {
        let issuer_key = KeyKit::generate();
        let client_key = KeyKit::generate();
        let config = VerifierConfig::new(vec![common::ISSUER.to_string()], BASE_URL);
        let replay = InMemoryReplayStore::with_window(config.replay_ttl());
        let verifier = Verifier::new(config, jwks_provider(&issuer_key), replay).unwrap();
        let ctx = AuthContext::new(verifier, BASE_URL);

        let counters = BackendCounters::new();
        let embedded = EmbeddedSparqClient::in_memory().expect("empty in-memory graph");
        let store = CompositeStore::new(
            CountingSparqClient::new(embedded, Arc::clone(&counters)),
            CountingBlobStore::new(InMemoryBlobStore::new(), Arc::clone(&counters)),
        );
        seed_root_owner_acl(&store, BASE_URL, common::WEBID).await;
        let ldp = LdpState::new(store, BASE_URL);
        let app = build_router(AppState::new(ctx, ldp));
        Self {
            app,
            issuer_key,
            client_key,
            counters,
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        extra: &[(&str, &str)],
        body: Body,
    ) -> axum::http::Response<Body> {
        let access = mint_access_token(&self.issuer_key, &self.client_key.thumbprint);
        let htu = format!("{BASE_URL}{path}");
        let proof = mint_dpop_proof(&self.client_key, method, &htu, &access);
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("DPoP {access}"))
            .header("dpop", proof);
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        for (k, v) in extra {
            builder = builder.header(*k, *v);
        }
        self.app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap()
    }

    /// Measure ONE request's backend-counter deltas over an OPERATION-SCOPED window.
    async fn measured(
        &self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> (axum::http::Response<Body>, CounterSnapshot) {
        let scope = self.counters.measure();
        let resp = self.request(method, path, None, extra, Body::empty()).await;
        (resp, scope.delta())
    }
}

/// Seed the ROOT `<base>/.acl` owner grant (Read/Write/Control + `acl:default` for descendants) —
/// the same fixture `read_path_counters.rs` uses, so the doc's governing ACL sits at k = 3.
async fn seed_root_owner_acl(store: &CountedEmbeddedStore, base_url: &str, owner_webid: &str) {
    let base = base_url.trim_end_matches('/');
    let root = format!("{base}/");
    let acl_iri = format!("{root}.acl");
    let acl_body = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#owner> a acl:Authorization;
         acl:agent <{owner_webid}>;
         acl:accessTo <{root}>;
         acl:default <{root}>;
         acl:mode acl:Read, acl:Write, acl:Control."#
    );
    store
        .write(&acl_iri, Bytes::from(acl_body), "text/turtle")
        .await
        .expect("seed root acl");
}

/// Container `/alice/c/` + doc `/alice/c/doc` inheriting the root ACL (k = 3 for the doc), then one
/// un-measured GET so the parsed-ACL cache is WARM for every measured op.
async fn fixture(h: &Harness) {
    let mk = h
        .request(
            "PUT",
            "/alice/c/",
            Some("text/turtle"),
            &[],
            Body::from("<#c> <http://xmlns.com/foaf/0.1/name> \"C\" ."),
        )
        .await;
    assert_eq!(mk.status(), StatusCode::CREATED);
    let put = h
        .request(
            "PUT",
            "/alice/c/doc",
            Some("text/turtle"),
            &[],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let warm = h
        .request("GET", "/alice/c/doc", None, &[], Body::empty())
        .await;
    assert_eq!(warm.status(), StatusCode::OK);
}

/// App-view seam counts, warm doc GET (k = 3), over the embedded engine. The app issues ONE
/// `store.read_plan` (seam count 1) + one live found-ACL re-confirm = **2 SPARQL queries**, + **1
/// blob get** — identical to the in-memory pins (`read_path_counters.rs`), because these are
/// app-layer store-method invocation counts, backend-agnostic. (The embedded engine's TRUE per-read
/// round-trips are higher — see `embedded_read_plan_fans_out`.)
#[tokio::test]
async fn embedded_get_doc_warm_k3_seam_counts_match_in_memory() {
    let h = Harness::new().await;
    fixture(&h).await;

    let (resp, d) = h.measured("GET", "/alice/c/doc", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], TURTLE.as_bytes());

    assert_eq!(
        d.sparql_queries, 2,
        "warm doc GET seam count = read_plan(1) + found-ACL re-confirm(1) over the embedded engine: {d:?}"
    );
    assert_eq!(
        d.blob_gets, 1,
        "warm doc GET fetches exactly the target bytes: {d:?}"
    );
    assert_eq!(d.sparql_updates, 0);
    assert_eq!(d.blob_puts, 0);
    assert_eq!(d.max_in_flight, 1, "strictly sequential");
}

/// App-view seam counts, warm HEAD (k = 3): same as GET — read_plan(1) + re-confirm(1) = 2 queries,
/// 1 blob get.
#[tokio::test]
async fn embedded_head_doc_warm_k3_seam_counts() {
    let h = Harness::new().await;
    fixture(&h).await;

    let (resp, d) = h.measured("HEAD", "/alice/c/doc", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        d.sparql_queries, 2,
        "warm HEAD seam count = read_plan(1) + re-confirm(1): {d:?}"
    );
    assert_eq!(d.blob_gets, 1, "HEAD still fetches the bytes today: {d:?}");
    assert_eq!(d.max_in_flight, 1);
}

/// App-view seam counts, warm container GET (k = 2): read_plan(1) + found-ACL re-confirm(1) + ONE
/// membership listing(1) = **3 queries**, **1 blob get** — matching `read_path_counters.rs`.
#[tokio::test]
async fn embedded_get_container_warm_seam_counts() {
    let h = Harness::new().await;
    fixture(&h).await;

    let (resp, d) = h.measured("GET", "/alice/c/", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        d.sparql_queries, 3,
        "warm container GET seam count = read_plan(1) + re-confirm(1) + ONE listing(1): {d:?}"
    );
    assert_eq!(d.blob_gets, 1, "container body bytes: {d:?}");
    assert_eq!(d.max_in_flight, 1);
}

/// The no-N+1 pin over the embedded engine: a container LISTING is ONE membership query independent
/// of child count — adding children must not change the per-read seam count.
#[tokio::test]
async fn embedded_container_listing_seam_count_independent_of_child_count() {
    let h = Harness::new().await;
    fixture(&h).await;

    let (resp, one_child) = h.measured("GET", "/alice/c/", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);

    for i in 0..4 {
        let put = h
            .request(
                "PUT",
                &format!("/alice/c/doc{i}"),
                Some("text/turtle"),
                &[],
                Body::from(format!(
                    "<https://pod.example/alice/c/doc{i}#it> <http://xmlns.com/foaf/0.1/name> \"D{i}\" ."
                )),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }

    let (resp, five_children) = h.measured("GET", "/alice/c/", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        five_children.sparql_queries, one_child.sparql_queries,
        "listing seam queries must be independent of child count: {one_child:?} vs {five_children:?}"
    );
    assert_eq!(five_children.blob_gets, one_child.blob_gets);
}

/// App-view 304 path (warm, k = 3): read_plan(1) + re-confirm(1) = 2 queries; the body byte-fetch
/// still happens today (1 blob get).
#[tokio::test]
async fn embedded_get_304_warm_seam_counts() {
    let h = Harness::new().await;
    fixture(&h).await;

    let (resp, _) = h.measured("GET", "/alice/c/doc", &[]).await;
    let etag = resp
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .unwrap()
        .to_string();

    let (resp, d) = h
        .measured("GET", "/alice/c/doc", &[("if-none-match", etag.as_str())])
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        d.sparql_queries, 2,
        "304 path seam count = read_plan(1) + re-confirm(1): {d:?}"
    );
    assert_eq!(
        d.blob_gets, 1,
        "304 path still fetches the bytes today: {d:?}"
    );
    assert_eq!(d.max_in_flight, 1);
}

// ---------------------------------------------------------------------------------------------------
// (2) True engine round-trips — the embedded backend's default read_plan FAN-OUT.
// ---------------------------------------------------------------------------------------------------

/// A [`SparqClient`] seam decorator that counts `get_meta` round-trips (via its own plain atomic —
/// independent of the `BackendCounters` seam used above) and — crucially — does NOT override
/// `read_plan`. So a `read_plan` call runs the trait DEFAULT (which loops `self.get_meta` over the
/// target + every ACL candidate), and each of those `get_meta` calls IS counted here. This makes the
/// embedded backend's true per-candidate read-plan fan-out visible at the seam (unlike
/// `CountingSparqClient`, whose `read_plan` override reports 1 and forwards the fan-out uncounted
/// into the inner engine). Every other method forwards transparently.
struct RawSeamCounter<S: SparqClient> {
    inner: S,
    get_meta_calls: Arc<AtomicU64>,
}

impl<S: SparqClient> RawSeamCounter<S> {
    fn new(inner: S) -> (Self, Arc<AtomicU64>) {
        let get_meta_calls = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner,
                get_meta_calls: Arc::clone(&get_meta_calls),
            },
            get_meta_calls,
        )
    }
}

#[async_trait]
impl<S: SparqClient> SparqClient for RawSeamCounter<S> {
    async fn get_meta(&self, iri: &str) -> Result<ResourceMeta, SparqError> {
        self.get_meta_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.get_meta(iri).await
    }
    async fn put_meta(&self, iri: &str, meta: ResourceMeta) -> Result<(), SparqError> {
        self.inner.put_meta(iri, meta).await
    }
    async fn exists(&self, iri: &str) -> Result<bool, SparqError> {
        self.inner.exists(iri).await
    }
    async fn delete_meta(&self, iri: &str) -> Result<(), SparqError> {
        self.inner.delete_meta(iri).await
    }
    async fn delete_meta_if_empty(
        &self,
        iri: &str,
        parent: Option<&str>,
    ) -> Result<DeleteOutcome, SparqError> {
        self.inner.delete_meta_if_empty(iri, parent).await
    }
    async fn create_child(
        &self,
        container: &str,
        child: &str,
        meta: ResourceMeta,
    ) -> Result<(), SparqError> {
        self.inner.create_child(container, child, meta).await
    }
    async fn remove_child(&self, container: &str, child: &str) -> Result<(), SparqError> {
        self.inner.remove_child(container, child).await
    }
    async fn list_children(&self, container: &str) -> Result<Vec<String>, SparqError> {
        self.inner.list_children(container).await
    }
    async fn referenced_blob_keys(&self) -> Result<HashSet<String>, SparqError> {
        self.inner.referenced_blob_keys().await
    }
    // NB: no `read_plan` override — the trait default fans out counted `get_meta` calls.
}

fn meta(bk: &str) -> ResourceMeta {
    ResourceMeta {
        content_type: "text/turtle".into(),
        blob_key: bk.into(),
        etag: "\"e1\"".into(),
        last_modified: None,
    }
}

/// **The round-trip-reduction target for the next phase.** The embedded backend has no combined
/// `read_plan`, so it inherits the trait default: a plan over a target + `N` ACL candidates costs
/// exactly `1 + N` sequential `get_meta` round-trips against the engine. Here `N = 4` (a doc at
/// depth k = 3: `doc.acl`, `c/.acl`, `alice/.acl`, `/.acl`), so **5 queries**, strictly sequential.
/// The collapsed backends (in-memory / the live HTTP one-combined-SELECT) do this in ONE round-trip;
/// implementing a combined `read_plan` on `EmbeddedSparqClient` collapses this pin from `1 + N` to 1
/// (a measured, intended win that this test will then re-pin).
#[tokio::test]
async fn embedded_read_plan_fans_out_to_one_plus_n_get_meta_round_trips() {
    let (raw, get_meta_calls) =
        RawSeamCounter::new(EmbeddedSparqClient::in_memory().expect("empty in-memory graph"));

    // Seed the target doc + the governing root ACL (both un-measured writes: put_meta, not counted).
    let target = "https://pod.example/alice/c/doc";
    let root_acl = "https://pod.example/.acl";
    raw.put_meta(target, meta("doc-blob")).await.unwrap();
    raw.put_meta(root_acl, meta("acl-blob")).await.unwrap();
    assert_eq!(
        get_meta_calls.load(Ordering::Relaxed),
        0,
        "seeding uses put_meta, not get_meta — the counter starts clean"
    );

    // The child→root ACL candidate list for the doc at k = 3 (the WAC walk's candidate set).
    let candidates: Vec<String> = [
        "https://pod.example/alice/c/doc.acl",
        "https://pod.example/alice/c/.acl",
        "https://pod.example/alice/.acl",
        "https://pod.example/.acl",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let plan: ReadPlan = raw.read_plan(target, &candidates).await.unwrap();

    // The plan is correct (target present; only the root ACL present among candidates) …
    assert!(plan.target.is_some(), "target metadata present in the plan");
    let present: Vec<&String> = plan
        .acls
        .iter()
        .filter(|(_, etag)| etag.is_some())
        .map(|(iri, _)| iri)
        .collect();
    assert_eq!(
        present,
        vec![root_acl],
        "only the root ACL is present among the candidates"
    );

    // … and it cost 1 (target) + N (candidates) = 5 sequential get_meta round-trips. The default
    // read_plan awaits each get_meta before the next (a sequential `for` loop), so the round-trip
    // count IS the sequential RTT depth. The collapsed backends (in-memory / the live HTTP
    // one-combined-SELECT) do this in ONE round-trip; a combined read_plan on EmbeddedSparqClient is
    // the next phase's win that collapses this pin from 1 + N to 1.
    assert_eq!(
        get_meta_calls.load(Ordering::Relaxed),
        1 + candidates.len() as u64,
        "embedded default read_plan = 1 target + N candidate get_meta round-trips (N={})",
        candidates.len()
    );
}
