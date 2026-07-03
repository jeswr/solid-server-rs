// AUTHORED-BY Claude Fable 5
//! read-1 (`docs/design/backend-read-path.md` §7): PINNED deterministic backend round-trip counts
//! per read operation, measured end-to-end through the assembled router (auth → WAC → LDP → store)
//! with the counting decorators at the `SparqClient`/`BlobStore` seams.
//!
//! These are the §1.1 RTT-model counts made executable: **exact integer pins** (the repo's
//! perf-gate discipline — deterministic metrics hard-gated, wall-clock advisory, never asserted).
//! `max_in_flight == 1` in every scenario is the await-depth witness: every backend call strictly
//! awaited the previous one, so the op's sequential RTT depth EQUALS the pinned call totals.
//!
//! Terminology (matching §1.1): a resource whose governing ACL sits at ancestor index *k*
//! (0 = its own `.acl`). BEFORE read-2 (pinned at the read-1 commit, `git log` this file) a read
//! cost `k+1` sequential ACL probes + 1 target meta = **k+2 SPARQL queries** warm (k+3 cold), +1
//! blob get (+1 cold), +1 query for a container listing. AFTER read-2 (the §3.1 combined read-plan
//! query) the WHOLE metadata chain is ONE query — the pins below are the AFTER table, with each
//! test doc recording its before→after delta (the deterministic evidence of the win):
//!
//!   op                         queries before → after   blob gets
//!   doc GET  warm (any k)              k+2 → 1              1
//!   doc GET  cold ACL                  k+3 → 2              2   (ACL bytes ride read-3 next)
//!   HEAD     warm                      k+2 → 1              1
//!   GET 304  warm                      k+2 → 1              1
//!   container GET warm                 k+3 → 2              1   (plan + ONE membership listing)
//!
//! Depth-independence is the point: the per-read query count no longer scales with k.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use common::{jwks_provider, mint_access_token, mint_dpop_proof, KeyKit, BASE_URL};
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::store::{
    BackendCounters, CompositeStore, CounterSnapshot, CountingBlobStore, CountingSparqClient,
    InMemoryBlobStore, InMemorySparqClient, Store,
};
use tower::ServiceExt;

const TURTLE: &str =
    "<https://pod.example/alice/c/doc#it> <http://xmlns.com/foaf/0.1/name> \"Doc\" .";

type CountedStore =
    CompositeStore<CountingSparqClient<InMemorySparqClient>, CountingBlobStore<InMemoryBlobStore>>;

/// The counting harness: the same assembled router the LDP e2e tests drive, with the counting
/// decorators wrapped around the in-memory backends and the shared [`BackendCounters`] exposed.
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
        let store = CompositeStore::new(
            CountingSparqClient::new(InMemorySparqClient::new(), Arc::clone(&counters)),
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

    /// Measure ONE request's backend-counter deltas.
    async fn measured(
        &self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> (axum::http::Response<Body>, CounterSnapshot) {
        let before = self.counters.snapshot();
        let resp = self.request(method, path, None, extra, Body::empty()).await;
        (resp, self.counters.snapshot().since(&before))
    }
}

/// Seed a ROOT `<base>/.acl` granting the test WebID Read/Write/Control on the root and (via
/// `acl:default`) all descendants — the same pod-root owner-default the LDP e2e harness seeds.
async fn seed_root_owner_acl(store: &CountedStore, base_url: &str, owner_webid: &str) {
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
        .write(&acl_iri, axum::body::Bytes::from(acl_body), "text/turtle")
        .await
        .expect("seed root acl");
}

/// Build the standard fixture: container `/alice/c/` + document `/alice/c/doc`, all inheriting the
/// root owner ACL (so the doc's governing ACL sits at ancestor index k = 3:
/// candidates = doc.acl → /alice/c/.acl → /alice/.acl → /.acl ✓present).
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
    // Warm the parsed-ACL cache (the PUTs above already resolved + cached the root ACL, but be
    // explicit: one un-measured GET so every measured request below is the WARM path).
    let warm = h
        .request("GET", "/alice/c/doc", None, &[], Body::empty())
        .await;
    assert_eq!(warm.status(), StatusCode::OK);
}

/// §3.7 row 1 — **doc GET, warm (k = 3)**: the ENTIRE metadata chain (target meta + all 4 ACL
/// candidates) is ONE combined read-plan query, + **1 blob get**. Before read-2 this was 5 queries
/// (k+2); the pin is now DEPTH-INDEPENDENT. `max_in_flight == 1` ⇒ RTT depth = 2.
#[tokio::test]
async fn get_doc_warm_k3_pins_one_combined_query_1_blob_get() {
    let h = Harness::new().await;
    fixture(&h).await;

    let (resp, d) = h.measured("GET", "/alice/c/doc", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], TURTLE.as_bytes());

    assert_eq!(
        d.sparql_queries, 1,
        "warm doc GET = ONE combined read-plan query at any depth (was k+2 = 5): {d:?}"
    );
    assert_eq!(
        d.blob_gets, 1,
        "warm doc GET fetches exactly the target bytes: {d:?}"
    );
    assert_eq!(d.sparql_updates, 0);
    assert_eq!(d.blob_puts, 0);
    assert_eq!(d.max_in_flight, 1, "strictly sequential ⇒ RTT depth = 2");
}

/// §3.7 rows 1+3 — **doc GET with an OWN `.acl` (k = 0), cold then warm**: cold = 1 combined
/// read-plan query + 1 ACL re-meta (inside `store.read(acl)` on the parse-cache miss) = **2
/// queries** + **2 blob gets** (ACL bytes + target bytes; was 3 queries — read-3 `read_at` for the
/// ACL bytes takes this to 1); warm = **1 query** + **1 blob** (was 2).
#[tokio::test]
async fn get_doc_own_acl_cold_then_warm_pins_k0_counts() {
    let h = Harness::new().await;
    fixture(&h).await;

    // Give the doc its OWN ACL (owner full access) — the governing ACL moves to k = 0, and its
    // parse is NOT yet cached (the PUT writes bytes; only a resolve parses).
    let own_acl = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#o> a acl:Authorization; acl:agent <{owner}>;
     acl:accessTo <https://pod.example/alice/c/doc>;
     acl:mode acl:Read, acl:Write, acl:Control."#,
        owner = common::WEBID
    );
    let put = h
        .request(
            "PUT",
            "/alice/c/doc.acl",
            Some("text/turtle"),
            &[],
            Body::from(own_acl),
        )
        .await;
    assert!(put.status().is_success(), "PUT own acl: {}", put.status());

    // COLD: the fresh own-ACL's first resolve reads + parses it.
    let (resp, cold) = h.measured("GET", "/alice/c/doc", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        cold.sparql_queries, 2,
        "cold doc GET = the plan + the ACL re-meta on the parse miss (was k+3 = 3): {cold:?}"
    );
    assert_eq!(
        cold.blob_gets, 2,
        "cold pays the ACL byte-fetch + the target bytes: {cold:?}"
    );
    assert_eq!(cold.max_in_flight, 1);

    // WARM: the parse is cached under the ACL's etag.
    let (resp, warm) = h.measured("GET", "/alice/c/doc", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        warm.sparql_queries, 1,
        "warm doc GET = ONE combined read-plan query (was k+2 = 2): {warm:?}"
    );
    assert_eq!(
        warm.blob_gets, 1,
        "warm fetches only the target bytes: {warm:?}"
    );
    assert_eq!(warm.max_in_flight, 1);
}

/// **HEAD, warm (k = 3)** — same backend cost as GET (the read path fetches the bytes for HEAD
/// too): **1 combined query** (was k+2 = 5), **1 blob get**.
#[tokio::test]
async fn head_doc_warm_k3_pins_same_as_get() {
    let h = Harness::new().await;
    fixture(&h).await;

    let (resp, d) = h.measured("HEAD", "/alice/c/doc", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        d.sparql_queries, 1,
        "warm HEAD = ONE combined read-plan query (was k+2 = 5): {d:?}"
    );
    assert_eq!(d.blob_gets, 1, "HEAD still fetches the bytes today: {d:?}");
    assert_eq!(d.max_in_flight, 1);
}

/// **304 path, warm (k = 3)** — a matching `If-None-Match` returns 304; the metadata chain is
/// **1 combined query** (was k+2 = 5). The body byte-fetch (**1 blob get**) still happens (the
/// precondition is evaluated after the read — skipping it for plain resources is read-4 territory).
#[tokio::test]
async fn get_304_warm_k3_pins_one_combined_query() {
    let h = Harness::new().await;
    fixture(&h).await;

    // Learn the current ETag.
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
        d.sparql_queries, 1,
        "304 path = ONE combined read-plan query (was k+2 = 5): {d:?}"
    );
    assert_eq!(
        d.blob_gets, 1,
        "304 path still fetches the bytes today: {d:?}"
    );
    assert_eq!(d.max_in_flight, 1);
}

/// §3.7 row 4 — **container GET, warm (k = 2)**: 1 combined read-plan query + 1 membership
/// listing = **2 queries** (was k+3 = 5; the §3.1 membership-fold that would make it 1 is read-5,
/// measure-first), **1 blob get**. The listing stays ONE query at any child count (no-N+1).
#[tokio::test]
async fn get_container_warm_k2_pins_plan_plus_listing_queries() {
    let h = Harness::new().await;
    fixture(&h).await;

    let (resp, d) = h.measured("GET", "/alice/c/", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        d.sparql_queries, 2,
        "warm container GET = the plan + ONE membership listing (was k+3 = 5): {d:?}"
    );
    assert_eq!(d.blob_gets, 1, "container body bytes: {d:?}");
    assert_eq!(d.max_in_flight, 1);
}

/// The no-N+1 pin (§7): a container LISTING is ONE membership query **independent of child
/// count** — adding children must not change the per-read query count.
#[tokio::test]
async fn container_listing_query_count_is_independent_of_child_count() {
    let h = Harness::new().await;
    fixture(&h).await;

    // Baseline: 1 child (the fixture doc).
    let (resp, one_child) = h.measured("GET", "/alice/c/", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Add 4 more children.
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
        "listing queries must be independent of child count: {one_child:?} vs {five_children:?}"
    );
    assert_eq!(five_children.blob_gets, one_child.blob_gets);
}
