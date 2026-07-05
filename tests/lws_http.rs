// AUTHORED-BY Claude Fable 5
//! End-to-end HTTP tests for the FLAG-GATED **LWS surface** (`src/lws` — the JLWS clean-slate
//! spec's M1 vertical slice), through the assembled router (auth + WAC + LDP + LWS hooks).
//!
//! Four harness configurations exercise the flag matrix:
//! - **flag OFF** (the default `LdpState`) — pins that no LWS route/header/behaviour exists and
//!   the Solid surface is unchanged (the full flag-off pin is the existing `ldp_http.rs` suite,
//!   which runs against the same default state);
//! - **LWS on, transform on, non-strict** — the composed Solid+LWS deployment;
//! - **LWS on, transform OFF** — byte-native only (no `ContentNegotiation` capability, no
//!   N-Triples conneg);
//! - **LWS on, STRICT PUT** — the pure-LWS D2/D3 create semantics.
//!
//! These tests are also the hand-written template for the `jeswr/lws-spec` `test-vectors/`
//! runner: every assertion is a plain (request → status/headers/body-predicate) pair over
//! `tower::ServiceExt::oneshot`, exactly the shape a vector file drives.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::http::{header, Request, StatusCode};
use common::{jwks_provider, mint_access_token, mint_dpop_proof, KeyKit, BASE_URL};
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::lws::LwsConfig;
use solid_server_rs::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient, Store};
use tower::ServiceExt;

const TURTLE: &str =
    "<https://pod.example/alice/data#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .";
const NTRIPLES_LINE: &str =
    "<https://pod.example/alice/data#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .";
const LWS_JSON: &str = "application/lws+json";
const NT: &str = "application/n-triples";

type TestStore = CompositeStore<InMemorySparqClient, InMemoryBlobStore>;

/// Seed the root owner ACL (Alice: Read/Write/Control on the root + all descendants) — the same
/// fixture `ldp_http.rs` uses, so every path is owner-controlled under the enforced WAC engine.
async fn seed_root_owner_acl(store: &TestStore, owner_webid: &str) {
    let base = BASE_URL.trim_end_matches('/');
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

/// One shared app + keys, with a configurable LWS state. `lws: None` is the flag-off default.
struct Harness {
    app: axum::Router,
    issuer_key: KeyKit,
    client_key: KeyKit,
    store: Arc<TestStore>,
}

/// A `Store` view over the shared `Arc` so the harness can BOTH hand the store to `LdpState` and
/// keep a handle for direct fixture writes (child `.acl`s). Delegates every method.
struct SharedStore(Arc<TestStore>);

#[async_trait::async_trait]
impl Store for SharedStore {
    async fn read(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::Resource> {
        self.0.read(iri).await
    }
    async fn meta(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<Option<solid_server_rs::store::ResourceMeta>> {
        self.0.meta(iri).await
    }
    async fn exists(&self, iri: &str) -> solid_server_rs::ServerResult<bool> {
        self.0.exists(iri).await
    }
    async fn write(
        &self,
        iri: &str,
        body: Bytes,
        content_type: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ResourceMeta> {
        self.0.write(iri, body, content_type).await
    }
    async fn create_in_container(
        &self,
        container: &str,
        child: &str,
        body: Bytes,
        content_type: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ResourceMeta> {
        self.0
            .create_in_container(container, child, body, content_type)
            .await
    }
    async fn delete(&self, iri: &str, parent: Option<&str>) -> solid_server_rs::ServerResult<()> {
        self.0.delete(iri, parent).await
    }
    async fn delete_container_if_empty(
        &self,
        iri: &str,
        parent: Option<&str>,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::DeleteOutcome> {
        self.0.delete_container_if_empty(iri, parent).await
    }
    async fn list_children(
        &self,
        container: &str,
    ) -> solid_server_rs::ServerResult<Vec<solid_server_rs::store::ValidatedChildIri>> {
        self.0.list_children(container).await
    }
    async fn read_plan(
        &self,
        target: &str,
        acl_candidates: &[String],
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ReadPlan> {
        self.0.read_plan(target, acl_candidates).await
    }
    async fn read_at(
        &self,
        iri: &str,
        meta: &solid_server_rs::store::ResourceMeta,
    ) -> solid_server_rs::ServerResult<Bytes> {
        self.0.read_at(iri, meta).await
    }
}

impl Harness {
    async fn with_lws(lws: Option<LwsConfig>) -> Self {
        let issuer_key = KeyKit::generate();
        let client_key = KeyKit::generate();
        let config = VerifierConfig::new(vec![common::ISSUER.to_string()], BASE_URL);
        let replay = InMemoryReplayStore::with_window(config.replay_ttl());
        let verifier = Verifier::new(config, jwks_provider(&issuer_key), replay).unwrap();
        let ctx = AuthContext::new(verifier, BASE_URL);
        let store = Arc::new(CompositeStore::new(
            InMemorySparqClient::new(),
            InMemoryBlobStore::new(),
        ));
        seed_root_owner_acl(&store, common::WEBID).await;
        let mut ldp = LdpState::new(SharedStore(store.clone()), BASE_URL);
        ldp.set_lws(lws.map(Arc::new));
        let app = build_router(AppState::new(ctx, ldp));
        Self {
            app,
            issuer_key,
            client_key,
            store,
        }
    }

    /// Flag OFF — the pure Solid surface (the `ldp_http.rs` default).
    async fn flag_off() -> Self {
        Self::with_lws(None).await
    }

    /// LWS on, transform on, non-strict — the composed Solid+LWS deployment.
    async fn lws() -> Self {
        Self::with_lws(Some(LwsConfig::new(BASE_URL, true, false))).await
    }

    /// LWS on, transform OFF — byte-native only.
    async fn lws_no_transform() -> Self {
        Self::with_lws(Some(LwsConfig::new(BASE_URL, false, false))).await
    }

    /// LWS on, STRICT PUT (pure-LWS D2/D3 semantics).
    async fn lws_strict() -> Self {
        Self::with_lws(Some(LwsConfig::new(BASE_URL, true, true))).await
    }

    fn auth_headers(&self, method: &str, path: &str) -> (String, String) {
        let access = mint_access_token(&self.issuer_key, &self.client_key.thumbprint);
        let htu = format!("{BASE_URL}{path}");
        let proof = mint_dpop_proof(&self.client_key, method, &htu, &access);
        (format!("DPoP {access}"), proof)
    }

    async fn request_with(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        extra: &[(&str, &str)],
        body: Body,
    ) -> axum::http::Response<Body> {
        let (authz, dpop) = self.auth_headers(method, path);
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", authz)
            .header("dpop", dpop);
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

    async fn request(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Body,
    ) -> axum::http::Response<Body> {
        self.request_with(method, path, content_type, &[], body)
            .await
    }

    /// An UNAUTHENTICATED request (no Authorization / DPoP) — discovery must be public.
    async fn unauth_request(
        &self,
        method: &str,
        path: &str,
        accept: Option<&str>,
    ) -> axum::http::Response<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(a) = accept {
            builder = builder.header("accept", a);
        }
        self.app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }
}

async fn body_bytes(resp: axum::http::Response<Body>) -> Bytes {
    to_bytes(resp.into_body(), usize::MAX).await.unwrap()
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    serde_json::from_slice(&body_bytes(resp).await).expect("response body is JSON")
}

fn header_value<'a>(resp: &'a axum::http::Response<Body>, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

fn link_values(resp: &axum::http::Response<Body>) -> Vec<String> {
    resp.headers()
        .get_all(header::LINK)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// 1. Discovery / storage description
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn discovery_document_advertises_conformance_and_capabilities() {
    let h = Harness::lws().await;

    // PUBLIC: an unauthenticated GET reaches the description (discovery precedes auth — the M2
    // RFC 9728 flow starts here).
    let resp = h.unauth_request("GET", "/.well-known/lws", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        header_value(&resp, "content-type").unwrap(),
        "application/ld+json;profile=\"https://w3id.org/jeswr/lws/v1\""
    );
    let doc = body_json(resp).await;
    assert_eq!(doc["id"], "https://pod.example/");
    assert_eq!(doc["type"], "Storage");
    let conforms: Vec<&str> = doc["conformsTo"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(conforms.contains(&"https://w3id.org/jeswr/lws/protocol/core/1.0"));
    assert!(conforms.contains(&"https://w3id.org/jeswr/lws/transform/rdf-1"));
    // The RDF opt-in capability entries (the maintainer's named deliverable): per-source
    // ContentNegotiation with the rdf-1 profile — including the ld+json source.
    let caps = doc["capability"].as_array().unwrap();
    let ld = caps
        .iter()
        .find(|c| c["source"] == "application/ld+json")
        .expect("application/ld+json source capability");
    assert_eq!(ld["type"], "ContentNegotiation");
    assert_eq!(ld["profile"], "https://w3id.org/jeswr/lws/transform/rdf-1");
    assert_eq!(
        ld["target"],
        serde_json::json!(["text/turtle", "application/n-triples"])
    );
    // The service set self-references the description.
    assert!(doc["service"].as_array().unwrap().iter().any(|s| {
        s["type"] == "StorageDescription"
            && s["serviceEndpoint"] == "https://pod.example/.well-known/lws"
    }));
}

#[tokio::test]
async fn discovery_conneg_same_bytes_only_content_type_varies() {
    let h = Harness::lws().await;

    let default = h.unauth_request("GET", "/.well-known/lws", None).await;
    let default_bytes = body_bytes(default).await;

    let lws = h
        .unauth_request("GET", "/.well-known/lws", Some(LWS_JSON))
        .await;
    assert_eq!(header_value(&lws, "content-type").unwrap(), LWS_JSON);
    assert_eq!(body_bytes(lws).await, default_bytes, "identical bytes");

    let json = h
        .unauth_request("GET", "/.well-known/lws", Some("application/json"))
        .await;
    assert_eq!(
        header_value(&json, "content-type").unwrap(),
        "application/json"
    );
    assert_eq!(body_bytes(json).await, default_bytes, "identical bytes");
}

#[tokio::test]
async fn discovery_reflects_transform_off() {
    let h = Harness::lws_no_transform().await;
    let resp = h.unauth_request("GET", "/.well-known/lws", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(
        doc["conformsTo"],
        serde_json::json!(["https://w3id.org/jeswr/lws/protocol/core/1.0"])
    );
    assert_eq!(doc["capability"], serde_json::json!([]));
}

#[tokio::test]
async fn flag_off_has_no_lws_route_headers_or_conneg() {
    let h = Harness::flag_off().await;

    // No discovery route: the path falls through to the LDP wildcard (401 anonymous — WAC).
    let resp = h.unauth_request("GET", "/.well-known/lws", None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Authenticated: 404 (no such resource) — still no LWS document.
    let resp = h
        .request("GET", "/.well-known/lws", None, Body::empty())
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // No LWS Link headers on reads.
    let put = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let get = h.request("GET", "/alice/data", None, Body::empty()).await;
    let links = link_values(&get).join("\n");
    assert!(!links.contains("lws#storageDescription"));
    assert!(!links.contains("rel=\"up\""));

    // No N-Triples conneg (406) and no LWS container shape (406).
    let nt = h
        .request_with("GET", "/alice/data", None, &[("accept", NT)], Body::empty())
        .await;
    assert_eq!(nt.status(), StatusCode::NOT_ACCEPTABLE);
    let lws_container = h
        .request_with(
            "GET",
            "/alice/",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(lws_container.status(), StatusCode::NOT_ACCEPTABLE);
}

// ---------------------------------------------------------------------------------------------
// 2. The LWS container representation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn lws_container_listing_shape_and_links() {
    let h = Harness::lws().await;

    // Fixtures: an RDF child, a binary child, and a sub-container under /alice/notes/.
    for (path, ct, body) in [
        ("/alice/notes/note1", Some("text/turtle"), TURTLE),
        ("/alice/notes/pic.bin", Some("text/plain"), "raw bytes"),
    ] {
        let resp = h.request("PUT", path, ct, Body::from(body)).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "fixture {path}");
    }
    let sub = h
        .request(
            "PUT",
            "/alice/notes/sub/",
            Some("text/turtle"),
            Body::empty(),
        )
        .await;
    assert_eq!(sub.status(), StatusCode::CREATED);

    // The LWS-profile request gets the flat server-managed listing.
    let resp = h
        .request_with(
            "GET",
            "/alice/notes/",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(header_value(&resp, "content-type").unwrap(), LWS_JSON);
    assert!(header_value(&resp, "vary").unwrap().contains("Accept"));
    // LWS containment + discovery metadata ride as Link headers.
    let links = link_values(&resp).join("\n");
    assert!(links.contains("<https://pod.example/alice/>; rel=\"up\""));
    assert!(links.contains(
        "<https://pod.example/.well-known/lws>; rel=\"https://w3id.org/jeswr/lws#storageDescription\""
    ));
    assert!(resp.headers().contains_key(header::ETAG));

    let doc = body_json(resp).await;
    assert_eq!(doc["@context"], "https://w3id.org/jeswr/lws/v1");
    assert_eq!(doc["id"], "https://pod.example/alice/notes/");
    assert_eq!(doc["type"], "Container");
    assert_eq!(doc["totalItems"], 3);
    let items = doc["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    let by_id = |id: &str| {
        items
            .iter()
            .find(|i| i["id"] == format!("https://pod.example/alice/notes/{id}"))
            .unwrap_or_else(|| panic!("member {id} missing"))
    };
    assert_eq!(by_id("note1")["type"], "DataResource");
    assert_eq!(by_id("note1")["mediaType"], "text/turtle");
    assert_eq!(by_id("pic.bin")["mediaType"], "text/plain");
    let sub = by_id("sub/");
    assert_eq!(sub["type"], "Container");
    assert!(
        sub.get("mediaType").is_none(),
        "containers carry no mediaType"
    );

    // A NORMAL request keeps the existing Solid LDP graph rendering (ldp:contains), unchanged.
    let solid = h
        .request_with(
            "GET",
            "/alice/notes/",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    assert_eq!(solid.status(), StatusCode::OK);
    assert_eq!(header_value(&solid, "content-type").unwrap(), "text/turtle");
    let ttl = String::from_utf8(body_bytes(solid).await.to_vec()).unwrap();
    assert!(ttl.contains("ldp#contains"));
    assert!(ttl.contains("note1"));
}

#[tokio::test]
async fn lws_container_listing_is_fail_closed_per_member() {
    let h = Harness::lws().await;

    // Two children; one gets its OWN restrictive `.acl` (granting only Bob), which overrides the
    // inherited owner default — Alice can no longer read it.
    for path in ["/alice/c/visible", "/alice/c/hidden"] {
        let resp = h
            .request("PUT", path, Some("text/turtle"), Body::from(TURTLE))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    let hidden = "https://pod.example/alice/c/hidden";
    let acl = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#bob-only> a acl:Authorization;
            acl:agent <https://pod.example/bob/profile/card#me>;
            acl:accessTo <{hidden}>;
            acl:mode acl:Read."#
    );
    h.store
        .write(&format!("{hidden}.acl"), Bytes::from(acl), "text/turtle")
        .await
        .expect("write child acl");

    // The LWS listing omits the unreadable member and counts only the visible view (D12).
    let resp = h
        .request_with(
            "GET",
            "/alice/c/",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["totalItems"], 1, "only the visible member is counted");
    let items = doc["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], "https://pod.example/alice/c/visible");

    // The EXISTING Solid rendering is deliberately unchanged (its membership disclosure follows
    // the Solid Protocol; the D12 fail-closed rule is an LWS-representation divergence).
    let solid = h
        .request_with(
            "GET",
            "/alice/c/",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    let ttl = String::from_utf8(body_bytes(solid).await.to_vec()).unwrap();
    assert!(
        ttl.contains("hidden"),
        "the Solid graph rendering is unchanged"
    );
}

// ---------------------------------------------------------------------------------------------
// 3. The RDF content-transformation opt-in
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn transform_derives_ntriples_with_per_representation_etags() {
    let h = Harness::lws().await;
    let put = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    // The stored (authoritative) representation: byte-exact, the stored ETag.
    let stored = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    assert_eq!(stored.status(), StatusCode::OK);
    let stored_etag = header_value(&stored, "etag").unwrap().to_string();
    assert_eq!(
        body_bytes(stored).await,
        Bytes::from_static(TURTLE.as_bytes())
    );

    // The DERIVED N-Triples representation: transformed body, a DISTINCT `+nt` validator,
    // Vary: Accept.
    let nt = h
        .request_with("GET", "/alice/data", None, &[("accept", NT)], Body::empty())
        .await;
    assert_eq!(nt.status(), StatusCode::OK);
    assert_eq!(header_value(&nt, "content-type").unwrap(), NT);
    assert!(header_value(&nt, "vary").unwrap().contains("Accept"));
    let nt_etag = header_value(&nt, "etag").unwrap().to_string();
    assert_ne!(nt_etag, stored_etag);
    assert!(nt_etag.contains("+nt"));
    let nt_body = String::from_utf8(body_bytes(nt).await.to_vec()).unwrap();
    assert!(
        nt_body.contains(NTRIPLES_LINE),
        "N-Triples line present: {nt_body}"
    );

    // JSON-LD stays negotiable exactly as on the Solid surface.
    let ld = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("accept", "application/ld+json")],
            Body::empty(),
        )
        .await;
    assert_eq!(ld.status(), StatusCode::OK);
    assert_eq!(
        header_value(&ld, "content-type").unwrap(),
        "application/ld+json"
    );
    let ld_etag = header_value(&ld, "etag").unwrap().to_string();
    assert_ne!(ld_etag, nt_etag);

    // Conditional read against the derived representation's own tag ⇒ 304.
    let cond = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("accept", NT), ("if-none-match", &nt_etag)],
            Body::empty(),
        )
        .await;
    assert_eq!(cond.status(), StatusCode::NOT_MODIFIED);

    // §authoritative-bytes: If-Match with the DERIVED representation's tag is accepted on a write
    // (both tags name the same resource state).
    let rewrite = h
        .request_with(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            &[("if-match", &nt_etag)],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(rewrite.status(), StatusCode::NO_CONTENT);
    // …and the STALE derived tag now fails (the state rotated).
    let stale = h
        .request_with(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            &[("if-match", &nt_etag)],
            Body::from(TURTLE),
        )
        .await;
    // NB: the body is identical, so the content-derived state part is unchanged — assert on the
    // FRESH etag instead: a write with a WRONG state part must 412.
    let fresh = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    let fresh_etag = header_value(&fresh, "etag").unwrap().to_string();
    if fresh_etag == stored_etag {
        // Same bytes ⇒ same state ⇒ the old tag still matches: 204 is correct here.
        assert_eq!(stale.status(), StatusCode::NO_CONTENT);
    } else {
        assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    }
    let wrong = h
        .request_with(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            &[("if-match", "\"0-bogus+nt\"")],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(wrong.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn transform_off_is_byte_native_only() {
    let h = Harness::lws_no_transform().await;
    let put = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    // No N-Triples target without the capability (the opt-in is honest: MUST NOT transform what
    // is not advertised).
    let nt = h
        .request_with("GET", "/alice/data", None, &[("accept", NT)], Body::empty())
        .await;
    assert_eq!(nt.status(), StatusCode::NOT_ACCEPTABLE);

    // The pre-existing Solid Turtle↔JSON-LD conneg is UNTOUCHED by the LWS transform flag (it is
    // Solid-surface behaviour, not part of the opt-in).
    let ld = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("accept", "application/ld+json")],
            Body::empty(),
        )
        .await;
    assert_eq!(ld.status(), StatusCode::OK);
}

#[tokio::test]
async fn transform_write_guard_blocks_nt_over_rdf_only_when_on() {
    // Transform ON: writing the target-only N-Triples type over an RDF-readable resource would
    // strand it ⇒ 415 problem details.
    let h = Harness::lws().await;
    let put = h
        .request("PUT", "/alice/doc", Some("text/turtle"), Body::from(TURTLE))
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let nt_over = h
        .request(
            "PUT",
            "/alice/doc",
            Some(NT),
            Body::from(NTRIPLES_LINE.to_string() + "\n"),
        )
        .await;
    assert_eq!(nt_over.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        header_value(&nt_over, "content-type").unwrap(),
        "application/problem+json"
    );
    let problem = body_json(nt_over).await;
    assert_eq!(
        problem["type"],
        "https://w3id.org/jeswr/lws/problems/not-a-source-type"
    );

    // ORDERING (the roborev Medium on c3eb4da): a FAILING precondition wins over the media-type
    // guard. An idempotent-create RETRY (`If-None-Match: *`) with N-Triples content against the
    // existing RDF resource keeps its non-mutating, retry-safe 412 (D2) — never a 415…
    let retry = h
        .request_with(
            "PUT",
            "/alice/doc",
            Some(NT),
            &[("if-none-match", "*")],
            Body::from(NTRIPLES_LINE.to_string() + "\n"),
        )
        .await;
    assert_eq!(retry.status(), StatusCode::PRECONDITION_FAILED);
    // …and a STALE If-Match is likewise 412 before any media-type judgement.
    let stale = h
        .request_with(
            "PUT",
            "/alice/doc",
            Some(NT),
            &[("if-match", "\"0-bogus\"")],
            Body::from(NTRIPLES_LINE.to_string() + "\n"),
        )
        .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    // A PASSING precondition still reaches the guard: If-Match with the CURRENT tag + NT ⇒ 415.
    let get = h
        .request_with(
            "GET",
            "/alice/doc",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    let etag = header_value(&get, "etag").unwrap().to_string();
    let guarded = h
        .request_with(
            "PUT",
            "/alice/doc",
            Some(NT),
            &[("if-match", &etag)],
            Body::from(NTRIPLES_LINE.to_string() + "\n"),
        )
        .await;
    assert_eq!(guarded.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // A fresh CREATE in N-Triples is byte-native storage (no transform expectations) — allowed.
    let create = h
        .request(
            "PUT",
            "/alice/raw.nt",
            Some(NT),
            Body::from(NTRIPLES_LINE.to_string() + "\n"),
        )
        .await;
    assert_eq!(create.status(), StatusCode::CREATED);

    // Flag OFF: the existing surface stores the NT overwrite as opaque bytes (204) — unchanged.
    let off = Harness::flag_off().await;
    let put = off
        .request("PUT", "/alice/doc", Some("text/turtle"), Body::from(TURTLE))
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let nt_over = off
        .request(
            "PUT",
            "/alice/doc",
            Some(NT),
            Body::from(NTRIPLES_LINE.to_string() + "\n"),
        )
        .await;
    assert_eq!(nt_over.status(), StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------------------------
// 4. Idempotent create (PUT + If-None-Match: *) + the strict D2/D3 semantics
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn idempotent_create_is_201_then_412_and_nonmutating() {
    let h = Harness::lws().await;

    let first = h
        .request_with(
            "PUT",
            "/alice/new.ttl",
            Some("text/turtle"),
            &[("if-none-match", "*")],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    // The retry is SAFE: 412, and the resource is NOT modified.
    let second = h
        .request_with(
            "PUT",
            "/alice/new.ttl",
            Some("text/turtle"),
            &[("if-none-match", "*")],
            Body::from("<#other> <http://xmlns.com/foaf/0.1/name> \"Mallory\" ."),
        )
        .await;
    assert_eq!(second.status(), StatusCode::PRECONDITION_FAILED);
    let get = h
        .request_with(
            "GET",
            "/alice/new.ttl",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    assert_eq!(body_bytes(get).await, Bytes::from_static(TURTLE.as_bytes()));

    // Non-strict: an unconditional PUT is still the Solid surface's create/replace (composition).
    let unconditional = h
        .request(
            "PUT",
            "/alice/plain.ttl",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(unconditional.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn strict_put_requires_conditional_and_existing_parent() {
    let h = Harness::lws_strict().await;

    // D2: every PUT is explicitly conditional — an unconditional PUT is 428 + problem details.
    let unconditional = h
        .request(
            "PUT",
            "/alice/x.ttl",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(unconditional.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(
        header_value(&unconditional, "content-type").unwrap(),
        "application/problem+json"
    );
    let problem = body_json(unconditional).await;
    assert_eq!(
        problem["type"],
        "https://w3id.org/jeswr/lws/problems/unconditional-put"
    );

    // D2: no auto-created intermediate containers — a create under a missing parent is 409
    // `missing-parent`.
    let orphan = h
        .request_with(
            "PUT",
            "/alice/a/b.ttl",
            Some("text/turtle"),
            &[("if-none-match", "*")],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(orphan.status(), StatusCode::CONFLICT);
    let problem = body_json(orphan).await;
    assert_eq!(
        problem["type"],
        "https://w3id.org/jeswr/lws/problems/missing-parent"
    );

    // Build the tree bottom-up: root, /alice/, /alice/a/ — each an idempotent container create
    // (trailing slash, empty body, no Content-Type needed).
    for path in ["/", "/alice/", "/alice/a/"] {
        let resp = h
            .request_with("PUT", path, None, &[("if-none-match", "*")], Body::empty())
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "create {path}");
    }
    // …and the child now lands.
    let child = h
        .request_with(
            "PUT",
            "/alice/a/b.ttl",
            Some("text/turtle"),
            &[("if-none-match", "*")],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(child.status(), StatusCode::CREATED);

    // Retry-safety in strict mode too: the same container create is a 412.
    let again = h
        .request_with(
            "PUT",
            "/alice/a/",
            None,
            &[("if-none-match", "*")],
            Body::empty(),
        )
        .await;
    assert_eq!(again.status(), StatusCode::PRECONDITION_FAILED);

    // D3: a container PUT with a body is a 400 (`container-body` problem) — a container is not a
    // data resource.
    let with_body = h
        .request_with(
            "PUT",
            "/alice/c2/",
            Some("text/turtle"),
            &[("if-none-match", "*")],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(with_body.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(with_body).await;
    assert_eq!(
        problem["type"],
        "https://w3id.org/jeswr/lws/problems/container-body"
    );

    // A conditional REPLACE (If-Match with the current tag) works.
    let get = h
        .request_with(
            "GET",
            "/alice/a/b.ttl",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    let etag = header_value(&get, "etag").unwrap().to_string();
    let replace = h
        .request_with(
            "PUT",
            "/alice/a/b.ttl",
            Some("text/turtle"),
            &[("if-match", &etag)],
            Body::from("<#me> <http://xmlns.com/foaf/0.1/name> \"Alice 2\" ."),
        )
        .await;
    assert_eq!(replace.status(), StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------------------------
// 5. Composition: the Solid surface is intact with the flag ON (non-strict)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn solid_surface_intact_with_lws_on() {
    let h = Harness::lws().await;

    // The Solid PUT (unconditional, auto-intermediate containers) still works.
    let put = h
        .request(
            "PUT",
            "/alice/deep/tree/data.ttl",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    // Byte-exact Turtle read-back + the Solid JSON-LD conneg.
    let get = h
        .request_with(
            "GET",
            "/alice/deep/tree/data.ttl",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(body_bytes(get).await, Bytes::from_static(TURTLE.as_bytes()));
    let ld = h
        .request_with(
            "GET",
            "/alice/deep/tree/data.ttl",
            None,
            &[("accept", "application/ld+json")],
            Body::empty(),
        )
        .await;
    assert_eq!(ld.status(), StatusCode::OK);

    // The Solid container rendering (ldp:contains graph) is the default for RDF Accepts.
    let container = h
        .request_with(
            "GET",
            "/alice/deep/tree/",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    assert_eq!(container.status(), StatusCode::OK);
    let ttl = String::from_utf8(body_bytes(container).await.to_vec()).unwrap();
    assert!(ttl.contains("ldp#contains"));
    assert!(ttl.contains("BasicContainer"));

    // Anonymous unauthorized read is still the WAC 401 with a challenge.
    let anon = h
        .unauth_request("GET", "/alice/deep/tree/data.ttl", None)
        .await;
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
    assert!(anon.headers().contains_key(header::WWW_AUTHENTICATE));
}

/// The M1-verify Low, locked as a regression test: a stored `application/ld+json` resource whose
/// `@context` is a hostile REMOTE URL must never trigger a server-side fetch when a derived
/// representation is negotiated — oxjsonld performs no remote-context resolution by construction,
/// so the parse fails and the transform degrades to the per-resource 406 problem
/// (`unparseable-source`), while the stored type stays byte-exact readable. A LIVE local listener
/// stands in for the "remote" context (the loopback stand-in for a metadata endpoint like
/// 169.254.169.254): the test fails if ANY connection arrives — pinning the no-SSRF invariant
/// against a future oxjsonld upgrade that might add remote context loading.
#[tokio::test]
async fn transform_never_fetches_a_remote_jsonld_context() {
    let h = Harness::lws().await;

    // A live listener the hostile @context points at. Bound on an ephemeral loopback port;
    // NOTHING should ever connect to it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind canary listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking canary listener");
    let canary = format!("http://{}/hostile-context", listener.local_addr().unwrap());

    let hostile = format!(
        r#"{{"@context": "{canary}", "@id": "https://pod.example/alice/ssrf", "name": "x"}}"#
    );

    // The HTTP write path already refuses the body (parse-on-write cannot resolve the remote
    // context — WITHOUT fetching it): the hostile document is unstorable over LDP. Pin that too.
    let put = h
        .request(
            "PUT",
            "/alice/ssrf",
            Some("application/ld+json"),
            Body::from(hostile.clone()),
        )
        .await;
    assert_eq!(put.status(), StatusCode::BAD_REQUEST);

    // Seed the hostile document DIRECTLY through the store (imported / pre-existing data — the
    // scenario the read-path regression is about), then negotiate the derived representation.
    h.store
        .write(
            "https://pod.example/alice/ssrf",
            Bytes::from(hostile.clone()),
            "application/ld+json",
        )
        .await
        .expect("seed hostile ld+json directly");

    // Negotiate the DERIVED N-Triples representation — the transform must attempt the parse
    // WITHOUT dereferencing the @context, fail, and answer the 406 unparseable-source problem.
    let nt = h
        .request_with("GET", "/alice/ssrf", None, &[("accept", NT)], Body::empty())
        .await;
    assert_eq!(nt.status(), StatusCode::NOT_ACCEPTABLE);
    let problem = String::from_utf8(body_bytes(nt).await.to_vec()).unwrap();
    assert!(
        problem.contains("unparseable-source"),
        "expected the unparseable-source problem, got: {problem}"
    );

    // The stored type stays byte-exact readable (authoritative bytes) — still no fetch.
    let stored = h
        .request_with(
            "GET",
            "/alice/ssrf",
            None,
            &[("accept", "application/ld+json")],
            Body::empty(),
        )
        .await;
    assert_eq!(stored.status(), StatusCode::OK);
    assert_eq!(
        String::from_utf8(body_bytes(stored).await.to_vec()).unwrap(),
        hostile
    );

    // THE invariant: no connection ever arrived at the hostile context host.
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {} // nothing connected — correct
        Ok((_, peer)) => panic!("the server fetched the remote @context (connection from {peer})"),
        Err(e) => panic!("canary listener failed: {e}"),
    }
}
