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
    /// The [`PinningStore`] snapshot state, when the harness was built generation-capable
    /// (`lws_pinned`) — lets a test age a snapshot out of the "backend" retention window.
    pins: Option<Arc<std::sync::Mutex<PinState>>>,
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
    async fn get_linkset(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<Option<(String, String)>> {
        self.0.get_linkset(iri).await
    }
    async fn set_linkset(
        &self,
        iri: &str,
        json: &str,
        new_rev: &str,
        expected: solid_server_rs::store::LinksetCas<'_>,
    ) -> solid_server_rs::ServerResult<bool> {
        self.0.set_linkset(iri, json, new_rev, expected).await
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
            pins: None,
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

    /// LWS on, STRICT LISTING (the pure-LWS container representation — §container-media-type /
    /// JLWSC-CMT-1/2). strict_listing is independent of strict_put, so this variant keeps the
    /// composed (auto-intermediate) PUT to isolate the listing behaviour under test; the pure-LWS
    /// conformance deployment sets BOTH (`from_env`).
    async fn lws_strict_listing() -> Self {
        Self::with_lws(Some(
            LwsConfig::new(BASE_URL, true, false).with_strict_listing(true),
        ))
        .await
    }

    fn auth_headers(&self, method: &str, path: &str) -> (String, String) {
        let access = mint_access_token(&self.issuer_key, &self.client_key.thumbprint);
        // The DPoP htu excludes the query (RFC 9449 §4.3), matching the server's parse_target —
        // so a `?linkset` / `?lws-page=N` request mints a valid proof.
        let htu = format!("{BASE_URL}{}", path.split('?').next().unwrap_or(path));
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

/// The media-type essence of a `Content-Type` value (parameters trimmed) — mirrors the conformance
/// harness's `mediaType` matcher (`value.split(';')[0].trim()`).
fn mediatype_of(ct: &str) -> &str {
    ct.split(';').next().unwrap_or("").trim()
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

/// #9 (JLWSC-CMT-1/2, CP-*, MA-1): the STRICT-LISTING pure-LWS deployment serves the LWS JSON-LD
/// listing as the DEFAULT container representation — a no-Accept / `application/ld+json` /
/// `application/json` GET all return the identical listing bytes, only `Content-Type` varying.
#[tokio::test]
async fn strict_listing_is_the_default_container_representation() {
    let h = Harness::lws_strict_listing().await;

    // Fixtures under /alice/notes/ (composed PUT auto-creates the intermediate container).
    for (path, ct, body) in [
        ("/alice/notes/a.txt", "text/plain", "alpha"),
        ("/alice/notes/sub/", "text/turtle", ""),
    ] {
        let resp = h
            .request("PUT", path, Some(ct), Body::from(body))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "fixture {path}");
    }

    // (a) No Accept ⇒ the LWS listing under application/ld+json (JLWSC-CMT-1 default type).
    let no_accept = h
        .request("GET", "/alice/notes/", None, Body::empty())
        .await;
    assert_eq!(no_accept.status(), StatusCode::OK);
    assert_eq!(
        mediatype_of(header_value(&no_accept, "content-type").unwrap()),
        "application/ld+json"
    );
    assert!(no_accept.headers().contains_key(header::ETAG));
    let bytes_default = body_bytes(no_accept).await;
    let doc: serde_json::Value = serde_json::from_slice(&bytes_default).unwrap();
    assert_eq!(doc["type"], "Container");
    assert_eq!(doc["id"], "https://pod.example/alice/notes/");
    assert_eq!(doc["totalItems"], 2);

    // (b) application/lws+json, application/ld+json, application/json ⇒ IDENTICAL bytes, only the
    // Content-Type label varies (JLWSC-CMT-2).
    let mut bodies = Vec::new();
    for (accept, want_ct) in [
        ("application/lws+json", "application/lws+json"),
        ("application/ld+json", "application/ld+json"),
        ("application/json", "application/json"),
    ] {
        let resp = h
            .request_with("GET", "/alice/notes/", None, &[("accept", accept)], Body::empty())
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "accept={accept}");
        assert_eq!(
            mediatype_of(header_value(&resp, "content-type").unwrap()),
            want_ct,
            "accept={accept}"
        );
        bodies.push(body_bytes(resp).await);
    }
    assert_eq!(bodies[0], bodies[1], "lws+json vs ld+json bytes identical");
    assert_eq!(bodies[1], bodies[2], "ld+json vs json bytes identical");
    assert_eq!(bodies[0], bytes_default, "conneg variants match the no-Accept body");
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

// ---------------------------------------------------------------------------------------------
// M3 §1 — RFC 9264 linkset metadata (`?linkset` + merge-patch + strict If-Match/428)
// ---------------------------------------------------------------------------------------------

/// A paged harness: LWS on, transform on, non-strict, PAGE SIZE 2 (so small fixtures paginate).
impl Harness {
    async fn lws_paged(page_size: usize) -> Self {
        Self::with_lws(Some(
            LwsConfig::new(BASE_URL, true, false)
                .with_page_size(std::num::NonZeroUsize::new(page_size)),
        ))
        .await
    }
}

#[tokio::test]
async fn linkset_serves_the_system_links_and_discovery() {
    let h = Harness::lws().await;
    let put = h
        .request(
            "PUT",
            "/alice/notes/a.ttl",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    // The 201 carries the spec-required create links (§http-create).
    let links = link_values(&put);
    assert!(
        links
            .iter()
            .any(|l| l.contains("?linkset>; rel=\"linkset\"")),
        "201 linkset link: {links:?}"
    );
    assert!(
        links
            .iter()
            .any(|l| l == "<https://pod.example/alice/notes/>; rel=\"up\""),
        "201 up link: {links:?}"
    );

    // The resource GET advertises its linkset (§metadata).
    let get = h
        .request("GET", "/alice/notes/a.ttl", None, Body::empty())
        .await;
    assert_eq!(get.status(), StatusCode::OK);
    assert!(link_values(&get)
        .iter()
        .any(|l| l == "<https://pod.example/alice/notes/a.ttl?linkset>; rel=\"linkset\""));

    // GET the linkset itself: RFC 9264 JSON, one context anchored at the resource, the
    // system-managed typed relations, an ETag + Accept-Patch/Allow advertisement.
    let ls = h
        .request("GET", "/alice/notes/a.ttl?linkset", None, Body::empty())
        .await;
    assert_eq!(ls.status(), StatusCode::OK);
    assert_eq!(
        header_value(&ls, "content-type").unwrap(),
        "application/linkset+json"
    );
    assert_eq!(
        header_value(&ls, "accept-patch").unwrap(),
        "application/merge-patch+json"
    );
    assert_eq!(
        header_value(&ls, "allow").unwrap(),
        "GET, HEAD, PATCH, OPTIONS"
    );
    // Vary: Accept — the linkset's STATUS varies by Accept (a non-accepting Accept is a 406), so
    // shared caches must key on it (the roborev Medium on 53296c0). The CORS layer merges its
    // own `Origin` dependency onto it (the same wire shape as the main read path).
    assert_eq!(header_value(&ls, "vary").unwrap(), "Accept, Origin");
    let etag = header_value(&ls, "etag").unwrap().to_string();
    assert!(
        etag.starts_with("\"ls0-"),
        "unpatched etag derives from the record: {etag}"
    );
    let doc = body_json(ls).await;
    let ctx = &doc["linkset"][0];
    assert_eq!(ctx["anchor"], "https://pod.example/alice/notes/a.ttl");
    assert_eq!(ctx["up"][0]["href"], "https://pod.example/alice/notes/");
    assert_eq!(
        ctx["type"][0]["href"],
        "https://w3id.org/jeswr/lws#DataResource"
    );
    assert_eq!(
        ctx["acl"][0]["href"],
        "https://pod.example/alice/notes/a.ttl.acl"
    );
    assert_eq!(
        ctx["https://w3id.org/jeswr/lws#storageDescription"][0]["href"],
        "https://pod.example/.well-known/lws"
    );

    // Conditional GET: If-None-Match on the linkset's own validator ⇒ 304.
    let not_modified = h
        .request_with(
            "GET",
            "/alice/notes/a.ttl?linkset",
            None,
            &[("if-none-match", &etag)],
            Body::empty(),
        )
        .await;
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

    // HEAD mirrors GET's headers without a body.
    let head = h
        .request("HEAD", "/alice/notes/a.ttl?linkset", None, Body::empty())
        .await;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(header_value(&head, "etag").unwrap(), etag);
    assert!(body_bytes(head).await.is_empty());

    // A non-preflight OPTIONS on the linkset URI advertises the LINKSET method surface, not the
    // LDP verb set (the roborev Low on 53296c0).
    let opt = h
        .request("OPTIONS", "/alice/notes/a.ttl?linkset", None, Body::empty())
        .await;
    assert_eq!(opt.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        header_value(&opt, "allow").unwrap(),
        "GET, HEAD, PATCH, OPTIONS"
    );
    assert_eq!(
        header_value(&opt, "accept-patch").unwrap(),
        "application/merge-patch+json"
    );
    // …while a plain resource's OPTIONS still advertises the full LDP verb set.
    let opt = h
        .request("OPTIONS", "/alice/notes/a.ttl", None, Body::empty())
        .await;
    assert!(header_value(&opt, "allow").unwrap().contains("PUT"));

    // A linkset of a MISSING resource is a 404 problem (post-authorization).
    let missing = h
        .request("GET", "/alice/notes/nope.ttl?linkset", None, Body::empty())
        .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        header_value(&missing, "content-type").unwrap(),
        "application/problem+json"
    );

    // An Accept that cannot take linkset+json is a 406 problem.
    let na = h
        .request_with(
            "GET",
            "/alice/notes/a.ttl?linkset",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    assert_eq!(na.status(), StatusCode::NOT_ACCEPTABLE);
}

#[tokio::test]
async fn linkset_merge_patch_full_flow() {
    let h = Harness::lws().await;
    h.request(
        "PUT",
        "/alice/doc.ttl",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let ls = h
        .request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
        .await;
    let etag0 = header_value(&ls, "etag").unwrap().to_string();

    // (1) No If-Match ⇒ 428 with the metadata-precondition problem (spec MUST).
    let no_precond = h
        .request(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            Body::from(
                r#"{"linkset":[{"describedby":[{"href":"https://pod.example/alice/meta"}]}]}"#,
            ),
        )
        .await;
    assert_eq!(no_precond.status(), StatusCode::PRECONDITION_REQUIRED);
    let problem = String::from_utf8(body_bytes(no_precond).await.to_vec()).unwrap();
    assert!(
        problem.contains("metadata-precondition-required"),
        "{problem}"
    );

    // (2) A non-merge-patch content type ⇒ 415 + Accept-Patch.
    let wrong_ct = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("text/n3"),
            &[("if-match", &etag0)],
            Body::from("{}"),
        )
        .await;
    assert_eq!(wrong_ct.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        header_value(&wrong_ct, "accept-patch").unwrap(),
        "application/merge-patch+json"
    );

    // (3) A stale If-Match ⇒ 412.
    let stale = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", "\"ls0-not-the-current-one\"")],
            Body::from("{}"),
        )
        .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);

    // (4) The real update: add a describedby + a custom absolute-URI relation. RFC 7386 array
    // semantics replace the whole context object, so the client echoes the system links
    // UNCHANGED (a no-op on them — allowed).
    let current = body_json(
        h.request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
            .await,
    )
    .await;
    let mut ctx = current["linkset"][0].clone();
    ctx["describedby"] =
        serde_json::json!([{ "href": "https://pod.example/alice/meta", "type": "text/turtle" }]);
    ctx["https://example.org/rel/source"] =
        serde_json::json!([{ "href": "https://upstream.example/orig" }]);
    let patch_doc = serde_json::json!({ "linkset": [ctx] });
    let ok = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", &etag0)],
            Body::from(patch_doc.to_string()),
        )
        .await;
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);
    let etag1 = header_value(&ok, "etag").unwrap().to_string();
    assert_ne!(etag1, etag0, "a successful update MUST rotate the ETag");
    assert!(etag1.starts_with("\"ls-"));

    // The update is visible on GET, beside the untouched system links.
    let after = h
        .request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
        .await;
    assert_eq!(header_value(&after, "etag").unwrap(), etag1);
    let doc = body_json(after).await;
    let ctx = &doc["linkset"][0];
    assert_eq!(
        ctx["describedby"][0]["href"],
        "https://pod.example/alice/meta"
    );
    assert_eq!(
        ctx["https://example.org/rel/source"][0]["href"],
        "https://upstream.example/orig"
    );
    assert_eq!(ctx["up"][0]["href"], "https://pod.example/alice/");

    // (5) The OLD etag no longer matches (lost-update protection) — a concurrent-writer replay
    // is a 412.
    let replay = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", &etag0)],
            Body::from("{}"),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::PRECONDITION_FAILED);

    // (6) Removal semantics. RFC 7386 nulls remove members only during OBJECT merging — but the
    // `linkset` member is an ARRAY, replaced wholesale, so a null inside the echoed context object
    // survives as a LITERAL null value ⇒ the strict validation rejects it (422). This pins the
    // array-replacement footgun the module docs call out…
    let nulls = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", &etag1)],
            Body::from(
                r#"{"linkset":[{"describedby":null,"https://example.org/rel/source":null}]}"#,
            ),
        )
        .await;
    assert_eq!(nulls.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // …the correct removal echoes the full context object WITHOUT the user members.
    let current = body_json(
        h.request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
            .await,
    )
    .await;
    let mut ctx = current["linkset"][0].clone();
    ctx.as_object_mut().unwrap().remove("describedby");
    ctx.as_object_mut()
        .unwrap()
        .remove("https://example.org/rel/source");
    let ok = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", &etag1)],
            Body::from(serde_json::json!({ "linkset": [ctx] }).to_string()),
        )
        .await;
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);
    let doc = body_json(
        h.request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
            .await,
    )
    .await;
    assert!(doc["linkset"][0].get("describedby").is_none());
}

#[tokio::test]
async fn linkset_rejects_system_managed_modifications_and_write_verbs() {
    let h = Harness::lws().await;
    h.request(
        "PUT",
        "/alice/doc.ttl",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let ls = h
        .request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
        .await;
    let etag = header_value(&ls, "etag").unwrap().to_string();
    let current = body_json(ls).await;

    // Retargeting `up` (a move attempt — the MoveResource capability is not offered) ⇒ 409 with
    // the spec-named system-managed-metadata problem.
    let mut ctx = current["linkset"][0].clone();
    ctx["up"] = serde_json::json!([{ "href": "https://pod.example/elsewhere/" }]);
    let resp = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", &etag)],
            Body::from(serde_json::json!({ "linkset": [ctx] }).to_string()),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let problem = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(problem.contains("system-managed-metadata"), "{problem}");
    // …and nothing changed.
    let after = h
        .request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
        .await;
    assert_eq!(header_value(&after, "etag").unwrap(), etag);

    // A relative/invalid href in a user relation ⇒ 422 (fail-closed validation).
    let mut ctx = current["linkset"][0].clone();
    ctx["describedby"] = serde_json::json!([{ "href": "/relative" }]);
    let resp = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", &etag)],
            Body::from(serde_json::json!({ "linkset": [ctx] }).to_string()),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Unparseable JSON ⇒ 400.
    let resp = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", &etag)],
            Body::from("{not json"),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // PUT/POST/DELETE on a linkset URI: 405 + Allow (the linkset's lifecycle is its resource's).
    for method in ["PUT", "POST", "DELETE"] {
        let resp = h
            .request(
                method,
                "/alice/doc.ttl?linkset",
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(
            header_value(&resp, "allow").unwrap(),
            "GET, HEAD, PATCH, OPTIONS",
            "{method}"
        );
    }

    // The resource itself is untouched by all of the above.
    let get = h
        .request("GET", "/alice/doc.ttl", None, Body::empty())
        .await;
    assert_eq!(get.status(), StatusCode::OK);
}

#[tokio::test]
async fn linkset_survives_content_rewrite_and_dies_with_the_resource() {
    let h = Harness::lws().await;
    h.request(
        "PUT",
        "/alice/doc.ttl",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    // Attach a user link.
    let ls = h
        .request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
        .await;
    let etag = header_value(&ls, "etag").unwrap().to_string();
    let current = body_json(ls).await;
    let mut ctx = current["linkset"][0].clone();
    ctx["describedby"] = serde_json::json!([{ "href": "https://pod.example/alice/meta" }]);
    let ok = h
        .request_with(
            "PATCH",
            "/alice/doc.ttl?linkset",
            Some("application/merge-patch+json"),
            &[("if-match", &etag)],
            Body::from(serde_json::json!({ "linkset": [ctx] }).to_string()),
        )
        .await;
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);

    // A content RE-WRITE preserves the user-managed metadata (independent lifecycles until DELETE).
    let rewrite = h
        .request(
            "PUT",
            "/alice/doc.ttl",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(rewrite.status(), StatusCode::NO_CONTENT);
    let doc = body_json(
        h.request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
            .await,
    )
    .await;
    assert_eq!(
        doc["linkset"][0]["describedby"][0]["href"],
        "https://pod.example/alice/meta"
    );

    // DELETE removes resource + linkset together (§metadata: MUST).
    let del = h
        .request("DELETE", "/alice/doc.ttl", None, Body::empty())
        .await;
    assert_eq!(del.status(), StatusCode::NO_CONTENT);
    let gone = h
        .request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
        .await;
    assert_eq!(gone.status(), StatusCode::NOT_FOUND);
    // A re-created resource starts with a FRESH (system-links-only) linkset.
    h.request(
        "PUT",
        "/alice/doc.ttl",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let doc = body_json(
        h.request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
            .await,
    )
    .await;
    assert!(
        doc["linkset"][0].get("describedby").is_none(),
        "no stale user links"
    );
}

#[tokio::test]
async fn linkset_is_read_gated_like_its_resource() {
    let h = Harness::lws().await;
    h.request(
        "PUT",
        "/alice/private.ttl",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    // Anonymous: the linkset of a private resource is a 401 (the same challenge as the resource),
    // NOT a metadata leak.
    let resp = h
        .unauth_request("GET", "/alice/private.ttl?linkset", None)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // And of a MISSING resource: the same 401 (no existence oracle through metadata).
    let resp = h
        .unauth_request("GET", "/alice/nope.ttl?linkset", None)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------------------------
// M3 §2 — paginated container listings + the member `size`
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn lws_listing_carries_size_and_stays_single_page_under_the_threshold() {
    let h = Harness::lws().await; // default page size (1000) — these listings are single-page
    h.request(
        "PUT",
        "/alice/notes/a.txt",
        Some("text/plain"),
        Body::from("four"),
    )
    .await;
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
    // No pagination links on a single-page listing.
    assert!(
        !link_values(&resp).iter().any(|l| l.contains("lws-page")),
        "single-page listings carry no page links"
    );
    let doc = body_json(resp).await;
    assert_eq!(doc["totalItems"], 1);
    let item = &doc["items"][0];
    assert_eq!(item["id"], "https://pod.example/alice/notes/a.txt");
    assert_eq!(item["mediaType"], "text/plain");
    assert_eq!(
        item["size"], 4,
        "the SHOULD-level byte length stamped at write time"
    );
}

#[tokio::test]
async fn lws_listing_paginates_deterministically_with_rfc8288_links() {
    let h = Harness::lws_paged(2).await;
    // Five members: pages of 2/2/1 in LEXICOGRAAPHIC order.
    for name in ["e.txt", "c.txt", "a.txt", "d.txt", "b.txt"] {
        let put = h
            .request(
                "PUT",
                &format!("/alice/notes/{name}"),
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }
    let ids_of = |doc: &serde_json::Value| -> Vec<String> {
        doc["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap().to_string())
            .collect()
    };

    // Page 1 (the bare container URI): first two members, first/next/last links, NO prev.
    let p1 = h
        .request_with(
            "GET",
            "/alice/notes/",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(p1.status(), StatusCode::OK);
    let links = link_values(&p1);
    assert!(
        links
            .iter()
            .any(|l| l == "<https://pod.example/alice/notes/?lws-page=1>; rel=\"first\""),
        "{links:?}"
    );
    assert!(
        links
            .iter()
            .any(|l| l == "<https://pod.example/alice/notes/?lws-page=2>; rel=\"next\""),
        "{links:?}"
    );
    assert!(
        links
            .iter()
            .any(|l| l == "<https://pod.example/alice/notes/?lws-page=3>; rel=\"last\""),
        "{links:?}"
    );
    assert!(
        !links.iter().any(|l| l.contains("rel=\"prev\"")),
        "{links:?}"
    );
    let etag1 = header_value(&p1, "etag").unwrap().to_string();
    let doc1 = body_json(p1).await;
    // totalItems counts the WHOLE visible membership on every page; items is the page.
    assert_eq!(doc1["totalItems"], 5);
    assert_eq!(
        ids_of(&doc1),
        vec![
            "https://pod.example/alice/notes/a.txt",
            "https://pod.example/alice/notes/b.txt"
        ]
    );

    // Page 2: prev+next+first+last; the middle slice.
    let p2 = h
        .request_with(
            "GET",
            "/alice/notes/?lws-page=2",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(p2.status(), StatusCode::OK);
    let links = link_values(&p2);
    assert!(
        links
            .iter()
            .any(|l| l.contains("lws-page=1>; rel=\"prev\"")),
        "{links:?}"
    );
    assert!(
        links
            .iter()
            .any(|l| l.contains("lws-page=3>; rel=\"next\"")),
        "{links:?}"
    );
    let etag2 = header_value(&p2, "etag").unwrap().to_string();
    assert_ne!(
        etag1, etag2,
        "each page is its own representation with its own validator"
    );
    let doc2 = body_json(p2).await;
    assert_eq!(doc2["totalItems"], 5);
    assert_eq!(
        ids_of(&doc2),
        vec![
            "https://pod.example/alice/notes/c.txt",
            "https://pod.example/alice/notes/d.txt"
        ]
    );

    // Page 3 (last): next MUST be omitted; the final member.
    let p3 = h
        .request_with(
            "GET",
            "/alice/notes/?lws-page=3",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    let links = link_values(&p3);
    assert!(
        !links.iter().any(|l| l.contains("rel=\"next\"")),
        "last page omits next: {links:?}"
    );
    assert!(links.iter().any(|l| l.contains("rel=\"first\"")));
    let doc3 = body_json(p3).await;
    assert_eq!(ids_of(&doc3), vec!["https://pod.example/alice/notes/e.txt"]);

    // NO member skipped or duplicated across the walk (the determinism pin).
    let mut walked = ids_of(&doc1);
    walked.extend(ids_of(&doc2));
    walked.extend(ids_of(&doc3));
    let mut expect: Vec<String> = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|n| format!("https://pod.example/alice/notes/{n}.txt"))
        .collect();
    expect.sort();
    assert_eq!(
        walked, expect,
        "pages tile the membership exactly — no skip, no dup"
    );

    // A page past the end: an EMPTY page (opaque URIs may outlive shrinkage), never an error.
    let past = h
        .request_with(
            "GET",
            "/alice/notes/?lws-page=9",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(past.status(), StatusCode::OK);
    let doc = body_json(past).await;
    assert_eq!(doc["items"].as_array().unwrap().len(), 0);
    assert_eq!(doc["totalItems"], 5);

    // An unusable page value: a 400 problem.
    let bad = h
        .request_with(
            "GET",
            "/alice/notes/?lws-page=zero",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // The SOLID rendering of the same container is completely untouched by pagination: the
    // Turtle listing still names every member, no page links.
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
    assert!(!link_values(&solid).iter().any(|l| l.contains("lws-page")));
    let ttl = String::from_utf8(body_bytes(solid).await.to_vec()).unwrap();
    for n in ["a", "b", "c", "d", "e"] {
        assert!(
            ttl.contains(&format!("{n}.txt")),
            "solid listing lists {n}.txt"
        );
    }
}

#[tokio::test]
async fn lws_gen_pin_is_honest_against_a_generation_less_backend() {
    // The snapshot-pin surface (sparq#1572 → sparq PR #1584) over a backend with NO generation
    // concept (this harness's in-memory store — same posture as the embedded engine or a
    // pre-#1584 sparq): (a) no pinned links are ever MINTED, and (b)+(c) ANY hand-crafted pin —
    // a bare generation integer and garbage alike — is the opaque 400 `invalid-generation`
    // problem, refused at the token-verification chokepoint BEFORE the backend is consulted
    // (prong 2 of `lws::container`'s disclosure closure: only a pin this server minted is ever
    // forwarded — the fail-closed honesty contract still holds: the server never silently serves
    // a DIFFERENT snapshot under a pinned URI). The 410 `snapshot-gone` restart now requires a
    // GENUINE minted token (expired TTL / backend-aged-out generation) and is pinned by
    // `an_expired_pin_is_the_410_snapshot_gone_restart` +
    // `a_verified_pin_the_backend_aged_out_is_410_snapshot_gone`.
    let h = Harness::lws_paged(2).await;
    for name in ["a.txt", "b.txt", "c.txt"] {
        let put = h
            .request(
                "PUT",
                &format!("/alice/notes/{name}"),
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }

    // (a) The paged listing's own links carry NO `lws-gen` (generation: None ⇒ unpinned links —
    // the graceful-degradation contract; a pinned link the server could not honour would strand
    // every walker at (b)).
    let p1 = h
        .request_with(
            "GET",
            "/alice/notes/",
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(p1.status(), StatusCode::OK);
    assert!(
        !link_values(&p1).iter().any(|l| l.contains("lws-gen")),
        "a generation-less backend must mint no pinned links: {:?}",
        link_values(&p1)
    );

    // (b)+(c) A hand-crafted pin — bare-integer or garbage — is the SAME opaque 400
    // `invalid-generation` problem (unminted; the backend is never consulted, so this backend
    // that could not honour a pin is never asked to).
    for forged in ["lws-page=2&lws-gen=7", "lws-gen=abc"] {
        let bad = h
            .request_with(
                "GET",
                &format!("/alice/notes/?{forged}"),
                None,
                &[("accept", LWS_JSON)],
                Body::empty(),
            )
            .await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST, "{forged}");
        assert_eq!(
            header_value(&bad, "content-type").unwrap(),
            "application/problem+json"
        );
        let problem = body_json(bad).await;
        assert_eq!(
            problem["type"],
            "https://w3id.org/jeswr/lws/problems/invalid-generation",
            "{forged}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// M3 §flag-off — byte-invariance pins for every new query surface
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn flag_off_ignores_linkset_and_page_queries_byte_identically() {
    let h = Harness::flag_off().await;
    h.request(
        "PUT",
        "/alice/doc.ttl",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;

    // `?linkset` serves THE RESOURCE exactly as the bare URI does (queries were never inspected).
    let bare = h
        .request("GET", "/alice/doc.ttl", None, Body::empty())
        .await;
    let with_query = h
        .request("GET", "/alice/doc.ttl?linkset", None, Body::empty())
        .await;
    assert_eq!(bare.status(), StatusCode::OK);
    assert_eq!(with_query.status(), StatusCode::OK);
    assert_eq!(
        header_value(&with_query, "content-type"),
        header_value(&bare, "content-type")
    );
    assert!(
        !link_values(&with_query)
            .iter()
            .any(|l| l.contains("linkset")),
        "no linkset link rides when the flag is off"
    );
    let (b1, b2) = (body_bytes(bare).await, body_bytes(with_query).await);
    assert_eq!(
        b1, b2,
        "flag-off: ?linkset is byte-identical to the bare GET"
    );

    // Writes to `?linkset` URIs hit the RESOURCE path unchanged (a PUT replaces the doc).
    let put = h
        .request(
            "PUT",
            "/alice/doc.ttl?linkset",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(
        put.status(),
        StatusCode::NO_CONTENT,
        "flag-off PUT is the plain resource PUT"
    );

    // `?lws-page` on a container GET changes nothing.
    let c1 = h
        .request_with(
            "GET",
            "/alice/",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    let c2 = h
        .request_with(
            "GET",
            "/alice/?lws-page=2",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    // …and `?lws-gen` (the snapshot pin) is likewise never inspected when the flag is off.
    let c3 = h
        .request_with(
            "GET",
            "/alice/?lws-page=2&lws-gen=7",
            None,
            &[("accept", "text/turtle")],
            Body::empty(),
        )
        .await;
    assert_eq!(c1.status(), StatusCode::OK);
    assert_eq!(c2.status(), StatusCode::OK);
    assert_eq!(c3.status(), StatusCode::OK);
    let b1 = body_bytes(c1).await;
    assert_eq!(b1, body_bytes(c2).await);
    assert_eq!(b1, body_bytes(c3).await);

    // And the 201 create response carries NO LWS links.
    let put = h
        .request(
            "PUT",
            "/alice/fresh.ttl",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    assert!(
        link_values(&put).is_empty(),
        "flag-off 201 carries no Link headers"
    );
}

// ---------------------------------------------------------------------------------------------
// Pinned listings × live WAC — the deleted-member metadata-disclosure closure (two prongs; see
// `src/lws/container.rs`'s module doc and `LdpState::authorize_listing_member`)
// ---------------------------------------------------------------------------------------------

/// The snapshot ledger behind [`PinningStore`]: (container, generation) → the members served at
/// that generation. Exposed on [`Harness::pins`] so a test can age a snapshot out (the backend
/// retention window).
#[derive(Default)]
struct PinState {
    next_gen: u64,
    snaps: std::collections::HashMap<
        (String, u64),
        Vec<(
            solid_server_rs::store::ValidatedChildIri,
            solid_server_rs::store::ResourceMeta,
        )>,
    >,
}

/// A GENERATION-CAPABLE store double modelling sparq PR #1584's snapshot surface at the `Store`
/// seam (the in-memory backend has no generation concept): an UNPINNED listing captures the
/// current members under a fresh monotonic generation and advertises it; a PINNED listing replays
/// the captured snapshot EXACTLY — the full `(IRI, ResourceMeta)` rows, `blob_key`/`size`/
/// `modified` included — or fails with the 410 `snapshot-gone` problem for a generation it no
/// longer holds — never a silent substitute. Every other method delegates to the shared composite
/// store, so authorization/`read_plan` always see the CURRENT state (exactly the live posture the
/// disclosure regressions depend on). Replaying the pinned METADATA verbatim while `read_plan`
/// reads live is what lets this double reproduce the round-5 metadata-STALENESS axis: a pinned
/// walk taken after a member is rewritten/recreated serves rows whose `blob_key` + size +
/// modified genuinely differ from the live incarnation the WAC walk authorizes.
struct PinningStore {
    inner: Arc<TestStore>,
    state: Arc<std::sync::Mutex<PinState>>,
}

#[async_trait::async_trait]
impl Store for PinningStore {
    async fn read(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::Resource> {
        self.inner.read(iri).await
    }
    async fn meta(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<Option<solid_server_rs::store::ResourceMeta>> {
        self.inner.meta(iri).await
    }
    async fn exists(&self, iri: &str) -> solid_server_rs::ServerResult<bool> {
        self.inner.exists(iri).await
    }
    async fn write(
        &self,
        iri: &str,
        body: Bytes,
        content_type: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ResourceMeta> {
        self.inner.write(iri, body, content_type).await
    }
    async fn create_in_container(
        &self,
        container: &str,
        child: &str,
        body: Bytes,
        content_type: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ResourceMeta> {
        self.inner
            .create_in_container(container, child, body, content_type)
            .await
    }
    async fn delete(&self, iri: &str, parent: Option<&str>) -> solid_server_rs::ServerResult<()> {
        self.inner.delete(iri, parent).await
    }
    async fn delete_container_if_empty(
        &self,
        iri: &str,
        parent: Option<&str>,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::DeleteOutcome> {
        self.inner.delete_container_if_empty(iri, parent).await
    }
    async fn list_children(
        &self,
        container: &str,
    ) -> solid_server_rs::ServerResult<Vec<solid_server_rs::store::ValidatedChildIri>> {
        self.inner.list_children(container).await
    }
    async fn read_plan(
        &self,
        target: &str,
        acl_candidates: &[String],
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ReadPlan> {
        // ALWAYS the current state — never the snapshot. This is the seam the current-existence
        // guard + the live WAC walk read through.
        self.inner.read_plan(target, acl_candidates).await
    }
    async fn read_at(
        &self,
        iri: &str,
        meta: &solid_server_rs::store::ResourceMeta,
    ) -> solid_server_rs::ServerResult<Bytes> {
        self.inner.read_at(iri, meta).await
    }
    async fn get_linkset(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<Option<(String, String)>> {
        self.inner.get_linkset(iri).await
    }
    async fn set_linkset(
        &self,
        iri: &str,
        json: &str,
        new_rev: &str,
        expected: solid_server_rs::store::LinksetCas<'_>,
    ) -> solid_server_rs::ServerResult<bool> {
        self.inner.set_linkset(iri, json, new_rev, expected).await
    }
    async fn list_children_snapshot(
        &self,
        container: &str,
        pin: Option<u64>,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ListingSnapshot> {
        match pin {
            None => {
                let snap = self.inner.list_children_snapshot(container, None).await?;
                let mut st = self.state.lock().expect("pin state lock");
                let g = st.next_gen;
                st.next_gen += 1;
                st.snaps
                    .insert((container.to_string(), g), snap.members.clone());
                Ok(solid_server_rs::store::ListingSnapshot {
                    members: snap.members,
                    generation: Some(g),
                })
            }
            Some(g) => {
                let st = self.state.lock().expect("pin state lock");
                match st.snaps.get(&(container.to_string(), g)) {
                    Some(members) => Ok(solid_server_rs::store::ListingSnapshot {
                        members: members.clone(),
                        generation: Some(g),
                    }),
                    // Aged out / never minted here: the restartable 410, mirroring the live
                    // client's SnapshotGone mapping.
                    None => Err(solid_server_rs::ServerError::LwsProblem {
                        status: 410,
                        type_uri: solid_server_rs::lws::PROBLEM_SNAPSHOT_GONE,
                        title: "the pagination snapshot is no longer available; restart from \
                                the container URI (an unpinned first page)",
                    }),
                }
            }
        }
    }
}

impl Harness {
    /// A GENERATION-CAPABLE paged harness: LWS on, page size `page_size`, snapshots served by
    /// [`PinningStore`] (so the server MINTS authenticated `lws-gen` tokens), pin-token TTL
    /// `pin_ttl_secs` (0 ⇒ every minted token is already expired — the deterministic 410 hook).
    async fn lws_pinned(page_size: usize, pin_ttl_secs: u64) -> Self {
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
        let pins = Arc::new(std::sync::Mutex::new(PinState::default()));
        let mut ldp = LdpState::new(
            PinningStore {
                inner: store.clone(),
                state: pins.clone(),
            },
            BASE_URL,
        );
        ldp.set_lws(Some(Arc::new(
            LwsConfig::new(BASE_URL, true, false)
                .with_page_size(std::num::NonZeroUsize::new(page_size))
                .with_pin_ttl_secs(pin_ttl_secs),
        )));
        let app = build_router(AppState::new(ctx, ldp));
        Self {
            app,
            issuer_key,
            client_key,
            store,
            pins: Some(pins),
        }
    }
}

/// Extract the server-minted `lws-gen` token from a response's own pagination links (every pinned
/// link carries the same token).
fn pin_token(resp: &axum::http::Response<Body>) -> Option<String> {
    link_values(resp).iter().find_map(|l| {
        let (_, rest) = l.split_once("lws-gen=")?;
        Some(rest.split('>').next().unwrap_or("").to_string())
    })
}

/// The member `id`s of a listing document.
fn item_ids(doc: &serde_json::Value) -> Vec<String> {
    doc["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|i| i["id"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn pinned_listing_never_discloses_a_member_deleted_since_the_snapshot() {
    // THE regression (adversarial-verify HIGH, independently flagged by codex — prong 1):
    // `/notes/` carries the root's `acl:default` Read for Alice; `/notes/secret.txt` existed at
    // generation G under a RESTRICTIVE own ACL (Bob-only), so Alice's gen-G listing correctly
    // OMITS it. The member (and its `.acl`) is then DELETED. Alice re-requests the walk pinned to
    // G with the token the server handed HER: the snapshot still contains the member + its
    // metadata, and live WAC on the now-deleted IRI would fall back to the permissive ancestor
    // `acl:default` — the current-existence guard must EXCLUDE it, disclosing nothing.
    let h = Harness::lws_pinned(2, 300).await;
    for name in ["a.txt", "b.txt", "c.txt", "secret.txt"] {
        let put = h
            .request(
                "PUT",
                &format!("/notes/{name}"),
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }
    const SECRET: &str = "https://pod.example/notes/secret.txt";
    const BOB: &str = "https://pod.example/bob/profile/card#me";
    // The restrictive OWN ACL (nearest-first: it fully overrides the root default): Bob only.
    let secret_acl = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#bob> a acl:Authorization;
       acl:agent <{BOB}>;
       acl:accessTo <{SECRET}>;
       acl:mode acl:Read, acl:Write."#
    );
    h.store
        .write(&format!("{SECRET}.acl"), Bytes::from(secret_acl), "text/turtle")
        .await
        .expect("seed the secret's own ACL");

    // Gen G: Alice's listing — secret.txt is invisible to her (live WAC), the walk is pinned.
    let p1 = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(p1.status(), StatusCode::OK);
    let token = pin_token(&p1).expect("a generation-capable backend mints pinned links");
    assert!(
        token.matches('.').count() == 2 && token.len() > 64,
        "the pin is the authenticated g.exp.mac token, never a bare integer: {token}"
    );
    let doc1 = body_json(p1).await;
    assert_eq!(doc1["totalItems"], 3, "a, b, c visible; secret denied live");

    // Bob deletes the member AND its ACL (directly through the store — the server-side state
    // change; Alice could not).
    h.store
        .delete(SECRET, Some("https://pod.example/notes/"))
        .await
        .expect("delete the secret member");
    h.store
        .delete(&format!("{SECRET}.acl"), None)
        .await
        .expect("delete its own ACL");

    // Alice walks the SAME pinned snapshot. The gen-G membership still contains secret.txt; the
    // guard must exclude it — never authorize it via the root acl:default fallback.
    let mut walked: Vec<String> = Vec::new();
    let mut raw_bodies = String::new();
    for page in 1..=2 {
        let resp = h
            .request_with(
                "GET",
                &format!("/notes/?lws-page={page}&lws-gen={token}"),
                None,
                &[("accept", LWS_JSON)],
                Body::empty(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "pinned page {page}");
        let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        raw_bodies.push_str(&body);
        let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            doc["totalItems"], 3,
            "the deleted member must not join the visible count"
        );
        walked.extend(item_ids(&doc));
    }
    assert!(
        !walked.iter().any(|id| id.contains("secret")),
        "REGRESSION: the deleted, formerly-denied member must be excluded from the pinned \
         listing, not authorized via the ancestor acl:default fallback — got {walked:?}"
    );
    assert!(
        !raw_bodies.contains("secret"),
        "no byte of the pinned pages may disclose the deleted member (IRI or metadata)"
    );
    // …and no over-exclusion: the legitimately-visible members all still tile the walk.
    let mut expect: Vec<String> = ["a", "b", "c"]
        .iter()
        .map(|n| format!("https://pod.example/notes/{n}.txt"))
        .collect();
    expect.sort();
    walked.sort();
    assert_eq!(walked, expect, "a, b, c remain visible across the pinned walk");

    // The PRESERVED design: WAC stays LIVE for still-existing members — a revocation lands on the
    // very next pinned request (the pin never freezes an ACL). Clamp c.txt to Bob-only mid-walk.
    const C: &str = "https://pod.example/notes/c.txt";
    let c_acl = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#bob> a acl:Authorization;
       acl:agent <{BOB}>;
       acl:accessTo <{C}>;
       acl:mode acl:Read."#
    );
    h.store
        .write(&format!("{C}.acl"), Bytes::from(c_acl), "text/turtle")
        .await
        .expect("revoke Alice on c.txt mid-walk");
    let resp = h
        .request_with(
            "GET",
            &format!("/notes/?lws-page=1&lws-gen={token}"),
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(
        doc["totalItems"], 2,
        "live revocation applies inside the pinned walk (a, b only)"
    );
    assert!(
        !item_ids(&doc).iter().any(|id| id.contains("c.txt")),
        "the still-existing-but-revoked member is omitted by the LIVE walk"
    );
}

/// The RACE-MODELLING store double for the listing-member TOCTOU regressions (the incarnation
/// re-bind in `LdpState::authorize_listing_member`): delegates everything to the shared composite
/// store, except that the FIRST `read_plan` targeting `victim` returns the CURRENT (pre-delete)
/// rows and then IMMEDIATELY deletes the victim + its own `.acl` from the inner store — so the
/// member is PRESENT at plan time (T0) and GONE by the time the planned walk's LIVE ACL
/// re-confirm (`read_acl_confirmed`, T2) and every later probe run. This is the deterministic
/// model of "member deleted BETWEEN the initial `read_plan` and the live ACL confirmation" — the
/// interleaving that reopened the deleted-member disclosure HIGH.
///
/// The OPTIONAL second act (`recreate_acl: Some(_)`) models the delete + same-IRI RECREATE race
/// (round 4 — the residual an independent re-verify + codex found in the exists-probe closure):
/// the first live `meta` probe of the deleted victim's own `.acl` that observes it ABSENT is, by
/// construction, the walk's `read_acl_confirmed` (T2) — the double then IMMEDIATELY recreates the
/// victim under the SAME IRI with `recreate_acl` as its (still-restrictive) own ACL (T2.5), so a
/// later bare existence probe (the OLD T3 guard) answers `true` for a DIFFERENT incarnation than
/// the one the ACL decision was computed against.
struct RaceDeletingStore {
    inner: Arc<TestStore>,
    victim: String,
    victim_parent: String,
    fired: std::sync::atomic::AtomicBool,
    /// `Some(acl-body)` ⇒ the recreate arm is armed (see the struct doc's second act).
    recreate_acl: Option<String>,
    recreated: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl Store for RaceDeletingStore {
    async fn read(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::Resource> {
        self.inner.read(iri).await
    }
    async fn meta(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<Option<solid_server_rs::store::ResourceMeta>> {
        let out = self.inner.meta(iri).await;
        // T2.5 — the recreate arm: the walk's live own-ACL re-confirm (T2) has just observed the
        // deleted victim's `.acl` as ABSENT; recreate the victim (a NEW incarnation, same IRI)
        // with a restrictive own ACL BEFORE any later probe runs. One-shot.
        if let Some(acl_body) = &self.recreate_acl {
            if self.fired.load(std::sync::atomic::Ordering::SeqCst)
                && iri == format!("{}.acl", self.victim)
                && matches!(out, Ok(None))
                && !self
                    .recreated
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                self.inner
                    .write(&self.victim, Bytes::from("recreated"), "text/plain")
                    .await
                    .expect("race recreate: member");
                self.inner
                    .write(
                        &format!("{}.acl", self.victim),
                        Bytes::from(acl_body.clone()),
                        "text/turtle",
                    )
                    .await
                    .expect("race recreate: own acl");
            }
        }
        out
    }
    async fn exists(&self, iri: &str) -> solid_server_rs::ServerResult<bool> {
        self.inner.exists(iri).await
    }
    async fn write(
        &self,
        iri: &str,
        body: Bytes,
        content_type: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ResourceMeta> {
        self.inner.write(iri, body, content_type).await
    }
    async fn create_in_container(
        &self,
        container: &str,
        child: &str,
        body: Bytes,
        content_type: &str,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ResourceMeta> {
        self.inner
            .create_in_container(container, child, body, content_type)
            .await
    }
    async fn delete(&self, iri: &str, parent: Option<&str>) -> solid_server_rs::ServerResult<()> {
        self.inner.delete(iri, parent).await
    }
    async fn delete_container_if_empty(
        &self,
        iri: &str,
        parent: Option<&str>,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::DeleteOutcome> {
        self.inner.delete_container_if_empty(iri, parent).await
    }
    async fn list_children(
        &self,
        container: &str,
    ) -> solid_server_rs::ServerResult<Vec<solid_server_rs::store::ValidatedChildIri>> {
        self.inner.list_children(container).await
    }
    async fn read_plan(
        &self,
        target: &str,
        acl_candidates: &[String],
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ReadPlan> {
        // T0: the plan observes the CURRENT rows (victim + its restrictive own-ACL present)…
        let plan = self.inner.read_plan(target, acl_candidates).await?;
        if target == self.victim && !self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
            // …then T1 — the race: the member AND its own ACL vanish AFTER the plan observed
            // them and BEFORE any LATER live probe (the walk's ACL re-confirm, the re-bind
            // confirm plan) runs. Only the FIRST victim-targeted plan races: subsequent
            // `read_plan`s (the re-bind confirm, later rounds) observe the true store.
            self.inner
                .delete(&self.victim, Some(&self.victim_parent))
                .await
                .expect("race delete: member");
            self.inner
                .delete(&format!("{}.acl", self.victim), None)
                .await
                .expect("race delete: own acl");
        }
        Ok(plan)
    }
    async fn read_at(
        &self,
        iri: &str,
        meta: &solid_server_rs::store::ResourceMeta,
    ) -> solid_server_rs::ServerResult<Bytes> {
        self.inner.read_at(iri, meta).await
    }
    async fn get_linkset(
        &self,
        iri: &str,
    ) -> solid_server_rs::ServerResult<Option<(String, String)>> {
        self.inner.get_linkset(iri).await
    }
    async fn set_linkset(
        &self,
        iri: &str,
        json: &str,
        new_rev: &str,
        expected: solid_server_rs::store::LinksetCas<'_>,
    ) -> solid_server_rs::ServerResult<bool> {
        self.inner.set_linkset(iri, json, new_rev, expected).await
    }
    async fn list_children_snapshot(
        &self,
        container: &str,
        pin: Option<u64>,
    ) -> solid_server_rs::ServerResult<solid_server_rs::store::ListingSnapshot> {
        self.inner.list_children_snapshot(container, pin).await
    }
}

impl Harness {
    /// A RACE harness: LWS on, single-page, the store wrapped in [`RaceDeletingStore`] so
    /// `victim` (+ its own `.acl`) is deleted between the listing member's `read_plan` (T0) and
    /// the walk's live ACL re-confirm (T2). `recreate_acl: Some(_)` arms the double's second
    /// act — the victim is RECREATED under the same IRI (with that own-ACL body) immediately
    /// after the T2 re-confirm observed its `.acl` absent (the delete+recreate race).
    async fn lws_racing(
        victim: &str,
        victim_parent: &str,
        recreate_acl: Option<String>,
    ) -> Self {
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
        let mut ldp = LdpState::new(
            RaceDeletingStore {
                inner: store.clone(),
                victim: victim.to_string(),
                victim_parent: victim_parent.to_string(),
                fired: std::sync::atomic::AtomicBool::new(false),
                recreate_acl,
                recreated: std::sync::atomic::AtomicBool::new(false),
            },
            BASE_URL,
        );
        ldp.set_lws(Some(Arc::new(LwsConfig::new(BASE_URL, true, false))));
        let app = build_router(AppState::new(ctx, ldp));
        Self {
            app,
            issuer_key,
            client_key,
            store,
            pins: None,
        }
    }
}

#[tokio::test]
async fn member_deleted_between_read_plan_and_live_acl_confirm_is_not_disclosed() {
    // THE TOCTOU regression (independent adversarial re-verify + codex — the race that REOPENED
    // the deleted-member disclosure HIGH the T0-only existence guard closed): the guard observed
    // existence exactly once, from the T0 `read_plan` target row, BEFORE `authorize_planned` —
    // whose `read_acl_confirmed` deliberately re-probes the found ACL LIVE at a LATER T2.
    // Sequence: (T0) `/notes/secret.txt` + its restrictive Bob-only own-ACL both present → the
    // plan's target row is Some, the guard passes; (T1) member + own-ACL both DELETED; (T2) the
    // live own-ACL re-confirm finds it gone → the walk falls back to the root's PERMISSIVE
    // `acl:default` → Allow → the deleted member's snapshot metadata is disclosed to Alice, whom
    // the own-ACL denied. The fix re-binds the decision strictly AFTER the ACL resolution: the
    // confirm re-plan finds the member's target row gone (existence is part of the confirm), so
    // the vanished member can never ride the ancestor-default fallback.
    //
    // MUTATION CHECK (verified by construction): with the post-decision re-bind confirm in
    // `LdpState::authorize_listing_member` removed, this test FAILS — the listing includes
    // secret.txt (totalItems 2) via the ancestor `acl:default` fallback, reproducing the
    // disclosure. The T0 guard alone CANNOT catch it: the race double serves the pre-delete plan.
    let h = Harness::lws_racing(
        "https://pod.example/notes/secret.txt",
        "https://pod.example/notes/",
        None,
    )
    .await;
    for name in ["a.txt", "secret.txt"] {
        let put = h
            .request(
                "PUT",
                &format!("/notes/{name}"),
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }
    const SECRET: &str = "https://pod.example/notes/secret.txt";
    const BOB: &str = "https://pod.example/bob/profile/card#me";
    // The restrictive OWN ACL (nearest-first: it fully overrides the root default): Bob only —
    // Alice (the requester) is DENIED on the member while it exists.
    let secret_acl = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#bob> a acl:Authorization;
       acl:agent <{BOB}>;
       acl:accessTo <{SECRET}>;
       acl:mode acl:Read, acl:Write."#
    );
    h.store
        .write(
            &format!("{SECRET}.acl"),
            Bytes::from(secret_acl),
            "text/turtle",
        )
        .await
        .expect("seed the secret's own ACL");

    // Alice lists /notes/. The snapshot captures BOTH members (secret still exists); secret's
    // per-member authorization then races: plan-present at T0, deleted (with its ACL) at T1,
    // live ACL confirm at T2 falls back to the permissive root default. The re-bind confirm plan
    // must exclude it — never disclose the deleted member's IRI or metadata.
    let resp = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        doc["totalItems"], 1,
        "the mid-race-deleted member must not join the visible count"
    );
    assert_eq!(
        item_ids(&doc),
        vec!["https://pod.example/notes/a.txt".to_string()],
        "only the untouched member is visible"
    );
    assert!(
        !body.contains("secret"),
        "REGRESSION (TOCTOU): a member deleted between the initial read_plan and the live ACL \
         confirmation must be EXCLUDED, not authorized via the ancestor acl:default fallback — \
         no byte of the listing may disclose it"
    );

    // …and the race is one-shot: a fresh listing (member genuinely gone throughout) is identical —
    // no over-exclusion, no error.
    let resp = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["totalItems"], 1);
}

#[tokio::test]
async fn member_deleted_and_recreated_in_the_decision_window_is_not_disclosed() {
    // THE DELETE + SAME-IRI RECREATE race (round 4 — the residual an independent adversarial
    // re-verify + codex found in the exists-probe closure): (T0) `/notes/secret.txt` + its
    // restrictive Bob-only own-ACL both present — the plan observes them; (T1) member + own-ACL
    // DELETED; (T2) the walk's live own-ACL re-confirm finds it gone → the walk falls back to the
    // root's PERMISSIVE `acl:default` → Allow, a decision computed while the member was ABSENT;
    // (T2.5) the member is RECREATED under the SAME IRI with a restrictive own-ACL that STILL
    // denies Alice; (T3) a bare existence probe now answers `true` — for a DIFFERENT incarnation
    // than the one the Allow was bound to. The OLD guard (`Allow && exists`) served the pinned
    // snapshot's metadata to Alice, whom BOTH the old AND the recreated own-ACL deny — the
    // invariant "disclosed only if it exists AND live WAC grants Read on it" held at NO instant.
    //
    // The fix RE-BINDS the decision to the live incarnation: a positive Allow is served only when
    // a SECOND full `read_plan`, taken strictly AFTER the decision, is IDENTICAL to the one the
    // decision consumed (`ResourceMeta` carries the per-write-unique `blob_key`, so ANY recreate
    // is a visible incarnation change). Here the confirm plan differs → the walk re-runs on the
    // RECREATED incarnation's rows → its restrictive own-ACL denies Alice → the member is
    // EXCLUDED.
    //
    // MUTATION CHECK (run against the pre-fix guard — `matches!(decision, Allow) &&
    // !store.exists(member)` with no re-bind): this test FAILS — the listing includes secret.txt
    // (totalItems 2) via the ancestor `acl:default` fallback, reproducing the disclosure. The
    // recreate makes the bare T3 existence probe TRUE, so only the incarnation re-bind catches it.
    const SECRET: &str = "https://pod.example/notes/secret.txt";
    const BOB: &str = "https://pod.example/bob/profile/card#me";
    // The recreated incarnation's own ACL: Bob only — Alice (the requester) is STILL denied.
    let recreated_acl = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#bob> a acl:Authorization;
       acl:agent <{BOB}>;
       acl:accessTo <{SECRET}>;
       acl:mode acl:Read, acl:Write."#
    );
    let h = Harness::lws_racing(
        SECRET,
        "https://pod.example/notes/",
        Some(recreated_acl.clone()),
    )
    .await;
    for name in ["a.txt", "secret.txt"] {
        let put = h
            .request(
                "PUT",
                &format!("/notes/{name}"),
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }
    // The ORIGINAL incarnation's restrictive own ACL (same shape): Alice denied at T0 too.
    h.store
        .write(
            &format!("{SECRET}.acl"),
            Bytes::from(recreated_acl),
            "text/turtle",
        )
        .await
        .expect("seed the secret's own ACL");

    // Alice lists /notes/. The snapshot captures BOTH members; secret's per-member authorization
    // then races through delete (T1) → fallback-Allow (T2) → recreate (T2.5). The re-bound
    // authorization must exclude it — never disclose the OLD incarnation's metadata.
    let resp = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        doc["totalItems"], 1,
        "the deleted-and-recreated member must not join the visible count"
    );
    assert_eq!(
        item_ids(&doc),
        vec!["https://pod.example/notes/a.txt".to_string()],
        "only the untouched member is visible"
    );
    assert!(
        !body.contains("secret"),
        "REGRESSION (delete+recreate TOCTOU): a member recreated under the same IRI inside the \
         decision window must be EXCLUDED — the absent-incarnation fallback Allow must never be \
         served against the recreated incarnation's existence"
    );
    // The race genuinely fired: the recreated incarnation EXISTS at the current store state —
    // i.e. the OLD bare existence probe would have answered `true` and served the leak.
    assert!(
        h.store.exists(SECRET).await.expect("exists probe"),
        "test-model check: the recreate must have landed (else this exercises the plain-delete \
         race, not the recreate residual)"
    );

    // No over-exclusion and no error afterwards: a fresh listing re-lists the untouched member
    // (the recreated victim carries no containment edge — `write` restores the record, not the
    // membership — so only a.txt is authoritative membership either way).
    let resp = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["totalItems"], 1);
}

#[tokio::test]
async fn pinned_listing_never_serves_stale_metadata_for_a_member_changed_since_the_snapshot() {
    // THE METADATA-STALENESS regression (round 5 — the residual an independent adversarial
    // re-verify found surviving rounds 1–4): the guard authorized the LIVE incarnation and the
    // re-bind loop compared two LIVE plans to each other, but NOTHING ever compared the live
    // incarnation to the SNAPSHOT incarnation whose metadata the listing actually SERVES. So a
    // member deleted+RECREATED (or simply REWRITTEN) at the same IRI with a now-PERMISSIVE
    // effective ACL between generation G and the request was re-walked, GRANTED on the NEW
    // incarnation → Allow → and served the gen-G OLD row: a big confidential file the requester
    // was DENIED at G, replaced by a tiny public note, handed the requester the dump's size +
    // write-time out of the pin.
    //
    // The double: `PinningStore` (generation-aware — the in-memory/embedded backends have no
    // generation concept) replays the FULL gen-G member rows VERBATIM (blob_key_OLD, old
    // size/modified) while every `read_plan` reads the live inner store (blob_key_NEW,
    // permissive ACL) — exactly the snapshot-vs-live divergence this axis needs.
    //
    // The fix: `authorize_listing_member` is handed the SNAPSHOT row's `blob_key` and serves an
    // Allow only when the live plan's `blob_key` EQUALS it (keys are minted unique per write, so
    // equality proves the member is unchanged since the snapshot and the pinned row IS the
    // incarnation live WAC just authorized). On mismatch the member is OMITTED fail-closed.
    //
    // MUTATION CHECK (why this test isolates exactly the snapshot comparison): the UNPINNED
    // control below proves live WAC ALLOWS both changed members' new incarnations (they are
    // listed, with the NEW metadata), and both members exist with rotated blob keys — so
    // existence, live WAC, and the live-vs-live re-bind all PASS for them. With the
    // snapshot-`blob_key` comparison removed, nothing else stands between the gen-G rows and the
    // pinned pages: both members would be listed with the OLD sizes, failing the assertions
    // below (this reproduces F1).
    let h = Harness::lws_pinned(2, 300).await;
    // Visible members (Alice, via the root default): a, b, c — 3 > page-size 2, so the walk is
    // paged and a pin token is minted.
    for name in ["a.txt", "b.txt", "c.txt"] {
        let put = h
            .request(
                "PUT",
                &format!("/notes/{name}"),
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }
    const SECRET: &str = "https://pod.example/notes/secret.txt";
    const LOOSENED: &str = "https://pod.example/notes/loosened.txt";
    const BOB: &str = "https://pod.example/bob/profile/card#me";
    let bob_only = |target: &str| {
        format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#bob> a acl:Authorization;
       acl:agent <{BOB}>;
       acl:accessTo <{target}>;
       acl:mode acl:Read, acl:Write."#
        )
    };
    // The gen-G incarnations: BIG confidential bodies (distinctive sizes 4096 / 8192) under
    // restrictive Bob-only own ACLs — Alice (the requester) is DENIED both at G.
    let put = h
        .request(
            "PUT",
            "/notes/secret.txt",
            Some("text/plain"),
            Body::from("C".repeat(4096)),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let put = h
        .request(
            "PUT",
            "/notes/loosened.txt",
            Some("text/plain"),
            Body::from("D".repeat(8192)),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    for target in [SECRET, LOOSENED] {
        h.store
            .write(
                &format!("{target}.acl"),
                Bytes::from(bob_only(target)),
                "text/turtle",
            )
            .await
            .expect("seed the restrictive own ACL");
    }
    let old_secret_key = h.store.meta(SECRET).await.unwrap().expect("seeded").blob_key;
    let old_loosened_key = h
        .store
        .meta(LOOSENED)
        .await
        .unwrap()
        .expect("seeded")
        .blob_key;

    // Gen G: Alice's pinned walk starts — she sees a, b, c only; the snapshot (with the OLD
    // secret/loosened rows) is captured behind the minted token.
    let p1 = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(p1.status(), StatusCode::OK);
    let token = pin_token(&p1).expect("a generation-capable backend mints pinned links");
    let doc1 = body_json(p1).await;
    assert_eq!(doc1["totalItems"], 3, "a, b, c visible; the big members denied live at G");

    // The changes since the snapshot — both flip the requester's live access to PERMISSIVE:
    // (1) secret.txt: deleted (own ACL with it) and RECREATED at the same IRI as a tiny PUBLIC
    //     note (no own ACL ⇒ the root's permissive acl:default now grants Alice) — the brief's
    //     worked case;
    // (2) loosened.txt: REWRITTEN in place (every write mints a fresh blob_key) and its own ACL
    //     replaced with one granting Alice — the modify + ACL-loosen variant.
    h.store
        .delete(SECRET, Some("https://pod.example/notes/"))
        .await
        .expect("delete the confidential member");
    h.store
        .delete(&format!("{SECRET}.acl"), None)
        .await
        .expect("delete its own ACL");
    let put = h
        .request(
            "PUT",
            "/notes/secret.txt",
            Some("text/plain"),
            Body::from("pub"),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED, "the public recreate");
    h.store
        .write(LOOSENED, Bytes::from("ok"), "text/plain")
        .await
        .expect("rewrite the member in place");
    let alice_acl = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#alice> a acl:Authorization;
         acl:agent <{}>;
         acl:accessTo <{LOOSENED}>;
         acl:mode acl:Read."#,
        common::WEBID
    );
    h.store
        .write(&format!("{LOOSENED}.acl"), Bytes::from(alice_acl), "text/turtle")
        .await
        .expect("loosen the own ACL to grant Alice");
    // Test-model checks: both members EXIST live, as NEW incarnations (rotated blob keys) — the
    // shape on which existence + live WAC + the live-vs-live re-bind all pass.
    let new_secret_key = h.store.meta(SECRET).await.unwrap().expect("recreated").blob_key;
    let new_loosened_key = h
        .store
        .meta(LOOSENED)
        .await
        .unwrap()
        .expect("rewritten")
        .blob_key;
    assert_ne!(old_secret_key, new_secret_key, "the recreate minted a new incarnation");
    assert_ne!(old_loosened_key, new_loosened_key, "the rewrite minted a new incarnation");

    // THE UNPINNED CONTROL (mutation-check half): a FRESH walk lists BOTH changed members to
    // Alice with the NEW metadata — live WAC genuinely allows the new incarnations, so the only
    // thing that can keep the OLD rows out of the pinned pages is the snapshot-incarnation
    // comparison. (Fresh snapshot ⇒ snapshot rows == live rows ⇒ the guard's blob_key gate
    // passes — no over-exclusion.)
    let fresh1 = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(fresh1.status(), StatusCode::OK);
    let fresh_token = pin_token(&fresh1).expect("the fresh walk is paged too");
    let fresh_doc1 = body_json(fresh1).await;
    assert_eq!(
        fresh_doc1["totalItems"], 5,
        "live WAC allows the new incarnations: a, b, c + both changed members"
    );
    let mut fresh_items: Vec<serde_json::Value> = Vec::new();
    for page in 1..=3 {
        let resp = h
            .request_with(
                "GET",
                &format!("/notes/?lws-page={page}&lws-gen={fresh_token}"),
                None,
                &[("accept", LWS_JSON)],
                Body::empty(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "fresh page {page}");
        let doc = body_json(resp).await;
        fresh_items.extend(doc["items"].as_array().cloned().unwrap_or_default());
    }
    let size_of = |items: &[serde_json::Value], iri: &str| -> Option<u64> {
        items
            .iter()
            .find(|i| i["id"] == iri)
            .and_then(|i| i["size"].as_u64())
    };
    assert_eq!(
        size_of(&fresh_items, SECRET),
        Some(3),
        "the fresh walk serves the NEW incarnation's size (\"pub\"), never the old dump's"
    );
    assert_eq!(
        size_of(&fresh_items, LOOSENED),
        Some(2),
        "the fresh walk serves the rewritten member's NEW size (\"ok\")"
    );

    // THE REGRESSION: Alice re-walks the ORIGINAL gen-G pin. The snapshot's rows for both
    // changed members are STALE (blob_key_OLD, sizes 4096/8192) — incarnations live WAC never
    // authorized for her. They must be OMITTED (blob_key mismatch ⇒ fail-closed), and no byte
    // of the old metadata may appear.
    let mut walked: Vec<String> = Vec::new();
    let mut raw_bodies = String::new();
    for page in 1..=2 {
        let resp = h
            .request_with(
                "GET",
                &format!("/notes/?lws-page={page}&lws-gen={token}"),
                None,
                &[("accept", LWS_JSON)],
                Body::empty(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "pinned page {page}");
        let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        raw_bodies.push_str(&body);
        let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            doc["totalItems"], 3,
            "members changed since the snapshot must not join the pinned visible count"
        );
        walked.extend(item_ids(&doc));
    }
    for leaked in ["secret", "loosened", "\"size\":4096", "\"size\":8192"] {
        assert!(
            !raw_bodies.contains(leaked),
            "REGRESSION (metadata staleness): no byte of a changed-since-snapshot member's \
             pinned row may be served — the gen-G metadata belongs to an incarnation the \
             requester was denied; found {leaked:?} in the pinned pages"
        );
    }
    // …and no over-exclusion of the genuinely-unchanged members: a, b, c still tile the pinned
    // walk with their (identical-to-live) pinned metadata.
    let mut expect: Vec<String> = ["a", "b", "c"]
        .iter()
        .map(|n| format!("https://pod.example/notes/{n}.txt"))
        .collect();
    expect.sort();
    walked.sort();
    assert_eq!(
        walked, expect,
        "unchanged members remain visible across the pinned walk (blob_key equality holds)"
    );
}

#[tokio::test]
async fn unminted_or_forged_pins_are_refused_before_the_backend() {
    // Prong 2: `lws-gen` is a server-minted HMAC token bound to (container, requester) — a bare
    // generation integer (the trivially-guessable pre-fix shape), a tampered token, or a token
    // replayed against a different container is the opaque 400 `invalid-generation` problem.
    let h = Harness::lws_pinned(2, 300).await;
    for c in ["notes", "other"] {
        for name in ["a.txt", "b.txt", "c.txt"] {
            let put = h
                .request(
                    "PUT",
                    &format!("/{c}/{name}"),
                    Some("text/plain"),
                    Body::from("x"),
                )
                .await;
            assert_eq!(put.status(), StatusCode::CREATED);
        }
    }
    let p1 = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(p1.status(), StatusCode::OK);
    let token = pin_token(&p1).expect("pinned links minted");

    let expect_400 = |resp: axum::http::Response<Body>, what: &'static str| async move {
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{what}");
        let problem = body_json(resp).await;
        assert_eq!(
            problem["type"], "https://w3id.org/jeswr/lws/problems/invalid-generation",
            "{what}"
        );
    };

    // (a) Guessed bare generations — the exact pre-fix attack shape — and assorted garbage.
    for forged in ["0", "1", "7", "18446744073709551615", "", "abc", "-1"] {
        let resp = h
            .request_with(
                "GET",
                &format!("/notes/?lws-gen={forged}"),
                None,
                &[("accept", LWS_JSON)],
                Body::empty(),
            )
            .await;
        expect_400(resp, "a guessed/unminted pin must be refused").await;
    }

    // (b) A TAMPERED minted token: a different generation under the real MAC, and a flipped MAC.
    let mut parts = token.splitn(3, '.');
    let (g, exp, mac) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let other_gen = format!("9{g}.{exp}.{mac}");
    let flipped_mac = {
        let mut m: Vec<u8> = mac.bytes().collect();
        let last = m.len() - 1;
        m[last] = if m[last] == b'0' { b'1' } else { b'0' };
        format!("{g}.{exp}.{}", String::from_utf8(m).unwrap())
    };
    for forged in [other_gen.as_str(), flipped_mac.as_str()] {
        let resp = h
            .request_with(
                "GET",
                &format!("/notes/?lws-gen={forged}"),
                None,
                &[("accept", LWS_JSON)],
                Body::empty(),
            )
            .await;
        expect_400(resp, "a tampered pin must be refused").await;
    }

    // (c) CROSS-CONTAINER replay: /notes/' own genuine token does not pin /other/.
    let resp = h
        .request_with(
            "GET",
            &format!("/other/?lws-gen={token}"),
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    expect_400(resp, "a pin is bound to its container").await;

    // (d) The genuine token still walks its own container (no over-refusal).
    let resp = h
        .request_with(
            "GET",
            &format!("/notes/?lws-page=2&lws-gen={token}"),
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "the server's own pin works");
}

#[tokio::test]
async fn an_expired_pin_is_the_410_snapshot_gone_restart() {
    // A GENUINE token past its TTL is 410 `snapshot-gone` — the walker's restart-unpinned path
    // (not the opaque 400: the token was really the server's). TTL 0 ⇒ immediately expired.
    let h = Harness::lws_pinned(2, 0).await;
    for name in ["a.txt", "b.txt", "c.txt"] {
        let put = h
            .request(
                "PUT",
                &format!("/notes/{name}"),
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }
    let p1 = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    assert_eq!(p1.status(), StatusCode::OK);
    let token = pin_token(&p1).expect("pins are still minted under a zero TTL");
    let resp = h
        .request_with(
            "GET",
            &format!("/notes/?lws-page=2&lws-gen={token}"),
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::GONE);
    let problem = body_json(resp).await;
    assert_eq!(
        problem["type"],
        "https://w3id.org/jeswr/lws/problems/snapshot-gone"
    );
}

#[tokio::test]
async fn a_verified_pin_the_backend_aged_out_is_410_snapshot_gone() {
    // Defence-in-depth ordering: the token VERIFIES (server-minted, unexpired) but the backend no
    // longer holds the generation — the store's SnapshotGone maps to the same 410 restart. (The
    // pre-prong-2 fail-closed-on-unacknowledged-pin guarantee, now reachable only via a genuine
    // token.)
    let h = Harness::lws_pinned(2, 300).await;
    for name in ["a.txt", "b.txt", "c.txt"] {
        let put = h
            .request(
                "PUT",
                &format!("/notes/{name}"),
                Some("text/plain"),
                Body::from("x"),
            )
            .await;
        assert_eq!(put.status(), StatusCode::CREATED);
    }
    let p1 = h
        .request_with("GET", "/notes/", None, &[("accept", LWS_JSON)], Body::empty())
        .await;
    let token = pin_token(&p1).expect("pinned links minted");
    // The backend's retention window moves on.
    h.pins
        .as_ref()
        .expect("pinned harness")
        .lock()
        .unwrap()
        .snaps
        .clear();
    let resp = h
        .request_with(
            "GET",
            &format!("/notes/?lws-page=2&lws-gen={token}"),
            None,
            &[("accept", LWS_JSON)],
            Body::empty(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::GONE);
    let problem = body_json(resp).await;
    assert_eq!(
        problem["type"],
        "https://w3id.org/jeswr/lws/problems/snapshot-gone"
    );
}
