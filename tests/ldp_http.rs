// AUTHORED-BY Claude Opus 4.8
//! End-to-end LDP HTTP tests through the assembled router (auth + GET/HEAD/PUT over the store).
//!
//! Each request carries a fresh, well-formed DPoP-bound token + a per-request proof (a new jti) so
//! the verifier's single-use replay protection does not reject the second request of a PUT→GET pair.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use common::{jwks_provider, mint_access_token, mint_dpop_proof, KeyKit, BASE_URL};
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient};
use tower::ServiceExt;

const TURTLE: &str =
    "<https://pod.example/alice/data#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .";

/// One shared app (so a PUT and a later GET hit the same store), plus the keys to mint requests.
struct Harness {
    app: axum::Router,
    issuer_key: KeyKit,
    client_key: KeyKit,
}

impl Harness {
    fn new() -> Self {
        let issuer_key = KeyKit::generate();
        let client_key = KeyKit::generate();
        let config = VerifierConfig::new(vec![common::ISSUER.to_string()], BASE_URL);
        let replay = InMemoryReplayStore::with_window(config.replay_ttl());
        let verifier = Verifier::new(config, jwks_provider(&issuer_key), replay).unwrap();
        let ctx = AuthContext::new(verifier, BASE_URL);
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        let ldp = LdpState::new(store, BASE_URL);
        let app = build_router(AppState {
            auth: Arc::new(ctx),
            ldp: Arc::new(ldp),
        });
        Self {
            app,
            issuer_key,
            client_key,
        }
    }

    /// A fresh `(Authorization, DPoP)` pair for one request (new proof jti each call).
    fn auth_headers(&self, method: &str, path: &str) -> (String, String) {
        let access = mint_access_token(&self.issuer_key, &self.client_key.thumbprint);
        let htu = format!("{BASE_URL}{path}");
        let proof = mint_dpop_proof(&self.client_key, method, &htu, &access);
        (format!("DPoP {access}"), proof)
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

    /// An authenticated request with arbitrary extra headers (Slug / If-Match / Range / Accept …).
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

    /// Create the container at `path` (a trailing-slash path) so a subsequent POST can target it.
    async fn make_container(&self, path: &str) {
        let resp = self
            .request(
                "PUT",
                path,
                Some("text/turtle"),
                Body::from("<#c> <http://xmlns.com/foaf/0.1/name> \"Container\" ."),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    /// An UNAUTHENTICATED request (no Authorization / DPoP).
    async fn unauth_request(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Body,
    ) -> axum::http::Response<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        self.app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn put_creates_then_get_reads_it_back() {
    let h = Harness::new();

    // PUT a fresh resource → 201 Created with a Location + ETag.
    let put = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    assert!(put.headers().contains_key(axum::http::header::ETAG));
    assert!(put.headers().contains_key(axum::http::header::LOCATION));

    // GET it back → 200 with the same bytes + content type.
    let get = h.request("GET", "/alice/data", None, Body::empty()).await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
        "text/turtle"
    );
    let bytes = to_bytes(get.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], TURTLE.as_bytes());
}

#[tokio::test]
async fn put_twice_is_a_replace_with_no_content() {
    let h = Harness::new();
    let first = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from("<#me> <http://xmlns.com/foaf/0.1/name> \"Alice 2\" ."),
        )
        .await;
    // A replace returns 204 No Content (the resource already existed).
    assert_eq!(second.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn head_returns_headers_without_a_body() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;

    let head = h.request("HEAD", "/alice/data", None, Body::empty()).await;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(head
        .headers()
        .contains_key(axum::http::header::CONTENT_TYPE));
    let bytes = to_bytes(head.into_body(), usize::MAX).await.unwrap();
    assert!(bytes.is_empty(), "HEAD must not return a body");
}

#[tokio::test]
async fn put_with_an_unsupported_content_type_is_415() {
    let h = Harness::new();
    let resp = h
        .request(
            "PUT",
            "/alice/data",
            Some("application/json"),
            Body::from("{}"),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn unauthenticated_put_is_forbidden_fail_closed() {
    // A write from a public/unauthenticated caller must be rejected (403), not allowed — the slice
    // has no ACLs yet, so it fails closed on writes rather than fail open.
    let h = Harness::new();
    let resp = h
        .unauth_request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // And nothing was written — a subsequent (authenticated) GET still 404s.
    let get = h.request("GET", "/alice/data", None, Body::empty()).await;
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_with_malformed_turtle_is_400() {
    let h = Harness::new();
    let resp = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from("<a> <b> ."), // missing object
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --- M2: content negotiation -------------------------------------------------------------------

#[tokio::test]
async fn get_negotiates_jsonld_from_stored_turtle() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;

    let get = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("accept", "application/ld+json")],
            Body::empty(),
        )
        .await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
        "application/ld+json"
    );
    let bytes = to_bytes(get.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    // The JSON-LD re-serialisation must contain the subject + the foaf name.
    assert!(text.contains("alice/data#me"), "JSON-LD body: {text}");
    assert!(text.contains("Alice"), "JSON-LD body: {text}");
}

#[tokio::test]
async fn get_with_unacceptable_accept_is_406() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let get = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("accept", "image/png")],
            Body::empty(),
        )
        .await;
    assert_eq!(get.status(), StatusCode::NOT_ACCEPTABLE);
}

// --- M2: Range ---------------------------------------------------------------------------------

#[tokio::test]
async fn get_with_a_range_returns_206_partial() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let get = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("range", "bytes=0-3")],
            Body::empty(),
        )
        .await;
    assert_eq!(get.status(), StatusCode::PARTIAL_CONTENT);
    let cr = get
        .headers()
        .get(axum::http::header::CONTENT_RANGE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(cr.starts_with("bytes 0-3/"), "Content-Range: {cr}");
    let bytes = to_bytes(get.into_body(), usize::MAX).await.unwrap();
    assert_eq!(bytes.len(), 4);
    assert_eq!(&bytes[..], &TURTLE.as_bytes()[0..4]);
}

#[tokio::test]
async fn head_with_a_range_is_200_not_206() {
    // Range is defined for GET; a HEAD with Range must NOT return 206.
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let head = h
        .request_with(
            "HEAD",
            "/alice/data",
            None,
            &[("range", "bytes=0-3")],
            Body::empty(),
        )
        .await;
    assert_eq!(head.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_with_an_unsatisfiable_range_is_416() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let get = h
        .request_with(
            "GET",
            "/alice/data",
            None,
            &[("range", "bytes=99999-100000")],
            Body::empty(),
        )
        .await;
    assert_eq!(get.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert!(get
        .headers()
        .contains_key(axum::http::header::CONTENT_RANGE));
}

// --- M2: conditional requests ------------------------------------------------------------------

#[tokio::test]
async fn put_if_none_match_star_blocks_overwrite() {
    let h = Harness::new();
    let first = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    // A second PUT with If-None-Match: * (create-only) must fail with 412 (it already exists).
    let second = h
        .request_with(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            &[("if-none-match", "*")],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(second.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn put_if_match_with_wrong_etag_is_412() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let resp = h
        .request_with(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            &[("if-match", "\"not-the-real-etag\"")],
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn put_if_match_with_correct_etag_succeeds() {
    let h = Harness::new();
    let first = h
        .request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    let etag = first
        .headers()
        .get(axum::http::header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let resp = h
        .request_with(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            &[("if-match", &etag)],
            Body::from("<#me> <http://xmlns.com/foaf/0.1/name> \"Updated\" ."),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// --- M2: POST ----------------------------------------------------------------------------------

#[tokio::test]
async fn post_creates_a_child_with_slug() {
    let h = Harness::new();
    h.make_container("/alice/").await;
    let resp = h
        .request_with(
            "POST",
            "/alice/",
            Some("text/turtle"),
            &[("slug", "note1")],
            Body::from("<#it> <http://xmlns.com/foaf/0.1/name> \"Note\" ."),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let location = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(location, "https://pod.example/alice/note1");

    // The child is readable at its minted Location.
    let get = h.request("GET", "/alice/note1", None, Body::empty()).await;
    assert_eq!(get.status(), StatusCode::OK);
}

#[tokio::test]
async fn post_mints_a_uri_without_a_slug() {
    let h = Harness::new();
    h.make_container("/alice/").await;
    let resp = h
        .request(
            "POST",
            "/alice/",
            Some("text/turtle"),
            Body::from("<#it> <http://xmlns.com/foaf/0.1/name> \"X\" ."),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let location = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with("https://pod.example/alice/"),
        "minted Location: {location}"
    );
    assert_ne!(location, "https://pod.example/alice/");
}

#[tokio::test]
async fn post_to_a_non_container_is_409() {
    let h = Harness::new();
    // The target is a plain resource path (no trailing slash) ⇒ not a container.
    let resp = h
        .request(
            "POST",
            "/alice/data",
            Some("text/turtle"),
            Body::from(TURTLE),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn post_to_a_missing_container_is_404() {
    let h = Harness::new();
    // The container path is well-formed but was never created — must not create a child under it.
    let resp = h
        .request(
            "POST",
            "/missing/",
            Some("text/turtle"),
            Body::from("<#it> <http://xmlns.com/foaf/0.1/name> \"X\" ."),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unauthenticated_post_is_forbidden() {
    let h = Harness::new();
    let resp = h
        .unauth_request("POST", "/alice/", Some("text/turtle"), Body::from(TURTLE))
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// --- M2: DELETE --------------------------------------------------------------------------------

#[tokio::test]
async fn delete_removes_a_resource() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;

    let del = h
        .request("DELETE", "/alice/data", None, Body::empty())
        .await;
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    // It is gone.
    let get = h.request("GET", "/alice/data", None, Body::empty()).await;
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_a_missing_resource_is_404() {
    let h = Harness::new();
    let del = h
        .request("DELETE", "/alice/gone", None, Body::empty())
        .await;
    assert_eq!(del.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_a_non_empty_container_is_409() {
    let h = Harness::new();
    // The container must exist before a child can be POSTed into it.
    h.make_container("/alice/").await;
    // POST a child into the container so it has a member.
    h.request_with(
        "POST",
        "/alice/",
        Some("text/turtle"),
        &[("slug", "child")],
        Body::from("<#it> <http://xmlns.com/foaf/0.1/name> \"C\" ."),
    )
    .await;

    let del = h.request("DELETE", "/alice/", None, Body::empty()).await;
    assert_eq!(del.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_an_empty_container_succeeds() {
    let h = Harness::new();
    h.make_container("/alice/").await;

    // The empty container can be deleted (the spec choice: empty ⇒ allowed, non-empty ⇒ 409).
    let del = h.request("DELETE", "/alice/", None, Body::empty()).await;
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    // It is gone — a subsequent GET is a 404.
    let get = h.request("GET", "/alice/", None, Body::empty()).await;
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_a_container_after_emptying_it_succeeds() {
    let h = Harness::new();
    h.make_container("/alice/").await;
    // POST a child, then DELETE the child (emptying the container), then DELETE the container.
    let post = h
        .request_with(
            "POST",
            "/alice/",
            Some("text/turtle"),
            &[("slug", "child")],
            Body::from("<#it> <http://xmlns.com/foaf/0.1/name> \"C\" ."),
        )
        .await;
    assert_eq!(post.status(), StatusCode::CREATED);
    let child_loc = post
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("POST returns a Location")
        .to_string();
    // The Location is an absolute IRI; DELETE wants the path.
    let child_path = child_loc
        .strip_prefix("https://pod.example")
        .unwrap_or(&child_loc)
        .to_string();

    // While the child is present, the container DELETE is refused.
    let del_full = h.request("DELETE", "/alice/", None, Body::empty()).await;
    assert_eq!(del_full.status(), StatusCode::CONFLICT);

    // Delete the child, which empties the container.
    let del_child = h.request("DELETE", &child_path, None, Body::empty()).await;
    assert_eq!(del_child.status(), StatusCode::NO_CONTENT);

    // Now the (empty) container can be deleted.
    let del_container = h.request("DELETE", "/alice/", None, Body::empty()).await;
    assert_eq!(del_container.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn unauthenticated_delete_is_forbidden() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let del = h
        .unauth_request("DELETE", "/alice/data", None, Body::empty())
        .await;
    assert_eq!(del.status(), StatusCode::FORBIDDEN);
}

// --- M2: PATCH (N3 Patch) ----------------------------------------------------------------------

const N3_PATCH: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
_:patch a solid:InsertDeletePatch;\n\
  solid:deletes { <https://pod.example/alice/data#me> foaf:name \"Alice\" . };\n\
  solid:inserts { <https://pod.example/alice/data#me> foaf:name \"Alice 2\" . }.\n";

#[tokio::test]
async fn patch_inserts_and_deletes_triples() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;

    let patch = h
        .request(
            "PATCH",
            "/alice/data",
            Some("text/n3"),
            Body::from(N3_PATCH),
        )
        .await;
    assert_eq!(patch.status(), StatusCode::NO_CONTENT);

    // The resource now carries the new name and not the old one.
    let get = h.request("GET", "/alice/data", None, Body::empty()).await;
    let bytes = to_bytes(get.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("Alice 2"), "patched body: {text}");
    assert!(
        !text.contains("\"Alice\""),
        "old value still present: {text}"
    );
}

#[tokio::test]
async fn patch_with_an_unsupported_media_type_is_415() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    // SPARQL Update is deferred — must be 415, never silently accepted.
    let resp = h
        .request(
            "PATCH",
            "/alice/data",
            Some("application/sparql-update"),
            Body::from("INSERT DATA { <#s> <#p> <#o> }"),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn patch_deleting_an_absent_triple_is_409() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let doc = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
_:patch solid:deletes { <https://pod.example/alice/data#me> foaf:name \"NotThere\" . }.\n";
    let resp = h
        .request("PATCH", "/alice/data", Some("text/n3"), Body::from(doc))
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// A templated `solid:where` patch end-to-end: bind the current name, delete it, insert a new one
/// (the canonical "rename" patch). The single solution drives the templates and the body reads back
/// with the new value.
#[tokio::test]
async fn patch_with_a_templated_where_renames() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let doc = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
_:patch solid:where   { <https://pod.example/alice/data#me> foaf:name ?n . };\n\
  solid:deletes { <https://pod.example/alice/data#me> foaf:name ?n . };\n\
  solid:inserts { <https://pod.example/alice/data#me> foaf:name \"Renamed\" . }.\n";
    let resp = h
        .request("PATCH", "/alice/data", Some("text/n3"), Body::from(doc))
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let get = h.request("GET", "/alice/data", None, Body::empty()).await;
    let bytes = to_bytes(get.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("Renamed"), "patched body: {text}");
    assert!(
        !text.contains("\"Alice\""),
        "old value still present: {text}"
    );
}

/// Spec: a non-empty `solid:where` with MULTIPLE solutions is a 409 (the Solid N3 Patch requires
/// exactly one mapping — it does not fan out per solution).
#[tokio::test]
async fn patch_with_a_multi_solution_where_is_409() {
    let h = Harness::new();
    // Two foaf:name triples on the same subject ⇒ the where binds ?n two ways ⇒ multiple solutions.
    let turtle =
        "<https://pod.example/alice/data#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .\n\
<https://pod.example/alice/data#me> <http://xmlns.com/foaf/0.1/name> \"Alicia\" .";
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(turtle),
    )
    .await;
    let doc = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
_:patch solid:where { <https://pod.example/alice/data#me> foaf:name ?n . };\n\
  solid:deletes { <https://pod.example/alice/data#me> foaf:name ?n . }.\n";
    let resp = h
        .request("PATCH", "/alice/data", Some("text/n3"), Body::from(doc))
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn unauthenticated_patch_is_forbidden() {
    let h = Harness::new();
    h.request(
        "PUT",
        "/alice/data",
        Some("text/turtle"),
        Body::from(TURTLE),
    )
    .await;
    let resp = h
        .unauth_request(
            "PATCH",
            "/alice/data",
            Some("text/n3"),
            Body::from(N3_PATCH),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
