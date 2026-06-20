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
        let (authz, dpop) = self.auth_headers(method, path);
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", authz)
            .header("dpop", dpop);
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
