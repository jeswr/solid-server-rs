// AUTHORED-BY Claude Opus 4.8
//! Auth-middleware tests — valid / invalid / missing token, driven through the real
//! `solid-oidc-verifier` (via the static-JWKS + in-memory-replay test doubles).
//!
//! Covers both the `AuthContext::authenticate` seam directly and the full axum middleware via an
//! end-to-end `oneshot` request through the router.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{jwks_provider, mint_access_token, mint_dpop_proof, KeyKit, BASE_URL, WEBID};
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient};
use tower::ServiceExt;

type TestVerifier = Verifier<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore>;

/// Build an `AuthContext` whose verifier trusts `issuer_key`, with the base URL == audience.
fn auth_context(
    issuer_key: &KeyKit,
) -> AuthContext<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore> {
    let config = VerifierConfig::new(vec![common::ISSUER.to_string()], BASE_URL);
    let replay = InMemoryReplayStore::with_window(config.replay_ttl());
    let verifier: TestVerifier =
        Verifier::new(config, jwks_provider(issuer_key), replay).expect("valid config");
    AuthContext::new(verifier, BASE_URL)
}

#[test]
fn missing_authorization_is_public_not_an_error() {
    let issuer_key = KeyKit::generate();
    let ctx = auth_context(&issuer_key);

    let token = ctx
        .authenticate(None, None, "GET", "/alice/data")
        .expect("no Authorization ⇒ public credentials, not an error");
    assert!(
        token.is_public(),
        "absent auth must yield public credentials"
    );
    assert!(token.web_id.is_none());
}

#[test]
fn valid_dpop_bound_token_authenticates() {
    // The client key is what the token is cnf-bound to; the issuer key signs the token.
    let issuer_key = KeyKit::generate();
    let client_key = KeyKit::generate();
    let ctx = auth_context(&issuer_key);

    let access = mint_access_token(&issuer_key, &client_key.thumbprint);
    let htu = format!("{BASE_URL}/alice/data");
    let proof = mint_dpop_proof(&client_key, "GET", &htu, &access);

    let token = ctx
        .authenticate(
            Some(format!("DPoP {access}")),
            Some(proof),
            "GET",
            "/alice/data",
        )
        .expect("a well-formed DPoP-bound token must authenticate");
    assert_eq!(token.web_id.as_deref(), Some(WEBID));
    assert_eq!(token.issuer.as_deref(), Some(common::ISSUER));
}

#[test]
fn token_from_an_untrusted_issuer_is_rejected() {
    // The verifier trusts `issuer_key`, but the token is signed by a DIFFERENT key.
    let trusted_key = KeyKit::generate();
    let rogue_key = KeyKit::generate();
    let client_key = KeyKit::generate();
    let ctx = auth_context(&trusted_key);

    let access = mint_access_token(&rogue_key, &client_key.thumbprint);
    let htu = format!("{BASE_URL}/alice/data");
    let proof = mint_dpop_proof(&client_key, "GET", &htu, &access);

    let err = ctx
        .authenticate(
            Some(format!("DPoP {access}")),
            Some(proof),
            "GET",
            "/alice/data",
        )
        .expect_err("a token whose signature does not verify against the JWKS must be rejected");
    assert_eq!(err.status().as_u16(), 401);
}

#[test]
fn dpop_proof_for_a_different_url_is_rejected() {
    let issuer_key = KeyKit::generate();
    let client_key = KeyKit::generate();
    let ctx = auth_context(&issuer_key);

    let access = mint_access_token(&issuer_key, &client_key.thumbprint);
    // The proof's htu binds to /other, but the request is for /alice/data — htu mismatch.
    let wrong_htu = format!("{BASE_URL}/other");
    let proof = mint_dpop_proof(&client_key, "GET", &wrong_htu, &access);

    let err = ctx
        .authenticate(
            Some(format!("DPoP {access}")),
            Some(proof),
            "GET",
            "/alice/data",
        )
        .expect_err("a DPoP proof bound to a different htu must be rejected");
    assert_eq!(err.status().as_u16(), 401);
}

#[test]
fn bearer_without_dpop_is_rejected() {
    let issuer_key = KeyKit::generate();
    let client_key = KeyKit::generate();
    let ctx = auth_context(&issuer_key);

    let access = mint_access_token(&issuer_key, &client_key.thumbprint);
    // A bare Bearer (no DPoP proof) — proof-of-possession is required by default.
    let err = ctx
        .authenticate(Some(format!("Bearer {access}")), None, "GET", "/alice/data")
        .expect_err("bare Bearer must be rejected when DPoP is required");
    assert_eq!(err.status().as_u16(), 401);
}

#[test]
fn replayed_dpop_proof_jti_is_rejected() {
    let issuer_key = KeyKit::generate();
    let client_key = KeyKit::generate();
    let ctx = auth_context(&issuer_key);

    let access = mint_access_token(&issuer_key, &client_key.thumbprint);
    let htu = format!("{BASE_URL}/alice/data");
    let proof = mint_dpop_proof(&client_key, "GET", &htu, &access);

    // First use succeeds.
    ctx.authenticate(
        Some(format!("DPoP {access}")),
        Some(proof.clone()),
        "GET",
        "/alice/data",
    )
    .expect("first use of a fresh proof authenticates");

    // Re-using the SAME proof (same jti) must fail — single-use replay protection.
    let err = ctx
        .authenticate(
            Some(format!("DPoP {access}")),
            Some(proof),
            "GET",
            "/alice/data",
        )
        .expect_err("a replayed DPoP jti must be rejected");
    assert_eq!(err.status().as_u16(), 401);
}

#[tokio::test]
async fn http_get_without_auth_is_public_and_reaches_a_404() {
    // End-to-end through the router: no Authorization ⇒ public credentials ⇒ the handler runs and,
    // since nothing is stored, returns 404 (NOT 401). Proves the middleware injects public creds.
    let issuer_key = KeyKit::generate();
    let app = test_app(&issuer_key);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/alice/data")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn http_get_with_a_bad_token_is_401_with_www_authenticate() {
    let issuer_key = KeyKit::generate();
    let app = test_app(&issuer_key);

    // A garbage token — the verifier rejects it, the middleware returns its 401 + challenge.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/alice/data")
                .header("authorization", "DPoP not-a-real-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers()
            .contains_key(axum::http::header::WWW_AUTHENTICATE),
        "a 401 from the verifier must carry a WWW-Authenticate challenge"
    );
}

/// Assemble the full app over the in-memory store + a verifier trusting `issuer_key`.
fn test_app(issuer_key: &KeyKit) -> axum::Router {
    let ctx = auth_context(issuer_key);
    let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
    let ldp = LdpState::new(store, BASE_URL);
    let state = AppState {
        auth: Arc::new(ctx),
        ldp: Arc::new(ldp),
    };
    build_router(state)
}
