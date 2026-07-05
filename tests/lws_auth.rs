// AUTHORED-BY Claude Fable 5
//! End-to-end HTTP tests for the **LWS auth chain (M2)** — RFC 9728 discovery challenge +
//! RFC 9068 `at+jwt` Bearer validation + the WAC hand-off — through the assembled router
//! (`jeswr/lws-spec` `index.html` §authz-discovery / §access-token / §presentation /
//! §rs-validation).
//!
//! Four harness postures pin the flag matrix:
//! - **flag OFF** — no LWS anywhere: 401s, Bearer handling, and the RFC 9728 route are
//!   byte-identical to pre-LWS (the invariance pins);
//! - **M1 surface only** (LWS on the LDP state, NO auth chain) — pins that M1 alone never
//!   changed a 401 (the M2 chain is a separate, additive wiring);
//! - **FULL** (surface + auth chain, Bearer baseline) — the maintainer's lws-keycloak posture;
//! - **PoP-REQUIRED** — the documented `SOLID_SERVER_LWS_REQUIRE_POP` toggle: the Bearer path is
//!   closed fail-closed and the discovery surfaces advertise the requirement.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::http::{header, Request, StatusCode};
use common::{jwks_provider, mint_access_token, mint_dpop_proof, KeyKit, BASE_URL, ISSUER, WEBID};
use serde_json::{json, Value};
use solid_oidc_verifier::config::{JwksProvider, VerifierConfig};
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::lws::auth::LwsBearerAuth;
use solid_server_rs::lws::LwsConfig;
use solid_server_rs::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient, Store};
use tower::ServiceExt;

const PRM_PATH: &str = "/.well-known/oauth-protected-resource";
/// A second agent (NOT the root owner) for the WAC 403 case.
const BOB: &str = "https://elsewhere.example/bob/profile#me";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Baseline VALID LWS `at+jwt` claims: trusted issuer, agent `sub`, storage-root audience,
/// well-inside the ≤300 s window.
fn lws_claims(sub: &str, aud: Value) -> Value {
    let n = now();
    json!({
        "iss": ISSUER,
        "sub": sub,
        "client_id": "lws-app",
        "aud": aud,
        "iat": n,
        "exp": n + 120,
        "jti": format!("lws-jti-{n}"),
    })
}

fn mint_lws(issuer_key: &KeyKit, claims: &Value) -> String {
    issuer_key.sign(&json!({ "alg": "ES256", "typ": "at+jwt" }), claims)
}

/// Which posture the harness runs.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    FlagOff,
    SurfaceOnly,
    Full,
    PopRequired,
}

struct Harness {
    app: axum::Router,
    issuer_key: KeyKit,
    client_key: KeyKit,
}

impl Harness {
    async fn build(mode: Mode) -> Self {
        let issuer_key = KeyKit::generate();
        let client_key = KeyKit::generate();
        // The Solid-OIDC verifier config this repo's tests use everywhere: trusted issuer +
        // audience = the base URL, DPoP-required posture.
        let config = VerifierConfig::new(vec![ISSUER.to_string()], BASE_URL);
        let replay = InMemoryReplayStore::with_window(config.replay_ttl());
        let verifier = Verifier::new(config, jwks_provider(&issuer_key), replay).unwrap();
        let mut ctx = AuthContext::new(verifier, BASE_URL);
        if matches!(mode, Mode::Full | Mode::PopRequired) {
            let jwks: Arc<dyn JwksProvider> = Arc::new(jwks_provider(&issuer_key));
            let lws = LwsBearerAuth::new(
                jwks,
                vec![ISSUER.to_string()],
                BASE_URL,
                mode == Mode::PopRequired,
            )
            .unwrap();
            ctx = ctx.with_lws_bearer(Some(Arc::new(lws)));
        }

        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        // Root owner ACL: Alice Read/Write/Control on the root + all descendants (the same
        // fixture `ldp_http.rs`/`lws_http.rs` use). Everything is therefore PRIVATE to Alice.
        let base = BASE_URL.trim_end_matches('/');
        let root = format!("{base}/");
        let acl_body = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#owner> a acl:Authorization;
         acl:agent <{WEBID}>;
         acl:accessTo <{root}>;
         acl:default <{root}>;
         acl:mode acl:Read, acl:Write, acl:Control."#
        );
        store
            .write(&format!("{root}.acl"), Bytes::from(acl_body), "text/turtle")
            .await
            .expect("seed root acl");

        let mut ldp = LdpState::new(store, BASE_URL);
        if mode != Mode::FlagOff {
            ldp.set_lws(Some(Arc::new(LwsConfig::new(BASE_URL, true, false))));
        }
        let app = build_router(AppState::new(ctx, ldp));
        Self {
            app,
            issuer_key,
            client_key,
        }
    }

    async fn send(&self, req: Request<Body>) -> axum::http::Response<Body> {
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// An anonymous request (no credentials at all).
    async fn anon(&self, method: &str, path: &str) -> axum::http::Response<Body> {
        self.send(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// A `Bearer <token>` request (the LWS presentation baseline).
    async fn bearer(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<(&str, &str)>,
    ) -> axum::http::Response<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let body = match body {
            Some((ct, b)) => {
                builder = builder.header(header::CONTENT_TYPE, ct);
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        self.send(builder.body(body).unwrap()).await
    }

    /// The existing Solid-OIDC DPoP flow (must keep working on every posture).
    async fn dpop(
        &self,
        method: &str,
        path: &str,
        body: Option<(&str, &str)>,
    ) -> axum::http::Response<Body> {
        let access = mint_access_token(&self.issuer_key, &self.client_key.thumbprint);
        let htu = format!("{BASE_URL}{path}");
        let proof = mint_dpop_proof(&self.client_key, method, &htu, &access);
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("DPoP {access}"))
            .header("dpop", proof);
        let body = match body {
            Some((ct, b)) => {
                builder = builder.header(header::CONTENT_TYPE, ct);
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        self.send(builder.body(body).unwrap()).await
    }

    /// PUT-then-GET a probe document under the given flow — pins that the flow fully works
    /// (auth + WAC + the store round-trip), independent of whether the bare root exists.
    async fn assert_dpop_flow_works(&self, path: &str) {
        let resp = self.dpop("PUT", path, Some(("text/plain", "probe"))).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "DPoP PUT {path}");
        let resp = self.dpop("GET", path, None).await;
        assert_eq!(resp.status(), StatusCode::OK, "DPoP GET {path}");
    }
}

/// All `WWW-Authenticate` values on a response (a 401 may carry several challenges).
fn challenges(resp: &axum::http::Response<Body>) -> Vec<String> {
    resp.headers()
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

fn lws_challenge(resp: &axum::http::Response<Body>) -> Option<String> {
    challenges(resp)
        .into_iter()
        .find(|c| c.contains("resource_metadata="))
}

async fn body_json(resp: axum::http::Response<Body>) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).expect("JSON body")
}

// --- 1. The RFC 9728 challenge (spec §authz-discovery) ------------------------------------------

#[tokio::test]
async fn anonymous_401_carries_the_rfc9728_challenge_without_error() {
    let h = Harness::build(Mode::Full).await;
    let resp = h.anon("GET", "/private/doc").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let lws = lws_challenge(&resp).expect("401 must advertise resource_metadata");
    assert!(lws.starts_with("Bearer "), "Bearer baseline scheme: {lws}");
    assert!(lws.contains(&format!("realm=\"{BASE_URL}/\"")), "{lws}");
    assert!(
        lws.contains(&format!("resource_metadata=\"{BASE_URL}{PRM_PATH}\"")),
        "{lws}"
    );
    // RFC 6750 §3.1: a challenge answering a credential-less request MUST NOT carry `error`.
    assert!(!lws.contains("error="), "{lws}");
    // The pre-existing DPoP challenge still rides beside it (multiple challenges are legal).
    assert!(
        challenges(&resp).iter().any(|c| c.starts_with("DPoP")),
        "the Solid DPoP challenge must survive: {:?}",
        challenges(&resp)
    );
}

#[tokio::test]
async fn rejected_token_401_carries_error_invalid_token() {
    let h = Harness::build(Mode::Full).await;
    // A presented-but-garbage Bearer token (not an LWS candidate — decided by the verifier).
    let resp = h.bearer("GET", "/private/doc", "garbage-token", None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let lws = lws_challenge(&resp).expect("401 must advertise resource_metadata");
    assert!(lws.contains("error=\"invalid_token\""), "{lws}");

    // A presented-and-LWS-shaped-but-invalid token (decided by the LWS verifier): same contract.
    let mut claims = lws_claims(WEBID, json!(format!("{BASE_URL}/")));
    claims["exp"] = json!(now() - 400);
    let resp = h
        .bearer(
            "GET",
            "/private/doc",
            &mint_lws(&h.issuer_key, &claims),
            None,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let lws = lws_challenge(&resp).expect("LWS rejection advertises resource_metadata");
    assert!(lws.contains("error=\"invalid_token\""), "{lws}");
    // Exactly one LWS challenge (the middleware must not double-append onto the verifier's own).
    assert_eq!(
        challenges(&resp)
            .iter()
            .filter(|c| c.contains("resource_metadata="))
            .count(),
        1
    );
}

#[tokio::test]
async fn prm_document_carries_the_lws_members() {
    let h = Harness::build(Mode::Full).await;
    let resp = h.anon("GET", PRM_PATH).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["resource"], json!(BASE_URL));
    assert_eq!(doc["authorization_servers"], json!([ISSUER]));
    assert_eq!(
        doc["jlws_storage_description"],
        json!(format!("{BASE_URL}/.well-known/lws"))
    );
    // Bearer baseline: the PoP-required member is honest (false), while the DPoP algs stay
    // advertised (PoP remains available as the optional profile).
    assert_eq!(doc["dpop_bound_access_tokens_required"], json!(false));
    assert!(doc["dpop_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a == "ES256"));
}

// --- 2. at+jwt Bearer accept + the WAC hand-off (spec §rs-validation / §presentation) -----------

#[tokio::test]
async fn valid_lws_bearer_authenticates_as_the_sub_agent() {
    let h = Harness::build(Mode::Full).await;
    let token = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    // Alice (the root owner) can write and read back over plain Bearer — the full chain:
    // challenge-discoverable AS → audience-restricted at+jwt → Bearer → WAC as `sub`.
    let resp = h
        .bearer(
            "PUT",
            "/alice/notes/x",
            &token,
            Some(("text/plain", "hello lws")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = h.bearer("GET", "/alice/notes/x", &token, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"hello lws");

    // A query string on the request URL does NOT break audience validation (roborev pass-2): the
    // target is query-stripped (parse_target / axum's uri().path()) before the audience check, so
    // the aud-scoped token authenticates and the same resource is served.
    let resp = h
        .bearer("GET", "/alice/notes/x?view=raw&t=1", &token, None)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"hello lws");

    // Even a token whose aud is a deeper subtree (…/alice/notes/) authenticates for a
    // query-bearing target under it — the query never narrows the containment.
    let scoped = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/alice/notes/"))),
    );
    let resp = h.bearer("GET", "/alice/notes/x?a=1", &scoped, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn authenticated_but_unauthorized_lws_agent_is_403() {
    let h = Harness::build(Mode::Full).await;
    // Seed a resource as the owner.
    let owner = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h
        .bearer(
            "PUT",
            "/alice/private",
            &owner,
            Some(("text/plain", "secret")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    // Bob authenticates fine (valid token) but the WAC engine denies: 403, not 401 — the
    // valid-token/unauthorized split the spec requires.
    let bob = mint_lws(
        &h.issuer_key,
        &lws_claims(BOB, json!(format!("{BASE_URL}/"))),
    );
    let resp = h.bearer("GET", "/alice/private", &bob, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn dpop_solid_flow_is_unchanged_with_lws_on() {
    let h = Harness::build(Mode::Full).await;
    h.assert_dpop_flow_works("/dpop-probe").await;
}

// --- 3. The audience-containment boundary, over HTTP (THE load-bearing case) --------------------

#[tokio::test]
async fn aud_scoped_token_cannot_reach_the_sibling_prefix() {
    let h = Harness::build(Mode::Full).await;
    // Seed docs under BOTH /alice/ and /alicemalicious/ as the owner (root-audience token).
    let owner = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    for path in ["/alice/doc", "/alicemalicious/doc"] {
        let resp = h
            .bearer("PUT", path, &owner, Some(("text/plain", "x")))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{path}");
    }
    // A token audience-scoped to …/alice — WAC would allow both (same owner), so any cross-read
    // can only come from the audience check.
    let scoped = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/alice"))),
    );
    let resp = h.bearer("GET", "/alice/doc", &scoped, None).await;
    assert_eq!(resp.status(), StatusCode::OK, "inside the audience");
    let resp = h.bearer("GET", "/alicemalicious/doc", &scoped, None).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "…/alice must NOT authorize the sibling …/alicemalicious (raw-prefix flaw)"
    );
    assert!(lws_challenge(&resp)
        .expect("aud rejection carries the challenge")
        .contains("error=\"invalid_token\""));
    // The trailing-slash spelling too.
    let scoped_slash = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/alice/"))),
    );
    let resp = h
        .bearer("GET", "/alicemalicious/doc", &scoped_slash, None)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // And the scoped token cannot WRITE outside its audience either.
    let resp = h
        .bearer(
            "PUT",
            "/alicemalicious/new",
            &scoped,
            Some(("text/plain", "escape")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- 4. The HTTP-level reject matrix (unit-exhaustive in src/lws/auth.rs; pinned here E2E) -------

#[tokio::test]
async fn http_reject_matrix() {
    let h = Harness::build(Mode::Full).await;
    let aud = json!(format!("{BASE_URL}/"));
    let n = now();

    // Forged signature (a key the issuer never published).
    let forger = KeyKit::generate();
    let t = mint_lws(&forger, &lws_claims(WEBID, aud.clone()));
    assert_eq!(
        h.bearer("GET", "/", &t, None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // Untrusted issuer.
    let mut c = lws_claims(WEBID, aud.clone());
    c["iss"] = json!("https://evil-as.example");
    let t = mint_lws(&h.issuer_key, &c);
    assert_eq!(
        h.bearer("GET", "/", &t, None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // Wrong typ.
    let t = h.issuer_key.sign(
        &json!({ "alg": "ES256", "typ": "JWT" }),
        &lws_claims(WEBID, aud.clone()),
    );
    assert_eq!(
        h.bearer("GET", "/", &t, None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // exp beyond the ≤300 s window.
    let mut c = lws_claims(WEBID, aud.clone());
    c["exp"] = json!(n + 3600);
    let t = mint_lws(&h.issuer_key, &c);
    assert_eq!(
        h.bearer("GET", "/", &t, None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // Missing client_id.
    let mut c = lws_claims(WEBID, aud.clone());
    c.as_object_mut().unwrap().remove("client_id");
    let t = mint_lws(&h.issuer_key, &c);
    assert_eq!(
        h.bearer("GET", "/", &t, None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // Multi-valued audience.
    let mut c = lws_claims(WEBID, aud.clone());
    c["aud"] = json!([format!("{BASE_URL}/"), "https://other.example/"]);
    let t = mint_lws(&h.issuer_key, &c);
    assert_eq!(
        h.bearer("GET", "/", &t, None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // A cnf-bound token presented bare (either flavour) — never accepted.
    let mut c = lws_claims(WEBID, aud.clone());
    c["cnf"] = json!({ "jkt": h.client_key.thumbprint });
    let t = mint_lws(&h.issuer_key, &c);
    assert_eq!(
        h.bearer("GET", "/", &t, None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // The production Solid DPoP-bound token presented WITHOUT its proof, as Bearer: rejected —
    // enabling LWS never downgrades a PoP-bound token to bearer.
    let solid = mint_access_token(&h.issuer_key, &h.client_key.thumbprint);
    assert_eq!(
        h.bearer("GET", "/", &solid, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

// --- 5. The PoP-required realm toggle (spec §presentation-pop) -----------------------------------

#[tokio::test]
async fn pop_required_realm_closes_bearer_and_advertises_it() {
    let h = Harness::build(Mode::PopRequired).await;
    // A fully valid LWS token is refused on Bearer presentation.
    let token = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h.bearer("GET", "/", &token, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let lws = lws_challenge(&resp).expect("challenge still advertises discovery");
    // §presentation-pop: the challenge lists only the required profile's scheme — no Bearer.
    assert!(lws.starts_with("DPoP "), "{lws}");
    // The anonymous challenge likewise.
    let resp = h.anon("GET", "/private/doc").await;
    let lws = lws_challenge(&resp).expect("challenge");
    assert!(lws.starts_with("DPoP "), "{lws}");
    assert!(!lws.contains("Bearer"), "{lws}");
    // The metadata advertises the requirement.
    let doc = body_json(h.anon("GET", PRM_PATH).await).await;
    assert_eq!(doc["dpop_bound_access_tokens_required"], json!(true));
    // The full-strength DPoP flow still works.
    h.assert_dpop_flow_works("/dpop-probe").await;
}

// --- 6. Flag-off byte-invariance (the M1 rule, extended to M2) -----------------------------------

#[tokio::test]
async fn flag_off_401s_and_bearer_handling_are_unchanged() {
    let h = Harness::build(Mode::FlagOff).await;
    // Anonymous 401: exactly the pre-LWS single DPoP challenge — no resource_metadata anywhere.
    let resp = h.anon("GET", "/private/doc").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(lws_challenge(&resp).is_none(), "{:?}", challenges(&resp));
    assert_eq!(challenges(&resp).len(), 1);
    // A perfectly valid LWS token is NOT accepted flag-off (the pre-LWS DPoP-required posture).
    let token = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h.bearer("GET", "/", &token, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(lws_challenge(&resp).is_none());
    // The RFC 9728 document is not mounted (no PoP tier, no LWS): the wildcard LDP route answers.
    let resp = h.anon("GET", PRM_PATH).await;
    assert_ne!(resp.status(), StatusCode::OK);
    // The DPoP flow works, obviously.
    h.assert_dpop_flow_works("/dpop-probe").await;
}

#[tokio::test]
async fn m1_surface_without_the_auth_chain_changes_no_401() {
    // The M1-only wiring (LWS on the LDP state, no LwsBearerAuth) — pins that M2 is a separate,
    // additive wiring: M1 deployments' 401s/Bearer handling were and remain untouched.
    let h = Harness::build(Mode::SurfaceOnly).await;
    let resp = h.anon("GET", "/private/doc").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(lws_challenge(&resp).is_none());
    let token = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h.bearer("GET", "/", &token, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(lws_challenge(&resp).is_none());
    // But the M1 discovery surface IS there.
    let resp = h.anon("GET", "/.well-known/lws").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- 7. Documented consequence: an unbound origin-audience at+jwt IS an LWS token ----------------

#[tokio::test]
async fn unbound_origin_audience_token_from_the_trusted_as_is_accepted_by_design() {
    // decisions/0005: with the LWS chain on, ANY unbound (`cnf`-less) at+jwt from a trusted AS
    // whose single audience is this storage IS an LWS access token — there is no separate "LWS
    // token type". That is the spec's design (the AS is trusted to assert `sub` as the agent);
    // the flag-off posture (rejected: DPoP required) is pinned above. PoP-BOUND tokens are never
    // downgraded (the bare-cnf rejection in the matrix).
    let h = Harness::build(Mode::Full).await;
    let mut c = lws_claims(WEBID, json!(BASE_URL)); // origin-root audience, no trailing slash
    c["webid"] = json!(WEBID); // even with Solid-shaped extras present
    let t = mint_lws(&h.issuer_key, &c);
    let resp = h
        .bearer("PUT", "/origin-aud/doc", &t, Some(("text/plain", "x")))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        h.bearer("GET", "/origin-aud/doc", &t, None).await.status(),
        StatusCode::OK
    );
}

// --- 8. Percent-encoded / traversal target spellings stay inside the audience --------------------

#[tokio::test]
async fn hostile_target_spellings_cannot_escape_the_audience() {
    let h = Harness::build(Mode::Full).await;
    let owner = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h
        .bearer(
            "PUT",
            "/alicemalicious/doc",
            &owner,
            Some(("text/plain", "x")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let scoped = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/alice/"))),
    );
    // Dot-segment traversal out of the audience subtree: normalized away or rejected — never a
    // 200 outside the audience.
    let resp = h
        .bearer("GET", "/alice/../alicemalicious/doc", &scoped, None)
        .await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "traversal must not escape the audience"
    );
    // Percent-encoded sibling spelling.
    let resp = h
        .bearer("GET", "/%61licemalicious/doc", &scoped, None)
        .await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "encoded sibling must not slip through"
    );

    // THE roborev-Medium exploit, executed end-to-end. A token scoped to …/bob/ against a target
    // whose url-normalized path lands in …/bob/ (…/alice/%2e%2e/bob/doc ⇒ …/bob/doc) but whose
    // ACTUAL store/WAC identity is the literal …/alice/%2e%2e/bob/doc (a resource under …/alice/,
    // which `parse_target` keeps verbatim). Pre-guard, the audience check would pass and hand the
    // request to WAC on the /alice/ identity — an audience-scope escape. The identity-guard makes
    // the audience check FAIL CLOSED (401 + the invalid_token challenge) on ANY renormalizing
    // target — so the /bob/-scoped token never reaches an /alice/-subtree resource.
    let bob_scoped = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/bob/"))),
    );
    for (method, path, body) in [
        ("GET", "/alice/%2e%2e/bob/doc", None),
        ("PUT", "/alice/%2e%2e/bob/new", Some(("text/plain", "x"))),
    ] {
        let resp = h.bearer(method, path, &bob_scoped, body).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}: the identity-ambiguous target must be refused by the audience guard"
        );
        assert!(
            lws_challenge(&resp)
                .expect("guard rejection carries the challenge")
                .contains("error=\"invalid_token\""),
            "{method} {path}: it is the audience/at+jwt guard (401 invalid_token), not WAC"
        );
    }
    // The guard is conservative: it refuses a renormalizing target even for the ROOT-audience
    // owner token (identity must be unambiguous before any containment decision) — never a 200.
    let resp = h.bearer("GET", "/alice/%2e%2e/bob/doc", &owner, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- 6. RFC 9396 authorization_details — NARROWING-ONLY, over HTTP (M3, spec §rar) --------------

/// Baseline LWS claims + an `authorization_details` member.
fn lws_claims_with_details(sub: &str, aud: Value, details: Value) -> Value {
    let mut claims = lws_claims(sub, aud);
    claims["authorization_details"] = details;
    claims
}

fn access_request(locations: Value, actions: Value) -> Value {
    json!({
        "type": "https://w3id.org/jeswr/lws#AccessRequest",
        "locations": locations,
        "actions": actions,
    })
}

#[tokio::test]
async fn authorization_details_narrows_locations_and_actions() {
    let h = Harness::build(Mode::Full).await;
    // Seed two docs as the (un-narrowed) owner.
    let owner = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    for path in ["/alice/notes/a.txt", "/alice/other.txt"] {
        let resp = h
            .bearer("PUT", path, &owner, Some(("text/plain", "x")))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{path}");
    }

    // The SAME agent, narrowed to read-only on /alice/notes/ — WAC allows everything for this
    // agent, so every denial below is attributable to the narrowing alone.
    let narrowed = mint_lws(
        &h.issuer_key,
        &lws_claims_with_details(
            WEBID,
            json!(format!("{BASE_URL}/")),
            json!([access_request(
                json!([format!("{BASE_URL}/alice/notes/")]),
                json!(["read"])
            )]),
        ),
    );

    // Covered (location + action): permitted — the WAC decision stands (rar-covering-claim vector).
    let resp = h.bearer("GET", "/alice/notes/a.txt", &narrowed, None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // A target OUTSIDE the locations: 403 insufficient_scope, even though WAC would allow
    // (rar-narrows-locations). NB 403 — the token is VALID; its scope is not.
    let resp = h.bearer("GET", "/alice/other.txt", &narrowed, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        lws_challenge(&resp)
            .expect("narrowing denial advertises the challenge")
            .contains("error=\"insufficient_scope\""),
        "the RFC 6750 §3.1 insufficient_scope challenge"
    );

    // An ACTION outside the grant (write under a read-only narrowing): 403 insufficient_scope.
    let resp = h
        .bearer(
            "PUT",
            "/alice/notes/a.txt",
            &narrowed,
            Some(("text/plain", "overwrite")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // …and DELETE likewise (delete is NOT implied by anything but odrl:delete).
    let resp = h
        .bearer("DELETE", "/alice/notes/a.txt", &narrowed, None)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // The narrowing denial reveals nothing about existence: a MISSING in-scope target and an
    // out-of-scope one answer the same shape for a non-covered action.
    let resp = h
        .bearer("DELETE", "/alice/notes/missing.txt", &narrowed, None)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The narrowed token still cannot escape its AUDIENCE either — narrowing composes UNDER the
    // aud ceiling, it never replaces it.
    let scoped_narrowed = mint_lws(
        &h.issuer_key,
        &lws_claims_with_details(
            WEBID,
            json!(format!("{BASE_URL}/alice/notes/")),
            json!([access_request(
                json!([format!("{BASE_URL}/")]), // WIDER location than the aud
                json!(["read"])
            )]),
        ),
    );
    let resp = h
        .bearer("GET", "/alice/other.txt", &scoped_narrowed, None)
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a location wider than the aud never widens past the aud ceiling"
    );
}

#[tokio::test]
async fn authorization_details_can_never_widen_beyond_wac() {
    let h = Harness::build(Mode::Full).await;
    // Seed a private doc as the owner.
    let owner = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h
        .bearer(
            "PUT",
            "/alice/private",
            &owner,
            Some(("text/plain", "secret")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // BOB's token carries a claim "granting" read+modify+delete on the whole storage — WAC (the
    // ceiling) still denies: 403, and the resource is untouched (the spec's rar-cannot-widen
    // MUST).
    let bob_widened = mint_lws(
        &h.issuer_key,
        &lws_claims_with_details(
            BOB,
            json!(format!("{BASE_URL}/")),
            json!([access_request(
                json!([format!("{BASE_URL}/")]),
                json!(["read", "modify", "delete"])
            )]),
        ),
    );
    let resp = h.bearer("GET", "/alice/private", &bob_widened, None).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "WAC remains the ceiling"
    );
    let resp = h
        .bearer(
            "PUT",
            "/alice/private",
            &bob_widened,
            Some(("text/plain", "clobber")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = h
        .bearer("DELETE", "/alice/private", &bob_widened, None)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // The owner still reads the ORIGINAL content — nothing was widened into existence.
    let resp = h.bearer("GET", "/alice/private", &owner, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"secret");
}

#[tokio::test]
async fn malformed_authorization_details_fail_closed_as_401() {
    let h = Harness::build(Mode::Full).await;
    let owner = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h
        .bearer("PUT", "/alice/doc", &owner, Some(("text/plain", "x")))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Every malformed shape rejects the TOKEN (401 invalid_token) — never "ignored ⇒ full WAC
    // baseline", which would silently widen past the AS's encoded decision.
    for bad in [
        json!("read-everything"), // not an array
        json!([]),                // empty
        json!([{ "type": "https://other.example/Grant",
                 "locations": [format!("{BASE_URL}/")],
                 "actions": ["read"] }]), // foreign entry type
        json!([{ "type": "https://w3id.org/jeswr/lws#AccessRequest",
                 "actions": ["read"] }]), // no locations
        json!([access_request(json!(["not-a-uri"]), json!(["read"]))]), // relative location
        json!([access_request(json!([format!("{BASE_URL}/")]), json!([]))]), // empty actions
    ] {
        let token = mint_lws(
            &h.issuer_key,
            &lws_claims_with_details(WEBID, json!(format!("{BASE_URL}/")), bad.clone()),
        );
        let resp = h.bearer("GET", "/alice/doc", &token, None).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "must reject: {bad}"
        );
        assert!(
            lws_challenge(&resp)
                .expect("fail-closed rejection carries the challenge")
                .contains("error=\"invalid_token\""),
            "{bad}"
        );
    }

    // An entry carrying constraints this server cannot evaluate (purposes/datatypes) is
    // intelligible but GRANTS NOTHING — a valid token whose scope covers nothing: 403.
    let constrained = mint_lws(
        &h.issuer_key,
        &lws_claims_with_details(
            WEBID,
            json!(format!("{BASE_URL}/")),
            json!([{
                "type": "https://w3id.org/jeswr/lws#AccessRequest",
                "locations": [format!("{BASE_URL}/")],
                "actions": ["read"],
                "purposes": ["https://purpose.example/marketing"],
            }]),
        ),
    );
    let resp = h.bearer("GET", "/alice/doc", &constrained, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(lws_challenge(&resp)
        .expect("challenge")
        .contains("error=\"insufficient_scope\""));
}

#[tokio::test]
async fn delete_only_narrowing_permits_exactly_delete() {
    let h = Harness::build(Mode::Full).await;
    let owner = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h
        .bearer("PUT", "/alice/tmp/x", &owner, Some(("text/plain", "x")))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let delete_only = mint_lws(
        &h.issuer_key,
        &lws_claims_with_details(
            WEBID,
            json!(format!("{BASE_URL}/")),
            json!([access_request(
                json!([format!("{BASE_URL}/alice/tmp/")]),
                json!(["delete"])
            )]),
        ),
    );
    // Read/write under a delete-only grant: 403.
    let resp = h.bearer("GET", "/alice/tmp/x", &delete_only, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = h
        .bearer(
            "PUT",
            "/alice/tmp/x",
            &delete_only,
            Some(("text/plain", "y")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // The granted action works (WAC allows — the owner).
    let resp = h.bearer("DELETE", "/alice/tmp/x", &delete_only, None).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn absent_authorization_details_leaves_the_wac_baseline() {
    // The rar-absent vector: no claim ⇒ the storage-server policy alone decides. This is exactly
    // the M2 baseline every earlier test in this file exercises; pin it explicitly beside the
    // narrowing cases.
    let h = Harness::build(Mode::Full).await;
    let owner = mint_lws(
        &h.issuer_key,
        &lws_claims(WEBID, json!(format!("{BASE_URL}/"))),
    );
    let resp = h
        .bearer("PUT", "/alice/base", &owner, Some(("text/plain", "x")))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = h.bearer("GET", "/alice/base", &owner, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
