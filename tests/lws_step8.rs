// AUTHORED-BY Claude Fable 5
//! End-to-end tests for the **step-8 spec-alignment increments A + B** (`decisions/0007`;
//! `jeswr/lws-spec` `docs/alignment/{dpop-sk,a2a-rdf}.md`) through the assembled router:
//!
//! - **A — DPoP-SK over LWS** (alignment verdict (c), AUTH-layer PoP presentation profile): the
//!   `pop_session` RFC 9728 member appears beside `jlws_storage_description` when the engine is
//!   on and never otherwise; a DPoP-SK attestation authenticates via the PoP dispatch on an
//!   LWS-on build (WAC enforced, replay still denied); a `cnf`-bound token is NEVER dispatched to
//!   the plain-Bearer LWS path (bare ⇒ 401; with its proof ⇒ the PoP path accepts); the M2
//!   Bearer baseline is unchanged beside it (D9: `dpop_bound_access_tokens_required` alone
//!   governs the posture — `pop_session` is additive).
//! - **B — the a2a-rdf discovery affordance** (verdict (d), REFERENCE + optional extension
//!   service): the `AgentInteractionService` storage-description entry appears exactly when the
//!   agent-card URL is configured, with the alignment doc's exact member set.
//! - **Flag-off invariance**: with no LWS (and no SK tier) neither new surface exists anywhere —
//!   the pre-step-8 route table and byte behaviour stand (extending the M1–M3 invariance pins).
//!
//! Where the lws-spec `dpop-sk`/`discovery` test vectors define server-observable expectations
//! (`prm-carries-pop-session`, `pop-required-single-member`, `sd-agent-interaction-service`),
//! this file asserts them in Rust; the language-neutral vector files themselves are increment C's
//! deliverable in `jeswr/lws-spec`. The DPoP-SK establishment/attestation negative matrices
//! (`establish-ok-none-binding`, `attest-*`) are already pinned byte-for-byte against the spec's
//! Appendix-A vectors by the `pop::sk` unit suites + `tests/pop_dpop_sk.rs`.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use common::{jwks_provider, mint_access_token, mint_dpop_proof, KeyKit, BASE_URL, ISSUER, WEBID};
use serde_json::{json, Value};
use solid_oidc_verifier::config::{JwksProvider, VerifierConfig};
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::lws::auth::LwsBearerAuth;
use solid_server_rs::lws::{
    LwsConfig, A2A_AGENT_INTERACTION_SERVICE, A2A_RDF_EXTENSION, STORAGE_DESCRIPTION_PATH,
};
use solid_server_rs::pop::sk::derive::{hmac_sign, SessionKey};
use solid_server_rs::pop::sk::{SkConfig, SkState, SESSION_ENDPOINT_PATH};
use solid_server_rs::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient, Store};
use tower::ServiceExt;

const PRM_PATH: &str = "/.well-known/oauth-protected-resource";
const CARD_URL: &str = "https://agent.example/.well-known/agent-card.json";
const DPOP_SK_PROFILE: &str = "https://w3id.org/jeswr/dpop-sk/v1";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Baseline VALID LWS `at+jwt` claims (the M2 shape: trusted issuer, agent `sub`, storage-root
/// audience, inside the ≤300 s window).
fn lws_claims(sub: &str) -> Value {
    let n = now();
    json!({
        "iss": ISSUER,
        "sub": sub,
        "client_id": "lws-app",
        "aud": format!("{BASE_URL}/"),
        "iat": n,
        "exp": n + 120,
        "jti": format!("lws-jti-{n}-{sub}"),
    })
}

/// The step-8 harness postures.
struct Posture {
    /// Mount the LWS surface + auth chain (the master flag). Off ⇒ the pre-LWS build.
    lws: bool,
    /// The LWS realm is PoP-required (`SOLID_SERVER_LWS_REQUIRE_POP`).
    require_pop: bool,
    /// Enable the DPoP-SK engine (what `SOLID_SERVER_LWS_POP_SESSION` — or the pre-existing
    /// `SOLID_SERVER_DPOP_SK` — wires in `main`: ONE shared `SkState`).
    sk: bool,
    /// The step-8-B agent-card URL (what `SOLID_SERVER_LWS_AGENT_CARD_URL` wires).
    agent_card: Option<&'static str>,
}

struct Harness {
    app: axum::Router,
    issuer_key: KeyKit,
    client_key: KeyKit,
}

impl Harness {
    async fn build(p: Posture) -> Self {
        let issuer_key = KeyKit::generate();
        let client_key = KeyKit::generate();
        let config = VerifierConfig::new(vec![ISSUER.to_string()], BASE_URL);
        let replay = InMemoryReplayStore::with_window(config.replay_ttl());
        let verifier = Verifier::new(config, jwks_provider(&issuer_key), replay).unwrap();
        let mut ctx = AuthContext::new(verifier, BASE_URL);
        if p.sk {
            ctx = ctx.with_dpop_sk(Some(Arc::new(SkState::new(SkConfig::default()))));
        }
        if p.lws {
            let jwks: Arc<dyn JwksProvider> = Arc::new(jwks_provider(&issuer_key));
            let lws = LwsBearerAuth::new(jwks, vec![ISSUER.to_string()], BASE_URL, p.require_pop)
                .unwrap();
            ctx = ctx.with_lws_bearer(Some(Arc::new(lws)));
        }

        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        // Root owner ACL: Alice Read/Write/Control on the root + all descendants (the shared
        // fixture) — everything is PRIVATE, so every accept below is a real WAC decision.
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
        if p.lws {
            ldp.set_lws(Some(Arc::new(
                LwsConfig::new(BASE_URL, true, false).with_agent_card_url(p.agent_card),
            )));
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

    /// A fresh cnf-bound Solid-OIDC access token + `Authorization`/`DPoP` headers for
    /// `method path` (the ordinary full-strength DPoP credentials).
    fn dpop_headers(&self, method: &str, path: &str) -> (String, String, String) {
        let access = mint_access_token(&self.issuer_key, &self.client_key.thumbprint);
        let htu = format!("{BASE_URL}{path}");
        let proof = mint_dpop_proof(&self.client_key, method, &htu, &access);
        (access.clone(), format!("DPoP {access}"), proof)
    }

    async fn dpop(
        &self,
        method: &str,
        path: &str,
        body: Option<(&str, &str)>,
    ) -> axum::http::Response<Body> {
        let (_, authz, proof) = self.dpop_headers(method, path);
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, authz)
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

    /// Establish a `cb=none` DPoP-SK session with one ordinary DPoP proof; returns
    /// (session_id, K, the bound access token).
    async fn establish_none(&self) -> (String, SessionKey, String) {
        let (access, authz, proof) = self.dpop_headers("POST", SESSION_ENDPOINT_PATH);
        let req = Request::builder()
            .method("POST")
            .uri(SESSION_ENDPOINT_PATH)
            .header(header::AUTHORIZATION, &authz)
            .header("dpop", &proof)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"cb":"none"}"#))
            .unwrap();
        let resp = self.send(req).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "establishment");
        let json = body_json(resp).await;
        let key_bytes = URL_SAFE_NO_PAD
            .decode(json["key"].as_str().unwrap())
            .unwrap();
        (
            json["session_id"].as_str().unwrap().to_string(),
            SessionKey::new(key_bytes.try_into().unwrap()),
            access,
        )
    }

    /// A DPoP-SK-attested request (NO DPoP proof header — the attestation replaces it), built
    /// exactly as a conforming client would (the same construction `tests/pop_dpop_sk.rs` pins).
    async fn attested(
        &self,
        method: &str,
        path: &str,
        access_token: &str,
        session_id: &str,
        key: &SessionKey,
        nonce: u64,
    ) -> axum::http::Response<Body> {
        let authz = format!("DPoP {access_token}");
        let params = format!(
            "(\"@method\" \"@target-uri\" \"authorization\");created={};keyid=\"{session_id}\";alg=\"hmac-sha256\";nonce=\"{nonce}\";tag=\"dpop-sk\"",
            now()
        );
        let base = format!(
            "\"@method\": {method}\n\"@target-uri\": {BASE_URL}{path}\n\"authorization\": {authz}\n\"@signature-params\": {params}"
        );
        let tag = hmac_sign(key, base.as_bytes());
        self.send(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, authz)
                .header("signature-input", format!("sig={params}"))
                .header("signature", format!("sig=:{}:", STANDARD.encode(tag)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

async fn body_json(resp: axum::http::Response<Body>) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).expect("JSON body")
}

fn challenges(resp: &axum::http::Response<Body>) -> Vec<String> {
    resp.headers()
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

// =================================================================================================
// A — the PRM shape (the lws-spec `prm-carries-pop-session` / `pop-required-single-member` pins)
// =================================================================================================

#[tokio::test]
async fn prm_carries_pop_session_beside_the_lws_members_when_enabled() {
    let h = Harness::build(Posture {
        lws: true,
        require_pop: false,
        sk: true,
        agent_card: None,
    })
    .await;
    let resp = h.anon("GET", PRM_PATH).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;

    // `prm-carries-pop-session`: the DPoP-SK member and the LWS members COEXIST in one document.
    let ps = &doc["pop_session"];
    assert_eq!(
        ps["endpoint"],
        json!(format!("{BASE_URL}{SESSION_ENDPOINT_PATH}"))
    );
    assert_eq!(ps["algs"], json!(["hmac-sha256"]));
    // No in-process TLS in this harness ⇒ tls-exporter MUST NOT be offered (inherited gating).
    assert_eq!(ps["channel_bindings"], json!(["none"]));
    assert_eq!(ps["profile"], json!(DPOP_SK_PROFILE));
    assert_eq!(
        doc["jlws_storage_description"],
        json!(format!("{BASE_URL}/.well-known/lws"))
    );
    assert_eq!(doc["authorization_servers"], json!([ISSUER]));
    // D9 / additive advertisement: offering DPoP-SK does NOT flip the realm PoP-required — the
    // one registered member stays an honest `false` on the Bearer baseline.
    assert_eq!(doc["dpop_bound_access_tokens_required"], json!(false));
}

#[tokio::test]
async fn prm_omits_pop_session_when_the_engine_is_off() {
    // LWS on, DPoP-SK engine off (the `SOLID_SERVER_LWS_POP_SESSION`-unset posture): the LWS
    // members are there, the pop_session member is NOT — and nothing else changed.
    let h = Harness::build(Posture {
        lws: true,
        require_pop: false,
        sk: false,
        agent_card: None,
    })
    .await;
    let doc = body_json(h.anon("GET", PRM_PATH).await).await;
    assert!(doc.get("pop_session").is_none(), "{doc}");
    assert_eq!(
        doc["jlws_storage_description"],
        json!(format!("{BASE_URL}/.well-known/lws"))
    );
    assert_eq!(doc["dpop_bound_access_tokens_required"], json!(false));
}

#[tokio::test]
async fn pop_required_realm_offers_dpop_sk_and_still_refuses_bearer() {
    // `pop-required-single-member`: dpop_bound_access_tokens_required: true + pop_session
    // coexist; the client may then use DPoP OR DPoP-SK; Bearer is refused.
    let h = Harness::build(Posture {
        lws: true,
        require_pop: true,
        sk: true,
        agent_card: None,
    })
    .await;
    let doc = body_json(h.anon("GET", PRM_PATH).await).await;
    assert_eq!(doc["dpop_bound_access_tokens_required"], json!(true));
    assert_eq!(doc["pop_session"]["profile"], json!(DPOP_SK_PROFILE));

    // Bearer (even a fully valid LWS token) is CLOSED — the challenge lists only DPoP.
    let token = h.issuer_key.sign(
        &json!({ "alg": "ES256", "typ": "at+jwt" }),
        &lws_claims(WEBID),
    );
    let resp = h.bearer("GET", "/", &token, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let lws_challenge = challenges(&resp)
        .into_iter()
        .find(|c| c.contains("resource_metadata="))
        .expect("discovery challenge");
    assert!(lws_challenge.starts_with("DPoP "), "{lws_challenge}");

    // DPoP still works (the mandatory baseline)…
    let resp = h.dpop("PUT", "/probe", Some(("text/plain", "x"))).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    // …and so does DPoP-SK: establish once, then attest (the second PoP profile, end to end).
    let (session_id, key, access) = h.establish_none().await;
    let resp = h
        .attested("GET", "/probe", &access, &session_id, &key, 1)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// =================================================================================================
// A — the PoP-path/Bearer-path dispatch composition (the M2 seam, untouched and proven)
// =================================================================================================

#[tokio::test]
async fn dpop_sk_attestation_and_lws_bearer_coexist() {
    let h = Harness::build(Posture {
        lws: true,
        require_pop: false,
        sk: true,
        agent_card: None,
    })
    .await;

    // Seed a private resource with ordinary DPoP.
    let resp = h
        .dpop("PUT", "/alice/data", Some(("text/plain", "hi")))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // One DPoP proof at establishment, then attested requests — the PoP path, with LWS mounted.
    let (session_id, key, access) = h.establish_none().await;
    let resp = h
        .attested("GET", "/alice/data", &access, &session_id, &key, 1)
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "attested GET under LWS-on");

    // A REPLAYED nonce is still denied — the SK verify runs at full strength beside LWS (and the
    // LWS challenge layer appends discovery to its 401, per §authz-discovery).
    let resp = h
        .attested("GET", "/alice/data", &access, &session_id, &key, 1)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "replayed nonce");
    assert!(
        challenges(&resp).iter().any(|c| c.contains("DPoP")),
        "standard DPoP challenge: {:?}",
        challenges(&resp)
    );

    // The M2 plain-Bearer LWS flow is UNCHANGED in the same build: write + read as the sub agent.
    let token = h.issuer_key.sign(
        &json!({ "alg": "ES256", "typ": "at+jwt" }),
        &lws_claims(WEBID),
    );
    let resp = h
        .bearer("PUT", "/alice/notes/x", &token, Some(("text/plain", "lws")))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "LWS Bearer PUT");
    let resp = h.bearer("GET", "/alice/notes/x", &token, None).await;
    assert_eq!(resp.status(), StatusCode::OK, "LWS Bearer GET");
}

#[tokio::test]
async fn cnf_bound_token_is_never_dispatched_to_the_lws_bearer_path() {
    let h = Harness::build(Posture {
        lws: true,
        require_pop: false,
        sk: true,
        agent_card: None,
    })
    .await;

    // A cnf-bound token with a URI-shaped audience (exactly the DPoP-SK-establishable shape).
    // Presented BARE as Bearer it must be REJECTED — `cnf` excludes it from LWS candidacy, and
    // the verifier path demands its proof (never a bearer downgrade on either branch).
    let access = mint_access_token(&h.issuer_key, &h.client_key.thumbprint);
    let resp = h.bearer("GET", "/alice/data", &access, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "bare cnf Bearer");

    // An LWS-shaped claims-set WITH a cnf binding, bare: same refusal (rs-validation step 5 —
    // whichever branch sees it, a PoP-bound token is never accepted bare).
    let mut claims = lws_claims(WEBID);
    claims["cnf"] = json!({ "jkt": h.client_key.thumbprint });
    let bound_lws = h
        .issuer_key
        .sign(&json!({ "alg": "ES256", "typ": "at+jwt" }), &claims);
    let resp = h.bearer("GET", "/alice/data", &bound_lws, None).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "bare cnf LWS-shaped"
    );

    // The SAME cnf-bound token WITH its DPoP proof validates via the PoP path (a seed write, so
    // the accept is a real end-to-end WAC-authorized mutation).
    let resp = h
        .dpop("PUT", "/alice/pop-doc", Some(("text/plain", "pop")))
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "cnf + proof via PoP path"
    );
}

// =================================================================================================
// B — the AgentInteractionService storage-description entry (`sd-agent-interaction-service`)
// =================================================================================================

#[tokio::test]
async fn storage_description_advertises_the_agent_when_configured() {
    let h = Harness::build(Posture {
        lws: true,
        require_pop: false,
        sk: false,
        agent_card: Some(CARD_URL),
    })
    .await;
    let resp = h.anon("GET", STORAGE_DESCRIPTION_PATH).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    let services = doc["service"].as_array().unwrap();
    // The required StorageDescription entry stands…
    assert!(services.iter().any(|s| s["type"] == "StorageDescription"));
    // …and the extension entry carries the alignment doc's exact members (`serviceEndpoint` = the
    // Agent CARD URL; `conformsTo` = the extension URI).
    let agent = services
        .iter()
        .find(|s| s["type"] == A2A_AGENT_INTERACTION_SERVICE)
        .expect("AgentInteractionService entry");
    assert_eq!(agent["serviceEndpoint"], json!(CARD_URL));
    assert_eq!(agent["conformsTo"], json!(A2A_RDF_EXTENSION));
    // Verdict (d): a reference affordance — the entry adds NO core conformance/capability claim.
    assert!(!doc["conformsTo"].to_string().contains("a2a-rdf"));
}

#[tokio::test]
async fn storage_description_omits_the_agent_entry_by_default() {
    let h = Harness::build(Posture {
        lws: true,
        require_pop: false,
        sk: false,
        agent_card: None,
    })
    .await;
    let doc = body_json(h.anon("GET", STORAGE_DESCRIPTION_PATH).await).await;
    let services = doc["service"].as_array().unwrap();
    assert_eq!(services.len(), 1, "exactly the StorageDescription entry");
    assert_eq!(services[0]["type"], "StorageDescription");
}

// =================================================================================================
// Flag-off invariance: NEITHER new surface exists on a build without the LWS flag (or SK tier)
// =================================================================================================

#[tokio::test]
async fn flag_off_build_has_neither_new_surface() {
    let h = Harness::build(Posture {
        lws: false,
        require_pop: false,
        sk: false,
        agent_card: None, // moot: without the master flag no LwsConfig exists at all
    })
    .await;
    // No RFC 9728 route (so no pop_session member anywhere) — the LDP wildcard answers.
    let resp = h.anon("GET", PRM_PATH).await;
    assert_ne!(resp.status(), StatusCode::OK);
    // No storage-description route (so no AgentInteractionService entry anywhere).
    let resp = h.anon("GET", STORAGE_DESCRIPTION_PATH).await;
    assert_ne!(resp.status(), StatusCode::OK);
    // The pre-LWS auth posture stands: a valid LWS-shaped Bearer token is NOT accepted…
    let token = h.issuer_key.sign(
        &json!({ "alg": "ES256", "typ": "at+jwt" }),
        &lws_claims(WEBID),
    );
    let resp = h.bearer("GET", "/", &token, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        challenges(&resp)
            .iter()
            .all(|c| !c.contains("resource_metadata=")),
        "no discovery challenge on a flag-off build: {:?}",
        challenges(&resp)
    );
    // …and the ordinary DPoP flow works, byte-identically to pre-step-8.
    let resp = h.dpop("PUT", "/probe", Some(("text/plain", "x"))).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = h.dpop("GET", "/probe", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
