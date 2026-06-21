// AUTHORED-BY Claude Opus 4.8
//! End-to-end HTTP tests for the WebSocketChannel2023 notification surface through the assembled
//! router: discovery (the `/.well-known/solid` storage description + the LDP read `Link` rels), the
//! auth-gated subscribe handshake (anonymous refused, authenticated returns `receiveFrom`), and a
//! default-`#[ignore]`d live WebSocket handshake that exercises subscribe → connect → mutate →
//! receive against a really-bound server.
//!
//! Each authenticated request carries a fresh DPoP-bound token + a per-request proof (a new jti) so
//! the verifier's single-use replay protection does not reject back-to-back requests.

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

const WS_TYPE: &str = "http://www.w3.org/ns/solid/notifications#WebSocketChannel2023";

/// A oneshot-driven app + the keys to mint authenticated requests. (For the live WS test a separately
/// bound server is used — see `live_websocket_*`.)
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

    fn auth_headers(&self, method: &str, path: &str) -> (String, String) {
        let access = mint_access_token(&self.issuer_key, &self.client_key.thumbprint);
        let htu = format!("{BASE_URL}{path}");
        let proof = mint_dpop_proof(&self.client_key, method, &htu, &access);
        (format!("DPoP {access}"), proof)
    }

    /// An authenticated request.
    async fn auth_request(
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

    /// An UNAUTHENTICATED request (no Authorization / DPoP).
    async fn anon_request(
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

async fn body_string(resp: axum::http::Response<Body>) -> String {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn well_known_solid_advertises_the_subscription_service() {
    let h = Harness::new();
    // Discovery is PUBLIC — no auth needed.
    let resp = h
        .anon_request("GET", "/.well-known/solid", None, Body::empty())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("notificationChannel"), "{body}");
    assert!(body.contains(WS_TYPE), "{body}");
    assert!(
        body.contains("https://pod.example/.notifications/WebSocketChannel2023/"),
        "{body}"
    );
}

#[tokio::test]
async fn ldp_read_advertises_discovery_link_headers() {
    let h = Harness::new();
    // Create a resource, then GET it and inspect the Link headers.
    let put = h
        .auth_request(
            "PUT",
            "/alice/data",
            Some("text/turtle"),
            Body::from("<#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" ."),
        )
        .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let get = h
        .auth_request("GET", "/alice/data", None, Body::empty())
        .await;
    assert_eq!(get.status(), StatusCode::OK);
    let links: Vec<String> = get
        .headers()
        .get_all(axum::http::header::LINK)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let all = links.join(" | ");
    assert!(all.contains("rel=\"describedby\""), "{all}");
    assert!(all.contains("storageDescription"), "{all}");
    assert!(all.contains("/.well-known/solid"), "{all}");
}

#[tokio::test]
async fn subscribe_rejects_anonymous_caller() {
    let h = Harness::new();
    let body = serde_json::json!({
        "@context": "https://www.w3.org/ns/solid/notifications-context/v1",
        "type": WS_TYPE,
        "topic": "https://pod.example/alice/data",
    })
    .to_string();
    let resp = h
        .anon_request(
            "POST",
            "/.notifications/WebSocketChannel2023/",
            Some("application/ld+json"),
            Body::from(body),
        )
        .await;
    // Fail-closed: no anonymous subscriptions.
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn subscribe_authenticated_returns_receive_from() {
    let h = Harness::new();
    let body = serde_json::json!({
        "@context": "https://www.w3.org/ns/solid/notifications-context/v1",
        "type": WS_TYPE,
        "topic": "https://pod.example/alice/data",
    })
    .to_string();
    let resp = h
        .auth_request(
            "POST",
            "/.notifications/WebSocketChannel2023/",
            Some("application/ld+json"),
            Body::from(body),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let out = body_string(resp).await;
    assert!(out.contains("\"receiveFrom\""), "{out}");
    assert!(
        out.contains("wss://pod.example/.notifications/WebSocketChannel2023/receive"),
        "{out}"
    );
    assert!(out.contains(WS_TYPE), "{out}");
}

// --- Live WebSocket end-to-end (default-ignored; binds a real server) ---------------------------

/// A really-bound server whose base URL matches the bound address, so DPoP htu + the WS upgrade work
/// against `127.0.0.1:<port>`. Returns the base URL + the keys.
async fn bind_live_server() -> (String, KeyKit, KeyKit) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let issuer_key = KeyKit::generate();
    let client_key = KeyKit::generate();
    // The audience must match the minted token's `aud` (the `BASE_URL` const), but the AuthContext's
    // base_url must be the BOUND address so the reconstructed DPoP `htu` matches the real request URL.
    let config = VerifierConfig::new(vec![common::ISSUER.to_string()], BASE_URL);
    let replay = InMemoryReplayStore::with_window(config.replay_ttl());
    let verifier = Verifier::new(config, jwks_provider(&issuer_key), replay).unwrap();
    let ctx = AuthContext::new(verifier, base_url.clone());
    let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
    let ldp = LdpState::new(store, base_url.clone());
    let app = build_router(AppState {
        auth: Arc::new(ctx),
        ldp: Arc::new(ldp),
    });

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base_url, issuer_key, client_key)
}

/// Default-ignored: a full subscribe → connect WebSocket → PUT → receive an AS2.0 Update over the
/// socket. Ignored because it depends on transport timing + a really-bound listener; run explicitly
/// with `cargo test --test notifications_http -- --ignored`.
#[tokio::test]
#[ignore = "live WebSocket handshake; run with --ignored"]
async fn live_websocket_delivers_update_on_put() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let (base_url, issuer_key, client_key) = bind_live_server().await;
    let topic = format!("{base_url}/alice/data");

    let auth = |method: &str, path: &str| {
        let access = mint_access_token(&issuer_key, &client_key.thumbprint);
        let htu = format!("{base_url}{path}");
        let proof = mint_dpop_proof(&client_key, method, &htu, &access);
        (format!("DPoP {access}"), proof)
    };

    let http = reqwest_like_client();

    // 1. Subscribe (authenticated) → get the receiveFrom URL.
    let (authz, dpop) = auth("POST", "/.notifications/WebSocketChannel2023/");
    let sub_body = serde_json::json!({
        "type": WS_TYPE,
        "topic": topic,
    })
    .to_string();
    let sub = http
        .post(format!("{base_url}/.notifications/WebSocketChannel2023/"))
        .header("authorization", authz)
        .header("dpop", dpop)
        .header("content-type", "application/ld+json")
        .body(sub_body)
        .send()
        .await
        .unwrap();
    assert_eq!(sub.status(), 200);
    let channel: serde_json::Value = sub.json().await.unwrap();
    let receive_from = channel["receiveFrom"].as_str().unwrap().to_string();

    // 2. Connect the WebSocket to receiveFrom.
    let (mut ws, _) = tokio_tungstenite::connect_async(&receive_from)
        .await
        .expect("ws connects");

    // Give the receive task a moment to register the subscriber before we mutate.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 3. PUT the topic resource (authenticated).
    let (authz, dpop) = auth("PUT", "/alice/data");
    let put = http
        .put(topic.clone())
        .header("authorization", authz)
        .header("dpop", dpop)
        .header("content-type", "text/turtle")
        .body("<#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .")
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "PUT status {}", put.status());

    // 4. Receive the AS2.0 notification over the socket (with a timeout so a miss fails, not hangs).
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("a notification arrived within the timeout")
        .expect("the stream yielded a frame")
        .expect("the frame is Ok");
    let text = match frame {
        WsMessage::Text(t) => t.to_string(),
        other => panic!("expected a text notification, got {other:?}"),
    };
    // A PUT-create ⇒ Create on the resource.
    assert!(text.contains("\"type\":\"Create\""), "{text}");
    assert!(text.contains(&format!("\"object\":\"{topic}\"")), "{text}");

    let _ = ws.send(WsMessage::Close(None)).await;
}

/// A tiny HTTP client over reqwest (already in the resolved tree via the verifier's network feature).
fn reqwest_like_client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}
