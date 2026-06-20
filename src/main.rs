// AUTHORED-BY Claude Opus 4.8
//! EXPERIMENTAL solid-server-rs binary entry point.
//!
//! Boots the M1 vertical slice: an axum server with DPoP-bound auth (delegated to
//! `solid-oidc-verifier`) over a GET/HEAD/PUT LDP path backed by a [`CompositeStore`]
//! (SPARQ-authoritative metadata + object_store-backup bytes).
//!
//! At M1 the storage + JWKS seams are the in-memory test doubles, so the server boots and serves a
//! coherent slice **without** a running SPARQ / S3 / IdP. M2 swaps in:
//! - the network-backed JWKS provider (OIDC discovery via the verifier's M2 adapter),
//! - the live SPARQ HTTP client (needs a running SPARQ),
//! - the `object_store`-backed blob store (S3 / Local),
//! - rustls TLS termination (the `rustls`/`aws-lc-rs` dependency is wired; the listener is plain TCP
//!   in M1 for a dependency-free local boot).

use solid_oidc_verifier::config::{StaticJwksProvider, VerifierConfig};
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure the rustls process-wide crypto provider (aws-lc-rs) is installed before any TLS use.
    // M2 uses this provider for rustls TLS termination; installing it here makes M1's wiring honest.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let base_url = std::env::var("SOLID_SERVER_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let bind = std::env::var("SOLID_SERVER_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let issuer = std::env::var("SOLID_SERVER_TRUSTED_ISSUER")
        .unwrap_or_else(|_| "https://idp.example/realms/solid".to_string());

    // --- Auth (delegated to solid-oidc-verifier). M1 uses the static-JWKS + in-memory replay seams.
    // M2: replace StaticJwksProvider with the network OIDC-discovery provider, and the in-memory
    // replay store with a shared (Redis SET NX) ReplayStore impl.
    let config = VerifierConfig::new(vec![issuer], base_url.clone());
    let jwks = StaticJwksProvider::new();
    let replay = InMemoryReplayStore::with_window(config.replay_ttl());
    let verifier = Verifier::new(config, jwks, replay)?;
    let auth = AuthContext::new(verifier, base_url.clone());

    // --- Storage. SPARQ authoritative for metadata; object_store backup-only for bytes.
    // M1 uses the in-memory doubles so the server boots without SPARQ / S3.
    let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
    let ldp = LdpState::new(store, base_url.clone());

    let app = build_router(AppState::new(auth, ldp));

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("solid-server-rs (EXPERIMENTAL) listening on http://{bind} (base {base_url})");
    eprintln!("WARNING: experimental parallel track — NOT the production prod-solid-server.");

    // Graceful shutdown on Ctrl-C. M2: drain in-flight + WS tasks (spike R: axum#3003).
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
