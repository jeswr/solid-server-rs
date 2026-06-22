// AUTHORED-BY Claude Opus 4.8
//! EXPERIMENTAL solid-server-rs binary entry point.
//!
//! Boots the vertical slice: an axum server with **real** DPoP-bound Solid-OIDC auth (delegated to
//! `solid-oidc-verifier`'s network adapters) over the LDP verb path backed by a [`CompositeStore`]
//! (SPARQ-authoritative metadata + object_store-backup bytes).
//!
//! ## Auth (REAL, network-backed)
//! The binary wires the verifier's M2 network adapters so token verification is genuine:
//! - [`NetworkJwksProvider`] performs OIDC discovery (`<issuer>/.well-known/openid-configuration`) →
//!   `jwks_uri` → JWKS fetch + parse, cached, **every** fetch through the DNS-pinned SSRF-guarded
//!   `SafeFetcher` (a `jwks_uri` at a private host fails closed).
//! - [`NetworkWebIdResolver`] (when the bidirectional WebID↔issuer check is enabled) fetches the
//!   WebID profile over the same SSRF-guarded path and extracts `solid:oidcIssuer`.
//! - The verification CORE (RFC 9068 `at+jwt`, RFC 9449 DPoP, RFC 7638 thumbprint, asymmetric-only,
//!   issuer-agnostic trusted-issuer allowlist, jti replay) is the verifier crate's — never reimplemented.
//!
//! Configuration is environment-driven (see the `*_ENV` constants below). Sensible production
//! defaults: HTTPS-only IdP/WebID (loopback refused), DPoP required, strict bidirectional check.
//!
//! ## TLS termination (config-gated)
//! When `SOLID_SERVER_TLS_CERT` + `SOLID_SERVER_TLS_KEY` (PEM file paths) are BOTH set, the binary
//! terminates HTTPS in-process via `axum-server` over the house rustls/aws-lc-rs stack; when NEITHER
//! is set it keeps the plain-TCP listener (terminate TLS at a reverse proxy). See [`solid_server_rs::tls`]
//! for the config-shape decision (PEM paths, both-or-neither validation, ACME noted as a future seam).
//! Both serve paths share the same `SOLID_SERVER_BIND` resolution (hostname:port accepted, not only a
//! numeric `SocketAddr`) and the same Ctrl-C graceful-drain behaviour.
//!
//! ## Still seamed (not in this slice)
//! - The live SPARQ HTTP client + the `object_store`-backed blob store (the binary still boots the
//!   in-memory store doubles so it runs without SPARQ / S3; swapping in `HttpSparqClient` is wiring).
//! - WAC authorization (gated on sparq#992 — the LDP layer is fail-closed: mutations need an
//!   authenticated caller, reads are public since no ACLs exist yet).

use std::sync::Arc;
use std::time::Duration;

use solid_oidc_verifier::config::{NetworkJwksProvider, VerifierConfig};
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::Verifier;
use solid_oidc_verifier::webid::{BidirectionalMode, NetworkWebIdResolver};
use solid_server_rs::app::{build_router, AppState};
use solid_server_rs::auth::AuthContext;
use solid_server_rs::ldp::handler::LdpState;
use solid_server_rs::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient};
use solid_server_rs::tls::{self, TlsMode};

// --- Environment configuration keys ----------------------------------------------------------------
const ENV_BASE_URL: &str = "SOLID_SERVER_BASE_URL";
const ENV_BIND: &str = "SOLID_SERVER_BIND";
const ENV_TRUSTED_ISSUER: &str = "SOLID_SERVER_TRUSTED_ISSUER";
/// The RS's identity required in a token's `aud` (RFC 9068). Defaults to the base URL.
const ENV_AUDIENCE: &str = "SOLID_SERVER_AUDIENCE";
/// Dev/IT ONLY: permit an `http:`/loopback IdP + WebID host (the SSRF gate normally refuses them).
/// Anything other than `1`/`true` keeps the production posture (HTTPS-only, no loopback).
const ENV_ALLOW_LOOPBACK: &str = "SOLID_SERVER_ALLOW_LOOPBACK";
/// JWKS cache TTL in seconds (how long a discovered keyset is reused before re-fetching). Default 300.
const ENV_JWKS_CACHE_TTL_SECS: &str = "SOLID_SERVER_JWKS_CACHE_TTL_SECS";
/// Bidirectional WebID↔issuer check mode: `strict` (default) / `warn` / `off`.
const ENV_BIDIRECTIONAL: &str = "SOLID_SERVER_BIDIRECTIONAL";
/// Dev/conformance ONLY: when `1`/`true`, seed the in-memory store with the conformance test users'
/// WebID profiles + container tree (the Solid CTH bootstraps by dereferencing those WebIDs). NEVER
/// set against a real (SPARQ/S3) backend. See [`solid_server_rs::seed`].
const ENV_SEED_CONFORMANCE: &str = "SOLID_SERVER_SEED_CONFORMANCE";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure the rustls process-wide crypto provider (aws-lc-rs) is installed before any TLS use.
    // The SSRF-guarded fetcher uses rustls for HTTPS to the IdP/WebID; installing it here is honest.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let base_url =
        std::env::var(ENV_BASE_URL).unwrap_or_else(|_| "http://localhost:3000".to_string());
    let bind = std::env::var(ENV_BIND).unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let issuer = std::env::var(ENV_TRUSTED_ISSUER)
        .unwrap_or_else(|_| "https://idp.example/realms/solid".to_string());
    // Audience defaults to the base URL (the RS's identity). RFC 9068 makes `aud` mandatory.
    let audience = std::env::var(ENV_AUDIENCE).unwrap_or_else(|_| base_url.clone());

    // Dev/IT escape hatch: allow an http:/loopback IdP+WebID. Defaults OFF (production HTTPS-only).
    let allow_loopback = env_flag(ENV_ALLOW_LOOPBACK);
    let jwks_cache_ttl = Duration::from_secs(
        std::env::var(ENV_JWKS_CACHE_TTL_SECS)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300),
    );
    let bidirectional = parse_bidirectional(std::env::var(ENV_BIDIRECTIONAL).ok().as_deref());

    // --- TLS termination mode (config-gated; both-or-neither). ------------------------------------
    // Resolve EARLY so a misconfiguration (one TLS var without the other) fails fast at boot, before
    // we stand up auth/storage. Filesystem + PEM validation happens just before binding, below.
    let tls_mode = tls::mode_from_env().map_err(|e| format!("TLS configuration error: {e}"))?;

    // --- Auth: REAL network-backed verification (delegated to solid-oidc-verifier). ----------------
    // The NetworkJwksProvider does OIDC discovery + JWKS fetch over the DNS-pinned SSRF-guarded path.
    let jwks = NetworkJwksProvider::new(jwks_cache_ttl, allow_loopback)
        .map_err(|e| format!("failed to init the network JWKS provider: {e}"))?;

    // Build the verifier config. When the bidirectional check is enabled, wire the network WebID
    // resolver — the verifier REFUSES strict/warn without a resolver (a security policy must not be
    // silently disabled by misconfiguration), so this is required, not optional.
    let mut config = VerifierConfig::new(vec![issuer.clone()], audience.clone());
    config = match bidirectional {
        BidirectionalMode::Off => config,
        mode => {
            let resolver = NetworkWebIdResolver::new(allow_loopback)
                .map_err(|e| format!("failed to init the network WebID resolver: {}", e.0))?;
            config.bidirectional(mode, Arc::new(resolver))
        }
    };
    // Surface a misconfiguration (e.g. empty issuer/audience) up front rather than per-request.
    config
        .validate()
        .map_err(|e| format!("invalid verifier configuration: {e}"))?;

    // The in-memory jti replay store fails CLOSED at capacity (single-instance posture). A shared
    // (Redis SET NX) ReplayStore is the horizontal-scaling seam.
    let replay = InMemoryReplayStore::with_window(config.replay_ttl());
    let verifier = Verifier::new(config, jwks, replay)?;
    let auth = AuthContext::new(verifier, base_url.clone());

    // --- Storage. SPARQ authoritative for metadata; object_store backup-only for bytes. -----------
    // The binary still boots the in-memory doubles so it runs without SPARQ / S3; wiring the live
    // HttpSparqClient + object_store blob store is the next storage slice.
    let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());

    // Dev/conformance seeding (gated, in-memory only): write the test users' WebID profiles + the
    // container tree the Solid CTH dereferences to bootstrap. Done BEFORE the store is moved into the
    // LDP state; a seeding failure aborts boot (better than a half-seeded store).
    if env_flag(ENV_SEED_CONFORMANCE) {
        solid_server_rs::seed::seed_conformance(&store, &base_url, &issuer)
            .await
            .map_err(|e| format!("conformance seeding failed: {e:?}"))?;
        eprintln!(
            "  SEEDED conformance users {:?} (WebID profiles + container tree) — DEV/CONFORMANCE ONLY.",
            solid_server_rs::seed::SEED_USERS
        );
    }

    let ldp = LdpState::new(store, base_url.clone());

    let app = build_router(AppState::new(auth, ldp));

    // Build the rustls config (reads + validates the PEM files) for TLS mode; `None` for plain mode.
    // Done after the router is assembled but before binding, so a bad cert/key fails at boot.
    let rustls_config = tls::build_rustls_config(&tls_mode)
        .await
        .map_err(|e| format!("TLS configuration error: {e}"))?;

    let scheme = if rustls_config.is_some() {
        "https"
    } else {
        "http"
    };
    eprintln!("solid-server-rs (EXPERIMENTAL) listening on {scheme}://{bind} (base {base_url})");
    eprintln!("  trusted issuer: {issuer}  audience: {audience}  bidirectional: {bidirectional:?}");
    if let TlsMode::Tls {
        cert_path,
        key_path,
    } = &tls_mode
    {
        eprintln!(
            "  TLS: terminating HTTPS in-process (cert {}, key {})",
            cert_path.display(),
            key_path.display()
        );
    } else {
        eprintln!("  TLS: plain HTTP — terminate TLS at a reverse proxy (set SOLID_SERVER_TLS_CERT + _KEY to enable in-process HTTPS).");
    }
    if allow_loopback {
        eprintln!("  WARNING: SOLID_SERVER_ALLOW_LOOPBACK is set — http:/loopback IdP+WebID permitted (DEV/IT ONLY).");
    }
    eprintln!("WARNING: experimental parallel track — NOT the production prod-solid-server.");

    match rustls_config {
        // HTTPS: axum-server terminates TLS over the process-wide aws-lc-rs rustls provider, with the
        // SAME graceful-shutdown + bind-resolution behaviour as the plain-HTTP path below.
        //
        // Bind-addr PARITY: resolve `bind` with `tokio::net::TcpListener::bind`, exactly as the plain
        // path does, so a hostname:port string (e.g. `localhost:3000`) works in TLS mode too — it
        // would be rejected by `SocketAddr::parse`, which only accepts a numeric address. We then hand
        // the already-bound listener to `axum_server::from_tcp_rustls`, which serves TLS over an
        // existing `std::net::TcpListener` (so no second, parse-restricted bind).
        Some(config) => {
            let tokio_listener = tokio::net::TcpListener::bind(&bind).await?;
            // axum-server wants a blocking `std::net::TcpListener`; converting the tokio one keeps the
            // resolved address (and avoids re-binding through the numeric-only `SocketAddr` path).
            let std_listener = tokio_listener.into_std()?;
            std_listener.set_nonblocking(true)?;

            // Graceful-shutdown PARITY: wire `shutdown_signal()` to `Handle::graceful_shutdown` so
            // Ctrl-C drains in-flight TLS connections instead of dropping them, matching the plain
            // path's `with_graceful_shutdown`.
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                // DRAIN TIMEOUT (best-call, per the standing rule): give in-flight requests up to 10s
                // to finish, then force-close. 10s is the conventional reverse-proxy / k8s
                // `terminationGracePeriod` default — long enough for a normal LDP request (incl. a
                // backend SPARQ round-trip) to complete, short enough that a stuck connection cannot
                // wedge shutdown. `Some(..)` (not `None`) is deliberate: `None` would wait FOREVER for
                // a hung connection, which is the opposite of graceful.
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            });

            axum_server::from_tcp_rustls(std_listener, config)?
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
        // Plain TCP (unchanged dev/test behaviour). Graceful shutdown on Ctrl-C.
        None => {
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }
    Ok(())
}

/// Read a boolean-ish env flag: `1` / `true` (case-insensitive) ⇒ true; anything else / absent ⇒ false.
fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref().map(str::trim),
        Some("1") | Some("true") | Some("TRUE") | Some("True")
    )
}

/// Parse the bidirectional-check mode env value. Default (absent/unknown) is `Strict` — the secure
/// posture: a WebID whose profile does not list the token issuer is rejected.
fn parse_bidirectional(raw: Option<&str>) -> BidirectionalMode {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("off") => BidirectionalMode::Off,
        Some("warn") => BidirectionalMode::Warn,
        // "strict", any other value, or absent ⇒ the secure default.
        _ => BidirectionalMode::Strict,
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
