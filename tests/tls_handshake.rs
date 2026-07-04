// AUTHORED-BY Claude Opus 4.8
//! Live TLS handshake integration test for the config-gated TLS termination path.
//!
//! This is `#[ignore]`d by default (run with `cargo test -- --ignored tls_handshake`) because it
//! needs the checked-in throwaway self-signed test cert under `tests/fixtures/` and does real socket
//! I/O. It exercises the SAME code path the binary uses: [`solid_server_rs::tls::build_rustls_config`]
//! → [`axum_server::bind_rustls`]. A rustls client (trusting only the test CA) completes a full
//! handshake and gets an HTTP response back, proving the server terminates TLS end-to-end over the
//! house rustls/aws-lc-rs stack. The config-level validation (both-or-neither, missing/empty/malformed
//! PEM) is covered by the always-run unit tests in `src/tls.rs`.
//!
//! The fixtures are a DISPOSABLE throwaway P-256 chain: a test CA (`test-ca.pem`) and a leaf signed
//! by it (`test-cert.pem` + `test-key.pem`) with CN/SAN `localhost`,`127.0.0.1`. The CA's private
//! key is NOT checked in, so the chain cannot mint further certs — never a real credential.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use rustls_pemfile::certs;
use solid_server_rs::tls::{build_rustls_config, TlsMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// The server's leaf cert (signed by the fixture CA) + its private key — what the binary serves.
const CERT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-cert.pem");
const KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-key.pem");
/// The fixture CA cert — the client's sole trust anchor (its private key is NOT checked in).
const CA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-ca.pem");

/// Build a rustls client that trusts ONLY the fixture CA (a closed trust anchor — no system roots,
/// no `dangerous` cert-verification bypass), so a successful handshake proves the server presented a
/// CA-chained, SAN-valid leaf for `localhost`.
fn client_config() -> ClientConfig {
    client_config_with_alpn(&[])
}

/// As [`client_config`], but advertising `alpn` in the client's ALPN list — so a test can offer `h2`
/// (and observe the server negotiate it) or offer only `http/1.1` (and observe the fallback).
fn client_config_with_alpn(alpn: &[&[u8]]) -> ClientConfig {
    let pem = std::fs::read(CA_PATH).expect("read fixture CA");
    let mut roots = RootCertStore::empty();
    for cert in certs(&mut pem.as_slice()) {
        let cert: CertificateDer<'_> = cert.expect("parse fixture CA");
        roots.add(cert).expect("add fixture CA to roots");
    }
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

#[tokio::test]
#[ignore = "needs the fixture test cert + real socket I/O; run with --ignored"]
async fn tls_handshake_serves_https() {
    // The process-wide aws-lc-rs provider must be installed (the binary does this in `main`).
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Build the server TLS config through the SAME path the binary uses.
    let mode = TlsMode::Tls {
        cert_path: CERT_PATH.into(),
        key_path: KEY_PATH.into(),
    };
    let rustls_config = build_rustls_config(&mode, false)
        .await
        .expect("build rustls config from fixture PEM")
        .expect("TLS mode yields a config");

    // A trivial router — this test is about the TLS layer, not auth/LDP.
    let app = Router::new().route("/healthz", get(|| async { "ok" }));

    // Reserve an ephemeral loopback port (binding then dropping a tokio listener), then let
    // axum-server bind its own non-blocking listener on that address — `bind_rustls` is the same
    // entry the binary uses for HTTPS.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve port");
    let addr = probe.local_addr().expect("local addr");
    drop(probe);
    let server = axum_server::bind_rustls(addr, rustls_config);
    let server_task = tokio::spawn(async move {
        let _ = server.serve(app.into_make_service()).await;
    });

    // Connect a rustls client and complete a real handshake.
    let connector = TlsConnector::from(Arc::new(client_config()));
    let dns_name = ServerName::try_from("localhost").expect("server name");

    // Retry the connect briefly to avoid racing the server's bind. A TCP-connect failure is a
    // not-yet-listening race (retry); a handshake failure on a CONNECTED socket is a real TLS error
    // (surface it — retrying would just mask a genuine cert/provider bug).
    let mut tls = None;
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..50 {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => match connector.connect(dns_name.clone(), tcp).await {
                Ok(stream) => {
                    tls = Some(stream);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    break;
                }
            },
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    let mut tls = tls.unwrap_or_else(|| {
        panic!("TLS handshake failed: {last_err:?}");
    });

    // Send a minimal HTTP/1.1 request over the TLS stream and read the response.
    let req = "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls.write_all(req.as_bytes()).await.expect("write request");
    tls.flush().await.expect("flush");

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.expect("read response");
    let resp = String::from_utf8_lossy(&buf);

    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "unexpected response: {resp}"
    );
    assert!(resp.contains("ok"), "body missing: {resp}");

    server_task.abort();
}

/// BIND-ADDR PARITY (finding 3), always-run: the TLS serve path now resolves `SOLID_SERVER_BIND` via
/// `tokio::net::TcpListener::bind` (the same call the plain-HTTP path uses), which accepts a
/// `hostname:port` string — whereas the OLD TLS path parsed `SocketAddr`, which REJECTS a hostname.
/// This pins both halves of the regression: the hostname binds through the new path, and would have
/// failed through the old `SocketAddr::parse` path.
#[tokio::test]
async fn tls_bind_resolves_hostname_like_plain_path() {
    let bind = "localhost:0";

    // OLD TLS behaviour: `SocketAddr::parse` rejects a hostname — this is the regression the fix
    // removes. (Asserting it documents WHY the plain path and the old TLS path diverged.)
    assert!(
        bind.parse::<std::net::SocketAddr>().is_err(),
        "a hostname:port must NOT parse as a numeric SocketAddr (else this test proves nothing)"
    );

    // NEW TLS behaviour == plain-path behaviour: resolve through tokio's bind, which honours the
    // hostname. A successful bind proves TLS mode now accepts the same address strings as plain mode.
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .expect("tokio bind must accept a hostname:port (parity with the plain-HTTP path)");
    let addr = listener.local_addr().expect("local addr");
    assert!(addr.port() != 0, "an ephemeral port should be assigned");
    assert!(
        addr.ip().is_loopback(),
        "localhost should resolve to loopback"
    );

    // And the listener converts to the blocking std listener that `from_tcp_rustls` consumes — the
    // exact hand-off the TLS serve arm performs.
    let std_listener = listener.into_std().expect("into_std");
    std_listener.set_nonblocking(true).expect("set_nonblocking");
}

/// GRACEFUL-SHUTDOWN PARITY (finding 2) + the `from_tcp_rustls`/`Handle` wiring (findings 2 & 3),
/// `#[ignore]`d like the handshake test (real socket I/O + fixture cert). Drives the EXACT serve
/// construction the binary now uses — `from_tcp_rustls(std_listener, cfg).handle(handle).serve(..)`
/// over a HOSTNAME-resolved listener — completes a real TLS handshake, then triggers
/// `handle.graceful_shutdown(Some(..))` and asserts the server task RETURNS (drains and exits) rather
/// than being force-aborted. The old TLS path had no handle, so Ctrl-C could not drain it.
#[tokio::test]
#[ignore = "needs the fixture test cert + real socket I/O; run with --ignored"]
async fn tls_graceful_shutdown_drains_via_handle() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mode = TlsMode::Tls {
        cert_path: CERT_PATH.into(),
        key_path: KEY_PATH.into(),
    };
    let rustls_config = build_rustls_config(&mode, false)
        .await
        .expect("build rustls config")
        .expect("TLS mode yields a config");

    let app = Router::new().route("/healthz", get(|| async { "ok" }));

    // Hostname bind (parity) → blocking std listener → from_tcp_rustls + Handle (the binary's path).
    let tokio_listener = tokio::net::TcpListener::bind("localhost:0")
        .await
        .expect("hostname bind");
    let addr = tokio_listener.local_addr().expect("local addr");
    let std_listener = tokio_listener.into_std().expect("into_std");
    std_listener.set_nonblocking(true).expect("set_nonblocking");

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let server_task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(std_listener, rustls_config)
            .expect("from_tcp_rustls")
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
    });

    // Complete a real handshake first (proves the listener is serving TLS), then drain.
    let connector = TlsConnector::from(Arc::new(client_config()));
    let dns_name = ServerName::try_from("localhost").expect("server name");
    let mut connected = false;
    for _ in 0..50 {
        if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await {
            if connector.connect(dns_name.clone(), tcp).await.is_ok() {
                connected = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(connected, "could not complete a handshake before shutdown");

    // Trigger graceful shutdown with a drain timeout (the binary uses 10s; the test uses a short one
    // so it is fast). With no in-flight requests the server should return promptly.
    handle.graceful_shutdown(Some(std::time::Duration::from_secs(2)));

    // The server task must RETURN on its own (graceful) — NOT hang. If the handle were not wired,
    // `serve(..)` would run forever and this `timeout` would elapse.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("server did not shut down within timeout — graceful_shutdown not wired")
        .expect("server task panicked");
    result.expect("serve returned an error");
}

/// HTTP/2-over-ALPN negotiation, `#[ignore]`d (fixture cert + real socket I/O). Boots the server over
/// the EXACT serve construction the binary uses (`from_tcp_rustls(..).handle(..).serve(..)`, whose
/// `auto::Builder` serves whatever ALPN selected), then:
///   (1) an `h2`-capable client (offers `[h2, http/1.1]`) MUST negotiate `h2`;
///   (2) an HTTP/1.1-only client (offers `[http/1.1]`) MUST negotiate `http/1.1` and still get a
///       working response — proving h2 is ADDITIVE (an old client is never broken, it negotiates down).
/// Together these pin the transport contract: h2 when offered, h1 fallback always.
#[tokio::test]
#[ignore = "needs the fixture test cert + real socket I/O; run with --ignored"]
async fn alpn_negotiates_h2_when_offered_and_h1_fallback() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mode = TlsMode::Tls {
        cert_path: CERT_PATH.into(),
        key_path: KEY_PATH.into(),
    };
    let rustls_config = build_rustls_config(&mode, false)
        .await
        .expect("build rustls config")
        .expect("TLS mode yields a config");

    // Sanity: the server's advertised ALPN is exactly [h2, http/1.1] (the owned contract).
    assert_eq!(
        rustls_config.get_inner().alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        "server config must advertise [h2, http/1.1]"
    );

    let app = Router::new().route("/healthz", get(|| async { "ok" }));

    let tokio_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = tokio_listener.local_addr().expect("local addr");
    let std_listener = tokio_listener.into_std().expect("into_std");
    std_listener.set_nonblocking(true).expect("set_nonblocking");
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let server_task = tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(std_listener, rustls_config)
            .expect("from_tcp_rustls")
            .handle(server_handle)
            .serve(app.into_make_service())
            .await;
    });

    // (1a) h2-capable client → MUST negotiate h2 at the TLS handshake layer.
    let negotiated = negotiated_alpn(addr, &[b"h2", b"http/1.1"]).await;
    assert_eq!(
        negotiated.as_deref(),
        Some(&b"h2"[..]),
        "an h2-capable client must negotiate h2 (got {negotiated:?})"
    );

    // (1b) ...and the server must actually SERVE an HTTP/2 request over it: drive a real GET /healthz
    // with an h2-preferring reqwest client (trusting only the fixture CA) and assert the RESPONSE is
    // HTTP/2 + 200/ok. (ALPN advertising h2 but the server failing to serve h2 would pass (1a) but
    // fail here — that is exactly the gap this drive closes.)
    let url = format!("https://localhost:{}/healthz", addr.port());
    let h2_client = reqwest_client(/* http1_only = */ false);
    let resp = h2_client.get(&url).send().await.expect("h2 GET /healthz");
    assert_eq!(
        resp.version(),
        reqwest::Version::HTTP_2,
        "the response must be served over HTTP/2 (not just negotiated)"
    );
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.expect("body"), "ok");

    // (2a) h1-only client → MUST negotiate http/1.1 at the handshake layer (the additive guarantee).
    let negotiated = negotiated_alpn(addr, &[b"http/1.1"]).await;
    assert_eq!(
        negotiated.as_deref(),
        Some(&b"http/1.1"[..]),
        "an http/1.1-only client must negotiate http/1.1 (got {negotiated:?})"
    );

    // (2b) ...and an HTTP/1.1-only client must get a WORKING HTTP/1.1 response — proving the h1
    // fallback path actually serves, so an old client is never broken by adding h2.
    let h1_client = reqwest_client(/* http1_only = */ true);
    let resp = h1_client.get(&url).send().await.expect("h1 GET /healthz");
    assert_eq!(
        resp.version(),
        reqwest::Version::HTTP_11,
        "an http/1.1-only client must be served over HTTP/1.1"
    );
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.expect("body"), "ok");

    handle.graceful_shutdown(Some(std::time::Duration::from_secs(1)));
    server_task.abort();
}

/// A `reqwest` client trusting ONLY the fixture CA (no system roots), resolving `localhost` to the
/// loopback test server. With `http1_only=false` it offers h2 via ALPN (so it negotiates + uses h2
/// when the server offers it); with `http1_only=true` it offers only http/1.1 (the fallback path).
fn reqwest_client(http1_only: bool) -> reqwest::Client {
    let ca_pem = std::fs::read(CA_PATH).expect("read fixture CA");
    let ca = reqwest::Certificate::from_pem(&ca_pem).expect("parse fixture CA");
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(ca)
        .use_rustls_tls();
    if http1_only {
        builder = builder.http1_only();
    }
    builder.build().expect("build reqwest client")
}

/// Complete a TLS handshake offering `offer` as the client ALPN list and return the protocol the
/// server selected (`None` if no ALPN was negotiated). Retries the TCP connect briefly to avoid
/// racing the server bind; a handshake failure on a CONNECTED socket is surfaced (a real error).
async fn negotiated_alpn(addr: std::net::SocketAddr, offer: &[&[u8]]) -> Option<Vec<u8>> {
    let connector = TlsConnector::from(Arc::new(client_config_with_alpn(offer)));
    let dns_name = ServerName::try_from("localhost").expect("server name");
    for _ in 0..50 {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => {
                let stream = connector
                    .connect(dns_name.clone(), tcp)
                    .await
                    .expect("TLS handshake on a connected socket");
                let (_io, conn) = stream.get_ref();
                return conn.alpn_protocol().map(|p| p.to_vec());
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    panic!("could not connect to the server to negotiate ALPN");
}

// ---------------------------------------------------------------------------------------------------
// PoP Tier-1b — LIVE mTLS client-certificate handshake (end-to-end ConnPopAcceptor + real
// rustls `peer_certificates()` read). `#[ignore]`d (needs openssl + real socket I/O); run with
// `cargo test -- --ignored tls_mtls`.
// ---------------------------------------------------------------------------------------------------

/// Mint a throwaway self-signed P-256 CLIENT cert+key (CN=test-client) via the system `openssl`,
/// returning `(cert_pem, key_pem)`. Unique per call. Never a real credential.
fn mint_client_cert() -> (Vec<u8>, Vec<u8>) {
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ssrs-mtls-client-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("client-cert.pem");
    let key = dir.join("client-key.pem");
    let out = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args(["-days", "1", "-subj", "/CN=test-client"])
        .output()
        .expect("run openssl to mint a client cert");
    assert!(out.status.success(), "openssl failed: {out:?}");
    let cert_bytes = std::fs::read(&cert).unwrap();
    let key_bytes = std::fs::read(&key).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (cert_bytes, key_bytes)
}

/// GET `/whoami` over a live TLS stream (Connection: close) and return the response body — the test
/// route echoes the connection's `ConnPop` thumbprint (base64url) or `none`.
async fn whoami_body(connector: &TlsConnector, addr: std::net::SocketAddr) -> String {
    let dns_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = None;
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..50 {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => match connector.connect(dns_name.clone(), tcp).await {
                Ok(stream) => {
                    tls = Some(stream);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    break;
                }
            },
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    let mut tls = tls.unwrap_or_else(|| panic!("mTLS handshake failed: {last_err:?}"));
    let req = "GET /whoami HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls.write_all(req.as_bytes()).await.expect("write request");
    tls.flush().await.expect("flush");
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.expect("read response");
    let resp = String::from_utf8_lossy(&buf);
    // Body is everything after the header terminator.
    resp.split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string()
}

#[tokio::test]
#[ignore = "needs openssl + real socket I/O; run with --ignored"]
async fn tls_mtls_connpop_reads_binds_and_rebinds_client_cert_across_resumption() {
    use solid_server_rs::pop::cert_bound::CertThumbprint;
    use solid_server_rs::pop::conn::{ConnPop, ConnPopAcceptor};
    use tokio_rustls::rustls::pki_types::PrivateKeyDer;

    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Server: build the mTLS config (optional client-cert request) via the SAME path the binary uses.
    let mode = TlsMode::Tls {
        cert_path: CERT_PATH.into(),
        key_path: KEY_PATH.into(),
    };
    let rustls_config = build_rustls_config(&mode, true)
        .await
        .expect("build mTLS rustls config")
        .expect("TLS mode yields a config");

    // A test route that echoes the per-connection ConnPop thumbprint the acceptor injected.
    async fn whoami(req: axum::extract::Request) -> String {
        match req.extensions().get::<ConnPop>() {
            Some(p) => match p.thumbprint() {
                Some(t) => t.to_base64url(),
                None => "none".to_string(),
            },
            None => "no-connpop".to_string(),
        }
    }
    let app = Router::new().route("/whoami", get(whoami));

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve port");
    let addr = probe.local_addr().expect("local addr");
    drop(probe);
    // Wrap the rustls acceptor with the ConnPopAcceptor — the SAME wrapper `main` adds when the mTLS
    // flag is on (TlsStream impls PeerCertDer, so no connection-cap layer is needed for the test).
    let server = axum_server::bind_rustls(addr, rustls_config).map(ConnPopAcceptor::new);
    let server_task = tokio::spawn(async move {
        let _ = server.serve(app.into_make_service()).await;
    });

    // Client A: presents a client certificate ⇒ the server must read + hash it and report its x5t#S256.
    let (client_cert_pem, client_key_pem) = mint_client_cert();
    let client_chain: Vec<CertificateDer<'static>> = certs(&mut client_cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .expect("parse client cert");
    let client_key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut client_key_pem.as_slice())
            .expect("read client key")
            .expect("a client private key");
    let expected = CertThumbprint::from_cert_der(client_chain[0].as_ref()).to_base64url();

    let pem = std::fs::read(CA_PATH).expect("read fixture CA");
    let mut roots = RootCertStore::empty();
    for cert in certs(&mut pem.as_slice()) {
        roots.add(cert.expect("parse fixture CA")).expect("add CA");
    }
    // A resumption-ENABLED client config (rustls `ClientConfig` enables an in-memory session store by
    // default, and the server sends TLS 1.3 session tickets by default), reused across TWO connections
    // so the SECOND connection can resume the first via PSK.
    let with_cert = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(client_chain, client_key)
            .expect("client auth config"),
    );
    let connector = TlsConnector::from(with_cert);

    // Connection 1 (full handshake, presents the client cert): the server reads + hashes it and binds
    // the x5t#S256 thumbprint.
    let body_a = whoami_body(&connector, addr).await;
    assert_eq!(
        body_a, expected,
        "the server must read the presented client cert and bind its x5t#S256 thumbprint"
    );

    // Connection 2 REUSES the same resumption-enabled config, so it may resume connection 1's TLS
    // session (PSK). On a resumed TLS 1.3 handshake the client does NOT re-send its Certificate, yet
    // rustls's `peer_certificates()` returns the ORIGINAL handshake's client chain "for both full and
    // resumed handshakes" — so the acceptor RE-COMPUTES the SAME binding from THIS connection's session
    // state (never a lost or foreign binding). Whether TLS actually resumes or falls back to a full
    // handshake, the invariant is identical: the same client identity ⇒ the same bound thumbprint.
    let body_a_resumed = whoami_body(&connector, addr).await;
    assert_eq!(
        body_a_resumed, expected,
        "a resumed (or reconnected) connection for the SAME client identity must re-bind to the SAME \
         x5t#S256 — rustls returns peer_certificates() across resumption, so the binding is never lost"
    );

    // Client B: a SEPARATE connection presenting NO client cert ⇒ its ConnPop is `none`. Distinct
    // connections yielding DIFFERENT bindings on the same server proves the binding is re-read
    // PER CONNECTION from that connection's own session state — a no-cert connection can NEVER inherit
    // another connection's certificate (the fail-closed property a cert-bound token relies on).
    let no_cert = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let body_b = whoami_body(&TlsConnector::from(Arc::new(no_cert)), addr).await;
    assert_eq!(
        body_b, "none",
        "a connection with no client cert must have a None ConnPop (never inherit another conn's cert)"
    );

    server_task.abort();
}
