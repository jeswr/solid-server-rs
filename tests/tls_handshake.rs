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
    let pem = std::fs::read(CA_PATH).expect("read fixture CA");
    let mut roots = RootCertStore::empty();
    for cert in certs(&mut pem.as_slice()) {
        let cert: CertificateDer<'_> = cert.expect("parse fixture CA");
        roots.add(cert).expect("add fixture CA to roots");
    }
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
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
    let rustls_config = build_rustls_config(&mode)
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
