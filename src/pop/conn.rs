// AUTHORED-BY Claude Opus 4.8
//! PoP Tier-1b — the per-connection client-certificate binding (`ConnPop`) + its acceptor wiring.
//!
//! Design: [`docs/design/high-throughput-pop-auth.md`](../../docs/design/high-throughput-pop-auth.md)
//! §7 (bead 2). This is the TRANSPORT half of RFC 8705 mTLS-bound tokens: read the client certificate
//! the peer presented on the TLS connection **once per connection**, compute its `cnf.x5t#S256`
//! thumbprint, and make it available to every request served over that connection so the auth layer
//! can match a cert-bound token against it ([`crate::auth`] + [`crate::pop::dispatch`]).
//!
//! ## Why once-per-connection (not once-per-request)
//! A TLS connection's client certificate is fixed for the connection's lifetime (RFC 8705 §3 + the
//! rustls `peer_certificates()` contract — it is the ORIGINAL handshake identity, returned identically
//! for full AND resumed handshakes). Hashing it once at accept time and stamping the result onto every
//! request via a request extension turns the RFC 8705 §3 per-request obligation into a 32-byte memcmp
//! (in [`crate::pop::cert_bound`]) rather than a per-request SHA-256 over the DER.
//!
//! ## TLS-resumption re-binding (a fail-closed property, not a special case)
//! A resumed TLS session is a NEW connection object with its OWN `ServerConnection`; the acceptor runs
//! [`ConnPopAcceptor::accept`] afresh for it and reads `peer_certificates()` from THAT connection. So a
//! resumed connection cannot inherit a stale/foreign cert binding from an earlier connection — its
//! `ConnPop` is (re)computed from its own session state. If a resumed connection presents no client
//! certificate, its `ConnPop.thumbprint` is `None` and a cert-bound token over it is rejected
//! fail-closed (never a downgrade to bearer). This is the connection-scoped-injection design, not a
//! bespoke resumption branch.
//!
//! ## Gating
//! This wiring is added to the serve path ONLY when the mTLS flag is on
//! ([`crate::tls::mtls_bound_tokens_from_env`]). With the flag off, no `ConnPop` is injected and the
//! auth layer runs no confirmation dispatch, so the DPoP/plain serve paths are byte-identical.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum_server::accept::Accept;

use super::cert_bound::CertThumbprint;

/// The per-connection proof-of-possession context: the SHA-256 thumbprint of the client certificate
/// the peer presented on THIS TLS connection, or `None` when the connection presented no client
/// certificate. Injected into every request's extensions by [`ConnPopService`]; read by the auth layer
/// to satisfy (or fail-closed reject) a cert-bound token.
///
/// `Clone` (cheap — a 32-byte thumbprint) so the connection-constant value can be stamped onto each
/// request; `Send + Sync + 'static` so it is a valid axum/http request extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnPop {
    /// The presented client certificate's `cnf.x5t#S256` thumbprint, or `None` if no client cert was
    /// presented on this connection.
    pub thumbprint: Option<CertThumbprint>,
}

impl ConnPop {
    /// Build the connection PoP from the peer certificate's DER bytes (the FIRST/leaf cert), computing
    /// the thumbprint once. `None` DER ⇒ no client certificate on this connection ⇒ `thumbprint: None`.
    pub fn from_peer_cert_der(der: Option<Vec<u8>>) -> Self {
        Self {
            thumbprint: der.map(|d| CertThumbprint::from_cert_der(&d)),
        }
    }

    /// The presented thumbprint, if any (borrowing, for the constant-time compare in
    /// [`crate::pop::cert_bound::verify_cert_binding`]).
    pub fn thumbprint(&self) -> Option<&CertThumbprint> {
        self.thumbprint.as_ref()
    }
}

/// A connection IO stream that can yield the peer (client) certificate DER it negotiated.
///
/// Implemented for the concrete TLS stream the serve path produces ([`tokio_rustls::server::TlsStream`])
/// and forwarded through the connection-cap wrapper ([`crate::transport::PermittedStream`], impl in
/// `transport.rs`). Reading it is only meaningful AFTER the TLS handshake has completed — the acceptor
/// calls it exactly there, once.
pub trait PeerCertDer {
    /// The DER bytes of the peer's leaf certificate, or `None` if the peer presented no client
    /// certificate (the common plain-DPoP case).
    fn peer_cert_der(&self) -> Option<Vec<u8>>;
}

impl<S> PeerCertDer for tokio_rustls::server::TlsStream<S> {
    fn peer_cert_der(&self) -> Option<Vec<u8>> {
        // `get_ref().1` is the rustls `ServerConnection`; `peer_certificates()` returns the client
        // chain (leaf first) for BOTH full and resumed handshakes, or `None` when no client cert was
        // presented. We copy the leaf DER (a public value) so nothing borrows the connection.
        let (_io, conn) = self.get_ref();
        conn.peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| cert.as_ref().to_vec())
    }
}

/// A tower [`Service`](tower::Service) wrapper that stamps a fixed [`ConnPop`] onto every request's
/// extensions before delegating to the inner service. One instance per connection (built by
/// [`ConnPopAcceptor`]), so the connection-constant PoP reaches every request — the same pattern axum's
/// `ConnectInfo` uses to surface per-connection data.
#[derive(Clone)]
pub struct ConnPopService<S> {
    inner: S,
    pop: ConnPop,
}

impl<S> ConnPopService<S> {
    /// Wrap `inner`, injecting `pop` into each request.
    pub fn new(inner: S, pop: ConnPop) -> Self {
        Self { inner, pop }
    }
}

impl<S, B> tower::Service<http::Request<B>> for ConnPopService<S>
where
    S: tower::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        // Insert the connection PoP so downstream (the auth middleware) can read it. `insert` REPLACES
        // any pre-existing `ConnPop` extension — a request cannot smuggle its own cert binding (the
        // value is set HERE from the TLS connection, never from client-controlled request data).
        req.extensions_mut().insert(self.pop.clone());
        self.inner.call(req)
    }
}

/// An [`Accept`] wrapper that reads the peer certificate ONCE (right after the inner accept completes
/// the TLS handshake), computes its [`ConnPop`], and wraps the produced service in a [`ConnPopService`]
/// so every request on the connection carries the binding. The IO stream is passed through UNCHANGED
/// (`type Stream = A::Stream`) — this wrapper only reads from it and wraps the SERVICE.
///
/// Layered OUTERMOST on the TLS serve path, above the connection-cap acceptor, so the handshake is
/// already complete when [`accept`](Self::accept) reads the cert. Added only when the mTLS flag is on.
#[derive(Clone)]
pub struct ConnPopAcceptor<A> {
    inner: A,
}

impl<A> ConnPopAcceptor<A> {
    /// Wrap `inner` (the connection-cap acceptor over the rustls acceptor).
    pub fn new(inner: A) -> Self {
        Self { inner }
    }
}

impl<A, I, S> Accept<I, S> for ConnPopAcceptor<A>
where
    A: Accept<I, S> + Clone + Send + Sync + 'static,
    A::Stream: PeerCertDer + Send,
    A::Service: Send + 'static,
    A::Future: Send,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = A::Stream;
    type Service = ConnPopService<A::Service>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            // The inner accept resolves AFTER the TLS handshake completes, so the peer certificate (if
            // any) is available on the produced stream. Read + hash it exactly once here.
            let (io_stream, svc) = inner.accept(stream, service).await?;
            let pop = ConnPop::from_peer_cert_der(io_stream.peer_cert_der());
            Ok((io_stream, ConnPopService::new(svc, pop)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::future::Ready;

    const CERT_A: &[u8] = b"-----fake-der-cert-A-----";

    #[test]
    fn conn_pop_hashes_present_cert_and_none_stays_none() {
        // A presented cert ⇒ its thumbprint; no cert ⇒ None (a cert-bound token over it is denied
        // fail-closed downstream).
        let with = ConnPop::from_peer_cert_der(Some(CERT_A.to_vec()));
        assert_eq!(
            with.thumbprint(),
            Some(&CertThumbprint::from_cert_der(CERT_A))
        );
        let without = ConnPop::from_peer_cert_der(None);
        assert_eq!(without.thumbprint(), None);
    }

    /// A stream stand-in exposing a fixed peer cert DER (models a handshaked TLS stream without needing
    /// a real handshake — the trait is the seam the acceptor consumes).
    struct FakeStream(Option<Vec<u8>>);
    impl PeerCertDer for FakeStream {
        fn peer_cert_der(&self) -> Option<Vec<u8>> {
            self.0.clone()
        }
    }

    #[test]
    fn peer_cert_der_trait_yields_the_presented_der() {
        assert_eq!(
            FakeStream(Some(CERT_A.to_vec())).peer_cert_der(),
            Some(CERT_A.to_vec())
        );
        assert_eq!(FakeStream(None).peer_cert_der(), None);
    }

    /// A trivial inner tower service that records the `ConnPop` (if any) it saw on the request, so the
    /// service-wrapper test can assert the extension was injected.
    #[derive(Clone)]
    struct RecordingService;
    impl tower::Service<http::Request<()>> for RecordingService {
        type Response = Option<ConnPop>;
        type Error = Infallible;
        type Future = Ready<Result<Option<ConnPop>, Infallible>>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<()>) -> Self::Future {
            std::future::ready(Ok(req.extensions().get::<ConnPop>().cloned()))
        }
    }

    #[tokio::test]
    async fn service_injects_conn_pop_into_request_extensions() {
        use tower::ServiceExt as _;
        let pop = ConnPop::from_peer_cert_der(Some(CERT_A.to_vec()));
        let svc = ConnPopService::new(RecordingService, pop.clone());
        let seen = svc
            .oneshot(http::Request::new(()))
            .await
            .expect("infallible");
        assert_eq!(
            seen,
            Some(pop),
            "the request must carry the connection's ConnPop"
        );
    }

    #[tokio::test]
    async fn service_replaces_a_smuggled_conn_pop_extension() {
        // Defence in depth: a request arriving with its OWN ConnPop extension (a hypothetical smuggle)
        // must be OVERWRITTEN by the connection's real value — never trusted.
        use tower::ServiceExt as _;
        let real = ConnPop::from_peer_cert_der(Some(CERT_A.to_vec()));
        let forged = ConnPop::from_peer_cert_der(Some(b"forged".to_vec()));
        let svc = ConnPopService::new(RecordingService, real.clone());
        let mut req = http::Request::new(());
        req.extensions_mut().insert(forged);
        let seen = svc.oneshot(req).await.expect("infallible");
        assert_eq!(
            seen,
            Some(real),
            "the connection's real ConnPop must win over a smuggled one"
        );
    }

    /// A mock acceptor producing a `FakeStream` + a unit service — exercises `ConnPopAcceptor::accept`
    /// end to end (reads the cert from the stream, wraps the service) without a TLS handshake.
    #[derive(Clone)]
    struct FakeAcceptor {
        der: Option<Vec<u8>>,
    }
    impl Accept<(), RecordingService> for FakeAcceptor {
        type Stream = FakeStream;
        type Service = RecordingService;
        type Future = Ready<io::Result<(FakeStream, RecordingService)>>;
        fn accept(&self, _stream: (), service: RecordingService) -> Self::Future {
            std::future::ready(Ok((FakeStream(self.der.clone()), service)))
        }
    }

    #[tokio::test]
    async fn acceptor_reads_cert_once_and_wraps_service() {
        use tower::ServiceExt as _;
        let acceptor = ConnPopAcceptor::new(FakeAcceptor {
            der: Some(CERT_A.to_vec()),
        });
        let (_stream, wrapped) = acceptor
            .accept((), RecordingService)
            .await
            .expect("accept ok");
        // The wrapped service must inject the ConnPop derived from the stream's cert.
        let seen = wrapped
            .oneshot(http::Request::new(()))
            .await
            .expect("infallible");
        assert_eq!(
            seen,
            Some(ConnPop::from_peer_cert_der(Some(CERT_A.to_vec())))
        );
    }

    #[tokio::test]
    async fn acceptor_no_client_cert_yields_none_binding() {
        use tower::ServiceExt as _;
        let acceptor = ConnPopAcceptor::new(FakeAcceptor { der: None });
        let (_stream, wrapped) = acceptor
            .accept((), RecordingService)
            .await
            .expect("accept ok");
        let seen = wrapped
            .oneshot(http::Request::new(()))
            .await
            .expect("infallible");
        assert_eq!(
            seen,
            Some(ConnPop { thumbprint: None }),
            "no client cert ⇒ a None-thumbprint ConnPop (cert-bound tokens denied fail-closed)"
        );
    }
}
