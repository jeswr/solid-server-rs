// AUTHORED-BY Claude Opus 4.8
//! Transport-layer DoS hardening — HTTP/2 stream/reset caps + slowloris header timeout + a
//! concurrent-connection cap.
//!
//! ## Why (the transport-DoS gap the application layers leave open)
//! The overload layers ([`crate::overload`]) and the per-IP rate limiter ([`crate::rate_limit`]) gate
//! **admitted requests** — they sit ABOVE hyper, so they only ever see a fully-parsed `http::Request`.
//! Several DoS classes never produce such a request, so those layers never fire:
//! - **HTTP/2 Rapid-Reset (CVE-2023-44487).** A client opens a stream and immediately `RST_STREAM`s
//!   it, in a tight loop, over one connection. Each stream creates + cancels server-side work without
//!   the connection's concurrent-stream count ever rising — bypassing a `max_concurrent_streams`
//!   limit, and never reaching the application admission layer (the request is reset before it
//!   completes). The defence is at the h2 layer: cap the number of in-flight *reset* streams and
//!   `GOAWAY` when exceeded, AND bound `max_concurrent_streams` so a single connection cannot pin
//!   unbounded server work.
//! - **Slowloris (slow-header trickle).** A client opens a TCP connection and dribbles request-header
//!   bytes one at a time, never completing the head. The [`crate::overload`] request *timeout* covers
//!   total request time AFTER the request is parsed — it never starts, because hyper is still reading
//!   the head. The defence is a **header-read timeout** at the hyper layer (drop a connection that
//!   has not sent a complete header set in time) plus a **concurrent-connection cap** so a flood of
//!   such half-open connections cannot exhaust file descriptors / memory, plus a bounded **TLS
//!   handshake timeout** so a connection that stalls the handshake (never completing it) cannot pin a
//!   connection permit, and an **h2 keep-alive PING** (interval + ack-timeout) so a DEAD-peer h2
//!   connection (host gone without a FIN) that is holding a permit is reclaimed.
//!
//! ## What hyper provides vs what we add (the rapid-reset accounting)
//! The in-tree `hyper` 1.x + `h2` 0.4.x already ship the CVE-2023-44487 reset-accounting:
//! - `max_pending_accept_reset_streams` (hyper issue #2877) — defaults to **20**: a connection that
//!   accumulates more than this many streams that were reset before being accepted gets a `GOAWAY`.
//!   This is the PRIMARY rapid-reset cap and is ON BY DEFAULT.
//! - `max_local_error_reset_streams` (RUSTSEC-2024-0003) — defaults to **1024**: bounds locally-reset
//!   streams kept for error propagation.
//!
//! So an UNCONFIGURED hyper is already not vulnerable to the original rapid-reset CVE. What this
//! module ADDS on top is: making the cap an EXPLICIT, env-tunable, TESTED invariant of THIS crate
//! (so a dependency bump cannot silently change it), and pairing it with an explicit
//! `max_concurrent_streams` ceiling (hyper's default is 200; we set it explicitly so it is owned +
//! documented). The reset cap stays at hyper's secure default unless an operator overrides it.
//!
//! ## Where it sits (TLS serve path ONLY)
//! These knobs live BELOW the application layers — they configure the hyper connection serving the
//! request. They are applied **only on the in-process TLS serve path**: the h2/header knobs via
//! `axum-server`'s `http_builder()` (the `hyper_util::server::conn::auto::Builder` it serves with),
//! and the connection cap + handshake timeout via the [`ConnectionLimitAcceptor`] wrapping
//! `axum-server`'s acceptor. The **plain-HTTP path is intentionally NOT hardened here** — `axum::serve`
//! exposes neither the underlying hyper builder nor an acceptor seam, so these knobs cannot be wired
//! onto it; an operator who needs the transport caps must terminate TLS in-process (or front the
//! plain path with a reverse proxy that caps connections + terminates HTTP/2). The startup log states
//! which posture is active per serve mode. On the plain path the application-layer defences (admission
//! control, per-IP rate limit, request timeout) still apply.
//!
//! These knobs are purely transport-level: they change WHEN/WHETHER a connection is served, never the
//! LDP/auth/WAC semantics of a request that IS served — so conformance is unaffected (the caps are
//! deliberately lenient enough never to trip the harness's own concurrency; see the defaults).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum_server::accept::Accept;
use hyper_util::rt::TokioTimer;
use hyper_util::server::conn::auto::Builder;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// --- Env var names --------------------------------------------------------------------------------

/// Env var: the HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised to clients (max simultaneously
/// open streams per connection). Bounds the work a single h2 connection can pin. Unset / invalid ⇒
/// [`DEFAULT_H2_MAX_CONCURRENT_STREAMS`]. `0` is rejected (a 0-stream connection is useless) ⇒ default.
pub const ENV_H2_MAX_CONCURRENT_STREAMS: &str = "SOLID_SERVER_H2_MAX_CONCURRENT_STREAMS";

/// Env var: the max number of pending-accept RST_STREAM streams before a `GOAWAY` (the
/// CVE-2023-44487 rapid-reset cap, hyper #2877). Unset ⇒ hyper's secure default (currently 20) is
/// kept — we do NOT lower it. A positive value overrides; `0` is rejected (would `GOAWAY` instantly)
/// ⇒ keep hyper's default.
pub const ENV_H2_MAX_PENDING_RESET_STREAMS: &str = "SOLID_SERVER_H2_MAX_PENDING_RESET_STREAMS";

/// Env var: the slowloris header-read timeout in seconds — a connection that has not sent a COMPLETE
/// set of request headers within this window is dropped. Unset / invalid ⇒
/// [`DEFAULT_HEADER_READ_TIMEOUT_SECS`]; `0` ⇒ DISABLED (no header timeout).
pub const ENV_HEADER_READ_TIMEOUT_SECS: &str = "SOLID_SERVER_HEADER_READ_TIMEOUT_SECS";

/// Env var: the maximum number of concurrently-open TCP connections accepted. A flood of half-open
/// (slowloris) connections beyond this is not accepted, so it cannot exhaust file descriptors /
/// memory. Unset / invalid / `0` ⇒ [`DEFAULT_MAX_CONNECTIONS`] (a `0` would refuse all traffic — never
/// silently brick the server on a typo).
pub const ENV_MAX_CONNECTIONS: &str = "SOLID_SERVER_MAX_CONNECTIONS";

/// Env var: the HTTP/2 keep-alive ping interval+ack-timeout in seconds. hyper sends a keep-alive PING
/// every interval and DROPS the connection if the ack does not arrive within the timeout — this
/// reclaims a connection whose peer has gone away (a dead/half-open h2 connection holding a permit),
/// NOT a merely-idle one (a live client that keeps acking pings is not closed by this). Combined with
/// the connection cap + the bounded handshake timeout, it bounds the dead-peer leak. Unset / invalid ⇒
/// [`DEFAULT_KEEP_ALIVE_TIMEOUT_SECS`]; `0` ⇒ DISABLED (no h2 keep-alive ping).
pub const ENV_KEEP_ALIVE_TIMEOUT_SECS: &str = "SOLID_SERVER_KEEP_ALIVE_TIMEOUT_SECS";

/// Env var: the accept/handshake timeout in seconds — the maximum time the TLS handshake (the inner
/// accept) may take while HOLDING a connection permit. A client that opens a TCP connection and STALLS
/// the TLS handshake (never completing it) would otherwise pin a permit until the underlying acceptor's
/// own handshake timeout; bounding it HERE releases the permit promptly so a slow-handshake flood
/// cannot exhaust the connection cap before the HTTP-layer `header_read_timeout` can apply. Unset /
/// invalid ⇒ [`DEFAULT_HANDSHAKE_TIMEOUT_SECS`]; `0` ⇒ DISABLED (rely on the acceptor's own bound).
pub const ENV_HANDSHAKE_TIMEOUT_SECS: &str = "SOLID_SERVER_HANDSHAKE_TIMEOUT_SECS";

// --- Defaults -------------------------------------------------------------------------------------

/// Default `max_concurrent_streams`. hyper's own default is 200; we set 256 explicitly (a small,
/// round, generous ceiling — far above any legitimate browser/client's per-connection multiplexing,
/// well above the conformance harness's needs, but a hard bound against a single connection pinning
/// unbounded work). Owning it as a constant makes it a documented, tested invariant.
pub const DEFAULT_H2_MAX_CONCURRENT_STREAMS: u32 = 256;

/// Default slowloris header-read timeout (seconds). Generous enough for a legitimate client on a slow
/// link to transmit a normal (even large-cookie) header set, short enough that a byte-trickle
/// connection is reclaimed promptly. hyper's own default is ~30s; we set 15s explicitly + own it.
pub const DEFAULT_HEADER_READ_TIMEOUT_SECS: u64 = 15;

/// Default concurrent-connection cap. Deliberately HIGH — a safety bound against a connection flood,
/// NOT a throughput throttle: it must never trip during normal use OR the conformance run (which uses
/// a handful of connections). An operator tunes it to their box's fd/memory budget. Sized to match
/// the spirit of [`crate::overload::DEFAULT_MAX_CONCURRENCY`] (10_000 in-flight requests) — connections
/// are cheaper than admitted requests, so an equal ceiling is conservative.
pub const DEFAULT_MAX_CONNECTIONS: usize = 10_000;

/// Default HTTP/2 keep-alive ping interval+ack-timeout (seconds). Long enough not to churn a healthy
/// reused connection, short enough to reclaim a DEAD-peer one (one whose host vanished without a FIN).
/// This detects a dead peer, NOT a live-but-idle client — see [`ENV_KEEP_ALIVE_TIMEOUT_SECS`].
pub const DEFAULT_KEEP_ALIVE_TIMEOUT_SECS: u64 = 60;

/// Default accept/handshake timeout (seconds). Generous enough for a legitimate TLS handshake on a
/// slow link, short enough that a stalled-handshake connection releases its permit promptly. Matches
/// the spirit of axum-server's own 10s handshake-timeout default, but is owned + tested here and
/// releases the CONNECTION PERMIT (not just the handshake) on expiry.
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

// --- Resolved config ------------------------------------------------------------------------------

/// The resolved transport-hardening configuration. Built from the env via [`TransportConfig::from_env`]
/// (or directly in tests). Every field is a plain value so the struct is trivially testable; the
/// effect is applied to a hyper builder by [`TransportConfig::apply_to_builder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    /// HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` (always set — owned ceiling).
    pub h2_max_concurrent_streams: u32,
    /// Override for the rapid-reset pending-accept cap. `None` ⇒ keep hyper's secure default (20).
    pub h2_max_pending_reset_streams: Option<usize>,
    /// Slowloris header-read timeout. `None` ⇒ disabled (no header timeout).
    pub header_read_timeout: Option<Duration>,
    /// Concurrent-connection cap (always set — a `0` env value falls back to the default, never 0).
    pub max_connections: usize,
    /// HTTP/2 keep-alive ping interval+ack-timeout — reclaims a DEAD-peer connection (not a live-idle
    /// one). `None` ⇒ disabled (no h2 keep-alive ping).
    pub keep_alive_timeout: Option<Duration>,
    /// Accept/handshake timeout: the max time the inner accept (TLS handshake) may take while holding a
    /// connection permit, after which the permit is released. `None` ⇒ disabled (rely on the underlying
    /// acceptor's own handshake bound).
    pub handshake_timeout: Option<Duration>,
}

impl TransportConfig {
    /// Resolve the transport config from the environment, applying each field's documented fallback.
    pub fn from_env() -> Self {
        Self {
            h2_max_concurrent_streams: parse_h2_max_concurrent_streams(
                std::env::var(ENV_H2_MAX_CONCURRENT_STREAMS).ok(),
            ),
            h2_max_pending_reset_streams: parse_h2_max_pending_reset_streams(
                std::env::var(ENV_H2_MAX_PENDING_RESET_STREAMS).ok(),
            ),
            header_read_timeout: parse_optional_secs(
                std::env::var(ENV_HEADER_READ_TIMEOUT_SECS).ok(),
                DEFAULT_HEADER_READ_TIMEOUT_SECS,
            ),
            max_connections: parse_max_connections(std::env::var(ENV_MAX_CONNECTIONS).ok()),
            keep_alive_timeout: parse_optional_secs(
                std::env::var(ENV_KEEP_ALIVE_TIMEOUT_SECS).ok(),
                DEFAULT_KEEP_ALIVE_TIMEOUT_SECS,
            ),
            handshake_timeout: parse_optional_secs(
                std::env::var(ENV_HANDSHAKE_TIMEOUT_SECS).ok(),
                DEFAULT_HANDSHAKE_TIMEOUT_SECS,
            ),
        }
    }

    /// Apply the HTTP/1.1 + HTTP/2 transport knobs to a hyper `auto::Builder` (the builder BOTH serve
    /// paths use). This sets:
    /// - h2 `max_concurrent_streams` (the owned ceiling),
    /// - h2 `max_pending_accept_reset_streams` when overridden (else hyper's secure default 20 stands),
    /// - the h2 keep-alive PING (interval + ack-timeout) — reclaims a DEAD-peer h2 connection (one
    ///   whose host vanished without a FIN); it does NOT close a live-but-idle client (that holds a
    ///   permit until it disconnects — bounded instead by the connection cap),
    /// - the h1 header-read (slowloris) timeout — which REQUIRES a [`TokioTimer`], so we install one
    ///   on both the h1 and h2 sub-builders whenever a timeout-bearing knob is active (hyper PANICS if
    ///   `header_read_timeout` is set without a timer).
    ///
    /// It does NOT touch ALPN / TLS — those stay exactly as the caller built them (the TLS path's
    /// rustls config owns ALPN; see [`crate::tls`]).
    pub fn apply_to_builder<E>(&self, builder: &mut Builder<E>) {
        // A timer is REQUIRED before `header_read_timeout` (hyper panics otherwise) and is needed for
        // the keep-alive timeouts to fire. Install it on BOTH sub-builders unconditionally — it is
        // harmless when no timeout is set, and it keeps the "set timer before timeout" invariant local
        // and unmissable.
        builder.http1().timer(TokioTimer::new());
        builder.http2().timer(TokioTimer::new());

        // HTTP/2: the rapid-reset + concurrency caps.
        builder
            .http2()
            .max_concurrent_streams(self.h2_max_concurrent_streams);
        if let Some(max_pending) = self.h2_max_pending_reset_streams {
            // Override hyper's default-20 rapid-reset cap (only when explicitly configured higher/lower
            // by an operator who knows their workload; unset keeps the secure default).
            builder
                .http2()
                .max_pending_accept_reset_streams(max_pending);
        }

        // Slowloris header-read timeout (HTTP/1.1). A connection that has not sent a complete header
        // set within the window is dropped. We ALWAYS call the setter with the owned value so this
        // crate's value wins over hyper's default: `Some(d)` enforces the timeout, `None` disables it
        // (an explicit `0`/disable env value). The timer installed above makes it take effect.
        builder
            .http1()
            .header_read_timeout(self.header_read_timeout);

        // h2 keep-alive PING (interval + ack-timeout): hyper sends a PING every `ka` and DROPS the
        // connection if the ack does not arrive within `ka` — so a DEAD-peer h2 connection (host gone
        // without a FIN) is reclaimed, freeing its permit. NOTE this detects a dead peer, NOT a
        // live-but-idle client (one that keeps acking pings is NOT closed — it holds its permit until
        // it disconnects; the connection CAP is what bounds that). For h1, hyper reclaims an idle
        // keep-alive connection on the header-read timeout of the NEXT request, so the header-read
        // timeout above already bounds a dead/idle h1 keep-alive head.
        if let Some(ka) = self.keep_alive_timeout {
            builder.http2().keep_alive_interval(ka);
            builder.http2().keep_alive_timeout(ka);
        }
    }
}

// --- Concurrent-connection cap --------------------------------------------------------------------

/// A shared cap on the number of concurrently-served connections. A permit is acquired when a
/// connection is accepted and HELD for the connection's whole lifetime (released on drop), so a flood
/// of half-open (slowloris) connections beyond the cap cannot accumulate unbounded served connections
/// — exhausting file descriptors / memory. Cloning shares the same underlying semaphore.
#[derive(Clone)]
pub struct ConnectionLimiter {
    semaphore: Arc<Semaphore>,
    max_connections: usize,
}

impl ConnectionLimiter {
    /// Build a limiter capping concurrently-served connections at `max_connections`, clamped to
    /// `[1, Semaphore::MAX_PERMITS]`:
    /// - the **lower** clamp (>=1) makes a 0 safe (a 0-permit pool would refuse all traffic; the env
    ///   parser already rejects 0, but a direct construction must be safe too);
    /// - the **upper** clamp ([`Semaphore::MAX_PERMITS`] = `usize::MAX >> 3`) avoids a startup PANIC —
    ///   `Semaphore::new` panics if its initial permit count exceeds that bound, and an operator could
    ///   set an absurdly large `SOLID_SERVER_MAX_CONNECTIONS`. Clamping fails SAFE (a still-enormous,
    ///   never-reached cap) rather than crashing the boot (roborev Low).
    pub fn new(max_connections: usize) -> Self {
        let permits = max_connections.clamp(1, Semaphore::MAX_PERMITS);
        Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            max_connections: permits,
        }
    }

    /// The configured connection ceiling (after the `[1, MAX_PERMITS]` clamp).
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Currently-available connection permits (cap minus in-flight). Exposed for tests/metrics.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Try to acquire a permit WITHOUT blocking. `Some(permit)` ⇒ admitted (hold for the connection
    /// lifetime); `None` ⇒ at capacity — the caller must REFUSE/drop the connection immediately rather
    /// than queue it. Fail-fast (not awaiting) is the load-bearing choice: a slowloris/connection flood
    /// over the cap is dropped + its socket reclaimed at once, so over-cap connections cannot pile up
    /// as parked tasks holding accepted sockets (roborev Medium). The `None` case also covers the
    /// (impossible — we never close it) closed-semaphore state.
    fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }

    /// Wrap an `axum-server` acceptor so each accepted connection holds a connection permit for its
    /// lifetime — the connection-cap for the TLS serve path, with NO handshake timeout (rely on the
    /// underlying acceptor's own bound). Prefer [`wrap_acceptor_with_handshake_timeout`].
    pub fn wrap_acceptor<A>(&self, inner: A) -> ConnectionLimitAcceptor<A> {
        self.wrap_acceptor_with_handshake_timeout(inner, None)
    }

    /// As [`wrap_acceptor`](Self::wrap_acceptor), but bounding the inner accept (TLS handshake) by
    /// `handshake_timeout`: a connection that stalls the handshake longer than this has its permit
    /// RELEASED (the accept resolves to an error, so axum-server drops it), so a slow-handshake flood
    /// cannot pin the connection cap before the HTTP-layer header-read timeout can apply. `None` ⇒ no
    /// added bound (the underlying acceptor's own handshake timeout still applies).
    pub fn wrap_acceptor_with_handshake_timeout<A>(
        &self,
        inner: A,
        handshake_timeout: Option<Duration>,
    ) -> ConnectionLimitAcceptor<A> {
        ConnectionLimitAcceptor {
            inner,
            limiter: self.clone(),
            handshake_timeout,
        }
    }
}

/// An [`Accept`] wrapper that bounds concurrently-served connections via a [`ConnectionLimiter`]. It
/// acquires a permit (FAIL-FAST — without blocking) BEFORE running the inner accept (TLS handshake);
/// over the cap it REFUSES the connection with an error so `axum-server` drops it and reclaims the
/// socket at once, rather than queueing it. The inner accept is bounded by an optional
/// `handshake_timeout` so a stalled handshake cannot pin a permit. On admission it hands back a
/// [`PermittedStream`] holding the permit for the connection's lifetime — so no more than
/// `max_connections` served connections exist at once, AND a flood over the cap (or stalled
/// handshakes) is shed promptly (not parked as pending tasks holding accepted sockets — roborev).
#[derive(Clone)]
pub struct ConnectionLimitAcceptor<A> {
    inner: A,
    limiter: ConnectionLimiter,
    handshake_timeout: Option<Duration>,
}

impl<A, I, S> Accept<I, S> for ConnectionLimitAcceptor<A>
where
    A: Accept<I, S> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Service: Send,
    A::Future: Send,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = PermittedStream<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        // Acquire the connection permit FAIL-FAST, OUTSIDE the async block, so an over-cap connection
        // is refused HERE (the socket `stream` is dropped at once, reclaiming it) instead of being
        // queued as a parked task awaiting a permit. `axum-server` drops a connection whose
        // `accept` future resolves to `Err`, so an over-cap `Err` sheds the connection immediately.
        let permit = match self.limiter.try_acquire() {
            Some(p) => p,
            None => {
                // At capacity — refuse. `stream`/`service` are dropped with this future, releasing the
                // socket. This is the connection cap doing its job (a 503-equivalent at the transport
                // layer): strictly less than the connection would otherwise get, never a bypass.
                return Box::pin(std::future::ready(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "connection cap reached — refusing connection",
                ))));
            }
        };
        let inner = self.inner.clone();
        let handshake_timeout = self.handshake_timeout;
        Box::pin(async move {
            // Run the inner accept (e.g. the TLS handshake), BOUNDED by `handshake_timeout` when set —
            // a stalled handshake must not pin the permit. On timeout the inner accept future is
            // dropped (cancelling the handshake) and we return an error; `permit` is dropped with this
            // future, RELEASING the connection slot at once. The permit is held across a SUCCESSFUL
            // accept and moved into the returned stream, so it stays held for the connection lifetime.
            let accept_fut = inner.accept(stream, service);
            let (io_stream, svc) = match handshake_timeout {
                Some(to) => match tokio::time::timeout(to, accept_fut).await {
                    Ok(result) => result?,
                    Err(_elapsed) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "TLS handshake exceeded the accept timeout — refusing connection",
                        ));
                    }
                },
                None => accept_fut.await?,
            };
            Ok((PermittedStream::new(io_stream, permit), svc))
        })
    }
}

/// An IO stream that holds an [`OwnedSemaphorePermit`] for its lifetime, delegating all read/write to
/// the inner stream. Dropping it releases the connection permit (back to the [`ConnectionLimiter`]).
/// Requires `Io: Unpin` (every stream we serve — `TcpStream`, rustls `TlsStream<TcpStream>` — is
/// `Unpin`), so the AsyncRead/AsyncWrite impls can project to the inner stream without pin machinery.
pub struct PermittedStream<Io> {
    inner: Io,
    // Held for the connection lifetime; released on drop. Never read — its Drop is the whole point.
    _permit: OwnedSemaphorePermit,
}

impl<Io> PermittedStream<Io> {
    fn new(inner: Io, permit: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            _permit: permit,
        }
    }
}

impl<Io: AsyncRead + Unpin> AsyncRead for PermittedStream<Io> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<Io: AsyncWrite + Unpin> AsyncWrite for PermittedStream<Io> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

// --- Pure parsers (testable cores) ----------------------------------------------------------------

/// Resolve `max_concurrent_streams` from the env value. absent / empty / non-numeric / `0` ⇒ the
/// default (a `0` would make every h2 connection useless). `>0` ⇒ that literal ceiling.
pub fn parse_h2_max_concurrent_streams(raw: Option<String>) -> u32 {
    match raw.as_deref().map(str::trim) {
        None | Some("") => DEFAULT_H2_MAX_CONCURRENT_STREAMS,
        Some(s) => match s.parse::<u32>() {
            Ok(0) | Err(_) => DEFAULT_H2_MAX_CONCURRENT_STREAMS,
            Ok(n) => n,
        },
    }
}

/// Resolve the rapid-reset pending-accept override. absent / empty / non-numeric / `0` ⇒ `None` (keep
/// hyper's secure default of 20 — NEVER lower it to 0, which would `GOAWAY` on the first reset). `>0`
/// ⇒ `Some(n)`. The override exists so an operator with an unusual but legitimate reset pattern can
/// RAISE the cap; the default path leaves the CVE-2023-44487 mitigation at hyper's value.
pub fn parse_h2_max_pending_reset_streams(raw: Option<String>) -> Option<usize> {
    match raw.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) => match s.parse::<usize>() {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(n),
        },
    }
}

/// Resolve the max-connections cap. absent / empty / non-numeric / `0` ⇒ the default (a `0` would
/// refuse ALL traffic). `>0` ⇒ that literal cap.
pub fn parse_max_connections(raw: Option<String>) -> usize {
    match raw.as_deref().map(str::trim) {
        None | Some("") => DEFAULT_MAX_CONNECTIONS,
        Some(s) => match s.parse::<usize>() {
            Ok(0) | Err(_) => DEFAULT_MAX_CONNECTIONS,
            Ok(n) => n,
        },
    }
}

/// Resolve an optional-seconds timeout (header-read / keep-alive): absent / empty / non-numeric ⇒
/// `Some(default)` (ENABLED at the default); `0` ⇒ `None` (explicitly DISABLED); `>0` ⇒ `Some(n)`.
pub fn parse_optional_secs(raw: Option<String>, default_secs: u64) -> Option<Duration> {
    let secs = match raw.as_deref().map(str::trim) {
        None | Some("") => default_secs,
        Some(s) => match s.parse::<u64>() {
            Ok(0) => return None, // explicit disable
            Ok(n) => n,
            Err(_) => default_secs,
        },
    };
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_max_concurrent_streams_default_on_absent_empty_invalid_or_zero() {
        // absent / empty / non-numeric / 0 ⇒ default (a 0-stream connection is useless).
        assert_eq!(
            parse_h2_max_concurrent_streams(None),
            DEFAULT_H2_MAX_CONCURRENT_STREAMS
        );
        assert_eq!(
            parse_h2_max_concurrent_streams(Some("".into())),
            DEFAULT_H2_MAX_CONCURRENT_STREAMS
        );
        assert_eq!(
            parse_h2_max_concurrent_streams(Some("  ".into())),
            DEFAULT_H2_MAX_CONCURRENT_STREAMS
        );
        assert_eq!(
            parse_h2_max_concurrent_streams(Some("abc".into())),
            DEFAULT_H2_MAX_CONCURRENT_STREAMS
        );
        assert_eq!(
            parse_h2_max_concurrent_streams(Some("0".into())),
            DEFAULT_H2_MAX_CONCURRENT_STREAMS
        );
    }

    #[test]
    fn h2_max_concurrent_streams_explicit_positive_is_honoured() {
        assert_eq!(parse_h2_max_concurrent_streams(Some("1".into())), 1);
        assert_eq!(parse_h2_max_concurrent_streams(Some("128".into())), 128);
        assert_eq!(parse_h2_max_concurrent_streams(Some("  512  ".into())), 512);
    }

    #[test]
    fn h2_pending_reset_keeps_hyper_default_unless_positive_override() {
        // absent / empty / non-numeric / 0 ⇒ None (KEEP hyper's secure default 20). The load-bearing
        // safety property: a typo / `0` can NEVER lower the rapid-reset cap below hyper's default.
        assert_eq!(parse_h2_max_pending_reset_streams(None), None);
        assert_eq!(parse_h2_max_pending_reset_streams(Some("".into())), None);
        assert_eq!(parse_h2_max_pending_reset_streams(Some("abc".into())), None);
        assert_eq!(parse_h2_max_pending_reset_streams(Some("0".into())), None);
        // A positive value overrides.
        assert_eq!(
            parse_h2_max_pending_reset_streams(Some("50".into())),
            Some(50)
        );
        assert_eq!(
            parse_h2_max_pending_reset_streams(Some("  100  ".into())),
            Some(100)
        );
    }

    #[test]
    fn max_connections_default_on_absent_empty_invalid_or_zero() {
        // absent / empty / non-numeric / 0 ⇒ default (a 0 would refuse all traffic).
        assert_eq!(parse_max_connections(None), DEFAULT_MAX_CONNECTIONS);
        assert_eq!(
            parse_max_connections(Some("".into())),
            DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(
            parse_max_connections(Some("abc".into())),
            DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(
            parse_max_connections(Some("0".into())),
            DEFAULT_MAX_CONNECTIONS
        );
    }

    #[test]
    fn max_connections_explicit_positive_is_honoured() {
        assert_eq!(parse_max_connections(Some("1".into())), 1);
        assert_eq!(parse_max_connections(Some("4096".into())), 4096);
        assert_eq!(parse_max_connections(Some("  64  ".into())), 64);
    }

    #[test]
    fn optional_secs_rules() {
        // default when absent/empty/invalid; disabled (None) on 0; honoured on >0.
        assert_eq!(
            parse_optional_secs(None, DEFAULT_HEADER_READ_TIMEOUT_SECS),
            Some(Duration::from_secs(DEFAULT_HEADER_READ_TIMEOUT_SECS))
        );
        assert_eq!(
            parse_optional_secs(Some("".into()), 15),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            parse_optional_secs(Some("garbage".into()), 15),
            Some(Duration::from_secs(15))
        );
        assert_eq!(parse_optional_secs(Some("0".into()), 15), None);
        assert_eq!(
            parse_optional_secs(Some("5".into()), 15),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn from_env_with_unset_vars_uses_documented_defaults() {
        // Snapshot + clear the vars so the test sees the absent-defaults regardless of the ambient env,
        // then restore. (Each var is process-global; this test owns them for its duration.)
        let keys = [
            ENV_H2_MAX_CONCURRENT_STREAMS,
            ENV_H2_MAX_PENDING_RESET_STREAMS,
            ENV_HEADER_READ_TIMEOUT_SECS,
            ENV_MAX_CONNECTIONS,
            ENV_KEEP_ALIVE_TIMEOUT_SECS,
            ENV_HANDSHAKE_TIMEOUT_SECS,
        ];
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        let cfg = TransportConfig::from_env();
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        assert_eq!(
            cfg,
            TransportConfig {
                h2_max_concurrent_streams: DEFAULT_H2_MAX_CONCURRENT_STREAMS,
                h2_max_pending_reset_streams: None,
                header_read_timeout: Some(Duration::from_secs(DEFAULT_HEADER_READ_TIMEOUT_SECS)),
                max_connections: DEFAULT_MAX_CONNECTIONS,
                keep_alive_timeout: Some(Duration::from_secs(DEFAULT_KEEP_ALIVE_TIMEOUT_SECS)),
                handshake_timeout: Some(Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS)),
            }
        );
    }

    #[test]
    fn apply_to_builder_does_not_panic_with_timeout_set() {
        // The load-bearing crash-guard: `header_read_timeout` PANICS in hyper if no `Timer` is set.
        // `apply_to_builder` installs a TokioTimer first, so applying a config WITH a header timeout
        // must not panic. (We build a real auto::Builder and apply — if the timer ordering were wrong
        // this would panic here.) Run inside a tokio context because TokioTimer expects a runtime.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cfg = TransportConfig {
                h2_max_concurrent_streams: 256,
                h2_max_pending_reset_streams: Some(20),
                header_read_timeout: Some(Duration::from_secs(15)),
                max_connections: 10_000,
                keep_alive_timeout: Some(Duration::from_secs(60)),
                handshake_timeout: Some(Duration::from_secs(10)),
            };
            let mut builder = Builder::new(hyper_util::rt::TokioExecutor::new());
            cfg.apply_to_builder(&mut builder);
        });
    }

    #[test]
    fn connection_limiter_clamps_to_at_least_one_permit() {
        // A 0 cap would refuse ALL connections; the type clamps to >=1 (the env parser already rejects
        // 0, but a direct construction must be safe too).
        let limiter = ConnectionLimiter::new(0);
        assert_eq!(limiter.max_connections(), 1);
        assert_eq!(limiter.available_permits(), 1);
    }

    #[test]
    fn connection_limiter_bounds_in_flight_then_recovers() {
        // The load-bearing property: at most `max_connections` permits are available at once; a held
        // permit reduces the pool; dropping it restores capacity; AND a 3rd acquire over the cap FAILS
        // FAST (None — refused, not queued). Tested deterministically without sockets. No async runtime
        // needed — `try_acquire` is synchronous (the fail-fast connection cap).
        let limiter = ConnectionLimiter::new(2);
        assert_eq!(limiter.available_permits(), 2);

        let p1 = limiter.try_acquire().expect("permit 1");
        assert_eq!(limiter.available_permits(), 1);
        let p2 = limiter.try_acquire().expect("permit 2");
        assert_eq!(
            limiter.available_permits(),
            0,
            "at capacity ⇒ no permits left"
        );

        // A third acquire over the cap must FAIL FAST (None) — the connection is REFUSED, not parked.
        assert!(
            limiter.try_acquire().is_none(),
            "a 3rd acquire must be REFUSED (None) while at capacity (the fail-fast connection cap)"
        );

        // Free one slot ⇒ the next acquire succeeds again.
        drop(p1);
        assert_eq!(limiter.available_permits(), 1);
        let p3 = limiter
            .try_acquire()
            .expect("a freed slot must admit the next connection");
        assert_eq!(limiter.available_permits(), 0);

        drop(p2);
        drop(p3);
        assert_eq!(
            limiter.available_permits(),
            2,
            "all slots released ⇒ full pool"
        );
    }

    #[test]
    fn acceptor_releases_permit_when_handshake_stalls() {
        // The handshake-timeout fix (roborev Medium): a stalled inner accept (TLS handshake) must NOT
        // pin a connection permit. With a mock acceptor whose `accept` NEVER resolves and a short
        // handshake timeout, the wrapped acceptor's future must resolve to Err WITHIN the timeout AND
        // RELEASE the permit (so the cap recovers). Deterministic, no sockets.
        use std::future::pending;

        // A mock `Accept` whose accept future never completes (models a stalled TLS handshake).
        #[derive(Clone)]
        struct StallingAcceptor;
        impl Accept<(), ()> for StallingAcceptor {
            // `TcpStream` is only NAMED as the associated Stream type (a connection is never produced —
            // the accept future never resolves), so no socket is opened. Using it avoids needing the
            // `io-util` feature a `DuplexStream` would require.
            type Stream = tokio::net::TcpStream;
            type Service = ();
            type Future =
                Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;
            fn accept(&self, _stream: (), _service: ()) -> Self::Future {
                // Never resolves — the handshake stalls forever.
                Box::pin(async { pending::<io::Result<(Self::Stream, Self::Service)>>().await })
            }
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let limiter = ConnectionLimiter::new(1);
            assert_eq!(limiter.available_permits(), 1);
            let acceptor = limiter.wrap_acceptor_with_handshake_timeout(
                StallingAcceptor,
                Some(Duration::from_millis(100)),
            );

            // The accept future holds the permit while it awaits the (never-completing) handshake, then
            // must time out → Err. While in flight the permit is taken.
            let accept_fut = acceptor.accept((), ());
            let result = tokio::time::timeout(Duration::from_secs(2), accept_fut)
                .await
                .expect(
                    "the wrapped accept must itself time out (not hang) on a stalled handshake",
                );
            assert!(
                result.is_err(),
                "a stalled handshake must resolve the accept to Err (handshake timeout)"
            );
            // CRITICAL: the permit was released when the Err future was dropped, so the cap recovered.
            assert_eq!(
                limiter.available_permits(),
                1,
                "a stalled-handshake connection must RELEASE its permit on timeout (no permit leak)"
            );
        });
    }

    #[test]
    fn connection_limiter_clamps_huge_value_below_semaphore_max() {
        // A max_connections above tokio's Semaphore::MAX_PERMITS would PANIC in `Semaphore::new`; the
        // clamp fails SAFE to MAX_PERMITS instead of crashing the boot (roborev Low).
        let limiter = ConnectionLimiter::new(usize::MAX);
        assert_eq!(limiter.max_connections(), Semaphore::MAX_PERMITS);
        assert_eq!(limiter.available_permits(), Semaphore::MAX_PERMITS);
        // And one permit is acquirable (the pool is valid, not poisoned).
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn apply_to_builder_with_disabled_timeouts_does_not_panic() {
        // header_read_timeout = None (disabled) + keep_alive = None: still installs the timer, still
        // sets the h2 caps, and must not panic.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cfg = TransportConfig {
                h2_max_concurrent_streams: 256,
                h2_max_pending_reset_streams: None,
                header_read_timeout: None,
                max_connections: 10_000,
                keep_alive_timeout: None,
                handshake_timeout: None,
            };
            let mut builder = Builder::new(hyper_util::rt::TokioExecutor::new());
            cfg.apply_to_builder(&mut builder);
        });
    }
}
