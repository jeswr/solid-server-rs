// AUTHORED-BY Claude Opus 4.8
//! Transport-layer DoS hardening — HTTP/2 stream/reset caps + slowloris header timeout + a
//! concurrent-connection cap + TLS-handshake timeout + a per-connection idle-keepalive timeout + a
//! max-requests-per-connection reuse cap.
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
//! - **Idle keep-alive hold (the two missing-guard companions).** Two further gaps the bounds above
//!   leave open, both enforced here (NOT hyper builder knobs — hyper 1.x exposes neither; see below):
//!   - a peer that completes a request, gets its response, then holds the keep-alive connection open
//!     sending NOTHING further — `header_read_timeout` only bounds a PARTIAL head (bytes started), and
//!     the h2 PING only reclaims a DEAD peer, so neither closes a LIVE peer on a fully-idle connection.
//!     The defence is a per-connection **idle-keepalive read timeout** at the IO layer
//!     ([`IdleTimeoutStream`]): no bytes for the window ⇒ close + reclaim the permit.
//!   - unbounded keep-alive REUSE of one connection — bounded by a **max-requests-per-connection** cap
//!     ([`MaxRequestsService`]) that sets `Connection: close` after N requests (HTTP/1.1 reuse
//!     rotation; default OFF).
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
//! and the connection cap + handshake timeout + the per-connection **idle-keepalive read timeout**
//! (IO-layer [`IdleTimeoutStream`]) + the **max-requests-per-connection** cap (service-layer
//! [`MaxRequestsService`]) via the [`ConnectionLimitAcceptor`] wrapping `axum-server`'s acceptor — the
//! last two are NOT hyper builder knobs (hyper 1.x exposes neither a per-connection idle timeout nor a
//! request-count cap), so they are owned here at the per-connection accept seam. The **plain-HTTP path
//! is intentionally NOT hardened here** — `axum::serve`
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

/// Env var: the per-connection **idle-keepalive timeout** in seconds — a kept-alive connection on which
/// NO bytes are read for this long (idle BETWEEN requests) is dropped, reclaiming its connection permit.
/// This is the missing-guard companion to the existing bounds: `header_read_timeout` bounds reading a
/// COMPLETE header set once bytes START arriving; the h2 keep-alive PING reclaims a DEAD peer (one that
/// stopped acking). NEITHER bounds a peer that completes a request then holds the keep-alive connection
/// open sending nothing further — that connection keeps its permit indefinitely. This idle-read timeout
/// closes it. (It is enforced at the IO layer, on the TLS serve path only — see
/// [`IdleTimeoutStream`].) Unset / invalid ⇒ [`DEFAULT_IDLE_TIMEOUT_SECS`]; `0` ⇒ DISABLED.
pub const ENV_IDLE_TIMEOUT_SECS: &str = "SOLID_SERVER_IDLE_TIMEOUT_SECS";

/// Env var: the **max requests per connection** cap — after serving this many requests on a single
/// HTTP/1.1 keep-alive connection the server sets `Connection: close` on the response, so hyper closes
/// the connection after it and the client must reconnect. This bounds how long one connection can be
/// reused (defence-in-depth: it forces periodic re-handshake/re-LB-balance and caps the work a single
/// long-lived connection can pin without ever re-entering the accept-time connection cap). Unset /
/// invalid / `0` ⇒ DISABLED (unlimited reuse — the default, so it never trips the conformance harness).
/// NOTE (h2): under HTTP/2 multiplexing "requests per connection" is fuzzy (no clean `Connection: close`
/// per stream); this cap is enforced on the per-request response header, which is an HTTP/1.1 construct —
/// see [`MaxRequestsService`]. The accept-time connection cap + the h2 stream/reset caps bound h2.
pub const ENV_MAX_REQUESTS_PER_CONN: &str = "SOLID_SERVER_MAX_REQUESTS_PER_CONN";

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

/// Default per-connection idle-keepalive timeout (seconds). Generous — it must NEVER trip a legitimate
/// keep-alive client between requests in normal use OR the conformance run (which reuses a handful of
/// connections with small inter-request gaps), only reclaim a connection a peer is holding open while
/// sending nothing. 75s mirrors the common reverse-proxy keep-alive-idle default (nginx
/// `keepalive_timeout 75s`), so it is a familiar, safely-large bound. An operator tightens it for a
/// hostile-facing edge.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 75;

/// Default max-requests-per-connection. `0` = DISABLED (unlimited keep-alive reuse) — the default,
/// because a bound here is a defence-in-depth knob (the connection cap + h2 stream caps already bound
/// the work a connection pins), and any finite value risks tripping the conformance harness / a
/// legitimate high-reuse client. An operator opts IN to connection rotation by setting a positive value.
pub const DEFAULT_MAX_REQUESTS_PER_CONN: u64 = 0;

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
    /// Per-connection idle-keepalive timeout: a kept-alive connection with no read activity for this
    /// long is dropped (reclaiming its permit). `None` ⇒ disabled. Enforced at the IO layer (see
    /// [`IdleTimeoutStream`]).
    pub idle_timeout: Option<Duration>,
    /// Max requests served on one connection before `Connection: close` is set (HTTP/1.1 reuse cap).
    /// `None` ⇒ disabled (unlimited reuse). Enforced at the per-connection service layer (see
    /// [`MaxRequestsService`]).
    pub max_requests_per_conn: Option<u64>,
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
            idle_timeout: parse_optional_secs(
                std::env::var(ENV_IDLE_TIMEOUT_SECS).ok(),
                DEFAULT_IDLE_TIMEOUT_SECS,
            ),
            max_requests_per_conn: parse_max_requests_per_conn(
                std::env::var(ENV_MAX_REQUESTS_PER_CONN).ok(),
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
    /// underlying acceptor's own bound) and no idle / max-requests guards. Prefer
    /// [`wrap_acceptor_with_guards`].
    pub fn wrap_acceptor<A>(&self, inner: A) -> ConnectionLimitAcceptor<A> {
        self.wrap_acceptor_with_handshake_timeout(inner, None)
    }

    /// As [`wrap_acceptor`](Self::wrap_acceptor), but bounding the inner accept (TLS handshake) by
    /// `handshake_timeout`: a connection that stalls the handshake longer than this has its permit
    /// RELEASED (the accept resolves to an error, so axum-server drops it), so a slow-handshake flood
    /// cannot pin the connection cap before the HTTP-layer header-read timeout can apply. `None` ⇒ no
    /// added bound (the underlying acceptor's own handshake timeout still applies). Idle / max-requests
    /// guards are OFF — see [`wrap_acceptor_with_guards`] for those.
    pub fn wrap_acceptor_with_handshake_timeout<A>(
        &self,
        inner: A,
        handshake_timeout: Option<Duration>,
    ) -> ConnectionLimitAcceptor<A> {
        self.wrap_acceptor_with_guards(inner, handshake_timeout, None, None)
    }

    /// The full guard wiring: the connection-cap permit + the optional `handshake_timeout` (as above),
    /// PLUS the two missing-guard companions:
    /// - `idle_timeout`: the per-connection idle-keepalive read timeout (a connection sending no bytes
    ///   for this long is dropped, reclaiming its permit) — enforced by wrapping the served IO in an
    ///   [`IdleTimeoutStream`]; `None` ⇒ no idle bound;
    /// - `max_requests_per_conn`: after this many requests on one connection the response carries
    ///   `Connection: close` (HTTP/1.1 reuse cap) — enforced by wrapping the per-connection service in a
    ///   [`MaxRequestsService`]; `None` ⇒ unlimited reuse.
    ///
    /// These are owned, env-tunable, TESTED transport invariants of this crate (see the module docs).
    pub fn wrap_acceptor_with_guards<A>(
        &self,
        inner: A,
        handshake_timeout: Option<Duration>,
        idle_timeout: Option<Duration>,
        max_requests_per_conn: Option<u64>,
    ) -> ConnectionLimitAcceptor<A> {
        ConnectionLimitAcceptor {
            inner,
            limiter: self.clone(),
            handshake_timeout,
            idle_timeout,
            max_requests_per_conn,
        }
    }
}

/// An [`Accept`] wrapper that bounds concurrently-served connections via a [`ConnectionLimiter`] AND
/// wires the per-connection idle / max-requests guards. It acquires a permit (FAIL-FAST — without
/// blocking) BEFORE running the inner accept (TLS handshake); over the cap it REFUSES the connection
/// with an error so `axum-server` drops it and reclaims the socket at once, rather than queueing it. The
/// inner accept is bounded by an optional `handshake_timeout` so a stalled handshake cannot pin a
/// permit. On admission it hands back:
/// - a [`PermittedStream`] (holding the permit for the connection lifetime) wrapping an
///   [`IdleTimeoutStream`] (the idle-keepalive read timeout) — so no more than `max_connections` served
///   connections exist at once, a flood over the cap (or a stalled handshake) is shed promptly, AND an
///   idle keep-alive connection is reclaimed; and
/// - a [`MaxRequestsService`] wrapping the per-connection service — so an HTTP/1.1 connection is closed
///   after the configured number of requests (`Connection: close`). Each accepted connection gets its
///   OWN request counter (it is created here, per `accept`), so the cap is per-connection.
#[derive(Clone)]
pub struct ConnectionLimitAcceptor<A> {
    inner: A,
    limiter: ConnectionLimiter,
    handshake_timeout: Option<Duration>,
    /// Per-connection idle-keepalive read timeout (`None` ⇒ no idle bound). Applied to the served IO.
    idle_timeout: Option<Duration>,
    /// Max requests per connection before `Connection: close` (`None` ⇒ unlimited). Applied to the
    /// per-connection service.
    max_requests_per_conn: Option<u64>,
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
    // The served IO is `PermittedStream` wrapping an `IdleTimeoutStream` (idle timeout is a no-op
    // passthrough when `None`), so the permit is held for the connection lifetime AND an idle connection
    // is reclaimed. The served service is wrapped in `MaxRequestsService` (a no-op passthrough when the
    // cap is `None`), so an HTTP/1.1 connection is closed after the configured number of requests.
    type Stream = PermittedStream<IdleTimeoutStream<A::Stream>>;
    type Service = MaxRequestsService<A::Service>;
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
        let idle_timeout = self.idle_timeout;
        let max_requests = self.max_requests_per_conn;
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
            // Wrap the served IO with the idle-keepalive timeout (no-op when `None`), then the permit;
            // and wrap the per-connection service with the max-requests cap (no-op when `None`). The
            // per-connection request counter lives INSIDE `MaxRequestsService` (a fresh counter per
            // accepted connection — see its docs), so the cap is genuinely per-connection.
            let idle_io = IdleTimeoutStream::new(io_stream, idle_timeout);
            let capped_svc = MaxRequestsService::new(svc, max_requests);
            Ok((PermittedStream::new(idle_io, permit), capped_svc))
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

// --- Idle-keepalive timeout (IO-layer read-inactivity bound) --------------------------------------

/// An IO stream that enforces a per-connection **idle-read timeout**: if no bytes are read for the
/// configured window, the next `poll_read` resolves to an `io::Error` (kind `TimedOut`), which hyper
/// surfaces as a connection close — reclaiming the connection (and its [`ConnectionLimiter`] permit, via
/// the outer [`PermittedStream`]). When the timeout is `None` it is a transparent pass-through (zero
/// overhead — no timer is created).
///
/// ## Why this is the right layer (and the gap it closes)
/// hyper exposes NO native idle-connection timeout (verified against hyper 1.x). The existing bounds do
/// NOT cover an idle keep-alive connection:
/// - `http1::Builder::header_read_timeout` bounds reading a COMPLETE header set once bytes START
///   arriving — it does not fire on a connection that has sent a full request, got its response, and now
///   holds the keep-alive connection open sending nothing;
/// - the h2 keep-alive PING reclaims a DEAD peer (one that stops acking), not a live peer holding an
///   idle connection.
///
/// Wrapping the connection IO with a read-inactivity timeout is the canonical fix in this stack.
///
/// ## The timer is reset on READ ACTIVITY (any progress), so a legitimate trickle is not killed
/// The `Sleep` deadline is reset whenever a `poll_read` makes progress (returns `Ready` with bytes OR a
/// clean EOF). It fires ONLY after a full idle window with the inner read PENDING the whole time — i.e.
/// the peer sent nothing. A slow-but-progressing reader resets the deadline on each chunk, so this never
/// kills a legitimately slow link; the slowloris HEADER trickle is bounded separately by
/// `header_read_timeout` (a complete-head deadline that a per-byte reset cannot defeat).
///
/// ## HTTP/2 interaction (deliberate, documented)
/// Under HTTP/2 the server's keep-alive PING (when configured) elicits a client PONG — a READ — so the
/// idle-read deadline is reset by that PONG traffic. The idle-read timeout therefore primarily bounds
/// HTTP/1.1 keep-alive idle (no PING traffic between requests); on h2 the PING/PONG liveness probe is the
/// dead-peer reclaim and this timeout is effectively subsumed by it (a peer that stops ponging is dropped
/// by the PING ack-timeout). This is correct: each protocol's idle/dead-peer reclaim is covered. The
/// default idle window (75s) is deliberately LARGER than the default PING interval (60s) so the two do
/// not race on a healthy h2 connection.
///
/// Requires `Io: Unpin` (every stream we serve is `Unpin`); the boxed `Sleep` keeps the wrapper `Unpin`.
pub struct IdleTimeoutStream<Io> {
    inner: Io,
    /// `None` ⇒ no idle bound (transparent pass-through). `Some((dur, sleep))` ⇒ enforce `dur` of
    /// read-inactivity; `sleep` is the live deadline, reset to `now + dur` on each read that progresses.
    idle: Option<(Duration, Pin<Box<tokio::time::Sleep>>)>,
}

impl<Io> IdleTimeoutStream<Io> {
    /// Wrap `inner` enforcing an idle-read timeout of `idle_timeout` (or a transparent pass-through when
    /// `None`). The deadline starts at `now + idle_timeout` (so a connection that sends nothing AT ALL
    /// after the handshake is still bounded).
    pub fn new(inner: Io, idle_timeout: Option<Duration>) -> Self {
        let idle = idle_timeout.map(|dur| (dur, Box::pin(tokio::time::sleep(dur))));
        Self { inner, idle }
    }
}

impl<Io: AsyncRead + Unpin> AsyncRead for IdleTimeoutStream<Io> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Poll the inner read first. On any progress (Ready), reset the idle deadline and return it.
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if let Some((dur, sleep)) = this.idle.as_mut() {
                    // Read progressed (bytes or EOF) ⇒ the connection is active ⇒ push the deadline out.
                    sleep.as_mut().reset(tokio::time::Instant::now() + *dur);
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                // Inner read is pending (no bytes available). If the idle deadline has now elapsed, the
                // connection has been silent for the whole window ⇒ close it with a TimedOut error.
                if let Some((_dur, sleep)) = this.idle.as_mut() {
                    if sleep.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connection idle past the keep-alive idle timeout — closing",
                        )));
                    }
                }
                Poll::Pending
            }
        }
    }
}

impl<Io: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutStream<Io> {
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

// --- Max-requests-per-connection (per-connection service-layer reuse cap) --------------------------

/// A `tower::Service` wrapper that caps how many requests are served on ONE connection: after `cap`
/// requests it sets `Connection: close` on the response, so hyper closes the (HTTP/1.1) connection
/// after that response and the client must reconnect. When `cap` is `None` it is a transparent
/// pass-through (the request count is not even tracked).
///
/// ## Per-connection counter (the load-bearing scoping)
/// The acceptor creates ONE `MaxRequestsService` per accepted connection (in `accept`), so its counter
/// is genuinely PER-CONNECTION. hyper CLONES the service per request to serve concurrent/pipelined
/// requests on the connection, so the counter is an `Arc<AtomicU64>` SHARED across those clones (the
/// `Clone` impl shares the `Arc`) — counting all requests on this one connection — but NOT shared with
/// any OTHER connection's service (each `accept` makes a fresh `Arc`). A `fetch_add` on each call gives
/// the request's 1-based ordinal; at/after the cap the response gets `Connection: close`.
///
/// ## Why a header, not `graceful_shutdown` (the correctness choice)
/// Setting `Connection: close` lets the IN-FLIGHT response complete cleanly and THEN closes the
/// connection — the HTTP-correct way to end keep-alive reuse. Calling hyper's per-connection
/// `graceful_shutdown` instead would be coarser (it tears the whole connection state down). The header
/// is exactly what a reverse proxy's `MaxKeepAliveRequests` does.
///
/// ## HTTP/2 (documented limitation)
/// `Connection: close` is an HTTP/1.1 hop-by-hop header; under HTTP/2 there is no per-stream
/// `Connection: close` (the equivalent is a connection-level GOAWAY, which hyper's SERVER builder does
/// not expose a hook for). So this cap is meaningful for HTTP/1.1 keep-alive reuse; h2 connection-pinning
/// is bounded instead by the accept-time connection cap + the h2 stream/reset caps. Setting the header on
/// an h2 response is harmless (hyper drops connection-specific headers on h2) — it simply has no effect
/// there. This is acknowledged in the env-var docs ([`ENV_MAX_REQUESTS_PER_CONN`]).
#[derive(Clone)]
pub struct MaxRequestsService<S> {
    inner: S,
    /// `None` ⇒ unlimited (pass-through). `Some((cap, count))` ⇒ close after `cap` requests; `count` is
    /// the shared per-connection request counter (shared across this connection's service clones).
    cap: Option<(u64, Arc<std::sync::atomic::AtomicU64>)>,
}

impl<S> MaxRequestsService<S> {
    /// Wrap `inner` with a per-connection request cap of `max_requests` (or a transparent pass-through
    /// when `None`). Creates a FRESH counter, so this must be called ONCE per connection (the acceptor
    /// does) for the cap to be per-connection.
    pub fn new(inner: S, max_requests: Option<u64>) -> Self {
        let cap = max_requests.map(|c| (c, Arc::new(std::sync::atomic::AtomicU64::new(0))));
        Self { inner, cap }
    }
}

impl<S, ReqBody, ResBody> tower::Service<http::Request<ReqBody>> for MaxRequestsService<S>
where
    S: tower::Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = MaxRequestsFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        // Compute whether THIS request is at/over the per-connection cap BEFORE calling the inner
        // service. `fetch_add` returns the prior value, so `n+1` is this request's 1-based ordinal; we
        // close on the cap-th request and every one after (the connection should already be closing, but
        // being monotone is robust if a race lets one more in).
        let at_cap = match &self.cap {
            Some((cap, count)) => {
                let ordinal = count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                ordinal >= *cap
            }
            None => false,
        };
        MaxRequestsFuture {
            inner: self.inner.call(req),
            close: at_cap,
        }
    }
}

pin_project_lite::pin_project! {
    /// The future for [`MaxRequestsService`]: awaits the inner response, then — when this request hit the
    /// per-connection cap — sets `Connection: close` so hyper ends keep-alive reuse after it. The inner
    /// future is structurally pinned via `pin_project_lite` (a SAFE, declarative-macro projection — the
    /// crate is `#![forbid(unsafe_code)]`, so no hand-rolled `unsafe` pin). No allocation: the inner
    /// future is held inline, not boxed.
    pub struct MaxRequestsFuture<F> {
        #[pin]
        inner: F,
        // Whether to stamp `Connection: close` on the produced response (this request hit the cap).
        close: bool,
    }
}

impl<F, ResBody, E> Future for MaxRequestsFuture<F>
where
    F: Future<Output = Result<http::Response<ResBody>, E>>,
{
    type Output = Result<http::Response<ResBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Ready(Ok(mut resp)) => {
                if *this.close {
                    // End keep-alive reuse after this response. `HeaderValue::from_static` is infallible
                    // for this constant. (On h2 hyper ignores this connection-specific header — see the
                    // service docs; harmless.)
                    resp.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
                Poll::Ready(Ok(resp))
            }
            other => other,
        }
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

/// Resolve the max-requests-per-connection cap. absent / empty / non-numeric / `0` ⇒ `None` (DISABLED —
/// unlimited keep-alive reuse, the safe default that never trips the conformance harness). `>0` ⇒
/// `Some(n)` (close the connection after `n` requests). A `0` mapping to disabled (NOT a 0-request
/// connection) is deliberate: a typo must never brick keep-alive, and a 0-request cap would be useless.
pub fn parse_max_requests_per_conn(raw: Option<String>) -> Option<u64> {
    match raw.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) => match s.parse::<u64>() {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(n),
        },
    }
}

/// Resolve an optional-seconds timeout (header-read / keep-alive / idle): absent / empty / non-numeric ⇒
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
                idle_timeout: Some(Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)),
                // Default-OFF: a finite reuse cap is opt-in (it could trip a high-reuse client / the
                // harness), so the documented default is `None` (unlimited keep-alive reuse).
                max_requests_per_conn: None,
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
                idle_timeout: Some(Duration::from_secs(75)),
                max_requests_per_conn: Some(10_000),
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
                idle_timeout: None,
                max_requests_per_conn: None,
            };
            let mut builder = Builder::new(hyper_util::rt::TokioExecutor::new());
            cfg.apply_to_builder(&mut builder);
        });
    }

    #[test]
    fn max_requests_per_conn_disabled_on_absent_empty_invalid_or_zero() {
        // The DEFAULT must be disabled (None) — a finite reuse cap is opt-in. A `0`/typo must NEVER
        // become a 0-request cap (which would brick keep-alive); it maps to None (unlimited).
        assert_eq!(parse_max_requests_per_conn(None), None);
        assert_eq!(parse_max_requests_per_conn(Some("".into())), None);
        assert_eq!(parse_max_requests_per_conn(Some("  ".into())), None);
        assert_eq!(parse_max_requests_per_conn(Some("abc".into())), None);
        assert_eq!(parse_max_requests_per_conn(Some("0".into())), None);
        // A positive value enables the cap.
        assert_eq!(parse_max_requests_per_conn(Some("1".into())), Some(1));
        assert_eq!(parse_max_requests_per_conn(Some("1000".into())), Some(1000));
        assert_eq!(parse_max_requests_per_conn(Some("  64  ".into())), Some(64));
    }

    #[tokio::test]
    async fn idle_timeout_stream_passes_through_then_fires_when_idle() {
        // Drive the IdleTimeoutStream over an in-memory duplex pair with a SHORT real idle window. A read
        // that gets bytes succeeds and RESETS the deadline; after a full idle window with no bytes, the
        // next read resolves to a TimedOut error (NOT a hang).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let idle_window = Duration::from_millis(150);
        let (mut client, server) = tokio::io::duplex(64);
        let mut idle = IdleTimeoutStream::new(server, Some(idle_window));

        // 1) A read that gets bytes succeeds (pass-through) and resets the idle deadline.
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        idle.read_exact(&mut buf)
            .await
            .expect("read passes through");
        assert_eq!(&buf, b"hello");

        // 2) Now go idle (no further writes). The next read must resolve to a TimedOut error within a
        // few idle windows (the idle guard fired) rather than hang. The outer timeout is generously
        // larger than the idle window so it only trips if the guard FAILED to fire (a real hang).
        let mut buf2 = [0u8; 1];
        let res = tokio::time::timeout(idle_window * 20, idle.read(&mut buf2)).await;
        let inner =
            res.expect("the idle read must RESOLVE (the guard fires), not hang past the window");
        let err = inner.expect_err("an idle connection past the window must resolve to an error");
        assert_eq!(
            err.kind(),
            io::ErrorKind::TimedOut,
            "the idle-keepalive guard must close with a TimedOut error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn idle_timeout_stream_none_is_transparent_passthrough() {
        // With idle = None the wrapper is a transparent pass-through: a delayed write is still read fine
        // (no timer, no spurious close) even though a real delay elapses between the read starting and
        // the bytes arriving.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, server) = tokio::io::duplex(64);
        let mut idle = IdleTimeoutStream::new(server, None);

        // Spawn a delayed writer; the read must wait for it (no idle bound closes it early).
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            client.write_all(b"x").await.unwrap();
            client // keep the client end alive until the read completes
        });
        let mut buf = [0u8; 1];
        idle.read_exact(&mut buf)
            .await
            .expect("None ⇒ transparent pass-through (a delayed read still succeeds)");
        assert_eq!(&buf, b"x");
        let _client = writer.await.unwrap();
    }

    #[tokio::test]
    async fn max_requests_service_stamps_connection_close_at_the_cap_only() {
        // A stub tower::Service returning a 200 with no body. Wrap it with a cap of 2 and call it 3
        // times (simulating 3 requests on ONE connection — the per-connection counter is shared across
        // the wrapper's clones the way hyper clones the service per request). The 1st response must NOT
        // carry `Connection: close`; the 2nd (== cap) and 3rd (over cap) MUST.
        use std::task::Poll;
        use tower::Service;

        #[derive(Clone)]
        struct Ok200;
        impl Service<http::Request<()>> for Ok200 {
            type Response = http::Response<()>;
            type Error = std::convert::Infallible;
            type Future =
                std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: http::Request<()>) -> Self::Future {
                Box::pin(async { Ok(http::Response::new(())) })
            }
        }

        let mut svc = MaxRequestsService::new(Ok200, Some(2));
        let has_close = |resp: &http::Response<()>| {
            resp.headers()
                .get(http::header::CONNECTION)
                .map(|v| v.as_bytes().eq_ignore_ascii_case(b"close"))
                .unwrap_or(false)
        };

        let r1 = svc.call(http::Request::new(())).await.unwrap();
        assert!(
            !has_close(&r1),
            "request 1 (< cap) must NOT carry Connection: close"
        );
        let r2 = svc.call(http::Request::new(())).await.unwrap();
        assert!(
            has_close(&r2),
            "request 2 (== cap) MUST carry Connection: close"
        );
        let r3 = svc.call(http::Request::new(())).await.unwrap();
        assert!(
            has_close(&r3),
            "request 3 (> cap) MUST also carry Connection: close (monotone after the cap)"
        );
    }

    #[tokio::test]
    async fn max_requests_service_none_never_stamps_close() {
        // With the cap disabled (None), no response ever gets `Connection: close` — unlimited reuse.
        use std::task::Poll;
        use tower::Service;

        #[derive(Clone)]
        struct Ok200;
        impl Service<http::Request<()>> for Ok200 {
            type Response = http::Response<()>;
            type Error = std::convert::Infallible;
            type Future =
                std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: http::Request<()>) -> Self::Future {
                Box::pin(async { Ok(http::Response::new(())) })
            }
        }

        let mut svc = MaxRequestsService::new(Ok200, None);
        for _ in 0..5 {
            let resp = svc.call(http::Request::new(())).await.unwrap();
            assert!(
                resp.headers().get(http::header::CONNECTION).is_none(),
                "with the cap disabled, no response may carry Connection: close"
            );
        }
    }
}
