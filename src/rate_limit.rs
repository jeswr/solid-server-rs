// AUTHORED-BY Claude Opus 4.8
//! Per-source rate limiting — a PRE-CRYPTO per-IP token bucket that rejects abusive traffic with a
//! **429** *before* the expensive DPoP signature verification ever runs.
//!
//! ## Why (the cost problem this solves)
//! The single most expensive thing this server does per request is the asymmetric DPoP/JWS signature
//! verification (an ES256 verify is ~hundreds of µs). [`crate::overload`] already caps GLOBAL
//! concurrency — but that is not enough: a single source can BOTH eat admission slots AND force a full
//! crypto verify for every bogus proof it sends, making attacker traffic cost the server its most
//! expensive operation per request. This layer adds a **per-IP token bucket OUTSIDE auth/WAC/crypto**:
//! a source that exceeds its rate gets a cheap 429 and its request NEVER reaches the verifier, so a
//! flood from one IP cannot make every bogus proof pay the crypto cost.
//!
//! ## Where it sits (the security-critical ordering)
//! Like admission control, this layer wraps the APP routes only (NOT the health routes) and runs
//! OUTSIDE auth — a rate-limited request is rejected (429) before authentication. This is correct AND
//! a security property, but the reasoning is the MIRROR of admission control's, so be explicit:
//!
//! - 🔒 **This layer only REJECTS EARLIER. It NEVER weakens auth/WAC.** A 429 grants strictly LESS
//!   access than the request would otherwise have gotten — it can never turn an unauthorized request
//!   into a success, never grant access, never let through a request the verifier would reject. A
//!   rate-limited request gets 429 and never reaches auth. (Compare [`crate::overload`]'s 503: same
//!   fail-safe-by-construction argument.)
//! - 🔒 **Fail-OPEN stance for the LIMITER ITSELF.** A limiter bug — or the (should-never-happen) case
//!   where [`ConnectInfo`] is absent from the request extensions — must NOT deny all traffic. So when
//!   the peer IP cannot be determined, the request is allowed to PROCEED to the normal auth stack,
//!   which still gates it. **Fail-open here means "proceed to auth, which still gates the request",
//!   NEVER "bypass auth".** The limiter is a cheap front door that can only ever turn a request away
//!   early; it has zero authority to admit one. So failing open costs only the rate-limit protection
//!   for that request, never any authorization guarantee.
//! - **Health/readiness endpoints are EXEMPT.** They are mounted OUTSIDE this layer (see
//!   [`crate::app::build_router_with_overload`]), so they are already exempt. As defence-in-depth, the
//!   middleware ALSO skips `/livez` + `/readyz` by path in case the layer is ever applied more broadly
//!   — a readiness probe must never be rate-limited (rate-limiting a healthy instance's probe would
//!   make a load balancer pull it).
//!
//! ## The bucket (hand-rolled, dependency-free — a deliberate choice)
//! A textbook per-IP **token bucket**: each source IP has a bucket holding up to `burst` tokens that
//! refill at `rate` tokens/second; a request costs one token; an empty bucket ⇒ 429. We hand-roll it
//! rather than pull in `governor` ON PURPOSE: `governor` is the reputable, widely-used standard Rust
//! rate-limiter, but it transitively adds ~15 crates (a second `getrandom 0.3`/`rand 0.9` line,
//! `quanta`, `futures-timer`, `spinning_top`, `web-time`, …) — a meaningful expansion of the
//! audit surface for a SECURITY-CRITICAL layer whose whole job is a ~50-line algorithm. The house rule
//! is a **minimal, audit-small surface** for security-critical paths; a hand-rolled bucket adds ZERO
//! new crates, reuses the SAME `getrandom 0.2` jitter source as [`crate::overload`], and matches its
//! house style (atomics, pure parse cores, exhaustive tests, fail-safe constants) exactly. The state
//! lives in a SHARDED set of `Mutex<HashMap<IpAddr, Bucket>>` so per-IP lock contention is bounded
//! without a concurrent-map dependency; each critical section is tiny (a map lookup + arithmetic, no
//! I/O, no lock held across an `.await`).
//!
//! ## Sizing — the default MUST NOT trip the conformance run or normal use
//! The default per-IP rate is DELIBERATELY GENEROUS (see [`DEFAULT_RATE_PER_IP`] /
//! [`DEFAULT_BURST`]) — high enough that it never sheds a conformance-harness request (the CTH hammers
//! from one IP) or normal use. As belt-and-suspenders, LOOPBACK source IPs are EXEMPT by default (the
//! CTH's socat sidecar forwards from loopback), so the harness cannot trip the limiter regardless of
//! the rate. The rate is env-tunable; a sentinel disables the layer entirely. See the env constants.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderName, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::app::{LIVEZ_PATH, READYZ_PATH};

// --- Env knobs + their testable parse cores -------------------------------------------------------

/// Env var: the per-IP sustained request rate (requests/second/IP) the token bucket refills at.
/// Unset / empty / invalid / `0` ⇒ [`DEFAULT_RATE_PER_IP`]. The sentinel `off` (case-insensitive)
/// DISABLES the rate-limit layer entirely (see [`parse_rate_per_ip`]).
pub const ENV_RATE_PER_IP: &str = "SOLID_SERVER_RATE_LIMIT_PER_IP";

/// Env var: the per-IP burst capacity (the bucket's max token count — how many requests a source may
/// make back-to-back before being throttled to the sustained rate). Unset / empty / invalid / `0` ⇒
/// [`DEFAULT_BURST`].
pub const ENV_BURST: &str = "SOLID_SERVER_RATE_LIMIT_BURST";

/// Env var: the X-Forwarded-For trusted-proxy hop COUNT. Unset / empty / invalid / `0` ⇒ XFF is NOT
/// trusted (the direct peer IP is used — the safe default, since an untrusted XFF is spoofable). A
/// positive integer N ⇒ trust the LAST N hops as our own reverse proxies and take the
/// `(N+1)`-th-from-the-right XFF entry as the client IP (standard XFF semantics). See
/// [`parse_trusted_proxy_hops`] and [`client_ip_from_xff`].
pub const ENV_TRUSTED_PROXY: &str = "SOLID_SERVER_TRUSTED_PROXY";

/// Env var: whether to EXEMPT loopback source IPs from the limit. `0`/`false` disables the exemption;
/// anything else / absent ⇒ exemption ON (the default). Loopback is exempt by default because the
/// conformance harness's socat sidecar forwards from loopback, so a loopback exemption guarantees the
/// CTH is never rate-limited regardless of the configured rate. An operator behind a loopback-bound
/// reverse proxy who relies on XFF should turn this OFF (and configure [`ENV_TRUSTED_PROXY`]).
pub const ENV_EXEMPT_LOOPBACK: &str = "SOLID_SERVER_RATE_LIMIT_EXEMPT_LOOPBACK";

/// The default sustained per-IP rate (requests/second). Chosen DELIBERATELY HIGH so it never trips
/// during normal use OR the conformance run (which, while it hammers from one IP, stays well under
/// this AND is loopback-exempt by default). This is a safety bound against per-source flooding, not a
/// throughput throttle; an operator tunes it down to defend a small box.
pub const DEFAULT_RATE_PER_IP: f64 = 500.0;

/// The default per-IP burst capacity (max tokens). Generous so a legitimate client's bursty traffic
/// (e.g. a page load firing many parallel sub-resource requests) is never throttled, while a sustained
/// flood is still bounded to [`DEFAULT_RATE_PER_IP`]/s after the burst drains.
pub const DEFAULT_BURST: f64 = 2000.0;

/// The base `Retry-After` (seconds) returned on a 429, before jitter — mirrors
/// [`crate::overload::RETRY_AFTER_BASE_SECS`]. Small because a per-IP throttle clears within a second
/// of refill for a well-behaved client.
pub const RETRY_AFTER_BASE_SECS: u64 = 1;
/// The maximum extra jitter (seconds) on top of [`RETRY_AFTER_BASE_SECS`]; the returned value is
/// `base + rand(0..=JITTER)` so throttled clients spread their retries (a thundering-herd guard),
/// mirroring [`crate::overload::RETRY_AFTER_JITTER_SECS`].
pub const RETRY_AFTER_JITTER_SECS: u64 = 4;

/// The number of shards in the per-IP bucket map. A power of two so the shard index is a cheap mask of
/// the IP hash. 64 keeps per-shard lock contention low under realistic peer-IP cardinality while
/// keeping memory trivial. Not security-relevant — purely a contention/throughput knob.
const NUM_SHARDS: usize = 64;

/// The idle TTL after which an untouched bucket is GC'd from its shard, so the map cannot grow without
/// bound under a churn of distinct source IPs (a memory-exhaustion guard). A bucket idle longer than
/// this would have fully refilled anyway, so dropping it loses no throttling state — a returning IP
/// just starts fresh at full burst, which is the correct (most-permissive-to-a-quiet-source) behaviour.
const IDLE_TTL: Duration = Duration::from_secs(600);

/// Resolve the per-IP rate config from the env value into a [`RateConfig`].
/// - the sentinel `off`/`OFF`/`Off`/`disabled` (case-insensitive) ⇒ [`RateConfig::Disabled`]
///   (the layer is not installed — see [`crate::app`]);
/// - absent / empty / non-numeric / `<= 0` ⇒ [`DEFAULT_RATE_PER_IP`] (never silently disable on a typo
///   — disabling requires the explicit `off` sentinel);
/// - a positive number ⇒ that rate.
pub fn rate_per_ip_from_env() -> RateConfig {
    parse_rate_per_ip(std::env::var(ENV_RATE_PER_IP).ok())
}

/// Testable core of [`rate_per_ip_from_env`]. See that fn for the rules.
pub fn parse_rate_per_ip(raw: Option<String>) -> RateConfig {
    match raw.as_deref().map(str::trim) {
        Some(s) if s.eq_ignore_ascii_case("off") || s.eq_ignore_ascii_case("disabled") => {
            RateConfig::Disabled
        }
        None | Some("") => RateConfig::Enabled(DEFAULT_RATE_PER_IP),
        Some(s) => match s.parse::<f64>() {
            Ok(n) if n.is_finite() && n > 0.0 => RateConfig::Enabled(n),
            // non-numeric, NaN/inf, or <= 0 ⇒ the safe default (never silently brick on a typo; a
            // `0` rate would refill nothing and throttle everything — disabling needs the `off` sentinel).
            _ => RateConfig::Enabled(DEFAULT_RATE_PER_IP),
        },
    }
}

/// Resolve the per-IP burst capacity from the env value.
/// - absent / empty / non-numeric / `<= 0` ⇒ [`DEFAULT_BURST`];
/// - a positive number ⇒ that capacity.
pub fn burst_from_env() -> f64 {
    parse_burst(std::env::var(ENV_BURST).ok())
}

/// Testable core of [`burst_from_env`]. See that fn for the rules.
pub fn parse_burst(raw: Option<String>) -> f64 {
    match raw.as_deref().map(str::trim) {
        None | Some("") => DEFAULT_BURST,
        Some(s) => match s.parse::<f64>() {
            Ok(n) if n.is_finite() && n > 0.0 => n,
            _ => DEFAULT_BURST,
        },
    }
}

/// Resolve the trusted-proxy hop count from the env value (see [`ENV_TRUSTED_PROXY`]).
/// - absent / empty / non-numeric / `0` ⇒ `0` (XFF NOT trusted — the safe default);
/// - a positive integer N ⇒ trust N proxy hops.
pub fn trusted_proxy_hops_from_env() -> usize {
    parse_trusted_proxy_hops(std::env::var(ENV_TRUSTED_PROXY).ok())
}

/// Testable core of [`trusted_proxy_hops_from_env`]. See that fn for the rules. A non-numeric or
/// negative value resolves to `0` (do NOT trust XFF) — fail-safe: an XFF misconfig must not silently
/// enable a spoofable bypass.
pub fn parse_trusted_proxy_hops(raw: Option<String>) -> usize {
    match raw.as_deref().map(str::trim) {
        None | Some("") => 0,
        Some(s) => s.parse::<usize>().unwrap_or(0),
    }
}

/// Resolve whether loopback source IPs are exempt (see [`ENV_EXEMPT_LOOPBACK`]).
/// `0`/`false` (case-insensitive) ⇒ NOT exempt; anything else / absent ⇒ exempt (the default).
pub fn exempt_loopback_from_env() -> bool {
    parse_exempt_loopback(std::env::var(ENV_EXEMPT_LOOPBACK).ok())
}

/// Testable core of [`exempt_loopback_from_env`]. See that fn for the rules.
pub fn parse_exempt_loopback(raw: Option<String>) -> bool {
    !matches!(
        raw.as_deref().map(str::trim),
        Some("0") | Some("false") | Some("FALSE") | Some("False") | Some("no") | Some("off")
    )
}

/// The resolved rate config: either ENABLED at a sustained rate or DISABLED entirely.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RateConfig {
    /// The rate-limit layer is installed with this sustained per-IP rate (requests/second).
    Enabled(f64),
    /// The rate-limit layer is NOT installed (the `off` sentinel) — every request proceeds to auth.
    Disabled,
}

// --- The token bucket -----------------------------------------------------------------------------

/// A single source's token bucket. `tokens` is a continuous (fractional) count that refills at
/// `rate`/s up to `capacity`; a request costs one token. `last_refill` timestamps the last update so
/// we can compute the elapsed refill lazily on each access (no background timer). `last_seen` drives
/// idle-bucket GC.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl Bucket {
    fn new(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
            last_seen: now,
        }
    }

    /// Refill lazily by the elapsed time, then try to spend one token. Returns `true` if a token was
    /// available (the request is ALLOWED) and `false` if the bucket was empty (the request is LIMITED).
    fn try_take(&mut self, rate: f64, capacity: f64, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        // Refill, clamped to capacity. `last_refill` advances to `now` regardless so refill is monotone.
        self.tokens = (self.tokens + elapsed * rate).min(capacity);
        self.last_refill = now;
        self.last_seen = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Observability counter: a monotonic total of requests rate-limited (429'd) since boot. A plain
/// atomic so a future `/metrics` exporter can read it lock-free (mirrors [`crate::overload`]).
#[derive(Debug, Default)]
pub struct RateLimitMetrics {
    limited_total: AtomicU64,
}

impl RateLimitMetrics {
    /// Total requests rate-limited (429'd) since boot.
    pub fn limited_total(&self) -> u64 {
        self.limited_total.load(Ordering::Relaxed)
    }
}

/// The shared rate-limiter state: the per-IP token-bucket map (sharded), the rate/burst sizing, the
/// XFF trust + loopback-exemption policy, and the metrics. `Clone` is cheap (`Arc` bumps) so it can be
/// handed to `from_fn_with_state` like [`crate::overload::AdmissionControl`].
#[derive(Clone)]
pub struct RateLimiter {
    shards: Arc<Vec<Mutex<HashMap<IpAddr, Bucket>>>>,
    rate: f64,
    capacity: f64,
    /// Number of trusted reverse-proxy hops in front of us; `0` ⇒ XFF is not trusted (use the peer IP).
    trusted_proxy_hops: usize,
    /// Whether loopback source IPs are exempt from the limit.
    exempt_loopback: bool,
    metrics: Arc<RateLimitMetrics>,
}

impl RateLimiter {
    /// Build a rate limiter. `rate` (tokens/s) and `capacity` (burst) are clamped to a small positive
    /// floor so the type is always safe to construct directly (e.g. in tests); the env parsers already
    /// reject non-positive values, this just makes the constructor total.
    pub fn new(rate: f64, capacity: f64, trusted_proxy_hops: usize, exempt_loopback: bool) -> Self {
        let rate = if rate.is_finite() && rate > 0.0 {
            rate
        } else {
            DEFAULT_RATE_PER_IP
        };
        let capacity = if capacity.is_finite() && capacity >= 1.0 {
            capacity
        } else {
            DEFAULT_BURST
        };
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self {
            shards: Arc::new(shards),
            rate,
            capacity,
            trusted_proxy_hops,
            exempt_loopback,
            metrics: Arc::new(RateLimitMetrics::default()),
        }
    }

    /// The metrics handle (limited counter), e.g. for a `/metrics` exporter.
    pub fn metrics(&self) -> Arc<RateLimitMetrics> {
        self.metrics.clone()
    }

    /// Pick the shard for an IP by a cheap hash (the IP's octet bytes), masked to the shard count.
    fn shard_for(&self, ip: &IpAddr) -> &Mutex<HashMap<IpAddr, Bucket>> {
        // A small FNV-1a over the address bytes — deterministic, fast, and good enough for shard
        // distribution (this is NOT a security boundary; it only spreads lock contention).
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let octets: &[u8] = match ip {
            IpAddr::V4(v4) => &v4.octets()[..],
            IpAddr::V6(v6) => &v6.octets()[..],
        };
        for &b in octets {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let idx = (hash as usize) & (NUM_SHARDS - 1);
        &self.shards[idx]
    }

    /// Try to admit one request from `ip`. `true` ⇒ allowed (a token was available, or the IP is
    /// loopback-exempt); `false` ⇒ rate-limited (the bucket was empty). Also GCs idle buckets in the
    /// touched shard so the map cannot grow without bound under distinct-IP churn.
    fn allow(&self, ip: IpAddr) -> bool {
        // Loopback exemption (belt-and-suspenders for the CTH socat hop). Checked here, not in the
        // middleware, so the exemption is part of the testable core.
        if self.exempt_loopback && ip.is_loopback() {
            return true;
        }
        let now = Instant::now();
        let shard = self.shard_for(&ip);
        // The critical section is tiny — a map lookup + arithmetic, NO I/O and NO `.await` held — so a
        // plain Mutex per shard is fine. A poisoned lock (a panic while held) is recovered via
        // `into_inner` so a single panicking request can never wedge the limiter for an IP shard.
        let mut map = match shard.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let bucket = map
            .entry(ip)
            .or_insert_with(|| Bucket::new(self.capacity, now));
        let allowed = bucket.try_take(self.rate, self.capacity, now);
        // Opportunistic GC of idle buckets in this shard (amortised — only the touched shard, and only
        // when it has grown past a small threshold, so it is O(shard size) at most occasionally).
        if map.len() > 1024 {
            map.retain(|_, b| now.saturating_duration_since(b.last_seen) < IDLE_TTL);
        }
        allowed
    }

    /// Drive one request for `ip` through the limiter for tests (exposes the testable [`allow`] core).
    #[doc(hidden)]
    pub fn allow_for_test(&self, ip: IpAddr) -> bool {
        self.allow(ip)
    }
}

// --- Peer-IP extraction (direct peer + optional trusted XFF) --------------------------------------

/// The HTTP `X-Forwarded-For` header name (lowercase, as stored in the header map).
const XFF: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Resolve the effective CLIENT IP for rate-limiting from the direct peer IP + (only when trusted) the
/// `X-Forwarded-For` header.
///
/// - `trusted_proxy_hops == 0` (the default) ⇒ ALWAYS use the direct `peer` IP and IGNORE any XFF. An
///   untrusted XFF is attacker-controlled and spoofable, so trusting it would let an attacker dodge the
///   per-IP limit by rotating a fake XFF on every request — a bypass. Fail-safe: ignore it by default.
/// - `trusted_proxy_hops == N > 0` ⇒ we sit behind N reverse proxies that each APPEND the IP they saw.
///   The rightmost N entries are then those proxies (incl. our direct one); the client IP is the
///   `(N+1)`-th from the right. If XFF has FEWER than `N` entries (a malformed/short header, or a
///   request that did not actually traverse N proxies), fall back to the direct peer IP — never trust a
///   too-short XFF, which could otherwise be spoofed to inject an arbitrary "client" IP.
pub fn resolve_client_ip(peer: IpAddr, xff: Option<&str>, trusted_proxy_hops: usize) -> IpAddr {
    if trusted_proxy_hops == 0 {
        return peer; // XFF untrusted — direct peer only.
    }
    match xff.and_then(|h| client_ip_from_xff(h, trusted_proxy_hops)) {
        Some(ip) => ip,
        None => peer, // too-short/malformed XFF ⇒ fall back to the direct peer (fail-safe).
    }
}

/// Parse the client IP from an `X-Forwarded-For` value given `trusted_proxy_hops` trusted hops. Returns
/// the `(trusted_proxy_hops + 1)`-th entry from the RIGHT (standard XFF semantics: each proxy appends),
/// or `None` if the header has fewer than `trusted_proxy_hops + 1` valid entries (so the caller falls
/// back to the direct peer IP). Entries that don't parse as an IP are skipped from the right, so a
/// proxy that wrote a junk token can't shift the index.
pub fn client_ip_from_xff(xff: &str, trusted_proxy_hops: usize) -> Option<IpAddr> {
    // Collect the right-to-left sequence of PARSEABLE IPs.
    let ips: Vec<IpAddr> = xff
        .split(',')
        .rev()
        .filter_map(|tok| tok.trim().parse::<IpAddr>().ok())
        .collect();
    // The client is the (trusted_proxy_hops)-th index from the right (0-based): index 0 is our direct
    // proxy, index 1 the one before it, … index `trusted_proxy_hops` is the real client.
    ips.get(trusted_proxy_hops).copied()
}

// --- The 429 response -----------------------------------------------------------------------------

/// Compute the jittered `Retry-After` (seconds) for a 429: `base + rand(0..=jitter)`. Reuses the same
/// OS-RNG (`getrandom 0.2`) jitter approach as [`crate::overload::jittered_retry_after_secs`] — a
/// jitter value needs no cryptographic strength, but reusing the one OS source keeps the surface small.
/// On the (vanishingly unlikely) `getrandom` failure, fall back to no jitter (just `base`) — the 429 is
/// still correct, only the retry spread is lost.
fn jittered_retry_after_secs() -> u64 {
    let mut buf = [0u8; 8];
    let jitter = if getrandom::getrandom(&mut buf).is_ok() {
        u64::from_le_bytes(buf) % (RETRY_AFTER_JITTER_SECS + 1)
    } else {
        0
    };
    RETRY_AFTER_BASE_SECS + jitter
}

/// Build the 429 response: `429 Too Many Requests` + `Retry-After: <jittered seconds>` +
/// `Cache-Control: no-store` + a short plain-text body. Mirrors [`crate::overload`]'s `shed_response`
/// but with 429 (a per-source rate limit) rather than 503 (a global overload). This is a FAIL-SAFE
/// response: it grants strictly less than the request would otherwise have gotten, so it can NEVER be
/// an authorization bypass.
fn rate_limited_response() -> Response {
    let retry_after = jittered_retry_after_secs();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::RETRY_AFTER, retry_after.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        "429 Too Many Requests: per-source rate limit exceeded. Retry after the indicated delay.\n",
    )
        .into_response()
}

// --- The middleware -------------------------------------------------------------------------------

/// The pre-crypto per-IP rate-limit middleware. Sits OUTSIDE auth/WAC/crypto (alongside admission
/// control). For each request it resolves the source IP, charges the source's token bucket, and either
/// LIMITS it (429 + jittered `Retry-After` — the inner stack, incl. the verifier, is NOT run) or lets
/// it PROCEED to the normal auth stack.
///
/// 🔒 Two security invariants (see the module docs):
/// 1. This layer can only REJECT a request early; it has zero authority to admit one. A 429 is strictly
///    less access than auth would grant, so it can never be a bypass.
/// 2. FAIL-OPEN for the limiter: if `ConnectInfo` is absent (should not happen once wired — see
///    `main`), proceed to auth (which still gates the request) rather than denying. "Fail-open" means
///    "proceed to auth", NEVER "bypass auth".
pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    req: Request,
    next: Next,
) -> Response {
    // Defence-in-depth: health probes are EXEMPT. They are already mounted outside this layer (so this
    // path is normally unreachable for them), but skip them by path too in case the layer is ever
    // applied more broadly — a readiness probe must never be rate-limited.
    let path = req.uri().path();
    if path == LIVEZ_PATH || path == READYZ_PATH {
        return next.run(req).await;
    }

    // Resolve the direct peer IP from ConnectInfo. ABSENT ⇒ FAIL OPEN (proceed to auth — which still
    // gates the request — never deny-all on a limiter wiring gap).
    let peer_ip = match req.extensions().get::<ConnectInfo<SocketAddr>>() {
        Some(ConnectInfo(addr)) => addr.ip(),
        None => return next.run(req).await,
    };

    // Only consult XFF when a trusted-proxy count is configured; otherwise the direct peer IP is used
    // (an untrusted XFF is spoofable — see `resolve_client_ip`).
    let xff = req
        .headers()
        .get(&XFF)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let client_ip = resolve_client_ip(peer_ip, xff.as_deref(), limiter.trusted_proxy_hops);

    if limiter.allow(client_ip) {
        next.run(req).await
    } else {
        let limited = limiter
            .metrics
            .limited_total
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        // Log the first 429 and then periodically, so a flood is visible without flooding the log.
        if limited == 1 || limited % 100 == 0 {
            eprintln!(
                "  RATE-LIMIT: per-source limit exceeded — returned 429 (limited_total={limited}, \
                 rate={}/s burst={}). The request never reached auth/crypto.",
                limiter.rate, limiter.capacity
            );
        }
        rate_limited_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // --- env parser tests (mirror overload.rs's pure-core tests) ---

    #[test]
    fn rate_default_on_absent_empty_invalid_or_nonpositive() {
        // Never silently disable on a typo — disabling requires the `off` sentinel.
        assert_eq!(
            parse_rate_per_ip(None),
            RateConfig::Enabled(DEFAULT_RATE_PER_IP)
        );
        assert_eq!(
            parse_rate_per_ip(Some("".into())),
            RateConfig::Enabled(DEFAULT_RATE_PER_IP)
        );
        assert_eq!(
            parse_rate_per_ip(Some("  ".into())),
            RateConfig::Enabled(DEFAULT_RATE_PER_IP)
        );
        assert_eq!(
            parse_rate_per_ip(Some("abc".into())),
            RateConfig::Enabled(DEFAULT_RATE_PER_IP)
        );
        assert_eq!(
            parse_rate_per_ip(Some("0".into())),
            RateConfig::Enabled(DEFAULT_RATE_PER_IP)
        );
        assert_eq!(
            parse_rate_per_ip(Some("-5".into())),
            RateConfig::Enabled(DEFAULT_RATE_PER_IP)
        );
        assert_eq!(
            parse_rate_per_ip(Some("nan".into())),
            RateConfig::Enabled(DEFAULT_RATE_PER_IP)
        );
    }

    #[test]
    fn rate_explicit_positive_is_honoured() {
        assert_eq!(
            parse_rate_per_ip(Some("1".into())),
            RateConfig::Enabled(1.0)
        );
        assert_eq!(
            parse_rate_per_ip(Some("250.5".into())),
            RateConfig::Enabled(250.5)
        );
        assert_eq!(
            parse_rate_per_ip(Some("  4096  ".into())),
            RateConfig::Enabled(4096.0)
        );
    }

    #[test]
    fn rate_off_sentinel_disables() {
        // The ONLY way to disable — and case-insensitive, with a `disabled` alias.
        assert_eq!(parse_rate_per_ip(Some("off".into())), RateConfig::Disabled);
        assert_eq!(parse_rate_per_ip(Some("OFF".into())), RateConfig::Disabled);
        assert_eq!(parse_rate_per_ip(Some("Off".into())), RateConfig::Disabled);
        assert_eq!(
            parse_rate_per_ip(Some("disabled".into())),
            RateConfig::Disabled
        );
    }

    #[test]
    fn burst_rules() {
        assert_eq!(parse_burst(None), DEFAULT_BURST);
        assert_eq!(parse_burst(Some("".into())), DEFAULT_BURST);
        assert_eq!(parse_burst(Some("garbage".into())), DEFAULT_BURST);
        assert_eq!(parse_burst(Some("0".into())), DEFAULT_BURST);
        assert_eq!(parse_burst(Some("-1".into())), DEFAULT_BURST);
        assert_eq!(parse_burst(Some("16".into())), 16.0);
        assert_eq!(parse_burst(Some("  64  ".into())), 64.0);
    }

    #[test]
    fn trusted_proxy_hops_rules() {
        // Default 0 (do NOT trust XFF) on absent/empty/invalid/negative — fail-safe.
        assert_eq!(parse_trusted_proxy_hops(None), 0);
        assert_eq!(parse_trusted_proxy_hops(Some("".into())), 0);
        assert_eq!(parse_trusted_proxy_hops(Some("abc".into())), 0);
        assert_eq!(parse_trusted_proxy_hops(Some("-1".into())), 0);
        assert_eq!(parse_trusted_proxy_hops(Some("0".into())), 0);
        assert_eq!(parse_trusted_proxy_hops(Some("1".into())), 1);
        assert_eq!(parse_trusted_proxy_hops(Some("  2  ".into())), 2);
    }

    #[test]
    fn exempt_loopback_rules() {
        // Default ON; explicit falsey values turn it off.
        assert!(parse_exempt_loopback(None));
        assert!(parse_exempt_loopback(Some("1".into())));
        assert!(parse_exempt_loopback(Some("true".into())));
        assert!(!parse_exempt_loopback(Some("0".into())));
        assert!(!parse_exempt_loopback(Some("false".into())));
        assert!(!parse_exempt_loopback(Some("no".into())));
        assert!(!parse_exempt_loopback(Some("off".into())));
    }

    // --- token-bucket core tests ---

    #[test]
    fn burst_then_throttle_then_refill() {
        // capacity 3, rate "0" effectively (use a tiny rate so refill in the test window is negligible).
        // We exempt-loopback OFF and drive a non-loopback IP.
        let rl = RateLimiter::new(0.0001, 3.0, 0, false);
        let ip = ipv4(203, 0, 113, 7);
        // The first `capacity` requests pass (the burst), the next is limited.
        assert!(rl.allow(ip), "burst 1");
        assert!(rl.allow(ip), "burst 2");
        assert!(rl.allow(ip), "burst 3");
        assert!(!rl.allow(ip), "4th exceeds the burst ⇒ limited");
    }

    #[test]
    fn refill_grants_more_after_wait() {
        // A high rate refills the bucket within a short sleep so a follow-up request passes.
        let rl = RateLimiter::new(1000.0, 1.0, 0, false);
        let ip = ipv4(203, 0, 113, 8);
        assert!(rl.allow(ip), "first token");
        assert!(!rl.allow(ip), "immediately exhausted (capacity 1)");
        std::thread::sleep(Duration::from_millis(20)); // 1000/s ⇒ ~20 tokens refilled, clamp to 1
        assert!(rl.allow(ip), "refilled after the wait");
    }

    #[test]
    fn per_ip_isolation_a_floods_b_unaffected() {
        // MUTATION KILL (per-IP isolation): a shared/global bucket would let A's flood throttle B.
        // capacity 2, negligible refill. A exhausts its bucket; B in the SAME window is unaffected.
        let rl = RateLimiter::new(0.0001, 2.0, 0, false);
        let a = ipv4(198, 51, 100, 1);
        let b = ipv4(198, 51, 100, 2);
        assert!(rl.allow(a), "A 1");
        assert!(rl.allow(a), "A 2");
        assert!(!rl.allow(a), "A is now throttled");
        // B must still have its FULL burst — a shared-bucket mutation would fail these.
        assert!(rl.allow(b), "B 1 unaffected by A's flood");
        assert!(rl.allow(b), "B 2 unaffected by A's flood");
        assert!(
            !rl.allow(b),
            "B then hits its OWN limit (proves B has an independent bucket)"
        );
    }

    #[test]
    fn does_not_trip_at_modest_sequential_rate_under_default() {
        // A modest sequential burst under the DEFAULT config must never be limited (the conformance/
        // normal-use guarantee). DEFAULT_BURST is generous; loopback-exempt is irrelevant here (use a
        // public IP), the burst alone covers it.
        let rl = RateLimiter::new(DEFAULT_RATE_PER_IP, DEFAULT_BURST, 0, false);
        let ip = ipv4(192, 0, 2, 50);
        for i in 0..(DEFAULT_BURST as usize) {
            assert!(
                rl.allow(ip),
                "request {i} under the default burst must pass"
            );
        }
    }

    #[test]
    fn loopback_is_exempt_when_enabled_and_not_when_disabled() {
        // Exempt ON (default): loopback never limited even past a tiny capacity.
        let rl_exempt = RateLimiter::new(0.0001, 1.0, 0, true);
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..10 {
            assert!(rl_exempt.allow(lo), "loopback exempt ⇒ always allowed");
        }
        // Exempt OFF: loopback is subject to the bucket like any IP.
        let rl_strict = RateLimiter::new(0.0001, 1.0, 0, false);
        assert!(rl_strict.allow(lo), "loopback 1 (capacity 1)");
        assert!(
            !rl_strict.allow(lo),
            "loopback IS limited when exemption is off"
        );
    }

    // --- XFF trust tests ---

    #[test]
    fn xff_ignored_by_default_spoof_does_not_dodge_limit() {
        // MUTATION KILL (XFF-spoof bypass): with trusted_proxy_hops=0, the direct peer IP is used and a
        // ROTATING fake XFF must NOT let one peer dodge the per-IP limit. We simulate the middleware's
        // IP resolution: same peer, different spoofed XFF each call ⇒ all map to the SAME peer bucket.
        let peer = ipv4(203, 0, 113, 9);
        let r1 = resolve_client_ip(peer, Some("1.2.3.4"), 0);
        let r2 = resolve_client_ip(peer, Some("5.6.7.8"), 0);
        assert_eq!(r1, peer, "XFF ignored when untrusted ⇒ direct peer");
        assert_eq!(r2, peer, "a rotated XFF still resolves to the same peer");
        // Drive it through a capacity-1 bucket: the second request (spoofing a new XFF) is still limited.
        let rl = RateLimiter::new(0.0001, 1.0, 0, false);
        assert!(rl.allow(r1), "first from the peer");
        assert!(
            !rl.allow(r2),
            "spoofing a new XFF does NOT grant a fresh bucket — same peer is throttled"
        );
    }

    #[test]
    fn xff_used_when_trusted_proxy_configured() {
        // trusted_proxy_hops=1: we trust ONE proxy (the rightmost entry is that proxy; the client is the
        // 2nd-from-right). XFF "client, proxy" ⇒ client = the LEFT entry here.
        let peer = ipv4(10, 0, 0, 1); // our reverse proxy's address (the direct peer)
        let client = resolve_client_ip(peer, Some("198.51.100.5, 10.0.0.1"), 1);
        assert_eq!(
            client,
            ipv4(198, 51, 100, 5),
            "client = (hops+1)-th from right"
        );
        // With two real clients behind the same proxy, each gets its OWN bucket (keyed by client IP).
        let rl = RateLimiter::new(0.0001, 1.0, 1, false);
        let c1 = resolve_client_ip(peer, Some("198.51.100.5, 10.0.0.1"), 1);
        let c2 = resolve_client_ip(peer, Some("198.51.100.6, 10.0.0.1"), 1);
        assert!(rl.allow(c1), "client 1 first");
        assert!(rl.allow(c2), "client 2 unaffected (own bucket)");
        assert!(!rl.allow(c1), "client 1 now limited");
    }

    #[test]
    fn xff_too_short_falls_back_to_peer() {
        // A trusted-1-hop config but an XFF with no client entry (only the proxy, or empty) ⇒ fall back
        // to the direct peer IP, never invent a client (fail-safe).
        let peer = ipv4(10, 0, 0, 1);
        assert_eq!(
            resolve_client_ip(peer, Some("10.0.0.1"), 1),
            peer,
            "only the proxy hop present ⇒ fall back to peer"
        );
        assert_eq!(
            resolve_client_ip(peer, Some(""), 1),
            peer,
            "empty XFF ⇒ fall back to peer"
        );
        assert_eq!(
            resolve_client_ip(peer, None, 1),
            peer,
            "absent XFF ⇒ fall back to peer"
        );
    }

    #[test]
    fn xff_skips_junk_tokens_from_the_right() {
        // A proxy that wrote a junk token must not shift the client index — non-IP tokens are skipped.
        let client = client_ip_from_xff("198.51.100.5, garbage, 10.0.0.1", 1);
        assert_eq!(client, Some(ipv4(198, 51, 100, 5)));
    }

    #[test]
    fn retry_after_within_bounds() {
        for _ in 0..1000 {
            let v = jittered_retry_after_secs();
            assert!(
                (RETRY_AFTER_BASE_SECS..=RETRY_AFTER_BASE_SECS + RETRY_AFTER_JITTER_SECS)
                    .contains(&v),
                "retry-after {v} out of band"
            );
        }
    }

    #[test]
    fn limited_response_is_429_with_retry_after_and_no_store() {
        let resp = rate_limited_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().contains_key(header::RETRY_AFTER),
            "must carry Retry-After"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
}
