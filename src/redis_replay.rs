// AUTHORED-BY Claude Opus 4.8
//! Distributed (shared) DPoP `jti` replay store backed by Redis — the horizontal-scaling enabler.
//!
//! ## Why this exists
//! The verifier's default [`InMemoryReplayStore`](solid_oidc_verifier::replay::InMemoryReplayStore) is
//! **per-instance**: a `jti` consumed on instance A is invisible to instance B, so the moment the
//! server is scaled horizontally behind a load balancer, replay protection silently breaks (a captured
//! DPoP proof can be replayed against a DIFFERENT instance within its freshness window). It also fails
//! CLOSED once its bounded in-memory set reaches capacity — a single-instance safety bound, not a
//! scaling story. A **shared** Redis set fixes both: every instance marks `jti`s in the one set, so a
//! replay is caught no matter which instance the proof first hit.
//!
//! ## Data model — one atomic round-trip, the NX reply IS the New/Replay signal
//! `SET dpop:jti:<jti> 1 NX PX <ttl_ms>`:
//! - `NX` makes the write happen ONLY if the key is absent. Redis replies with the value on a write
//!   (the key was new) and `nil` when the key already existed (a replay). That single reply IS the
//!   atomic check-and-set: `Some(..)` ⇒ [`MarkResult::New`], `nil`/`None` ⇒ [`MarkResult::Replay`].
//!   There is NO `GET`-then-`SET` race — the decision is made server-side in one command.
//! - `PX <ttl_ms>` sets the key's expiry to EXACTLY the `ttl` the verifier passes to `mark()` (the
//!   proof-freshness window). Once the key expires the `jti` is re-markable, mirroring the in-memory
//!   store's lazy-expiry semantics (a genuinely stale proof is independently rejected by the proof's
//!   own `iat` freshness check).
//! - The key is the **FULL** `jti` string (namespaced, never hashed/truncated): a hash collision would
//!   be either a false replay (reject a legitimate proof) or — worse — a missed replay (accept a
//!   captured one). `jti` is short and high-entropy; the full string is the only safe key.
//!
//! ## Fail-closed (non-negotiable)
//! ANY Redis error — pool exhaustion, connect timeout, command timeout, a malformed reply — returns a
//! [`ReplayBackendError`], which the verifier maps to its existing 503 (`replay_fail_closed` defaults
//! true). We NEVER fail open: a fail-open Redis outage would be a GLOBAL replay-protection bypass
//! across the whole fleet. A slow Redis becomes a fast 503, never a worker pile-up (see the timeout).
//!
//! ## Off the async runtime (no worker-blocking)
//! [`ReplayStore::mark`] is a SYNC trait method called directly from inside the async axum handler's
//! Tokio runtime. We must NOT block a Tokio worker on the Redis RTT, and we must NOT call a blocking
//! Redis client from inside the runtime (it would either block a worker or, for an async client,
//! trip "runtime within a runtime"). We mirror the verifier's `net.rs` discipline EXACTLY: a dedicated
//! background OS thread owns an **r2d2 pool of blocking Redis connections** and serves `mark` jobs over
//! a channel; `mark` ships the job and blocks on a plain `std::sync::mpsc` reply (NOT a runtime entry),
//! so it is safe to call from inside the caller's runtime and never parks a Tokio worker on socket I/O.
//! A TIGHT op/connect timeout (default 50 ms) turns a slow/unreachable Redis into a fast 503.

use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use solid_oidc_verifier::replay::{
    InMemoryReplayStore, MarkResult, ReplayBackendError, ReplayStore,
};

/// The Redis key namespace for a DPoP `jti`. The full `jti` is appended verbatim.
const JTI_KEY_PREFIX: &str = "dpop:jti:";

/// Default per-operation SOCKET timeout (50 ms) — the HOT-PATH bound. Applied as the connection's
/// read/write timeout so a slow Redis fails an in-flight `SET` FAST (fail-closed → a quick 503), never
/// a worker pile-up. Tight by design.
pub const DEFAULT_OP_TIMEOUT: Duration = Duration::from_millis(50);

/// Floor for the pool's connection-ACQUISITION timeout (`pool.get()`), which covers TCP connect + the
/// redis handshake + r2d2's own scheduling overhead — a one-off cost paid only when a connection must
/// be established (the warm hot path leases an idle connection ~instantly). It is intentionally MORE
/// generous than [`DEFAULT_OP_TIMEOUT`] (the hot-path socket bound): a 50 ms hot-path bound is right for
/// an in-flight op, but the cold connection-establish + r2d2 scheduling legitimately needs more, so
/// the acquisition timeout is `max(op_timeout * 4, this floor)`. Still bounded, so an UNREACHABLE Redis
/// fails closed within it rather than blocking the worker indefinitely.
const POOL_ACQUIRE_TIMEOUT_FLOOR: Duration = Duration::from_millis(500);

/// The pool connection-acquisition timeout derived from the per-op timeout: comfortably above it (to
/// absorb establish + r2d2 overhead) but still bounded (fail-closed against an unreachable Redis).
fn pool_acquire_timeout(op_timeout: Duration) -> Duration {
    (op_timeout * 4).max(POOL_ACQUIRE_TIMEOUT_FLOOR)
}

/// Number of dedicated Redis worker threads draining the shared job channel CONCURRENTLY (roborev
/// Medium: a single worker serialised all marks, so a slow Redis or bursty auth could queue requests
/// behind one worker far longer than the 50 ms socket timeout, stalling the auth path). With N workers,
/// up to N marks run their `SET NX PX` IN PARALLEL (each on its own pooled connection); the shared
/// `Receiver` mutex is held ONLY for the brief `recv()`, never during the Redis op, so the op
/// concurrency is genuinely N. Each op is still bounded by the tight socket timeout, so a slow Redis
/// degrades to fast 503s rather than a pile-up.
const DEFAULT_WORKERS: usize = 8;

/// r2d2 connection-pool size — one connection per worker so all workers can hold a connection at once
/// (a worker never waits on the pool for a peer's connection). Bounds total Redis connections.
const DEFAULT_POOL_SIZE: u32 = DEFAULT_WORKERS as u32;

/// A `mark` job sent to a Redis worker thread: the `jti`, its TTL, and a reply channel.
type MarkJob = (
    String,
    Duration,
    Sender<Result<MarkResult, ReplayBackendError>>,
);

/// A distributed DPoP-`jti` replay store backed by a shared Redis (`SET NX PX`).
///
/// Construct with [`RedisReplayStore::connect`]. Cloning is cheap (the channel sender is cloneable);
/// every clone shares the one worker thread + pool. Implements [`ReplayStore`] so it drops into the
/// SAME `SharedReplay`/verifier/cache wiring the in-memory store uses (`main.rs` swap only).
pub struct RedisReplayStore {
    /// Ship a `mark` job to the dedicated worker thread. Cloneable + `Send`/`Sync`, used from `&self`.
    tx: Sender<MarkJob>,
}

impl RedisReplayStore {
    /// Connect to Redis at `url` (e.g. `redis://127.0.0.1:6379`) with the [`DEFAULT_OP_TIMEOUT`].
    ///
    /// Builds an r2d2 pool of BLOCKING connections (so the worker threads do ordinary blocking Redis I/O
    /// — never a Tokio runtime), spawns [`DEFAULT_WORKERS`] worker threads that share the pool + a single
    /// job channel (so up to N marks run their `SET NX PX` concurrently), and **eagerly validates one
    /// connection** so a misconfigured/unreachable Redis fails at boot (fail-closed) rather than only on
    /// the first authenticated request.
    pub fn connect(url: &str) -> Result<Self, ReplayBackendError> {
        Self::connect_with_timeout(url, DEFAULT_OP_TIMEOUT)
    }

    /// Connect with an explicit op/connect timeout (the test seam; production uses [`Self::connect`]).
    pub fn connect_with_timeout(
        url: &str,
        op_timeout: Duration,
    ) -> Result<Self, ReplayBackendError> {
        let client = redis::Client::open(url)
            .map_err(|e| ReplayBackendError(format!("redis client open failed: {e}")))?;

        // r2d2 pool of blocking connections. `connection_timeout` bounds how long `pool.get()` waits to
        // establish/lease a connection (TCP connect + redis handshake + r2d2 scheduling) — set to the
        // ACQUISITION timeout (more generous than the hot-path socket op bound, but still bounded so an
        // UNREACHABLE Redis fails CLOSED within it, never blocking the worker forever). The tight 50 ms
        // hot-path bound is applied separately as the per-connection read/write SOCKET timeout (see
        // `apply_timeouts`). `max_size` bounds Redis connections; `min_idle(0)` + `build_unchecked` means
        // connections are created LAZILY on demand (no eager establishment of all `max_size` at build,
        // which would block boot needlessly — we validate connectivity ourselves with one explicit PING
        // in `run_worker`, so boot still fails closed against a dead Redis).
        let pool = r2d2::Pool::builder()
            .max_size(DEFAULT_POOL_SIZE)
            .min_idle(Some(0))
            .connection_timeout(pool_acquire_timeout(op_timeout))
            .build_unchecked(client);

        // The shared job channel: `mark` sends here; the N worker threads drain it concurrently. A std
        // channel (not Tokio): `mark` blocks on the REPLY channel, which is a plain recv (NOT a runtime
        // entry), so calling it from inside the caller's async runtime is safe. `Receiver` is
        // single-consumer, so we share it across workers behind a `Mutex` — held ONLY for the brief
        // `recv()`, never during the Redis op, so the N workers' Redis ops run genuinely in parallel.
        let (tx, rx) = std::sync::mpsc::channel::<MarkJob>();
        let shared_rx = Arc::new(Mutex::new(rx));

        // ONE eager init validation (connect + PING) on the boot thread BEFORE spawning workers, so a
        // misconfigured/unreachable Redis fails synchronously at boot (fail-closed) rather than silently
        // and only at first `mark`. Doing it here (not per-worker) keeps boot a single round-trip.
        validate_connection(&pool, op_timeout)?;

        // Spawn the worker pool. Each worker owns a clone of the pool handle (cheap `Arc`) + the shared
        // receiver, and loops serving marks until the channel closes (all `tx` senders dropped).
        for i in 0..DEFAULT_WORKERS {
            let pool = pool.clone();
            let rx = Arc::clone(&shared_rx);
            std::thread::Builder::new()
                .name(format!("solid-redis-replay-{i}"))
                .spawn(move || run_worker(pool, rx, op_timeout))
                .map_err(|e| {
                    ReplayBackendError(format!("redis replay worker spawn failed: {e}"))
                })?;
        }

        Ok(Self { tx })
    }
}

impl Clone for RedisReplayStore {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl ReplayStore for RedisReplayStore {
    fn mark(&self, jti: &str, ttl: Duration) -> Result<MarkResult, ReplayBackendError> {
        // A non-positive TTL means the proof is already past its freshness window: mirror the in-memory
        // store and treat it as fresh WITHOUT touching Redis (the proof's own `iat` check rejects it
        // independently; a `PX 0` would be a malformed Redis command anyway).
        if ttl <= Duration::ZERO {
            return Ok(MarkResult::New);
        }

        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        // Ship the job to the dedicated worker. A send error means the worker thread is gone — fail
        // CLOSED (never silently accept the proof because the backend is unavailable).
        self.tx
            .send((jti.to_string(), ttl, reply_tx))
            .map_err(|_| ReplayBackendError("redis replay worker is not available".to_string()))?;

        // Block on the reply (a plain channel recv — NOT a Tokio runtime entry, so safe inside the
        // caller's async runtime). The Redis RTT happens on the worker thread, never on this one. A
        // dropped reply (worker died mid-op) fails CLOSED.
        reply_rx.recv().map_err(|_| {
            ReplayBackendError("redis replay worker dropped the request".to_string())
        })?
    }
}

/// Eagerly validate ONE connection (lease + bounded PING) so an unreachable/misconfigured Redis fails
/// CLOSED at boot rather than only on the first authenticated request. Called once on the boot thread
/// before the workers spawn.
fn validate_connection(
    pool: &r2d2::Pool<redis::Client>,
    op_timeout: Duration,
) -> Result<(), ReplayBackendError> {
    let mut conn = pool
        .get()
        .map_err(|e| ReplayBackendError(format!("redis pool connect failed at init: {e}")))?;
    apply_timeouts(&mut conn, op_timeout)
        .map_err(|e| ReplayBackendError(format!("redis connection timeout setup failed: {e}")))?;
    redis::cmd("PING")
        .query::<()>(&mut *conn)
        .map_err(|e| ReplayBackendError(format!("redis PING failed at init: {e}")))
}

/// A worker thread's loop: drain the SHARED job channel and serve each `mark` as one `SET NX PX`
/// round-trip on a pooled connection, until the channel closes (all senders dropped). The receiver
/// mutex is held ONLY for the brief `recv()` — NOT during the Redis op — so N workers' Redis ops run
/// genuinely in parallel (no head-of-line blocking behind a slow op). All blocking Redis I/O happens
/// HERE, off the Tokio runtime. A requester that has gone away just drops the result.
fn run_worker(
    pool: r2d2::Pool<redis::Client>,
    rx: Arc<Mutex<Receiver<MarkJob>>>,
    op_timeout: Duration,
) {
    loop {
        // Lock ONLY to pull the next job, then release BEFORE the Redis op so peers can pull theirs and
        // run concurrently. A poisoned mutex (a peer worker panicked mid-`recv`) ends this worker (the
        // others, and boot-time validation, keep the fail-closed contract). `recv()` returns `Err` when
        // the channel is closed (the store dropped) → the worker exits cleanly.
        let job = match rx.lock() {
            Ok(guard) => guard.recv(),
            Err(_) => return,
        };
        match job {
            Ok((jti, ttl, reply)) => {
                let _ = reply.send(mark_one(&pool, &jti, ttl, op_timeout));
            }
            Err(_) => return, // channel closed: store dropped, no more work.
        }
    }
}

/// Perform ONE atomic `SET dpop:jti:<jti> 1 NX PX <ttl_ms>` on a pooled blocking connection.
///
/// The `NX` reply is the New/Replay signal in a single round-trip: a non-nil reply ⇒ the key was set
/// (NEW), a `nil` reply ⇒ the key already existed (REPLAY). Any pool/connection/command error returns
/// a [`ReplayBackendError`] (fail-closed). The full `jti` is the key (namespaced, never hashed).
fn mark_one(
    pool: &r2d2::Pool<redis::Client>,
    jti: &str,
    ttl: Duration,
    op_timeout: Duration,
) -> Result<MarkResult, ReplayBackendError> {
    // Get a pooled connection. Pool exhaustion / connect failure within `connection_timeout` ⇒ error
    // ⇒ fail-closed.
    let mut conn = pool
        .get()
        .map_err(|e| ReplayBackendError(format!("redis pool get failed: {e}")))?;

    // Apply the read/write socket timeouts so a hung Redis can't wedge the worker — a slow op errors
    // out within the timeout and fails closed.
    apply_timeouts(&mut conn, op_timeout)
        .map_err(|e| ReplayBackendError(format!("redis connection timeout setup failed: {e}")))?;

    let key = format!("{JTI_KEY_PREFIX}{jti}");
    // PX millisecond expiry = EXACTLY the ttl the verifier passed. Round UP to >=1 ms so a sub-ms but
    // positive ttl never collapses to `PX 0` (which Redis rejects) — it always sets a real expiry.
    let ttl_ms = ttl_millis_at_least_one(ttl);

    // `SET key 1 NX PX <ms>` — the value `1` is a placeholder (presence is all that matters). Typed as
    // `Option<String>`: `Some(_)` ⇒ the SET happened (key was absent) ⇒ NEW; `None` (nil) ⇒ the key
    // already existed ⇒ REPLAY. This is the whole atomic check-and-set, server-side, race-free.
    let set: redis::RedisResult<Option<String>> = redis::cmd("SET")
        .arg(&key)
        .arg(1)
        .arg("NX")
        .arg("PX")
        .arg(ttl_ms)
        .query(&mut *conn);

    match set {
        Ok(Some(_)) => Ok(MarkResult::New),
        Ok(None) => Ok(MarkResult::Replay),
        Err(e) => Err(ReplayBackendError(format!("redis SET NX failed: {e}"))),
    }
}

/// Convert a positive `ttl` to whole milliseconds, clamped to AT LEAST 1 (so a sub-millisecond but
/// positive ttl never produces `PX 0`, which Redis rejects) and saturated to `u64::MAX` on overflow.
/// `mark` already returned early for a non-positive ttl, so this only ever sees `ttl > 0`.
fn ttl_millis_at_least_one(ttl: Duration) -> u64 {
    let ms = ttl.as_millis();
    if ms == 0 {
        1
    } else {
        u64::try_from(ms).unwrap_or(u64::MAX)
    }
}

/// Apply the op timeout as the connection's read + write socket timeouts, so a hung Redis fails the op
/// within the bound (fail-closed) instead of blocking the worker thread indefinitely.
fn apply_timeouts(conn: &mut redis::Connection, op_timeout: Duration) -> redis::RedisResult<()> {
    conn.set_read_timeout(Some(op_timeout))?;
    conn.set_write_timeout(Some(op_timeout))?;
    Ok(())
}

/// A single concrete [`ReplayStore`] type that dispatches to EITHER the verifier's per-instance
/// in-memory store OR the distributed [`RedisReplayStore`], decided at boot from config.
///
/// This is the seam that lets `main.rs` keep ONE monomorphised replay type (`SharedReplay<BackendReplay>`)
/// regardless of backend — the verifier, the token cache, the `AppState`, and `build_router` are all
/// generic over `R: ReplayStore`, so a single concrete `R` keeps the whole wiring unchanged. The
/// in-memory arm is byte-for-byte the existing behaviour (it forwards verbatim to `InMemoryReplayStore`),
/// so the DEFAULT (no Redis URL) path — and thus conformance — is unchanged; only the `mark` call gains
/// one cheap enum match. The Redis arm is selected ONLY when an operator sets the Redis URL.
pub enum BackendReplay {
    /// The default per-instance store (single-node v1). Unchanged behaviour; the default path.
    InMemory(InMemoryReplayStore),
    /// The shared, distributed Redis store (`SET NX PX`) — the horizontal-scaling backend.
    Redis(RedisReplayStore),
}

impl ReplayStore for BackendReplay {
    fn mark(&self, jti: &str, ttl: Duration) -> Result<MarkResult, ReplayBackendError> {
        match self {
            BackendReplay::InMemory(s) => s.mark(jti, ttl),
            BackendReplay::Redis(s) => s.mark(jti, ttl),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_millis_clamps_to_at_least_one() {
        // A sub-millisecond positive ttl must not collapse to PX 0.
        assert_eq!(ttl_millis_at_least_one(Duration::from_nanos(1)), 1);
        assert_eq!(ttl_millis_at_least_one(Duration::from_micros(500)), 1);
        // A whole-millisecond ttl passes through.
        assert_eq!(ttl_millis_at_least_one(Duration::from_millis(1)), 1);
        assert_eq!(ttl_millis_at_least_one(Duration::from_millis(250)), 250);
        assert_eq!(
            ttl_millis_at_least_one(Duration::from_secs(330)),
            330_000_u64
        );
    }

    #[test]
    fn key_uses_full_jti_namespaced() {
        // Document the keying contract: full jti, never hashed/truncated.
        let jti = "abc.def-GHI_123~unusual";
        assert_eq!(
            format!("{JTI_KEY_PREFIX}{jti}"),
            "dpop:jti:abc.def-GHI_123~unusual"
        );
    }

    #[test]
    fn connect_to_unreachable_redis_fails_closed() {
        // An unreachable Redis must fail at CONNECT (fail-closed), not silently succeed. Port 1 is
        // reserved/unused; the tight timeout makes this fast. (No live Redis needed for this assertion.)
        let res = RedisReplayStore::connect_with_timeout(
            "redis://127.0.0.1:1",
            Duration::from_millis(50),
        );
        assert!(
            res.is_err(),
            "connecting to an unreachable Redis must fail closed, got Ok"
        );
    }

    #[test]
    fn backend_replay_inmemory_arm_forwards_verbatim() {
        // The `BackendReplay::InMemory` arm must behave EXACTLY like the underlying in-memory store:
        // first mark of a jti ⇒ New, a second within the window ⇒ Replay. This is what guarantees the
        // default (no-Redis) path — and thus conformance — is unchanged by introducing the enum.
        let store =
            BackendReplay::InMemory(InMemoryReplayStore::with_window(Duration::from_secs(60)));
        let ttl = Duration::from_secs(60);
        assert_eq!(store.mark("jti-A", ttl).unwrap(), MarkResult::New);
        assert_eq!(
            store.mark("jti-A", ttl).unwrap(),
            MarkResult::Replay,
            "a repeated jti within its window must be reported as a replay"
        );
        assert_eq!(
            store.mark("jti-B", ttl).unwrap(),
            MarkResult::New,
            "a distinct jti must be fresh"
        );
    }
}
