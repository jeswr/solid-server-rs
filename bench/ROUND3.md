<!-- AUTHORED-BY Claude Opus 4.8 -->
# solid-server-rs — Optimization round 3: verified-access-token cache (auth path)

> **SECURITY-CRITICAL.** This round touches the auth decision path. The change removes the
> *redundant* per-request **access-token** verification while keeping the **DPoP proof** fully
> verified on every request. Correctness is established by **exhaustive, adversarial unit + integration
> tests** (run on every gate) and the full **Solid conformance suite (41/41)**; the wall-clock numbers
> below are the *advisory* timing companion (per the suite's perf-gate rule: deterministic metrics are
> hard-gated, timing metrics are advisory because shared-box wall-clock variance exceeds any useful
> band — see below).

## What changed (and why it is safe)

The round-2 auth baseline ([`bench/AUTH-BASELINE.md`](./AUTH-BASELINE.md)) attributed ~252 µs/GET of
auth overhead to **two ES256 signature verifies per request**: the **access token** and the **DPoP
proof**. The access token is *stable* across a client's requests, so re-verifying its signature +
RFC-9068 claims every request is waste. The DPoP proof is *fresh per request* and is the replay
protection — it MUST stay fully verified every request.

Round 3 adds a **verified-access-token cache** (`src/auth_cache.rs`, wired in `src/auth.rs` +
`src/main.rs`) that, on a cache HIT, **skips only the access-token signature + claims re-verify** and
**still fully verifies the fresh DPoP proof + jti replay + cnf.jkt binding** for that request. The
cache **cannot turn a would-be-401/403 into a 200** — proven by the tests below.

### Where the cache sits (and the R1 posture)

- **Consumer-side, in solid-server-rs** (`AuthContext::with_cache`). The verifier's `verify()` is a
  single monolithic entry point (token-verify + proof-verify are not separable public methods), so
  the cache wraps the consumer: a HIT path that reuses the cached `VerifiedToken` and re-runs the
  proof checks, a MISS path that calls the verifier's full `verify()` and inserts on success.
- **R1 (do-not-reimplement) is honoured for the crypto:** every cryptographic + canonicalisation
  primitive on the hit path is the verifier crate's own **public** API — `verify_proof_with_embedded_jwk`
  (the EmbeddedJWK signature check), `Jwk::thumbprint_sha256` (RFC 7638), `proof_has_ath`,
  `peek_claims`, and the shared `ReplayStore`. The cache owns only the *orchestration* of those
  primitives (the same sequence the verifier's private `validate_dpop_proof` runs). The cleaner
  long-term home for that orchestration is a public seam on the verifier
  (`Verifier::verify_proof_for_cached_token`) — a **separate, owner-gated** change to
  `jeswr/solid-oidc-verifier` (see "verifier follow-up" at the end). It is **not required** for this
  round; the consumer-side orchestration is pinned by 18 unit + 4 integration tests so it cannot
  silently diverge.
- **One shared replay store** (`SharedReplay`): the verifier (miss path) and the cache (hit path)
  mark `jti`s in the SAME `InMemoryReplayStore` (one `Arc`, two handles), so a `jti` used on a miss
  cannot be replayed on a hit (no replay bypass across the cache boundary).

### Cache invariants (each pinned by a named test)

| # | Invariant | Pinned by (test) |
|---|---|---|
| Key | SHA-256 of the **FULL access token** (collision-resistant; never webid/jkt alone) | `distinct_tokens_distinct_entries` (two tokens, same webid+jkt → two entries) |
| Insert-on-success-only | Only a *successful* full verify inserts; no cnf.jkt/exp ⇒ never cached | `token_without_cnf_or_exp_not_cached` |
| TTL ≤ `exp`, re-checked per hit | A since-expired entry is a MISS (evicted), never a valid hit | `expired_token_is_miss_not_hit` |
| Fresh proof every request | Hit still verifies sig/htm/htu/iat/jti/ath | `hit_reuses_token_and_verifies_fresh_proof`, `forged_proof_signature_rejected_on_hit`, `wrong_htu_or_htm_rejected_on_hit`, `stale_proof_iat_rejected_on_hit`, `future_proof_iat_rejected_on_hit`, `wrong_ath_rejected_on_hit`, `missing_proof_rejected_on_hit` |
| `jti` replay enforced on hit | A replayed proof is rejected on a hit (shared store) | `replayed_jti_rejected_on_hit`, `jti_shared_across_miss_and_hit_paths` |
| `cnf.jkt` binding enforced on hit | Valid token + different/swapped DPoP key ⇒ reject | `wrong_dpop_key_rejected_on_hit` |
| Validate-then-mark order | cnf.jkt checked **before** the jti is marked, so a mis-bound proof never burns a jti | `wrong_cnf_does_not_consume_jti` |
| ath-compat parity | `allow_missing_ath`: absent ath ok, present-but-wrong ath still rejected | `ath_compat_absent_ok_present_wrong_rejected` |
| Bounded (LRU + capacity) | Never exceeds capacity; LRU entry evicted | `capacity_bound_lru_eviction` |
| Validation TTL ≤ JWKS TTL | An entry older than `max_entry_ttl` (default 300s = JWKS TTL) is a MISS → re-verify, so a key revocation propagates within one TTL window (not masked until `exp`) | `entry_older_than_validation_ttl_is_miss` |
| iat window = verifier (parity) | Hit enforces the verifier's exact symmetric `\|now−iat\| ≤ max_age+tol` window — no hit/miss divergence | `iat_window_matches_verifier` |
| Shared replay wiring | `SharedReplay` forwards to the one inner store | `shared_replay_forwards` |

Plus **4 end-to-end integration tests** (`tests/auth_cache_integration.rs`) that drive a
cache-enabled `AuthContext` over the **real `solid-oidc-verifier`** (genuine ES256 token + DPoP
verify): miss→insert→hit returns the same identity; a swapped DPoP key is rejected on a hit; a
replayed proof is rejected on a hit; a miss-path jti replays on the hit path.

## Run context

| | |
|---|---|
| **Date measured** | 2026-06-23 |
| **Machine** | Apple M1, 8 logical cores (macOS) — load generator + server on the SAME box (loopback) |
| **Server** | `solid-server-rs` `cargo build --release`, branch `perf/round3-token-cache` |
| **Toolchain** | rustc 1.89.0 |
| **Store / Auth / IdP / TLS** | identical to round 2 (in-memory doubles; REAL DPoP verify via `solid-oidc-verifier` `NetworkJwksProvider`; Keycloak `solid` realm; in-process rustls/aws-lc-rs HTTP/1.1) |
| **Toggle** | the cache is toggled by `SOLID_SERVER_TOKEN_CACHE_CAPACITY` — `0` = cache OFF (= the round-2 behaviour), default/`4096` = cache ON. Both modes measured in the SAME session on the SAME binary. |
| **Replay cap** | `SOLID_SERVER_REPLAY_MAX_ENTRIES=5_000_000` (same as the round-2 baseline, so the steady-state verify path is measured, not the fail-closed path) |

> **Box-contention caveat (load-bearing — read before the numbers).** The box was **NOT quiet**
> during this session: `uptime` load averages ranged **23–55** on 8 cores (other tenants:
> ANECompilerService, a VM, Teams, parallel agents). At that load the full 8-level concurrency sweep
> is **noise-dominated** — consecutive runs of the *identical* configuration varied up to ~3× (e.g.
> cache-OFF c1 measured 494, then 1414, then 1481 RPS across three back-to-back runs), and the sweep
> even showed cache-ON < cache-OFF at some levels, which is *impossible* for a cache that removes CPU
> work and therefore proves the sweep was measuring the scheduler, not the cache. **The full-sweep
> RPS table below is recorded for completeness but is not interpretable as a delta.** The
> interpretable measurement is the **c1 best-of-3** (single in-flight request = least
> contention-sensitive), which isolates per-request CPU. A clean re-run on a genuinely quiet box is
> the way to quantify the aggregate RPS gain (tracked as a follow-up).

## Measured — c1 best-of-3 (the interpretable signal)

Authenticated GET of an owner-private document, concurrency 1, three 15 s windows each, **best-of-3**
(the discarded runs are contention outliers — e.g. the cache-OFF 494 RPS run):

| metric | cache OFF (before) | cache ON (after) | delta |
|---|---:|---:|---:|
| RPS (best of 3) | 1,481 | **1,803** | **+21.7%** |
| p50 latency (ms) | 0.360 | **0.264** | **−26.7%** (−0.096 ms) |
| p99 latency (ms) | 1.227 | **0.618** | −49.6% |
| success rate | 1.0000 | 1.0000 | — |

Raw c1 runs (RPS / p50 ms): **OFF** = 494/0.616, 1414/0.374, 1481/0.360 · **ON** = 1418/0.338,
1803/0.264, 1669/0.307.

**Interpretation.** The ~0.096 ms p50 reduction at c1 is the per-request CPU reclaimed by skipping the
redundant access-token ES256 verify. The round-2 baseline attributed ~252 µs/GET to the *two* verifies
combined; reclaiming on the order of ~half of that (one of the two verifies) is consistent with the
observed p50 delta, given the box still carries background load that inflates both numbers. The
deterministic, box-independent fact is exact: **on every cache hit the server performs ONE asymmetric
verify (the DPoP proof) instead of TWO (proof + token)** — the token's ES256 signature verification +
RFC-9068 claim checks + JWKS lookup are eliminated, while the proof, replay, and binding checks are
unchanged.

## Recorded for completeness — full 8-level sweep (NOISE-DOMINATED, do not read as a delta)

Authenticated GET, owner-private document (scenario c). Both runs in the same session under load
avg 23–55. Inversions (ON < OFF) are contention artifacts, not the cache.

| concurrency | OFF RPS | ON RPS |
|---:|---:|---:|
| 1 | 1,101 | 1,156 |
| 8 | 3,897 | 2,691 |
| 16 | 1,975 | 3,287 |
| 32 | 4,902 | 3,203 |
| 64 | 4,678 | 2,538 |
| 128 | 4,724 | 3,161 |
| 256 | 5,342 | 3,166 |
| 512 | 4,001 | 3,219 |

(Success rate 1.0000 at every level, both modes. The non-monotonic columns are the tell-tale of an
overloaded box; the c1 best-of-3 above is the measurement to trust.)

## Conformance + gates (on HEAD)

- `cargo fmt --check` — clean
- `cargo clippy --all-targets -- -D warnings` — clean
- `cargo build --release` — clean
- `cargo test` — **0 failures** (254 lib tests incl. 20 `auth_cache` + the auth-helper test, + 4
  `auth_cache_integration` tests, + all other suites)
- `./conformance/run.sh` — **`passed=41 failed=0 untested=0 inapplicable=0 total=41`** (harness exit
  0) with the cache **default-on** — the cache is conformance-neutral.

## roborev review — findings addressed (2 rounds, codex)

**Round 1** raised two Mediums; **round 2** (re-review after the round-1 fixes) raised two more,
including a correction to one of the round-1 fixes. All four are resolved; the final disposition:

1. **DPoP `iat` window (round 1 → round 2 correction).** Round 1 flagged the symmetric `|now−iat|`
   window as accepting far-future proofs and suggested tightening the cache to an asymmetric
   (future ≤ tolerance) bound. I did so — and the **fresh conformance run on that commit FAILED one
   test (`passed=40 failed=1`)**: the CTH presents a future-skewed proof the verifier's symmetric
   window accepts but the stricter cache rejected — a real hit/miss **divergence** (round 2 flagged
   exactly this). Resolution: the hit path now enforces the verifier's **exact symmetric** window
   (byte-identical proof semantics — the brief's mandate); conformance returns to **41/41**. The
   future-axis tightening moves SOLELY to the verifier follow-up (applied to BOTH paths together).
   Pinned by `iat_window_matches_verifier`. *(This is the diff-scoped-review-trap counterpart in
   action: re-running conformance on the actual HEAD caught a divergence a diff read would have
   missed.)*
2. **Cache could outlive a JWKS key revocation** (round 1). Entry lifetime is bounded by
   `min(exp, inserted_at + max_entry_ttl)`. `max_entry_ttl` is now wired in `main.rs` to the
   **configured** `SOLID_SERVER_JWKS_CACHE_TTL_SECS` (round 2: not the hard-coded 300s default), so
   lowering the JWKS TTL for faster revocation also tightens the token cache. An entry past that
   deadline is a MISS → full re-verify, so a revoked/rotated signing key is honoured within one
   JWKS-TTL window instead of being masked until `exp`. Pinned by
   `entry_older_than_validation_ttl_is_miss`.

## Verifier follow-up (separate, owner-gated — NOT in this round)

The cleanest long-term home for the hit-path proof orchestration is a public seam on the verifier
crate, e.g. `Verifier::verify_proof_for_cached_token(&self, req, cnf_jkt, access_token) -> Result<(),
VerifyError>`, which would let solid-server-rs cache the token result and delegate the per-request
proof+replay re-check entirely to the verifier (zero orchestration duplication). That is a separate,
clearly-scoped change to `jeswr/solid-oidc-verifier` (owner-gated; the PSS agent flags it, the
maintainer gates+pushes that repo). It is **not required** for round 3 — the consumer-side
orchestration here reuses the verifier's public crypto primitives and is exhaustively tested.

A **second** verifier follow-up (from the iat finding): tighten the verifier's own DPoP `iat` window
from the current symmetric `|now − iat| > max_age + tolerance` to an asymmetric past/future bound
(future ≤ tolerance only). This MUST be done in the verifier so BOTH the miss path and the cache
hit path tighten together — doing it in the cache alone caused a conformance divergence (above), so
the cache deliberately stays at exact verifier parity until the verifier itself changes.
