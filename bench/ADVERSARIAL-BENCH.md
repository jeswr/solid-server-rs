# Adversarial benchmark suite

> EXPERIMENTAL solid-server-rs. This suite validates that the server's **protections hold under load**
> and measures the (advisory) timing side-channels the PSS charter's perf-gate note flags. It runs
> against the in-memory test-double backends (no docker) with the production auth posture (verified-
> token cache ON).

## Two halves

1. **Strict invariants — `tests/adversarial_invariants.rs` (`cargo test --test adversarial_invariants`).**
   Deterministic pass/fail security assertions over the full router. These **gate** (they run in
   `cargo test`). No timing, no wall-clock — every assertion is a reproducible status comparison.
2. **Under-load measurement — `examples/adversarial_bench.rs`.** Drives the same arms as concurrent
   hostile traffic and emits a JSON report whose `deterministic.invariant_holds` flags are strict and
   whose `timing_advisory` blocks are ADVISORY. The example **exits non-zero** if any invariant fails
   under load.

## Arms

| arm | strict invariant (deterministic) | advisory measurement |
|---|---|---|
| `existence_nondisclosure` | a foreign authenticated reader gets the **same** denial status for an existing-forbidden vs a non-existent resource (existence not disclosed) and is **never** served a 200 | the two paths' median-latency ratio (a gross divergence ⇒ timing side-channel) |
| `replay_storm` | the same DPoP proof (fixed `jti`) replayed ⇒ **at most one** accept, the rest 401 | reject latency |
| `jti_churn` | many fresh `jti`s against one token ⇒ all accepted (the replay store never false-rejects) | per-op latency as the store grows |
| `cache_bust` | a distinct valid token per request (every request a cache **miss**) still correctly authorizes; a forged-issuer token is still rejected | hit-vs-miss throughput ratio — the amplification the pre-crypto rate-limiter defends (per-verify cost is **measured**, not hard-coded) |
| `bogus_proof` / `bogus_token` | garbage credentials ⇒ **never** a 200 | reject latency |
| `post_attack_invariants` | after the flood, re-exec WAC on the **live** server: the owner is still authorized, the foreign reader still denied (the attack corrupted nothing) | — |

## Running

```bash
bench/run-adversarial.sh                                    # strict tests + a default under-load run
bench/run-adversarial.sh --requests 1000 --concurrency 64
cargo test --test adversarial_invariants                    # just the gating invariants
cargo run --release --example adversarial_bench -- --requests 500 --concurrency 32 --out path.json
```

## Output

A JSON report (default `bench/results/adversarial/adversarial-report.json`, gitignored) with a
top-level `all_invariants_hold` boolean and one object per arm:

```
{ harness, generated_unix, build_profile, driver, notes, all_invariants_hold,
  arms: [ { name, description,
            deterministic: { mode:"deterministic", …arm-specific counts…, invariant_holds },
            timing_advisory: { mode:"timing_advisory", disclaimer, …percentiles/ratios… } } ] }
```

**No performance numbers are committed to markdown** — read the generated JSON. The per-verify cost
that the `cache_bust` amplification is measured against comes from the deterministic
`examples/auth_hotpath_microbench` (the component-by-component crypto/parse budget), never a
hard-coded figure.

## Not (yet) covered — follow-ups

The following adversarial surfaces need a real bound listener (TLS/HTTP-2 frames) or exceed what the
in-memory doubles express, so they are **not** in this in-process suite:

- Raw HTTP/2 frame floods (rapid-reset / MadeYouReset / SETTINGS-PING / CONTINUATION / HPACK /
  0-window / blended multiplex). The frame-level rapid-reset attack is already regression-tested in
  `tests/transport_dos.rs`; a broader `adversarial_h2` example (behind an `adversarial-h2` feature,
  driving the `h2` crate against the axum-server HTTPS listener) is a follow-up.
- Slowloris / slow-body / slow-TLS clients (`slow_client`) — needs the real socket path.
- The victim-survival closed-loop triplet (measuring a legitimate client's success rate WHILE the
  attack runs against a live listener).

These are tracked against the same bead as this suite.
