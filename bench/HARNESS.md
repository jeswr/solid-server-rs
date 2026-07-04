# Local performance benchmark harness (`bench_harness`)

> EXPERIMENTAL solid-server-rs. This harness measures the server's hot paths against **in-memory
> test-double backends** — no docker, Keycloak, S3, or SPARQ required — so it runs anywhere `cargo`
> does and is fully reproducible.

## What it does

`examples/bench_harness.rs` boots the assembled router (`build_router`) over the in-memory doubles
(`InMemorySparqClient` + `InMemoryBlobStore`) with the **production auth posture** (the verified-token
cache is ON), seeds a small fixture set, then drives concurrent load over each hot path through the
**full request stack** (DPoP auth verify → WAC ACL resolve → store → content handling), via an
in-process `tower::Service` `oneshot` driver. Client-side ES256 proof signing happens **outside** the
timed window (requests are pre-built and pre-signed), so the timing reflects the **server**, not the
load client's crypto.

## The deterministic-vs-advisory split (PSS charter perf-gate rule)

Every metric block in the JSON report carries a `mode`:

- **`"deterministic"` — strict / comparable.** Reproducible integer counts: HTTP `status`,
  `response_bytes`, and — via a counting `#[global_allocator]` — `alloc_count_per_op` +
  `alloc_bytes_per_op` for **one** request measured in isolation on a single-threaded runtime (the
  minimum over N warm iterations — the stable allocation floor). These are the metrics a future perf
  gate may hard-compare against a committed best-ever floor.
- **`"timing_advisory"` — ADVISORY, never a merge gate.** Wall-clock-derived throughput (req/s) and
  p50/p90/p99/p999/max latency under concurrency. Shared-runner wall-clock variance exceeds any useful
  band even best-of-N, so these are measured, reported, and tracked — but a timing-only change can
  **never** block a merge. Every timing block repeats this in its `disclaimer` field.

## Scenarios (the hot paths)

| scenario | path exercised |
|---|---|
| `authed_get_cached` | DPoP-authed GET of a small private resource; verified-token cache **HIT** (steady state — token sig not re-verified, fresh proof + jti + `cnf.jkt` are) |
| `authed_get_cold` | same, DISTINCT access token per request — cache **MISS** (full token verify each time) |
| `public_get` | anonymous GET of a public resource — the pre-crypto public-read fast path |
| `container_listing` | authed GET of a container with children (the `ldp:contains` listing) |
| `put_create` | authed PUT creating a fresh resource at a unique path (201) |
| `conditional_put_412` | authed PUT with `If-None-Match: *` on an existing resource → 412 (write-path precondition; non-mutating, race-free) |

> Note: the plan's "conditional GET → 304" is **not** a scenario, because this server applies
> conditional preconditions to **mutations only** — a GET carrying `If-None-Match` is not turned into
> a 304 (see `src/ldp/conditional.rs`). Benchmarking a "304" that actually returns 200 would be
> dishonest; the GET-conditional-304 optimization is a genuine server gap tracked as a follow-up.

## Running

```bash
bench/run-bench.sh                                  # defaults: requests=600, concurrencies=1,8,32,64
bench/run-bench.sh --requests 2000 --concurrencies 1,16,64,128
cargo run --release --example bench_harness -- --requests 600 --concurrencies 1,8,32 --out path.json
```

Always build `--release`; timing is meaningless in a debug build (the harness prints a warning and the
report's `build_profile` records which was used — the deterministic block is still valid in debug).

## Output

A machine-readable JSON report (default `bench/results/harness/bench-report.json`, gitignored —
regenerate on demand). Its shape:

```
{ harness, generated_unix, build_profile, driver, notes,
  scenarios: [ { name, description,
                 deterministic: { mode:"deterministic", status, response_bytes,
                                  alloc_count_per_op, alloc_bytes_per_op },
                 timing_advisory: { mode:"timing_advisory", disclaimer,
                                    levels: [ { concurrency, requests, errors, success_rate,
                                                throughput_rps, latency_us:{p50,p90,p99,p999,max} } ] } } ] }
```

**No performance numbers are committed to markdown** (charter: no hard-coded perf numbers) — read the
generated JSON. To compare rounds, diff two reports' `deterministic` blocks (strict) and treat the
`timing_advisory` blocks as directional only.

## Scope / caveats

- The `oneshot` driver exercises the full application stack (routing, middleware, auth, WAC, store,
  serialization) but **not** the socket/TLS/HTTP-transport layer. For a transport-level load run
  against a real listener (TLS, HTTP/2), see `bench/run.sh` / `bench/run-auth.sh` (which need the
  docker stack). This harness is the dependency-light, always-runnable complement.
- The counting allocator adds a Relaxed-atomic pair around every allocation; it perturbs timing
  slightly but consistently (timing is advisory anyway) and gives the deterministic allocation floor.
