# `bench/syscalls.sh` — Linux syscalls-per-request (deterministic; beyond-50k §4 P0.1 + P0.2)

The measurement the beyond-50k design doc (`docs/design/beyond-50k-throughput.md` §2.1/§4)
requires before ANY Phase-1/2/3 syscall-reduction work: the prior "30% net-syscall" figure was
macOS loopback kernel *time* under `samply`, not a Linux syscall *count*. This harness produces
real Linux per-request syscall counts as a **deterministic** metric, plus an **advisory** `perf`
CPU profile, with no Docker/Keycloak/S3/SPARQ dependency.

## What it measures

Per request class, on ONE warm keep-alive HTTP/1.1 connection, exactly `SYS_N` requests with
`strace -f -c` attached to the (quiesced, warmed) server only during the measured window:

| class | request | path |
|---|---|---|
| `anon-doc` | anonymous `GET` | `/bench/public/doc` (auth-free read hot path) |
| `listing` | anonymous `GET` | `/bench/listing/` (container render, `CHILDREN` members) |
| `authed-doc` | DPoP-authed `GET` | `/bench/private/doc` (token-cache-hit verify path) |
| `put` | DPoP-authed `PUT` (replace) | `/bench/private/put-target` (uniform update path) |
| `idle` | none | background (timer/epoll) noise floor |

- **Deterministic** (can hard-gate): integer syscall counts / `SYS_N` per class, per syscall;
  response bytes per request. Repeated `SYS_REPS` times so stability is visible.
- **Advisory** (never a gate): `perf stat` software counters + `perf record -g -e cpu-clock`
  kernel/user split + top symbols over an untraced `PERF_N`-request window per class.

## How it stays deterministic + honest

- The driver (`examples/syscall_load.rs`) **pauses between warm-up and measurement** (READY/GO
  protocol on stdin/stdout) so the tracer attaches to an already-warm server: JWKS fetch, token
  cache fill, ACL cache fill, and the connection handshake all land OUTSIDE the measured window.
- The driver **verifies the code path** before measuring: preflight asserts public=200,
  private-anon=**401**, private-authed=200, put=201/204 — and the measured phase must be
  status-uniform, or the run aborts. No silent 401-path measurement.
- Auth needs no Keycloak: the driver embeds a **loopback mock OIDC issuer** (discovery + JWKS)
  and mints DPoP-bound RFC 9068 tokens; the server verifies through its REAL network path
  (`SOLID_SERVER_TRUSTED_ISSUER=http://127.0.0.1:<port>` + `SOLID_SERVER_ALLOW_LOOPBACK=1`,
  the same posture as `conformance/run.sh`).
- Plain HTTP (no in-process TLS): counts are the server's own socket pattern. The TLS(-vs-kTLS)
  syscall delta is a separate follow-up measurement.
- Known caveat (recorded in every report): strace slows the server, which can change
  reactor/timer **batching** — per-request I/O syscalls are robust; `epoll_wait`-class amortized
  counts are approximate. The `idle` window quantifies the noise floor.

## Running (Linux only — the EC2 lane)

**Turnkey fresh-box recipe: [`RUN-ON-EC2.md`](./RUN-ON-EC2.md)** — clone → build → boot → load →
strace → emit + commit the report, including the one-time `kernel.yama.ptrace_scope=0` sysctl the
strace attach requires. Short form:

```bash
# deps: dnf install -y strace perf gcc gcc-c++ cmake perl-core git python3 curl  (+ rustup toolchain)
sudo sysctl kernel.yama.ptrace_scope=0   # REQUIRED — strace attaches to a sibling process
./bench/syscalls.sh                       # add SKIP_PERF=1 to skip the advisory perf pass
```

Runs against the **in-memory store** (`PSS_SPARQ_BACKEND=memory`) + the driver's embedded mock OIDC
issuer — **no Docker/Keycloak/S3/SPARQ**, default `cargo build` (no `embedded-sparq` feature).

Knobs: `SYS_N` (5000), `SYS_WARMUP` (200), `SYS_REPS` (2), `PERF_N` (50000), `IDLE_SECS` (5),
`CHILDREN` (100), `SYS_PORT`/`SYS_ISSUER_PORT` (3400/3401), `SKIP_PERF=1`, `INSTANCE_LABEL`.

## Outputs

- `bench/syscalls-results/<date>-linux.json` — **committed**, machine-readable, the single source
  of truth for any number cited in markdown (the no-hard-coded-perf rule).
- `bench/syscalls-results/<date>-linux.md` — **committed**, generated rendering of the same data.
- `bench/syscalls-results/raw/<timestamp>/` — regenerable DEV artifacts (strace tables, perf.data,
  logs), **gitignored**.

The latest committed report is the P0.1 baseline the beyond-50k phases gate against; P0.2's
verdict (does Linux reproduce a syscall-dominated cheap-read path?) is read from the same report.
