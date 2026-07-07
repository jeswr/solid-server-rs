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

## nl48 — doc-serve "write-coalescing": already coalesced; the aggregate `write` is the reactor waker

Bead `suite-tracker-nl48` reads the P0.1 anon-doc line — `write` 1.04/req **+** `writev` 1.04/req —
as "the response head + body are not coalesced; collapse them into one write-class syscall (~20%
write-class reduction)". That premise is **already resolved and is a misattribution of the aggregate
count**, on two independently-verified grounds:

1. **The response IS already one vectored socket write.** The merged P1.4 audit
   (`tests/response_write_coalescing.rs`, commits `9735725` / `f87ec0d` / `579fcbf`) drives the REAL
   assembled router over the REAL `axum::serve` path and measures, at the hyper→transport **socket**
   seam, **exactly 1 `writev` and 0 plain `write` per response** for the anonymous GET, the 206 Range
   GET, the container listing, and the authenticated (DPoP-bound) GET. hyper's h1 encoder already
   buffers the response head + the single length-delimited `Bytes` body into one `WriteBuf` and
   flushes it as one vectored write (Queue strategy — a loopback `TcpStream` advertises
   `is_write_vectored() == true`). Forcing hyper's Flatten strategy (`http1::Builder::writev(false)`)
   would only turn that 1 `writev` into 1 `write` (plus a body-into-header **memcpy**) — same
   write-class count, strictly worse — so there is no serialization change to make. (On the in-process
   TLS path rustls advertises `is_write_vectored() == false`, so hyper ALREADY flattens to a single
   `write` there — an inference from the strategy selection, confirmable on the EC2.)

2. **The aggregate `write` 1.04/req is NOT the response — it is the tokio runtime's reactor waker.**
   `strace -f -c` (what `syscalls.sh` uses) tallies **every** `write(2)` by the whole process with NO
   fd attribution, so a non-socket write is counted indistinguishably from a socket write. The server
   runs on the default multi-thread `#[tokio::main]` runtime; under a **single** keep-alive
   ping-pong connection each request triggers ~one cross-worker unpark, and mio wakes a parked worker
   by `write(2)`-ing 8 bytes to an **eventfd**. That is the `write` 1.04/req. It is a
   single-connection-benchmark artifact: under real concurrent load one wakeup services many ready
   connections, so it amortizes toward 0/req. Reducing it at all is a runtime-architecture lever
   (SO_REUSEPORT thread-per-core accept — the separate P1.7 / Phase-3 direction), **not** a
   response-serialization change, and out of a pure micro-opt's scope.

**Confirm it on the EC2 (turns the inference into a measurement):**

```bash
sudo sysctl kernel.yama.ptrace_scope=0
./bench/syscalls-fd-kind.sh          # re-runs the anon-doc window under `strace -f -yy -e trace=write,writev`
```

`-yy` annotates each fd with its kind; the script buckets write/writev into `socket` (`<TCP:…>` — the
response) vs `eventfd` (`<anon_inode:[eventfd]>` — the reactor waker). The hypothesis it validates:
**writev/socket ≈ 1.0, write/socket ≈ 0.0, write/eventfd ≈ 1.0**. `SCEN=put ./bench/syscalls-fd-kind.sh`
does the same for the PUT class.

### Secondary (PUT-class) findings — investigated, deliberately NOT changed

- **`getrandom` 1.0/req on PUT** is one `getrandom(2)` per write, from `CompositeStore::mint_blob_key`
  (`src/store/mod.rs`) drawing the **128-bit collision-resistant blob-key suffix** from the OS CSPRNG.
  It could be amortized with a seeded userspace CSPRNG (one OS draw per batch), but that path is
  **security-adjacent** (its unique-per-write key is what a whole delete/recreate race-class fix
  depends on, and it deliberately **fails closed** on RNG error) and the saving — one tiny syscall on
  a write dominated by ECDSA verify (~12–14 % CPU in the advisory profile) — does not justify
  changing a hardened storage invariant. Per the bead's "fix only if clean", left as-is.
- **`futex` 2.14/req on PUT** is lock traffic in the **in-memory test-double store**
  (`InMemorySparqClient` / `InMemoryBlobStore` — the harness runs `PSS_SPARQ_BACKEND=memory`, no
  Docker/SPARQ/S3). It is a benchmark-harness artifact and does **not** reflect the production
  SPARQ-HTTP + blob path, so there is nothing production-relevant to reduce here.
