<!-- AUTHORED-BY Claude Fable 5 -->
# Beyond ~50k req/s — per-request syscall reduction + I/O-runtime evaluation (design proposal)

> **Status: PROPOSAL (proceed-and-document).** Maintainer-requested. This is the throughput/I/O
> half of a two-proposal pair; the auth half is
> [`docs/design/high-throughput-pop-auth.md`](./high-throughput-pop-auth.md) (high-throughput
> proof-of-possession auth). The seam between them is **connection amortization**: HTTP/2
> multiplexing + TLS session resumption amortize both the TLS handshake (this doc) *and* a
> connection-bound PoP check (that doc) across many requests on one connection. Nothing here
> changes LDP/auth/WAC semantics; every phase re-runs the CTH (41/41) and the adversarial
> invariants (`tests/adversarial_invariants.rs`) before landing.

## 1. Where "~50k" comes from — what the harness actually measures

The figure is the **anonymous public-document ceiling of the committed `oha` HTTPS harness**
(`bench/run.sh`), NOT an authenticated or backend-connected number:

- **Setup** ([`bench/BASELINE.md`](../../bench/BASELINE.md), run context 2026-06-23): Apple M1
  (8 logical cores), loopback, load generator and server contending for the same cores;
  in-memory store doubles (`InMemorySparqClient` + `InMemoryBlobStore` — **no S3, no live
  SPARQ**); in-process rustls/aws-lc-rs TLS; `oha` 1.14.0 with keep-alive; HTTP/1.1 at baseline
  time (HTTP/2 via ALPN landed later — `bench/HTTP2-BACKPRESSURE.md`).
- **The number**: public-doc GET saturates at **≈44–45k RPS at c=16** (`bench/BASELINE.md`),
  with later same-harness passes ranging **≈39–48k** (`bench/SKIP-CRYPTO.md` recorded 40.7k /
  45.9k / 42.7k / 47.8k across passes at c=16–32 — ±~15% run-to-run). "~50k" is the round-up of
  that band.
- **What it is a ceiling *of***: the TLS-record + HTTP-framing + loopback-syscall pipeline for a
  tiny response. The server used only ≈3.4 of 8 cores at saturation (`bench/BASELINE.md`) — on
  this topology the client and the loopback round-trip are part of the bottleneck, so the
  absolute RPS is **advisory** per the perf-gate rule; the *distribution* of where CPU goes
  (§2) is the trustworthy signal.
- The other regimes measured by the committed harnesses: **authed private-doc ≈11.7k RPS**
  at c=16 (`bench/AUTH-BASELINE.md` — the round-2 measurement, real DPoP verify against
  Keycloak, taken *before* the round-3 verified-token cache landed), **listing (100 children)
  ≈20–21k** (`bench/BASELINE.md`), and the
  in-process `tower::Service` harness (`examples/bench_harness.rs`, `bench/HARNESS.md`) which
  exercises the full stack minus the socket/TLS transport and emits **deterministic**
  (status/bytes/alloc-count) + **timing-advisory** JSON blocks.

**Prior rounds already banked the cheap application-level wins** — do not re-propose them:
O(N) listing render + single-pass ACL (`bench/ROUND1.md`), the verified-access-token cache
(`bench/ROUND3.md`), the ETag-keyed ACL cache (`bench/ACL-CACHE.md`), the P1 render/auth
micro-dedups (`bench/P1-QUICKWINS.md`), the per-child IRI-guard ASCII fast path
(`bench/ROUND4-PROFILE.md`), HTTP/2 ALPN + overload/backpressure (`bench/HTTP2-BACKPRESSURE.md`),
pre-crypto rate limiting, and the scoped anonymous public-read skip (`bench/SKIP-CRYPTO.md`,
`decisions/0002`). Unmerged prototypes exist on branches: `perf-b-mimalloc` /
`perf-b-mimalloc-fix` (mimalloc global allocator — Linux/musl + peak-RSS validation still
open), `perf-c-alloc-reduction` (read-response header allocations), `perf-a-http2-guards`
(transport-guard hardening), and `perf-crypto-offload` (**measured NO win, default-OFF** —
evidence, not a lever).

## 2. Bottleneck model — keyed to what the harness can measure

From the round-4 sampling profile (`bench/ROUND4-PROFILE.md`, `samply` @1000 Hz, park-excluded
active CPU, c=16):

| cost category | (a) anon public-doc | (b) authed private-doc | (c) listing (100 children) |
|---|---:|---:|---:|
| NET-SYSCALL (kernel recv/send/kqueue) | **30.3%** | 12.3% | 14.5% |
| MALLOC (sys + rust) | **27.2%** | 13.4% | 25.9% |
| rustls/hyper framing ("our-binary OTHER") | 15.2% | 7.8% | 10.6% |
| tokio/mio/axum runtime | 7.6% | 3.3% | 3.7% |
| memcpy / platform | 6.3% | 3.5% | 8.1% |
| our handler / orchestration logic | 5.1% | 3.3% | **27.6%** |
| HTTP/JSON parse | 3.7% | 5.3% | 4.6% |
| TLS record crypto (AES-GCM) | 2.0% | — | 2.4% |
| **ES256 ECDSA verify** | — | **49.9%** | — |

Reading it as a lever map, per regime:

- **Regime A — anonymous cache-hit read (the "~50k" path).** Syscalls + allocator + TLS/HTTP
  framing are ~73% of active CPU; our logic is 5%. This is the ONLY regime where syscall
  reduction and runtime changes are the first-order levers. Upper bound honesty: eliminating
  *all* NET-SYSCALL + MALLOC time (impossible) caps the theoretical win at ~2.4×; realistic
  phase-1 outcomes are **1.1–1.5×** on this path.
- **Regime B — authenticated read (the production path).** The ES256 DPoP-proof verify is
  **half of active CPU and is the floor** (the proof is fresh per request by design; the
  redundant token re-verify is already cached away — `bench/ROUND3.md`). Syscall/allocator work
  addresses only the remaining ~26% band, so the *authed* ceiling moves at most ~1.3× from
  everything in this doc combined. Moving the authed ceiling materially is the **sibling
  proposal's job** ([`high-throughput-pop-auth.md`](./high-throughput-pop-auth.md)): faster or
  amortized PoP, batch verification, session-bound credentials. The shared lever is
  **connection amortization** (§4.2): one TLS handshake + one connection-level auth
  establishment, many cheap requests.
- **Regime C — cache-miss / real backends.** The entire baseline runs on in-memory doubles.
  With the live `HttpSparqClient` (SPARQL 1.1 over HTTP, hyper-util pooled client —
  `src/store/http.rs`) and `object_store` S3, a miss pays **network round-trips measured in
  hundreds of µs to ms** — one metadata query + one blob fetch dwarfs the ~20–50 µs of
  server CPU per cheap request. **No syscall or runtime optimization is visible in this
  regime**; the levers are (i) the existing pooled/keep-alive backend connections, (ii) body
  and decision caches (ACL cache landed; a blob/response cache is future work), and (iii) the
  **`embedded-sparq` feature** (`decisions/0001`) which deletes the SPARQ HTTP hop entirely —
  the single biggest "syscall reduction" available anywhere in the codebase, already
  scaffolded behind an opt-in feature.

### 2.1 The per-request syscall profile today (tokio/epoll, HTTP/1.1|2 keep-alive)

The serve path is `axum-server` (TLS, rustls) / `axum::serve` (plain TCP) over hyper 1.x on
tokio's multi-threaded work-stealing runtime with a mio epoll (Linux) / kqueue (macOS) reactor.
On a warm keep-alive connection the *expected* per-request syscall shape is:

- ≥1 `recvmsg`/`read` (request bytes; possibly 2 if the TLS record boundary splits),
- ≥1 `sendmsg`/`write`/`writev` (response; header+body may or may not coalesce into one
  vectored write),
- an amortized share of `epoll_wait`/`kevent` wakeups (one wakeup can service many
  connections),
- occasional `accept4` + per-connection socket setup (amortized by keep-alive; HTTP/2
  multiplexing amortizes it further),
- timer/waker maintenance (`timerfd`/eventfd wakeups under load are batched by tokio).

**Honesty flag: this shape is *inferred*, not yet measured.** The 30.3% "NET-SYSCALL" figure is
macOS loopback kernel time under `samply`, which is neither a Linux syscall *count* nor a
production-NIC cost. The first deliverable of this proposal (§4.0) is therefore a **deterministic
Linux syscalls-per-request metric** — until it exists, every syscall-reduction claim below is a
hypothesis with a measurement plan, not a number.

## 3. Deterministic-vs-advisory measurement discipline (the perf-gate rule, applied)

Per the repo's established split (`bench/HARNESS.md`, mirroring the PSS charter): every metric
proposed below is classified up front. **Deterministic** metrics (reproducible integer counts)
may hard-gate against a committed floor; **timing** metrics (anything wall-clock-derived —
RPS, latency, CPU%) are **advisory, never a merge gate**.

| proposed metric | class | how measured |
|---|---|---|
| syscalls per request, per class (`read`/`write`/`epoll_wait`/`accept4`…) | **deterministic** (integer count over a fixed N-request script, single connection, quiesced server) | `strace -fc --syscall-times` (Linux) around a fixed-request run; report count deltas. Kernel/libc-version-pinned in the report header. |
| allocations per op (`alloc_count_per_op`, `alloc_bytes_per_op`) | **deterministic** | already emitted by `examples/bench_harness.rs` (counting `#[global_allocator]`, min-over-N floor) |
| TLS handshakes: full vs resumed count over a fixed reconnect script | **deterministic** | rustls handshake-kind is observable per connection; count over a scripted M-reconnect run |
| ES256 verifies per request (1 on token-cache hit) | **deterministic** | pinned by tests since round 3 |
| backend round-trips per LDP op | **deterministic** | count at the `SparqClient`/`BlobStore` seam (test doubles already count) |
| RPS / p50/p99/p999 / CPU% | **advisory** | existing `bench/run.sh` / `run-auth.sh` / `bench_harness` timing blocks, `disclaimer`-tagged |
| peak RSS under a `MAX_CONCURRENCY`-saturating flood (allocator swap acceptance) | **advisory-but-required** (wall-clockless, yet machine-dependent; treat as a bounded acceptance check, not a gate number) | `/usr/bin/time -v` / cgroup memory.peak during the flood arm of `examples/adversarial_bench.rs` |

A change in this workstream lands on its **deterministic delta** (fewer syscalls, fewer allocs,
fewer handshakes, fewer round-trips — byte-identical responses proven by tests), with the RPS
effect reported as advisory context. This is exactly how rounds 1–4 were landed.

## 4. Phased plan

### Phase 0 — measure on the deployment OS (prerequisite, small)

The whole syscall story is currently macOS-profiled; the deploy target is Linux
(`node:24-alpine`-era boxes / EC2). Before optimizing syscalls, count them where they cost:

- **P0.1 — Linux syscall-count harness.** A `bench/syscalls.sh` that boots the release binary
  under `strace -fc` (accepting the slowdown — counts, not timing), drives a fixed-N
  single-connection keep-alive script for each scenario (public-doc h1, public-doc h2,
  authed-doc, listing), and emits a JSON `{scenario, syscall: count/N}` table. Deterministic;
  becomes the hard-gateable floor for every later phase. Runs on the EC2 lane (the box the
  suite already has) since Docker is unavailable locally.
- **P0.2 — re-run the round-4 profile on Linux** (`perf` instead of `samply`) to get the Linux
  NET-SYSCALL/MALLOC split. If the Linux profile does NOT reproduce a ≥25% syscall band on the
  cheap-read path, phases 2–3 deflate accordingly — write the verdict into this doc's
  follow-up.

### Phase 1 — cheap deterministic wins on the current tokio stack (low risk, weeks)

Ordered by (expected impact × confidence) ÷ risk. Each is independently landable and
independently reversible.

1. **P1.1 — land the parked allocator swap (mimalloc)** — branch `perf-b-mimalloc`(+`-fix`),
   already written and supply-chain-reviewed (mimalloc 0.1.52 / libmimalloc-sys 0.1.49, MIT,
   vendored-C build documented). Targets the **27.2% MALLOC band** (regime A) — the largest
   single addressable slice after syscalls. Blocked-on (its own commit message says so):
   musl-target build check, Dockerized CTH 41/41, and **peak-RSS under a
   concurrency-saturating flood** (allocator page retention changes the OOM/DoS envelope —
   the adversarial-bench flood arm is the acceptance test). jemalloc was already considered
   and rejected for musl page-size pain — don't relitigate.
2. **P1.2 — land `perf-c-alloc-reduction`** (per-request read-response header allocations) —
   deterministic alloc-count delta via the bench-harness floor; the `bench/BASELINE.md` rank-4
   target.
3. **P1.3 — TLS session resumption: size it for production.** rustls `ServerConfig` defaults
   (verified against docs.rs/rustls): an in-memory **session cache of only 256 sessions**,
   **2 TLS 1.3 resumption tickets** per handshake, and **`max_early_data_size = 0`** (0-RTT
   off). Resumption therefore already *works*, but a 256-entry cache is a handful of
   concurrent clients before eviction forces full handshakes. Change (in `src/tls.rs`, the
   same seam that owns ALPN): env-tunable `ServerSessionMemoryCache` size (default e.g. 10k)
   and/or a process-lifetime `Ticketer` for stateless tickets. **Deterministic metric:
   resumed-vs-full handshake counts over a scripted reconnect run.** This is the doc's half of
   the connection-amortization pact with the auth proposal: a resumed handshake skips the
   asymmetric key exchange, exactly as the connection-bound PoP skips per-request asymmetric
   verifies. **Keep 0-RTT OFF** (§6).
4. **P1.4 — vectored-write / response-coalescing audit.** Verify (via the P0.1 counts) whether
   header+body leave as one `writev`-equivalent or two writes per response through
   axum-server → tokio-rustls → hyper. If two: enable/exploit `poll_write_vectored`
   pass-through or pre-concatenate small responses into one `Bytes`. Deterministic: write-class
   syscalls per request drops from 2→1. (Unverified today which of the two we get — that is
   the point of measuring first.)
5. **P1.5 — TCP tuning audit**: confirm `TCP_NODELAY` on accepted sockets on BOTH serve paths
   (axum-server and plain `axum::serve`), keep-alive timeouts already owned by
   `src/transport.rs`. Deterministic-ish (socket option state is inspectable); latency effect
   advisory.
6. **P1.6 — backend round-trip amortization (regime C).** (a) confirm the `HttpSparqClient`'s
   hyper-util legacy pool reuses connections under load (pool metrics / P0.1 `connect` counts);
   (b) same for `object_store`'s S3 client; (c) promote the **`embedded-sparq`** backend
   (`decisions/0001`) from opt-in experiment to the benchmarked configuration for the
   single-node deployment — it deletes ~every SPARQ metadata syscall+RTT (an HTTP request per
   metadata op → a function call). Deterministic: backend round-trips per LDP op, already
   countable at the seam.
7. **P1.7 — SO_REUSEPORT sharded accept** (only if P0.1 shows accept-path contention at high
   connection churn): N listeners with `SO_REUSEPORT`, one per worker, kernel-level load
   spread. Cheap to prototype on tokio via `socket2`; measurable as accept-latency tail.
   Low priority: keep-alive + h2 make accepts rare in our regimes.

Expected phase-1 aggregate on regime A: **advisory ~1.15–1.4×** (mostly P1.1 + P1.4); on
regime B: small (the crypto floor); on regime C: potentially **multiples** via P1.6/embedded —
which is where real deployments live.

### Phase 2 — kTLS (kernel TLS offload) + sendfile for blob bodies (medium lever, opt-in)

`sendfile`/`splice` zero-copy is **impossible under userspace TLS** — bytes must traverse
userspace for record encryption. The only path that composes zero-copy with HTTPS is **kernel
TLS**: complete the handshake in rustls, then push the negotiated secrets into the kernel TLS
ULP (`setsockopt(SOL_TCP, TCP_ULP, "tls")`) so the kernel encrypts records — after which
`sendfile` from a file-backed blob is legal, and even ordinary writes skip one userspace
copy. The maintained integration is the **`ktls` crate (now under the rustls org, v6.0.2,
2025-04-07)** which wires tokio-rustls server/client connections onto kernel TLS.

Honest scoping:

- **Payoff profile**: sendfile pays on **large byte-exact blobs** (media in pods). Our measured
  hot path serves ~hundreds-of-bytes RDF documents, where per-request overhead is syscall
  *count*, not copy *bandwidth* — kTLS helps there only by removing the userspace encrypt+copy
  (the 2.0% AES-GCM slice + part of memcpy). So this phase is really a **large-blob
  optimization**, not a "~50k → more" lever.
- **Costs**: Linux-only (config-gated like everything else here); kernel `CONFIG_TLS` ULP with
  a cipher-suite × TLS-version support matrix that must be verified per target kernel
  (**unverified here — spike task**); hyper has no sendfile body — a sendfile path needs a
  custom connection-level response writer for the blob-body case, bypassing the normal body
  plumbing (a real, contained, but non-trivial transport change); and the blob store must
  expose file-backed reads (today `BlobStore::get` returns `Bytes`; S3-backed blobs would need
  a local cache file to sendfile from).
- **Verdict**: park behind a decision gate — implement only when (i) large-blob serving is a
  measured workload, and (ii) P0.1 shows the copy/encrypt band matters. File the bead; don't
  build yet.

### Phase 3 — the big lever: thread-per-core io_uring runtime (evaluate, don't leap)

**What it buys, mechanically.** io_uring replaces per-op syscalls with shared
submission/completion rings: many I/O ops submitted with one `io_uring_enter` (or zero
syscalls in `SQPOLL` mode), multishot accept/recv, and registered buffers that eliminate
per-op buffer mapping (Axboe, "Efficient IO with io_uring", kernel.dk). A thread-per-core
architecture on top (each core owns its connections + state, no cross-core locks or
work-stealing migrations) additionally removes the tokio runtime's stealing/waking overhead
(7.6% on regime A) and the shared-state cache-line traffic. Combined, the addressable band on
regime A is the NET-SYSCALL (30.3%) + runtime (7.6%) slices — a **theoretical ≤1.6× regime-A
ceiling move**, realistically 1.2–1.4×, and **much less on regimes B/C** (crypto floor;
backend RTT).

**Candidate runtimes (primary-source status, checked 2026-07-03):**

| | monoio | glommio | tokio-uring |
|---|---|---|---|
| model | thread-per-core, io_uring with **epoll/kqueue fallback** | cooperative thread-per-core, io_uring-only | io_uring driver under a tokio current-thread runtime |
| latest release | 0.2.4 (2024-08-20, crates.io) | 0.9.0 (2024-03-25, crates.io) | 0.5.0 (2024-05-27, crates.io) |
| repo activity | active — pushed 2026-05-29 (monoio-rs/monoio, ~5k stars; moved from bytedance/) | sporadic — pushed 2026-04-22, no release since 2024 | slow — pushed 2025-07-07; README: "still very young" |
| kernel floor | io_uring ≥5.6; falls back to epoll (Linux) / kqueue (macOS — dev boxes keep working) | ≥5.8 + 512 KiB memlock | "5.11+ known to work" |
| HTTP story | none first-class ("HTTP framework … on the way"); `monoio-compat` 0.2.2 poll-compat wrapper; bytedance `monoio-http` exists but is not axum | none | tokio-compatible libs run, but the uring driver is current-thread + young |
| TLS | `monoio-tls` wrapper | none first-class | tokio ecosystem |

**Recommendation: monoio, if and only if the decision criterion below fires.** It is the only
one of the three that is (a) actively maintained, (b) designed for exactly this shape
(io-bound network servers, thread-per-core), and (c) able to keep macOS dev + conformance
workflows alive via its kqueue legacy driver. glommio's release cadence has stalled and it is
Linux-only with no HTTP/TLS story; tokio-uring is explicitly young, current-thread, and does
not deliver the thread-per-core sharding that is half the pitch.

**The honest cost — this is an I/O-layer rewrite, not a swap:**

1. **axum/hyper/tower do not port.** They are tokio-trait-bound; monoio's ecosystem equivalents
   (`monoio-http`, `monoio-tls`) are immature, and `monoio-compat` reintroduces poll-based
   readiness emulation over a completion runtime — spending much of the io_uring benefit to
   keep hyper. A real adoption rewrites `src/transport.rs` + `src/tls.rs` + the serve loop +
   the middleware stack (auth/overload/rate-limit/CORS layers are tower layers today) against
   a new HTTP implementation — with a fresh CVE-class surface (h2 rapid-reset, slowloris,
   header parsing) that hyper has already absorbed years of hardening for. `tests/transport_dos.rs`
   exists precisely because that surface is subtle.
2. **The security-critical shared state does not shard.** The DPoP `jti` replay store MUST stay
   globally consistent — a proof replayed onto a different core must still be caught, so a
   thread-per-core design keeps at least one cross-core synchronization point per authed
   request (or an even-costlier shared/Redis store). The verified-token cache and ACL cache
   can be per-core (N× memory, N× cold misses — acceptable), but the "no cross-core locking"
   pitch is structurally capped on exactly the path that matters (regime B). This interacts
   directly with the sibling auth proposal — evaluate them together.
3. **The verifier stack is tokio-bound.** `solid-oidc-verifier`'s `network` feature (JWKS/WebID
   fetch, reqwest) and the Redis replay client assume tokio; a monoio frontend needs a tokio
   side-runtime for backend I/O (a supportable hybrid — frontend rings, backend tokio thread —
   but more moving parts).
4. **io_uring is a container/security liability.** Google reported **60% of 2022–23 kCTF kernel
   exploit submissions targeted io_uring** and responded by disabling it on ChromeOS and
   production Google servers, seccomp-filtering it on Android, and restricting it in GKE
   (security.googleblog.com "Learnings from kCTF VRP's 42 Linux kernel exploits"); Docker's
   **default seccomp profile blocks `io_uring_setup/enter/register` since Docker 25.0**
   (moby/moby#46762, merged 2023-11-02, matching containerd). A PSS-suite server that
   *requires* a loosened seccomp profile to run in a container is a real posture regression
   the charter's security-first rule must weigh — at minimum it forces the epoll fallback in
   containers, which forfeits the entire win there.

**Decision criterion (all four, else stay on tokio):**

- **D1**: the P0.1 Linux syscall count shows ≥~5 syscalls/request on the cheap read AND the
  Linux `perf` profile attributes ≥25% of server CPU to syscall entry/exit + socket I/O on the
  production target (not macOS loopback);
- **D2**: phase 1 has landed and the remaining regime-A gap still blocks a *named* deployment
  need that horizontal scaling (stateless core + Redis replay + LB — already designed) cannot
  meet more cheaply;
- **D3**: the deployment can run io_uring at all (bare EC2 / custom seccomp accepted by the
  maintainer as a `needs:user` security decision);
- **D4**: a 2-week spike — a monoio thread-per-core **static-response TLS echo** matching our
  response sizes, benchmarked with the same harness discipline against the tokio server on the
  same Linux box — shows ≥1.3× advisory RPS with the deterministic syscall count ≥3× lower.
  (A spike below that does not justify rewriting a hardened transport.)

If the criterion fires, the adoption shape is a **hybrid**: monoio owns accept+TLS+HTTP/1.1
(h2 negotiated down or terminated separately) on N cores with per-core caches; auth/WAC/store
logic stays runtime-agnostic (it already is — `tower::Service` oneshot tests prove it); tokio
survives on a side thread for verifier/Redis/S3 I/O. That keeps the rewrite confined to the
transport crate-boundary and keeps the CTH + adversarial suites as the invariant harness.

## 5. What NOT to do (diminishing or negative returns)

- **Don't rewrite the runtime before Linux numbers exist.** Every syscall figure we have is
  macOS loopback. Phase 0 costs days; a wrong phase-3 costs a quarter.
- **Don't enable TLS 0-RTT early data.** `max_early_data_size` stays 0: 0-RTT is replayable by
  design, and this server's whole auth model is anti-replay (DPoP `jti`); accepting replayable
  early data under a replay-proof auth scheme is incoherent and the CTH won't catch it.
- **Don't re-attempt crypto offload to the blocking pool** — measured NO win
  (`perf-crypto-offload`, default-OFF, kept as evidence).
- **Don't extend the skip-crypto fast path to credentialed reads** — decided unsafe
  (`decisions/0002`; it downgraded owner `WAC-Allow` modes and failed conformance).
- **Don't chase loopback RPS as the KPI.** The client contends for the same cores; past c≈16
  the harness measures contention. The deterministic counters are the KPI; RPS is context.
- **Don't buy h2 tuning beyond what landed.** Measured: h2 wins 2.8–3.1× at c=1 (connection
  amortization) and is ~0.8–0.9× at c≥16 on the CPU-bound loopback (`bench/HTTP2-BACKPRESSURE.md`)
  — more h2 knobs won't move the saturated ceiling.
- **No HTTP/3/QUIC.** New userspace transport, new DoS surface, no Solid-client demand signal;
  strictly after the auth proposal's levers, if ever.
- **Don't swap to jemalloc** — musl page-size pain already adjudicated in the mimalloc branch.
- **Don't shard the replay store per-core or per-instance** for speed — it is the replay
  protection; sharding it re-opens the replay window across shards (same reasoning as the
  fail-closed capacity behaviour in `bench/AUTH-BASELINE.md`).
- **Accept the crypto floor in this workstream.** 49.9% of authed active CPU is ES256; no I/O
  work changes that. That budget belongs to
  [`high-throughput-pop-auth.md`](./high-throughput-pop-auth.md).

## 6. Follow-up beads (build-ready)

| id (proposed) | task | phase | gate class |
|---|---|---|---|
| perf-p0-syscount | `bench/syscalls.sh` — strace-based deterministic syscalls/request harness (Linux/EC2 lane) + JSON report | 0 | deterministic |
| perf-p0-linuxprof | re-run the round-4 profile with `perf` on the Linux target; write the Linux NET-SYSCALL/MALLOC split into a `bench/LINUX-PROFILE.md` | 0 | measurement |
| perf-p1-mimalloc | validate + land `perf-b-mimalloc-fix`: musl build, Dockerized CTH 41/41, peak-RSS flood acceptance | 1 | deterministic (alloc source) + advisory RSS |
| perf-p1-allocred | rebase + land `perf-c-alloc-reduction` on the bench-harness alloc floor | 1 | deterministic |
| perf-p1-resumption | env-tunable rustls session-cache size / ticketer in `src/tls.rs`; scripted resumed-vs-full handshake count | 1 | deterministic |
| perf-p1-writev | P0.1-driven write-coalescing audit (2 writes → 1 per response if confirmed) | 1 | deterministic |
| perf-p1-backend | backend-RTT counters at the SparqClient/BlobStore seams + pooled-connection verification; embedded-sparq benchmark config | 1 | deterministic |
| perf-p2-ktls-spike | kTLS spike: `ktls` crate + kernel matrix verification; decision memo only | 2 | spike |
| perf-p3-monoio-spike | the D4 monoio TLS-echo spike, same-box tokio comparison; decision memo against D1–D4 | 3 | spike |

## 7. Sources

Repo evidence (all in-tree): `bench/BASELINE.md`, `bench/AUTH-BASELINE.md`,
`bench/ROUND1.md`, `bench/ROUND3.md`, `bench/ROUND4-PROFILE.md`, `bench/P1-QUICKWINS.md`,
`bench/HTTP2-BACKPRESSURE.md`, `bench/SKIP-CRYPTO.md`, `bench/HARNESS.md`,
`examples/bench_harness.rs`, `tests/adversarial_invariants.rs`, `tests/transport_dos.rs`,
`src/tls.rs`, `src/transport.rs`, `src/store/http.rs`, `decisions/0001-embed-sparq-in-process.md`,
`decisions/0002-skip-crypto-when-identity-independent.md`, branches `perf-a-http2-guards`,
`perf-b-mimalloc(-fix)`, `perf-c-alloc-reduction`, `perf-crypto-offload`.

External (verified 2026-07-03 against the live source):

- monoio — <https://github.com/bytedance/monoio> (redirects to monoio-rs/monoio; repo
  pushed 2026-05-29): thread-per-core io_uring/epoll/kqueue, kernel 5.6+, "HTTP framework …
  on the way"; crates.io newest 0.2.4 (2024-08-20); `monoio-compat` 0.2.2 (2024-03-27).
- glommio — <https://github.com/DataDog/glommio> (pushed 2026-04-22): cooperative
  thread-per-core io_uring, kernel ≥5.8, 512 KiB memlock; crates.io newest 0.9.0 (2024-03-25).
- tokio-uring — <https://github.com/tokio-rs/tokio-uring> ("still very young"; pushed
  2025-07-07); crates.io newest 0.5.0 (2024-05-27).
- rustls `ServerConfig` defaults — <https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html>:
  256-session in-memory cache, `send_tls13_tickets` default 2, `max_early_data_size` default 0.
- ktls — <https://github.com/rustls/ktls> (rustls org; ktls-v6.0.2, 2025-04-07); crates.io:
  "Configures kTLS for tokio-rustls client and server connections." Kernel cipher/version
  matrix **not verified here** — spike task perf-p2-ktls-spike.
- io_uring security posture — Google, "Learnings from kCTF VRP's 42 Linux kernel exploits
  submissions" (60% of submissions exploited io_uring; disabled on ChromeOS + Google
  production servers, filtered on Android, restricted in GKE):
  <https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html>; Docker
  default-seccomp block of `io_uring_setup/enter/register` — <https://github.com/moby/moby/pull/46762>
  (merged 2023-11-02, Docker 25.0).
- io_uring mechanics (batched SQ/CQ, SQPOLL) — J. Axboe, "Efficient IO with io_uring",
  <https://kernel.dk/io_uring.pdf>.

**Unverified / to-verify flags carried in-text:** the per-request syscall shape (§2.1 — P0.1
measures it); whether header+body coalesce into one write (§4 P1.4); the kTLS kernel
cipher/version matrix (§4 phase 2); monoio-compat's exact hyper interop surface (phase-3 spike
scope).
