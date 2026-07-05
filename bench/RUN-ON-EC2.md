<!-- AUTHORED-BY Claude Fable 5 -->
# Turnkey EC2 runbook — the Linux syscalls-per-request baseline (beyond-50k P0.1 + P0.2)

The syscall-count harness (`bench/syscalls.sh`) is **Linux-only** — `strace`/`perf` do not exist on
macOS. This is the copy-paste recipe to produce the committed P0.1/P0.2 baseline on a **fresh,
ephemeral** EC2 box, from clone → build → boot → load → strace → emit the report. It replaces the
macOS loopback figures the design doc flags as unverified (`docs/design/beyond-50k-throughput.md`
§2.1 / §4 Phase 0).

**What it does NOT need (verified):** no Docker, no MinIO, no Keycloak, no SPARQ service, no S3, no
network egress beyond crates.io + GitHub. The server runs on the **in-memory store double**
(`PSS_SPARQ_BACKEND=memory`) and the load driver embeds its **own loopback mock OIDC issuer** and
mints DPoP-bound RFC 9068 tokens, so the real verify path (discovery → JWKS → `at+jwt` → DPoP proof
→ replay → WAC) is exercised end-to-end with zero external dependencies. This is the **lightest
config that still hits the real handler + auth + store hot path** — and it is the *correct* one for
P0.1, because P0.1 counts the server's **front-door socket** syscalls (the `writev`/`write`/`read`
pattern that P1.4 vectored-write and P1.7 `SO_REUSEPORT` gate against); an `http`/`embedded` store
backend would inject store-side syscalls that contaminate that count. The default `cargo build`
(no features) is used — the `embedded-sparq` feature (and its `sparq-*` git deps) is deliberately
NOT enabled.

---

## 0. Box

Any Linux box with `strace` + `perf` works; the deterministic syscall **counts are
instance-independent** (integer counts over a fixed request script). Recommended for a comfortable
build + a usable advisory `perf` profile:

- **AL2023** or **Ubuntu 22.04/24.04**, x86_64 (arm64 also fine).
- **≥ 2 vCPU, ≥ 8 GB RAM, ≥ 20 GB gp3** — the release build pulls `aws-lc-rs` (needs cmake + a C
  toolchain) and a large crate graph; a 2 GB box will OOM the linker.
- A larger instance with a real PMU makes the *advisory* `perf` profile richer, but is not required
  — `perf` falls back to software counters, and the perf pass can be skipped entirely (see §4).

This follows the standing **ephemeral-ec2-gate-runner** recipe: launch tagged + self-terminating,
run, copy the artifact off, terminate. The orchestrator launches the box (this repo's agents do
not) — see the suite EC2 rules.

## 1. Install toolchain + tracers

**AL2023:**
```bash
sudo dnf install -y git strace perf gcc gcc-c++ cmake perl-core python3 curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

**Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install -y git strace linux-tools-common "linux-tools-$(uname -r)" \
  build-essential cmake perl python3 curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

> On some cloud kernels the exact `linux-tools-$(uname -r)` / `perf` package is unavailable or
> version-mismatched. That does not block the **deterministic** metric — run with `SKIP_PERF=1`
> (§4). `strace` is the only hard requirement.

## 2. Clone (public, anonymous — no SSH keys, no token)

```bash
git clone https://github.com/jeswr/solid-server-rs.git
cd solid-server-rs
```

All dependencies resolve over `git+https` from public repos — the only git dependency the default
build pulls is `solid-oidc-verifier` (public). Cargo fetches it anonymously; **no GitHub token or
SSH key is needed on the box.** (`sparq-core`/`sparq-engine` are pulled ONLY under the
`embedded-sparq` feature, which this harness does not use.)

## 3. Allow strace to attach (REQUIRED — one-time sysctl)

`bench/syscalls.sh` runs `strace -p <server-pid>`, where the traced server is a **sibling** of the
tracer (not its child). Under the common default `kernel.yama.ptrace_scope=1`, a process may only
trace its own descendants, so the attach is **denied (EPERM)** and the run would otherwise produce
**empty, zero-count tables**. Set:

```bash
sudo sysctl kernel.yama.ptrace_scope=0
sudo sysctl kernel.perf_event_paranoid=-1   # only needed for the advisory perf pass (§4)
sudo sysctl kernel.kptr_restrict=0          # only for perf-report kernel symbol resolution
```

The harness now **fails loudly** with this exact hint if any strace table comes back empty, so a
missed sysctl can never silently land a bogus baseline.

## 4. Run

```bash
# Full run (deterministic syscall counts + advisory perf profile):
INSTANCE_LABEL="$(TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'); \
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || uname -n)" \
  ./bench/syscalls.sh

# Deterministic-only (skip perf entirely — this is the GATE metric, and needs no perf sysctls):
SKIP_PERF=1 ./bench/syscalls.sh
```

The script builds the release server + the `syscall_load` driver itself (release + debuginfo for
perf symbols), boots the server on plain HTTP over the in-memory store, and runs the strace pass
(idle noise floor + `anon-doc`/`listing`/`authed-doc`/`put`, each ×`SYS_REPS`) followed by the
advisory perf pass. Cold build + run is ~5–15 min on a 2–4 vCPU box.

Knobs (env): `SYS_N` (5000), `SYS_WARMUP` (200), `SYS_REPS` (2), `PERF_N` (50000), `IDLE_SECS` (5),
`CHILDREN` (100 — listing container members), `SYS_PORT`/`SYS_ISSUER_PORT` (3400/3401),
`SKIP_PERF`, `INSTANCE_LABEL` (host label in the report header). Defaults reproduce the committed
baseline.

## 5. Collect the committed artifact

The run writes two files, which ARE the committed baseline:

```
bench/syscalls-results/<YYYY-MM-DD>-linux.json   # machine-readable — the source of truth
bench/syscalls-results/<YYYY-MM-DD>-linux.md     # generated human rendering
```

Everything under `bench/syscalls-results/raw/` is a regenerable DEV artifact (gitignored).

Because the box is **ephemeral** (and has no GitHub push credential), do NOT commit on the box.
Copy the two generated files back to the main checkout and commit from there:

```bash
# from the orchestrator / your workstation, pull the two files off the box:
scp ec2-user@<box>:solid-server-rs/bench/syscalls-results/*-linux.json \
    ec2-user@<box>:solid-server-rs/bench/syscalls-results/*-linux.md \
    ./bench/syscalls-results/
# then, in the solid-server-rs checkout:
git add bench/syscalls-results/*-linux.json bench/syscalls-results/*-linux.md
git commit -m "docs(bench): refresh Linux syscalls-per-request baseline (P0.1/P0.2)"
```

(Alternatively `cat` each file over the SSM/SSH session and paste them into the checkout — the
`.json` is the load-bearing one; the `.md` regenerates from it.)

## 6. Read the verdict

- **P0.1** — the per-class `syscalls/req` table in the `.md`/`.json` is the baseline the beyond-50k
  phases gate against. In particular the `writev` + `write` per-request counts on the read classes
  answer P1.4 (do header + body coalesce into one write, or is it 2→1 to win?); `accept4`/`epoll`
  behaviour under connection churn informs P1.7 (`SO_REUSEPORT`).
- **P0.2** — the advisory `perf` section gives the Linux kernel/user CPU split + top symbols; the
  design's D1 gate asks whether Linux reproduces a syscall-dominated cheap-read path (≥25% of
  server CPU in syscall entry/exit + socket I/O). If it does not, the runtime-rewrite phases (2/3)
  do not open.

## Guarantees / caveats

- **Deterministic vs advisory** (the perf-gate rule): integer syscall counts and response bytes are
  the deterministic metric (can hard-gate); every `perf`-derived number (sampled CPU %, RPS) is
  **advisory** and marked so in the report — never a merge gate.
- `strace` slows the server heavily, so reactor-amortized syscalls (`epoll_wait`, timer maintenance)
  can BATCH differently under trace. Per-request I/O syscalls (`read`/`recvfrom`/`write`/`writev`)
  are robust; amortized counts are approximate. The `idle` window quantifies the noise floor. This
  is inherent to counting syscalls and is recorded in every report.
- Plain HTTP (no in-process TLS): the counts are the server's own socket pattern. The TLS(-vs-kTLS)
  syscall delta is a separate follow-up measurement.
- Self-contained: no hard-coded local paths or secrets; all keys are generated in-process by the
  driver; the mock-issuer key is derived deterministically from `ISSUER_SEED` (a public,
  non-secret harness constant) only so the two passes present the same JWKS to the JWKS-caching
  server.
