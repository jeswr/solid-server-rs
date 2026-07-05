#!/usr/bin/env bash
# AUTHORED-BY Claude Fable 5
#
# Linux syscalls-per-request measurement harness for solid-server-rs (beyond-50k §4 P0.1 + P0.2).
#
# WHY: the design doc's "30% net-syscall" figure was macOS loopback kernel TIME under samply — not a
# Linux syscall COUNT. Every Phase-1/2/3 syscall-reduction lever is a hypothesis until real Linux
# per-request syscall counts exist. This script produces them, deterministically:
#
#   1. builds the server (release + debuginfo for perf symbols) and the fixed-N driver
#      (`examples/syscall_load.rs`);
#   2. boots the server on plain HTTP over the in-memory store, bench-seeded — NO Docker, NO
#      Keycloak, NO S3/SPARQ (the driver embeds a loopback mock OIDC issuer for the authed classes);
#   3. STRACE PASS (the deterministic metric): per scenario the driver warms up and pauses; we
#      attach `strace -f -c` to the quiesced warm server, the driver fires EXACTLY $SYS_N requests
#      down ONE keep-alive connection, we detach; syscall-table counts / N = syscalls-per-request.
#      Repeated $SYS_REPS times per scenario so run-to-run stability is visible in the report. An
#      `idle` window measures the background (timer/epoll) noise floor the counts sit on.
#   4. PERF PASS (advisory context): same protocol untraced-by-strace with $PERF_N requests, under
#      `perf stat` (software counters — t3-class EC2 exposes no PMU) + `perf record -g` (cpu-clock
#      sampling); `perf report` renders the kernel/user CPU split + top symbols.
#   5. renders bench/syscalls-results/<date>-linux.{json,md} via bench/syscalls-report.py.
#      The .json/.md pair is the COMMITTED generated artifact markdown prose must cite; everything
#      under bench/syscalls-results/raw/ is a regenerable DEV artifact (gitignored).
#
# Determinism discipline (the perf-gate rule): integer syscall counts over a fixed request script
# are the deterministic metric; everything wall-clock-derived (perf %, RPS) is ADVISORY and marked
# so in the report. Honesty caveat baked into the report: strace slows the server ~an order of
# magnitude, which can change epoll_wait/timer BATCHING — per-request read/write/send counts are
# robust, reactor-amortized counts are approximate. That is inherent to counting syscalls.
#
# Usage (Linux only; strace + perf + python3 required — the EC2 lane):
#   ./bench/syscalls.sh
# Knobs: SYS_N (5000) SYS_WARMUP (200) SYS_REPS (2) PERF_N (50000) IDLE_SECS (5) CHILDREN (100)
#        SYS_PORT (3400) SYS_ISSUER_PORT (3401) SKIP_PERF (unset) INSTANCE_LABEL (uname -n)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

[ "$(uname -s)" = "Linux" ] || { echo "ERROR: Linux-only (strace/perf syscall counting) — run on the EC2 lane, see bench/SYSCALLS.md" >&2; exit 1; }
command -v strace >/dev/null || { echo "ERROR: strace not installed (dnf install -y strace)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not installed" >&2; exit 1; }
SKIP_PERF="${SKIP_PERF:-}"
if [ -z "$SKIP_PERF" ]; then
  command -v perf >/dev/null || { echo "ERROR: perf not installed (dnf install -y perf), or set SKIP_PERF=1" >&2; exit 1; }
fi

SYS_N="${SYS_N:-5000}"
SYS_WARMUP="${SYS_WARMUP:-200}"
SYS_REPS="${SYS_REPS:-2}"
PERF_N="${PERF_N:-50000}"
IDLE_SECS="${IDLE_SECS:-5}"
CHILDREN="${CHILDREN:-100}"
PORT="${SYS_PORT:-3400}"
ISSUER_PORT="${SYS_ISSUER_PORT:-3401}"
BASE="http://127.0.0.1:${PORT}"
INSTANCE_LABEL="${INSTANCE_LABEL:-$(uname -n)}"
# The bench pod owner WebID: SYNTHETIC https (never dereferenced — BIDIRECTIONAL=off). Needed
# because the verifier requires an https: webid claim while this harness serves plain HTTP, so the
# seed's derived http: owner could never match a token (see seed_bench_with_owner / SYSCALLS.md).
BENCH_OWNER_WEBID="${BENCH_OWNER_WEBID:-https://bench.invalid/profile/card#me}"
# A FIXED seed for the driver's deterministic mock-issuer key. Both driver processes (the strace
# pass + the perf pass) derive the SAME issuer keypair from it, so the server's cached JWKS (TTL
# raised to 24h below) validates BOTH passes' tokens. A per-process random issuer key would make the
# second pass fail `InvalidSignature` against the first pass's still-cached key.
ISSUER_SEED="${ISSUER_SEED:-solid-server-rs-syscall-harness-issuer-v1}"

RESULTS="$HERE/syscalls-results"
STAMP="$(date -u +%Y-%m-%d)"
RAW="$RESULTS/raw/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RAW"

# --- build (release + debuginfo so perf report symbolizes; codegen unchanged otherwise) -----------
echo ">> Building server + driver (release, debuginfo for perf symbols) ..."
( cd "$REPO" && CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release --bin solid-server-rs --example syscall_load )
SERVER_BIN="$REPO/target/release/solid-server-rs"
DRIVER_BIN="$REPO/target/release/examples/syscall_load"
[ -x "$SERVER_BIN" ] && [ -x "$DRIVER_BIN" ] || { echo "ERROR: build did not produce $SERVER_BIN / $DRIVER_BIN" >&2; exit 1; }

# --- boot the server: plain HTTP, in-memory store, bench-seeded, mock-issuer trust ----------------
# Mirrors the conformance auth posture (ALLOW_LOOPBACK + http loopback issuer + BIDIRECTIONAL=off)
# but with NO TLS: the counted syscalls are the server's own socket pattern; the TLS delta is a
# separate follow-up. RATE_LIMIT off + REPLAY_MAX_ENTRIES raised = the documented bench posture
# (bench/README.md) so the limiter/replay-cap never contaminates the steady-state counts.
# JWKS TTL is raised so no mid-window JWKS refetch lands in a measured count.
echo ">> Booting solid-server-rs (plain HTTP, in-memory, bench-seeded) at ${BASE} ..."
SOLID_SERVER_BIND="127.0.0.1:${PORT}" \
SOLID_SERVER_BASE_URL="$BASE" \
SOLID_SERVER_AUDIENCE="$BASE" \
SOLID_SERVER_TRUSTED_ISSUER="http://127.0.0.1:${ISSUER_PORT}" \
SOLID_SERVER_ALLOW_LOOPBACK=1 \
SOLID_SERVER_BIDIRECTIONAL=off \
SOLID_SERVER_SEED_BENCH="$CHILDREN" \
SOLID_SERVER_SEED_BENCH_OWNER="$BENCH_OWNER_WEBID" \
SOLID_SERVER_RATE_LIMIT_PER_IP=off \
SOLID_SERVER_REPLAY_MAX_ENTRIES=5000000 \
SOLID_SERVER_JWKS_CACHE_TTL_SECS=86400 \
PSS_SPARQ_BACKEND=memory \
  "$SERVER_BIN" > "$RAW/server.log" 2>&1 &
SERVER_PID=$!

cleanup() {
  # $SERVER_PID is OUR direct child — no pgrep pattern matching, nothing else can be killed.
  kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for i in $(seq 1 40); do
  if curl -s -o /dev/null -w '%{http_code}' "${BASE}/bench/public/doc" 2>/dev/null | grep -q 200; then
    echo ">> Server ready (bench fixtures seeded)."; break
  fi
  sleep 0.5
  [ "$i" = 40 ] && { echo "ERROR: server not ready; log:" >&2; cat "$RAW/server.log" >&2; exit 1; }
done

# --- one driver pass under a given attach/detach recipe -------------------------------------------
# Runs the driver as a coprocess; on each READY attaches the tracer(s), sends GO, and on DONE
# detaches. $1 = pass name (strace|perf), $2 = comma scenario list, $3 = N.
run_pass() {
  local pass="$1" scen_list="$2" n="$3"
  echo ">> ${pass} pass: scenarios=${scen_list} n=${n}"
  local fifo="$RAW/${pass}.fifo"
  mkfifo "$fifo"
  # Keep a writer fd open for the fifo so the driver never sees EOF between GO lines.
  exec 4<>"$fifo"
  # `set +e` around the pipeline so a driver failure surfaces the diagnostic below instead of
  # aborting the script at the pipe (errexit + pipefail would otherwise exit here, skipping the
  # fifo cleanup + the "see the driver log" message).
  set +e
  "$DRIVER_BIN" --base "$BASE" --issuer-port "$ISSUER_PORT" --webid "$BENCH_OWNER_WEBID" \
    --issuer-seed "$ISSUER_SEED" \
    --scenarios "$scen_list" --n "$n" --warmup "$SYS_WARMUP" --idle-secs "$IDLE_SECS" \
    < "$fifo" 2>> "$RAW/driver-${pass}.log" | {
    local idx=0 tracer_pids=()
    while read -r tag scen rest; do
      case "$tag" in
        READY)
          tracer_pids=()
          if [ "$pass" = "strace" ]; then
            strace -f -c -o "$RAW/strace-${idx}-${scen}.txt" -p "$SERVER_PID" 2>> "$RAW/strace-attach.log" &
            tracer_pids+=("$!")
          else
            perf stat -p "$SERVER_PID" -o "$RAW/perfstat-${idx}-${scen}.txt" 2>/dev/null &
            tracer_pids+=("$!")
            perf record -o "$RAW/perf-${idx}-${scen}.data" -F 497 -g -e cpu-clock -p "$SERVER_PID" \
              >> "$RAW/perf-record.log" 2>&1 &
            tracer_pids+=("$!")
          fi
          sleep 1.5  # let the tracer finish attaching to all runtime threads before load starts
          echo "GO" >&4
          ;;
        DONE)
          # Land the driver's one-line JSON summary, then detach the tracer(s).
          printf '%s\n' "$rest" > "$RAW/driver-${pass}-${idx}-${scen}.json"
          sleep 0.5  # drain: let trailing response syscalls land before detach
          local tp
          for tp in "${tracer_pids[@]}"; do kill -INT "$tp" 2>/dev/null || true; done
          for tp in "${tracer_pids[@]}"; do wait "$tp" 2>/dev/null || true; done
          idx=$((idx + 1))
          ;;
      esac
    done
  }
  local rc="${PIPESTATUS[0]}"
  set -e
  exec 4>&-
  rm -f "$fifo"
  if [ "$rc" != 0 ]; then
    echo "ERROR: driver exited rc=$rc in the ${pass} pass — results INVALID. Driver log:" >&2
    tail -5 "$RAW/driver-${pass}.log" >&2 || true
    exit 1
  fi
}

# --- STRACE PASS (deterministic): idle noise floor once, then each class x SYS_REPS ----------------
STRACE_SCENARIOS="idle"
for _ in $(seq 1 "$SYS_REPS"); do
  STRACE_SCENARIOS="${STRACE_SCENARIOS},anon-doc,listing,authed-doc,put"
done
run_pass strace "$STRACE_SCENARIOS" "$SYS_N"

# --- GUARD: a DENIED strace attach leaves an EMPTY -o summary table, which the report would render
# as "0 syscalls/request" — a silently-bogus committed baseline. The usual cause on a fresh box is
# YAMA: strace attaches to the SERVER, which is a SIBLING (not a descendant) of the tracer, so
# `kernel.yama.ptrace_scope` must be 0 (see bench/RUN-ON-EC2.md). Fail loudly with that hint rather
# than emit a zero-count report.
strace_tables=0
for f in "$RAW"/strace-*.txt; do
  [ -e "$f" ] || continue
  strace_tables=$((strace_tables + 1))
  if [ ! -s "$f" ]; then
    echo "ERROR: strace produced an EMPTY summary table ($f) — the attach was almost certainly DENIED." >&2
    echo "       Run: sudo sysctl kernel.yama.ptrace_scope=0   (strace must attach to a sibling process)" >&2
    echo "       then re-run ./bench/syscalls.sh. See bench/RUN-ON-EC2.md. strace attach log:" >&2
    cat "$RAW/strace-attach.log" >&2 2>/dev/null || true
    exit 1
  fi
done
if [ "$strace_tables" = 0 ]; then
  echo "ERROR: the strace pass produced NO summary tables in $RAW — results INVALID (attach denied?)." >&2
  cat "$RAW/strace-attach.log" >&2 2>/dev/null || true
  exit 1
fi
echo ">> strace pass OK: $strace_tables non-empty syscall tables."

# --- PERF PASS (advisory): one window per class ---------------------------------------------------
if [ -z "$SKIP_PERF" ]; then
  run_pass perf "anon-doc,listing,authed-doc,put" "$PERF_N"
  echo ">> Rendering perf reports ..."
  for data in "$RAW"/perf-*.data; do
    [ -e "$data" ] || continue
    stem="$(basename "$data" .data)"
    perf report --stdio --percent-limit 1 -i "$data" > "$RAW/${stem}-symbols.txt" 2>/dev/null || true
    perf report --stdio --sort dso -i "$data" > "$RAW/${stem}-dso.txt" 2>/dev/null || true
  done
fi

# --- render the committed report -------------------------------------------------------------------
echo ">> Rendering the report ..."
GIT_SHA="$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
python3 "$HERE/syscalls-report.py" \
  --raw "$RAW" \
  --out-json "$RESULTS/${STAMP}-linux.json" \
  --out-md "$RESULTS/${STAMP}-linux.md" \
  --n "$SYS_N" --perf-n "$PERF_N" --warmup "$SYS_WARMUP" --idle-secs "$IDLE_SECS" \
  --children "$CHILDREN" --git-sha "$GIT_SHA" --instance "$INSTANCE_LABEL"

echo ">> DONE. Committed-artifact candidates:"
echo "   $RESULTS/${STAMP}-linux.json"
echo "   $RESULTS/${STAMP}-linux.md"
echo "   (raw regenerable artifacts in $RAW — gitignored)"
