#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
#
# syscalls-fd-kind.sh — the nl48 CONFIRM run: attribute the doc-GET write-class syscalls BY FD KIND.
#
# ## Why this exists (bead suite-tracker-nl48)
# The P0.1 aggregate baseline (`bench/syscalls-results/2026-07-04-linux.md`) shows a `write` 1.04/req
# + `writev` 1.04/req pair on the anonymous doc-GET class and reads it as "the response head+body are
# not coalesced — collapse them into one write-class syscall". That reading is WRONG, and the merged
# P1.4 audit already proved it: `tests/response_write_coalescing.rs` drives the REAL router over the
# REAL `axum::serve` path and measures — at the hyper→transport socket seam — exactly **1 writev, 0
# write PER RESPONSE** (public GET, 206 Range, listing, authed GET). The response IS already one
# vectored socket write. See the merged commits `9735725` / `f87ec0d` / `579fcbf`.
#
# So the aggregate `write` 1.04/req is NOT the response. `strace -f -c` (what `syscalls.sh` uses)
# tallies ALL write(2) calls by the whole process with NO fd attribution, so a NON-socket write is
# indistinguishable from a socket write in that summary. This script closes that gap: it re-runs the
# anon-doc window under `strace -f -yy -e trace=write,writev` — the `-yy` flag annotates every fd with
# its KIND — and buckets each write/writev into `socket` (`<TCP:…>`/`<socket:…>` — the response) vs
# `eventfd` (`<anon_inode:[eventfd]>` — the tokio multi-thread runtime's mio reactor waker) vs other.
#
# ## The hypothesis this run confirms (or refutes)
#   - socket `writev`  ≈ 1 / req   → the response (head+body already coalesced — matches P1.4).
#   - socket `write`   ≈ 0 / req   → NO split head/body write on the response.
#   - eventfd `write`  ≈ 1 / req   → the reactor waker unpark. This is the P0.1 aggregate `write` —
#     a SINGLE-connection ping-pong artifact (one cross-worker wakeup per request); under real
#     concurrent load one wakeup services many ready connections, so it amortizes toward 0/req.
# If those hold, the doc-serve response path is ALREADY at the one-write-class-per-response target and
# there is NO response-serialization change to make; the only remaining write-class lever is
# runtime-level (SO_REUSEPORT thread-per-core accept — the separate P1.7/Phase-3 direction), which is
# out of a pure micro-opt's scope.
#
# ## Usage (Linux only — the EC2 lane; needs strace + a built server)
#   sudo sysctl kernel.yama.ptrace_scope=0     # strace attaches to a sibling process
#   ./bench/syscalls-fd-kind.sh                # add SCEN=put to also break down the PUT class
# Knobs: FD_N (400 requests — plenty to read the ratio; NOT the 5000 of the gated harness, since a
# full -yy trace is far heavier than -c), SCEN (anon-doc|put|listing|authed-doc), FD_PORT/FD_ISSUER_PORT.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

[ "$(uname -s)" = "Linux" ] || { echo "ERROR: Linux-only (strace fd-kind tracing) — run on the EC2 lane, see bench/SYSCALLS.md" >&2; exit 1; }
command -v strace >/dev/null || { echo "ERROR: strace not installed (dnf install -y strace)" >&2; exit 1; }

FD_N="${FD_N:-400}"
SCEN="${SCEN:-anon-doc}"
WARMUP="${FD_WARMUP:-200}"
PORT="${FD_PORT:-3410}"
ISSUER_PORT="${FD_ISSUER_PORT:-3411}"
CHILDREN="${CHILDREN:-100}"
BASE="http://127.0.0.1:${PORT}"
BENCH_OWNER_WEBID="${BENCH_OWNER_WEBID:-https://bench.invalid/profile/card#me}"
ISSUER_SEED="${ISSUER_SEED:-solid-server-rs-syscall-harness-issuer-v1}"

RAW="$HERE/syscalls-results/raw/fd-kind-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RAW"

echo ">> Building server + driver (release) ..."
( cd "$REPO" && cargo build --release --bin solid-server-rs --example syscall_load )
SERVER_BIN="$REPO/target/release/solid-server-rs"
DRIVER_BIN="$REPO/target/release/examples/syscall_load"
[ -x "$SERVER_BIN" ] && [ -x "$DRIVER_BIN" ] || { echo "ERROR: build did not produce the binaries" >&2; exit 1; }

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
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }   # $SERVER_PID is OUR direct child
trap cleanup EXIT INT TERM

for i in $(seq 1 40); do
  if curl -s -o /dev/null -w '%{http_code}' "${BASE}/bench/public/doc" 2>/dev/null | grep -q 200; then
    echo ">> Server ready (bench fixtures seeded)."; break
  fi
  sleep 0.5
  [ "$i" = 40 ] && { echo "ERROR: server not ready; log:" >&2; cat "$RAW/server.log" >&2; exit 1; }
done

# One driver pass under strace -yy, mirroring the proven READY/GO coprocess dance in syscalls.sh but
# with the fd-annotating full trace (not `-c`) restricted to write/writev on the single class.
TRACE="$RAW/strace-yy-${SCEN}.txt"
fifo="$RAW/fd.fifo"; mkfifo "$fifo"; exec 4<>"$fifo"
set +e
"$DRIVER_BIN" --base "$BASE" --issuer-port "$ISSUER_PORT" --webid "$BENCH_OWNER_WEBID" \
  --issuer-seed "$ISSUER_SEED" --scenarios "$SCEN" --n "$FD_N" --warmup "$WARMUP" --idle-secs 1 \
  < "$fifo" 2>> "$RAW/driver.log" | {
  tracer=""
  while read -r tag scen rest; do
    case "$tag" in
      READY)
        # `-yy` annotates each fd with its kind. No `-e status=` filter (older strace lacks it; failed
        # write/writev are essentially nonexistent on a healthy loopback, and the awk only tallies
        # lines that carry a return value `= <n>`).
        strace -f -yy -e trace=write,writev -o "$TRACE" -p "$SERVER_PID" \
          2>> "$RAW/strace-attach.log" &
        tracer="$!"
        sleep 1.5   # let strace attach to every runtime thread before load starts
        echo "GO" >&4
        ;;
      DONE)
        printf '%s\n' "$rest" > "$RAW/driver-${scen}.json"
        sleep 0.5
        kill -INT "$tracer" 2>/dev/null || true
        wait "$tracer" 2>/dev/null || true
        ;;
    esac
  done
}
rc="${PIPESTATUS[0]}"
set -e
exec 4>&-; rm -f "$fifo"
[ "$rc" = 0 ] || { echo "ERROR: driver rc=$rc — see $RAW/driver.log" >&2; tail -5 "$RAW/driver.log" >&2 || true; exit 1; }

if ! [ -s "$TRACE" ]; then
  echo "ERROR: empty strace output ($TRACE) — the attach was almost certainly DENIED." >&2
  echo "       Run: sudo sysctl kernel.yama.ptrace_scope=0   then re-run. Attach log:" >&2
  cat "$RAW/strace-attach.log" >&2 2>/dev/null || true
  exit 1
fi

echo
echo "== nl48 write-class attribution by fd kind — scenario=${SCEN}, N=${FD_N} (successful calls) =="
# Each traced line looks like:  [pid 123] writev(7<TCP:[127.0.0.1:3410->127.0.0.1:54xxx]>, [...], 2) = 116
# or:                           [pid 124] write(9<anon_inode:[eventfd]>, "\1\0\0\0\0\0\0\0", 8) = 8
# Bucket by (call, fd-kind). The counts/N confirm: socket writev ~1, socket write ~0, eventfd write ~1.
awk -v n="$FD_N" '
  function kind(line) {
    if (line ~ /<(TCP|UDP|socket):/)      return "socket";
    if (line ~ /<anon_inode:\[eventfd\]>/) return "eventfd";
    if (line ~ /<pipe:/)                   return "pipe";
    return "other";
  }
  /[ \t]writev\(/ { v[kind($0)]++; next }
  /[ \t]write\(/  { w[kind($0)]++; next }
  END {
    printf "  %-18s %8s %10s\n", "bucket", "count", "per-req";
    for (k in v) printf "  writev/%-11s %8d %10.3f\n", k, v[k], v[k]/n;
    for (k in w) printf "  write /%-11s %8d %10.3f\n", k, w[k], w[k]/n;
    print "";
    print "  EXPECT (nl48 hypothesis): writev/socket ~1.0  write/socket ~0.0  write/eventfd ~1.0";
    print "  => response = 1 vectored socket write (already coalesced); the aggregate write(2) is the";
    print "     tokio reactor waker (eventfd), NOT a split response head — no serialization fix applies.";
  }
' "$TRACE"
echo
echo ">> raw fd-annotated trace: $TRACE"
