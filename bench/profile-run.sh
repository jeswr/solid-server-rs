#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Profiling driver (MEASUREMENT-ONLY, NOT committed to main). samply LAUNCHES the server (no
# task_for_pid entitlement needed for a samply-spawned child). After the load window we send SIGINT
# to the SERVER process (samply's child) directly — its Ctrl-C graceful-shutdown exits cleanly, and
# samply (which is waiting on its child) then writes the profile. (Signalling samply itself does NOT
# propagate to the child, so we target the server PID.)
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-3220}"
BASE_URL="https://localhost:${PORT}"
CHILDREN="${CHILDREN:-100}"
CERT="$REPO/bench/tls/server-cert.pem"
KEY="$REPO/bench/tls/server-key.pem"
SERVER_BIN="$REPO/target/release/solid-server-rs"
DIAL="127.0.0.1:${PORT}"
SCENARIO="${SCENARIO:-public}"   # public | listing
CONC="${CONC:-16}"
RECORD_SECS="${RECORD_SECS:-20}"
OUT="${OUT:-$REPO/bench/prof-${SCENARIO}.json.gz}"

case "$SCENARIO" in
  public)  URL="https://${DIAL}/bench/public/doc" ;;
  listing) URL="https://${DIAL}/bench/listing/" ;;
  *) echo "unknown SCENARIO $SCENARIO" >&2; exit 1 ;;
esac

pkill -f "target/release/solid-server-rs" 2>/dev/null || true
pkill -f "samply record" 2>/dev/null || true
sleep 1
rm -f "$OUT"

echo ">> samply launching server at $BASE_URL, seed=$CHILDREN ..."
SOLID_SERVER_BIND="127.0.0.1:${PORT}" \
SOLID_SERVER_BASE_URL="$BASE_URL" \
SOLID_SERVER_AUDIENCE="$BASE_URL" \
SOLID_SERVER_ALLOW_LOOPBACK=1 \
SOLID_SERVER_BIDIRECTIONAL=off \
SOLID_SERVER_TRUSTED_ISSUER="http://localhost:8080/realms/solid" \
SOLID_SERVER_SEED_BENCH="$CHILDREN" \
SOLID_SERVER_TLS_CERT="$CERT" \
SOLID_SERVER_TLS_KEY="$KEY" \
samply record --no-open --save-only -o "$OUT" -- "$SERVER_BIN" \
  > "$REPO/bench/prof-server-${SCENARIO}.log" 2>&1 &
SAMPLY_PID=$!

ready=0
for i in $(seq 1 80); do
  if curl -sf --insecure -o /dev/null "https://${DIAL}/bench/public/doc"; then ready=1; break; fi
  sleep 0.25
done
[ "$ready" = 1 ] || { echo "server not ready"; cat "$REPO/bench/prof-server-${SCENARIO}.log"; kill "$SAMPLY_PID" 2>/dev/null; exit 1; }
# pgrep -x matches by exact process name (comm) — the server's comm is "solid-server-rs", samply's is
# "samply", so this selects the server child without matching samply's cmdline.
SERVER_PID="$(pgrep -x solid-server-rs | head -1)"
echo ">> ready (server pid=$SERVER_PID); warm-up 3s ..."
oha --no-tui --insecure --output-format quiet -c "$CONC" -z 3s "$URL" >/dev/null 2>&1 || true

echo ">> load c=$CONC for ${RECORD_SECS}s against $URL ..."
oha --no-tui --insecure --output-format json -c "$CONC" -z "${RECORD_SECS}s" "$URL" \
    > "$REPO/bench/prof-${SCENARIO}-oha.json" 2>/dev/null || true

echo ">> load done; SIGINT server ($SERVER_PID) → graceful exit → samply writes profile ..."
kill -INT "$SERVER_PID" 2>/dev/null || true
# Wait for samply to flush the profile (it writes once the child exits).
for i in $(seq 1 60); do
  [ -f "$OUT" ] && break
  sleep 0.5
done
wait "$SAMPLY_PID" 2>/dev/null || true

echo ">> profile: $(ls -la "$OUT" 2>/dev/null || echo MISSING)"
python3 -c "import json; d=json.load(open('$REPO/bench/prof-${SCENARIO}-oha.json')); s=d['summary']; print(f\"  RPS={s['requestsPerSec']:.0f}  successRate={s.get('successRate','?')}  p50={s.get('latencyPercentiles',{}).get('p50','?')}\")" 2>/dev/null || echo "  (oha parse skipped)"
