#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Profile the AUTHENTICATED (DPoP) GET hot path: samply launches the server (conformance-seeded, the
# exact auth env run-auth.sh uses), the auth_load Rust client mints a DPoP token + drives a c=CONC
# authed sweep against the private fixture for the window, then we SIGINT the SERVER (samply's child)
# so it exits and samply writes the profile. MEASUREMENT-ONLY, not committed to main.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${AUTH_BENCH_PORT:-3000}"
BASE_URL="https://localhost:${PORT}"
CONNECT_HOST="${AUTH_CONNECT_HOST:-127.0.0.1}"
ISSUER="${AUTH_ISSUER:-http://localhost:8080/realms/solid}"
CLIENT_ID="${AUTH_CLIENT_ID:-conformance-alice}"
CLIENT_SECRET="${AUTH_CLIENT_SECRET:-conformance-alice-secret}"
CERT="$REPO/bench/tls/server-cert.pem"
KEY="$REPO/bench/tls/server-key.pem"
SERVER_BIN="$REPO/target/release/solid-server-rs"
CLIENT_BIN="$REPO/target/release/examples/auth_load"
CONC="${CONC:-16}"
RECORD_SECS="${RECORD_SECS:-20}"
SCEN="${SCEN:-doc}"   # doc (private doc, scenario c) | listing (private listing, scenario d)
OUT="${OUT:-$REPO/bench/prof-auth-${SCEN}.json.gz}"
RESULTS="$REPO/bench/results-auth-prof"; mkdir -p "$RESULTS"

if [ "$SCEN" = listing ]; then TARGET="/alice/test/"; CHILDREN="${AUTH_LISTING_CHILDREN:-100}"; PUTFIX=1
else TARGET="/alice/test/bench-private"; CHILDREN=0; PUTFIX=1; fi

pkill -f "target/release/solid-server-rs" 2>/dev/null || true
pkill -f "samply record" 2>/dev/null || true
sleep 1
rm -f "$OUT"

echo ">> samply launching server (conformance-seeded) at $BASE_URL ..."
SOLID_SERVER_BIND="127.0.0.1:${PORT}" \
SOLID_SERVER_BASE_URL="$BASE_URL" \
SOLID_SERVER_AUDIENCE="$BASE_URL" \
SOLID_SERVER_ALLOW_LOOPBACK=1 \
SOLID_SERVER_BIDIRECTIONAL=off \
SOLID_SERVER_TRUSTED_ISSUER="$ISSUER" \
SOLID_SERVER_SEED_CONFORMANCE=1 \
SOLID_SERVER_SEED_BENCH=1 \
SOLID_SERVER_REPLAY_MAX_ENTRIES=5000000 \
SOLID_SERVER_TLS_CERT="$CERT" \
SOLID_SERVER_TLS_KEY="$KEY" \
samply record --no-open --save-only -o "$OUT" -- "$SERVER_BIN" \
  > "$REPO/bench/prof-server-auth-${SCEN}.log" 2>&1 &
SAMPLY_PID=$!

ready=0
for i in $(seq 1 80); do
  if curl -sf --insecure -o /dev/null "https://${CONNECT_HOST}:${PORT}/bench/public/doc"; then ready=1; break; fi
  sleep 0.25
done
[ "$ready" = 1 ] || { echo "server not ready"; cat "$REPO/bench/prof-server-auth-${SCEN}.log"; kill "$SAMPLY_PID" 2>/dev/null; exit 1; }
# pgrep -x matches by exact process name (comm) — the server's comm is "solid-server-rs", samply's is
# "samply", so this selects the server child without matching samply's cmdline.
SERVER_PID="$(pgrep -x solid-server-rs | head -1)"
echo ">> ready (server pid=$SERVER_PID); driving authed c=$CONC for ${RECORD_SECS}s, scen=$SCEN ..."

AUTH_BASE_URL="$BASE_URL" \
AUTH_CONNECT_HOST="$CONNECT_HOST" \
AUTH_ISSUER="$ISSUER" \
AUTH_CLIENT_ID="$CLIENT_ID" \
AUTH_CLIENT_SECRET="$CLIENT_SECRET" \
AUTH_TARGET_PATH="$TARGET" \
AUTH_LISTING_PATH="" \
AUTH_LISTING_CHILDREN="$CHILDREN" \
AUTH_PUT_FIXTURE="$PUTFIX" \
AUTH_DURATION_SECS="$RECORD_SECS" \
AUTH_WARMUP_SECS=4 \
AUTH_CONCURRENCY="$CONC" \
AUTH_OUT_DIR="$RESULTS" \
"$CLIENT_BIN" > "$RESULTS/authed-${SCEN}.tsv" 2>"$RESULTS/client-${SCEN}.err" || { echo "CLIENT FAILED"; cat "$RESULTS/client-${SCEN}.err"; }

echo ">> sweep done; SIGINT server ($SERVER_PID) → samply writes profile ..."
kill -INT "$SERVER_PID" 2>/dev/null || true
for i in $(seq 1 60); do [ -f "$OUT" ] && break; sleep 0.5; done
wait "$SAMPLY_PID" 2>/dev/null || true
echo ">> profile: $(ls -la "$OUT" 2>/dev/null || echo MISSING)"
echo ">> authed sweep tsv:"; cat "$RESULTS/authed-${SCEN}.tsv" 2>/dev/null | tail -4
