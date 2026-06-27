#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# A/B listing-render micro-bench (MEASUREMENT-ONLY, not committed): boot a GIVEN binary in-memory
# over TLS bench-seeded with N children, sweep the listing scenario at c=CONC for one window, print
# the RPS. Interleaved BEFORE/AFTER reps average out box noise. Wall-clock timing is ADVISORY (per the
# perf-gate rule) — the deterministic substance is the eliminated per-child Unicode table lookup.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$1"; CHILDREN="${2:-100}"; PORT="${3:-3260}"; CONC="${CONC:-16}"; DUR="${DUR:-6s}"
CERT="$REPO/bench/tls/server-cert.pem"; KEY="$REPO/bench/tls/server-key.pem"
DIAL="127.0.0.1:${PORT}"; BASE="https://localhost:${PORT}"; URL="https://${DIAL}/bench/listing/"

pkill -f "$BIN" 2>/dev/null || true; sleep 0.5
SOLID_SERVER_BIND="127.0.0.1:${PORT}" SOLID_SERVER_BASE_URL="$BASE" SOLID_SERVER_AUDIENCE="$BASE" \
SOLID_SERVER_ALLOW_LOOPBACK=1 SOLID_SERVER_BIDIRECTIONAL=off \
SOLID_SERVER_TRUSTED_ISSUER="http://localhost:8080/realms/solid" SOLID_SERVER_SEED_BENCH="$CHILDREN" \
SOLID_SERVER_TLS_CERT="$CERT" SOLID_SERVER_TLS_KEY="$KEY" \
"$BIN" >/tmp/ab-server.log 2>&1 &
PID=$!
for i in $(seq 1 80); do curl -sf --insecure -o /dev/null "https://${DIAL}/bench/public/doc" && break; sleep 0.25; done
oha --no-tui --insecure --output-format quiet -c "$CONC" -z 2s "$URL" >/dev/null 2>&1 || true
J=$(oha --no-tui --insecure --output-format json -c "$CONC" -z "$DUR" "$URL" 2>/dev/null)
kill -INT "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true
echo "$J" | python3 -c "import json,sys; d=json.load(sys.stdin); s=d['summary']; print(f\"{s['requestsPerSec']:.0f}\t{s.get('successRate')}\t{s.get('latencyPercentiles',{}).get('p50')}\")"
