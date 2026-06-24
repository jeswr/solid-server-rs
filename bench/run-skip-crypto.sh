#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Skip-crypto opt-3 measurement: the ANONYMOUS PUBLIC-read path the implemented skip actually changes.
#
# IMPORTANT (see decisions/0002 + bench/SKIP-CRYPTO.md): the implemented opt-3 skip fires ONLY for a
# GET/HEAD that carries NO Authorization/DPoP header. A CREDENTIALED (proof-carrying) read is NEVER
# short-circuited — the WAC-Allow `user=` field is identity-dependent and a forged proof is
# indistinguishable from an owner's without the crypto (the credentialed variant FAILED conformance).
# So this script measures the ANONYMOUS public read (BENCH_MODE=anon, the default — the path the skip
# changes). There is no crypto win on the anonymous path (no proof to verify); the result is whether
# the small structural difference (one fewer token construction + a layer hop) shows above noise.
#
# An EXPLORATORY authed-public sweep (BENCH_MODE=authed) is retained only to demonstrate that the
# ES256 verify is the cost — it drives proof-carrying reads the middleware does NOT skip, so a delta
# there is NOT a shippable result (it is the conformance-failing configuration). Default is `anon`.
#
# Run it on each binary in turn:  SERVER_BIN=<path> AUTH_OUT_DIR=<dir> ./bench/run-skip-crypto.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

PORT="${BENCH_PORT:-3000}"
BASE_URL="https://localhost:${PORT}"
CONNECT_HOST="${BENCH_CONNECT_HOST:-127.0.0.1}"
ISSUER="${AUTH_ISSUER:-http://localhost:8080/realms/solid}"
SERVER_BIN="${SERVER_BIN:-$REPO/target/release/solid-server-rs}"
OUT_DIR="${AUTH_OUT_DIR:-$REPO/bench/results-skip}"
CERT="${BENCH_CERT:-$HERE/tls/server-cert.pem}"
KEY="${BENCH_KEY:-$HERE/tls/server-key.pem}"
CONCURRENCY="${AUTH_CONCURRENCY:-1 8 16 32 64 128}"
DURATION_SECS="${AUTH_DURATION_SECS:-10}"
# Keep the replay store large so the unique-jti-per-request sweep does not fill it within the window.
REPLAY_MAX_ENTRIES="${AUTH_REPLAY_MAX_ENTRIES:-5000000}"
# `anon` (default) = the ANONYMOUS public-read path the implemented skip actually changes.
# `authed` = the EXPLORATORY proof-carrying-public path the middleware does NOT skip (NOT a shippable
# result — see the header). Default `anon`.
BENCH_MODE="${BENCH_MODE:-anon}"

[ -f "$CERT" ] || bash "$HERE/gen-cert.sh"
rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR"

echo ">> Booting $SERVER_BIN (in-memory, TLS, conformance+bench seeded) at ${BASE_URL} ..."
SOLID_SERVER_BIND="127.0.0.1:${PORT}" \
SOLID_SERVER_BASE_URL="$BASE_URL" \
SOLID_SERVER_AUDIENCE="$BASE_URL" \
SOLID_SERVER_ALLOW_LOOPBACK=1 \
SOLID_SERVER_BIDIRECTIONAL=off \
SOLID_SERVER_TRUSTED_ISSUER="$ISSUER" \
SOLID_SERVER_SEED_CONFORMANCE=1 \
SOLID_SERVER_SEED_BENCH=1 \
SOLID_SERVER_REPLAY_MAX_ENTRIES="$REPLAY_MAX_ENTRIES" \
SOLID_SERVER_TLS_CERT="$CERT" \
SOLID_SERVER_TLS_KEY="$KEY" \
"$SERVER_BIN" > "$OUT_DIR/server.log" 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

for i in $(seq 1 40); do
  if curl -sk -o /dev/null -w '%{http_code}' "https://${CONNECT_HOST}:${PORT}/bench/public/doc" 2>/dev/null | grep -q 200; then
    echo ">> Server ready (public bench doc readable)."; break
  fi
  sleep 0.25
  [ "$i" = 40 ] && { echo "ERROR: server not ready; log:" >&2; cat "$OUT_DIR/server.log" >&2; exit 1; }
done

if [ "$BENCH_MODE" = "authed" ]; then
  echo ">> EXPLORATORY authed-public sweep (proof-carrying GET — NOT skipped by the middleware) ..."
  # Set BOTH flags explicitly + mutually exclusive so an inherited AUTH_ANON in the environment can't
  # silently flip the mode (auth_load treats AUTH_ANON=1 as anonymous regardless of AUTH_EXPECT_PUBLIC).
  MODE_ENV=(AUTH_ANON=0 AUTH_EXPECT_PUBLIC=1)
else
  echo ">> ANONYMOUS public-read sweep (the path opt-3 implements) — GET /bench/public/doc, no token ..."
  MODE_ENV=(AUTH_ANON=1 AUTH_EXPECT_PUBLIC=0)
fi
# Run through `env` so the per-mode assignment (`AUTH_ANON=1` / `AUTH_EXPECT_PUBLIC=1`) is applied as
# an ENVIRONMENT variable, not executed as a command. (A bare `"${MODE_ENV[@]}"` in a leading
# assignment list is treated as the command word once the array expands — the bug review flagged.)
env "${MODE_ENV[@]}" \
  AUTH_BASE_URL="$BASE_URL" \
  AUTH_CONNECT_HOST="$CONNECT_HOST" \
  AUTH_ISSUER="$ISSUER" \
  AUTH_TARGET_PATH="/bench/public/doc" \
  AUTH_PUT_FIXTURE=0 \
  AUTH_LISTING_PATH="" \
  AUTH_CONCURRENCY="$CONCURRENCY" \
  AUTH_DURATION_SECS="$DURATION_SECS" \
  AUTH_REPLAY_MAX_ENTRIES="$REPLAY_MAX_ENTRIES" \
  AUTH_OUT_DIR="$OUT_DIR" \
  "$REPO/target/release/examples/auth_load" | tee "$OUT_DIR/sweep.tsv"

echo ">> Done. Results in $OUT_DIR (*-public-doc-c*.json + sweep.tsv). Mode: $BENCH_MODE."
