#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Reproducible AUTHENTICATED (DPoP) HTTPS load benchmark for the EXPERIMENTAL Rust solid-server-rs.
#
# This is the round-2 auth-path companion to `bench/run.sh` (the auth-FREE `oha` sweep). It measures
# the realistic PRODUCTION path: an authenticated GET over DPoP, where the server pays
#   DPoP-proof verify + access-token verify + JWKS-cache lookup + token parse + the single ACL
#   read/parse (round-1 Opt #2 lands its saving HERE) + the store byte fetch + response assembly.
# `oha` cannot mint a fresh RFC 9449 DPoP proof per request, so this drives a small Rust load client
# (`examples/auth_load.rs`) that DOES — see that file's module doc and bench/README.md "Auth bench".
#
# Token flow (REUSED from conformance — no new auth flow invented): the load client obtains a
# DPoP-bound RFC 9068 access token from the SAME Keycloak `solid` realm + `conformance-alice`
# client-credentials service account the conformance harness uses (conformance/config/solid-server-rs.env),
# then mints a fresh DPoP proof per request (htu = exact URL, htm = GET, unique jti, ath over the
# token). The server is booted with SOLID_SERVER_SEED_CONFORMANCE=1 (so alice's WebID + owner-controlled
# pod exist) — the load client PUTs a private fixture document into alice's pod, asserts a single authed
# GET → 200 (and an anonymous GET → 401, i.e. genuinely private) BEFORE the sweep, then sweeps.
#
# It also re-runs the ANONYMOUS public-doc + listing sweep (via the same client, no token) at matched
# concurrency so the AUTH OVERHEAD (authed RPS/latency vs anonymous) is measured on the SAME box,
# binary, TLS stack, and run — not compared across separate runs. (The anon numbers here use the auth
# client with no credentials so the client overhead is identical; the absolute anon ceiling is in
# bench/BASELINE.md from the `oha` harness.)
#
# Prerequisites:
#   - The `solid` Keycloak realm UP at http://localhost:8080/realms/solid with the conformance-alice
#     DPoP service-account client (the SAME realm prod-solid-server conformance uses — `docker compose
#     up -d` in prod-solid-server). NOTHING about that realm is modified by this script.
#   - A `--release` build of the server + the example (this script builds both if missing/stale).
#   - openssl (for the self-signed cert via bench/gen-cert.sh).
#
# Re-run: `./bench/run-auth.sh`. Override knobs via env (see the CONFIG block). The numbers it prints
# are REAL measurements on the box it runs on — record the machine + date in bench/AUTH-BASELINE.md.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

# --- CONFIG (override via env) ------------------------------------------------------------------
PORT="${AUTH_BENCH_PORT:-3000}"                 # 3000 == the conformance base the realm tokens' aud expects
BASE_URL="https://localhost:${PORT}"
CONNECT_HOST="${AUTH_CONNECT_HOST:-127.0.0.1}"  # dial the IPv4 literal (IPv6-localhost trap — see bench/README)
ISSUER="${AUTH_ISSUER:-http://localhost:8080/realms/solid}"
CLIENT_ID="${AUTH_CLIENT_ID:-conformance-alice}"
CLIENT_SECRET="${AUTH_CLIENT_SECRET:-conformance-alice-secret}"
DURATION_SECS="${AUTH_DURATION_SECS:-10}"       # measured window per concurrency level
WARMUP_SECS="${AUTH_WARMUP_SECS:-3}"            # discarded warm-up before each scenario
CONCURRENCY="${AUTH_CONCURRENCY:-1 8 16 32 64 128 256 512}"
LISTING_CHILDREN="${AUTH_LISTING_CHILDREN:-100}" # children PUT into the authed-listing container (scenario d)
# DPoP replay-store capacity for the bench server. The PRODUCTION default is 100_000 live jtis within
# the proof-age TTL window (~305s) — which a SUSTAINED high-RPS authed run fills in seconds, after
# which the store CORRECTLY fails closed (rejecting further proofs). That is a real production
# behaviour (documented as a round-3 finding in bench/AUTH-BASELINE.md), but it would CONTAMINATE the
# steady-state verify-cost measurement (we'd measure the fail-closed path, not the auth path). So the
# bench raises the cap (dev/bench-only env, default-off in the server — UNSET ⇒ 100_000 unchanged) to
# comfortably exceed the total request count of one full sweep, so every level measures the genuine
# verify path at 100% success. 5,000,000 covers an 8-level × 10s sweep at this box's RPS.
REPLAY_MAX_ENTRIES="${AUTH_REPLAY_MAX_ENTRIES:-5000000}"
SERVER_BIN="${SERVER_BIN:-$REPO/target/release/solid-server-rs}"
CLIENT_BIN="${CLIENT_BIN:-$REPO/target/release/examples/auth_load}"
CERT="$HERE/tls/server-cert.pem"
KEY="$HERE/tls/server-key.pem"
RESULTS="$HERE/results-auth"

# --- pre-flight ---------------------------------------------------------------------------------
# Keycloak reachable? (the realm that mints the DPoP-bound token). A clear message beats a cryptic
# token-endpoint error from the client.
curl -s -m 5 "${ISSUER%/}/.well-known/openid-configuration" -o /dev/null \
  || { echo "ERROR: Keycloak realm unreachable at ${ISSUER} — is 'docker compose up -d' running (prod-solid-server)?" >&2; exit 1; }

# ALWAYS (re)build — a stale binary silently mismeasures the code you changed (same rationale as run.sh).
echo ">> Building release server + auth-load example (no-op if current) ..."
( cd "$REPO" && cargo build --release && cargo build --release --example auth_load )

bash "$HERE/gen-cert.sh"

rm -rf "$RESULTS"; mkdir -p "$RESULTS"

# --- boot the server (in-memory, TLS, CONFORMANCE-seeded so alice's pod exists) -----------------
# Conformance seed (not bench seed): it seeds alice's WebID + owner-controlled pod, into which the
# load client PUTs the private fixture. ALLOW_LOOPBACK + http issuer + BIDIRECTIONAL=off match the
# conformance run (the realm token's iss is localhost:8080 → must resolve to loopback; aud is the
# base URL). These are the EXACT auth env knobs conformance/run.sh uses — the verify path is identical.
echo ">> Booting solid-server-rs (in-memory, TLS, conformance-seeded) at ${BASE_URL} ..."
SOLID_SERVER_BIND="127.0.0.1:${PORT}" \
SOLID_SERVER_BASE_URL="$BASE_URL" \
SOLID_SERVER_AUDIENCE="$BASE_URL" \
SOLID_SERVER_ALLOW_LOOPBACK=1 \
SOLID_SERVER_BIDIRECTIONAL=off \
SOLID_SERVER_TRUSTED_ISSUER="$ISSUER" \
SOLID_SERVER_SEED_CONFORMANCE=1 \
SOLID_SERVER_SEED_BENCH="$LISTING_CHILDREN" \
SOLID_SERVER_REPLAY_MAX_ENTRIES="$REPLAY_MAX_ENTRIES" \
SOLID_SERVER_TLS_CERT="$CERT" \
SOLID_SERVER_TLS_KEY="$KEY" \
"$SERVER_BIN" > "$RESULTS/server.log" 2>&1 &
SERVER_PID=$!

cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Readiness: alice's WebID card readable (seeding done).
for i in $(seq 1 40); do
  if curl -sk -o /dev/null -w '%{http_code}' "https://${CONNECT_HOST}:${PORT}/alice/profile/card" 2>/dev/null | grep -q 200; then
    echo ">> Server ready (alice WebID readable)."; break
  fi
  sleep 0.25
  [ "$i" = 40 ] && { echo "ERROR: server did not become ready; log:" >&2; cat "$RESULTS/server.log" >&2; exit 1; }
done

# Note the box (for the AUTH-BASELINE doc — recorded by hand, never Date.now).
echo ">> Machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"

# --- (1) the AUTHENTICATED sweep (scenarios c + d) ----------------------------------------------
# The client PUTs the private fixture, asserts 200 (authed) + 401 (anon), then sweeps both scenarios.
echo ""
echo ">> AUTHENTICATED sweep (DPoP) — scenarios (c) private doc + (d) private listing (${LISTING_CHILDREN} children) ..."
AUTH_BASE_URL="$BASE_URL" \
AUTH_CONNECT_HOST="$CONNECT_HOST" \
AUTH_ISSUER="$ISSUER" \
AUTH_CLIENT_ID="$CLIENT_ID" \
AUTH_CLIENT_SECRET="$CLIENT_SECRET" \
AUTH_TARGET_PATH="/alice/test/bench-private" \
AUTH_LISTING_PATH="/alice/test/" \
AUTH_LISTING_CHILDREN="$LISTING_CHILDREN" \
AUTH_PUT_FIXTURE=1 \
AUTH_DURATION_SECS="$DURATION_SECS" \
AUTH_WARMUP_SECS="$WARMUP_SECS" \
AUTH_CONCURRENCY="$CONCURRENCY" \
AUTH_OUT_DIR="$RESULTS" \
"$CLIENT_BIN" | tee "$RESULTS/authed.tsv"

# --- (2) the ANONYMOUS comparison sweep (same client, no token) on the PUBLIC bench doc ---------
# Driven by the SAME client (so client overhead matches) but with no credentials, against the
# public bench fixture seeded by SOLID_SERVER_SEED_BENCH. This is the apples-to-apples AUTH-OVERHEAD
# baseline (auth client w/ token vs auth client w/o token, same box/binary/TLS/run).
echo ""
echo ">> ANONYMOUS comparison sweep (same client, no token) — public bench doc ..."
AUTH_BASE_URL="$BASE_URL" \
AUTH_CONNECT_HOST="$CONNECT_HOST" \
AUTH_ANON=1 \
AUTH_TARGET_PATH="/bench/public/doc" \
AUTH_LISTING_PATH="" \
AUTH_PUT_FIXTURE=0 \
AUTH_DURATION_SECS="$DURATION_SECS" \
AUTH_WARMUP_SECS="$WARMUP_SECS" \
AUTH_CONCURRENCY="$CONCURRENCY" \
AUTH_OUT_DIR="$RESULTS" \
"$CLIENT_BIN" | tee "$RESULTS/anon.tsv"

echo ""
echo ">> DONE. Per-level JSON + tsv summaries in $RESULTS/. Server log: $RESULTS/server.log"
echo ">> Record the numbers in bench/AUTH-BASELINE.md (machine + date, by hand)."
