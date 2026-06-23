#!/usr/bin/env bash
# Run the Solid Conformance Test Harness (CTH) against the EXPERIMENTAL Rust solid-server-rs.
#
# Boots solid-server-rs with the IN-MEMORY store doubles (CompositeStore over InMemorySparqClient +
# InMemoryBlobStore — NO S3, NO live SPARQ; S3 is explicitly out of scope) terminating TLS in-process,
# seeded with the conformance test users (SOLID_SERVER_SEED_CONFORMANCE=1), then drives the harness's
# protocol + WAC suites against it and tears everything down.
#
# Prerequisites:
#   - The `solid` Keycloak realm up at http://localhost:8080/realms/solid with the conformance-alice /
#     conformance-bob DPoP service-account clients (the SAME realm prod-solid-server conformance uses —
#     `docker compose up -d` in prod-solid-server). NOTHING about that realm is modified by this script.
#   - An ath-patched CTH docker image (default `pss-cth:ath`): the published harness omits the RFC 9449
#     DPoP `ath` claim and cannot authenticate against a server that enforces it. Build it per
#     prod-solid-server/conformance/README.md, or override CTH_IMAGE.
#   - The solid-contrib/specification-tests manifests (reused from the sibling prod-solid-server clone
#     by default; override SPEC_TESTS).
#   - A release build of solid-server-rs (`cargo build --release`); override SERVER_BIN.
#
# Networking (the load-bearing part — see conformance/README.md "Networking"):
#   The server runs on the HOST and trusts/validates against a `localhost`-based issuer/audience, because
#   the verifier's SSRF guard only permits an http: issuer that resolves to LOOPBACK, and Keycloak
#   echoes its issuer from the request host (so the token `iss` MUST be `localhost:8080`). The harness
#   runs with `--network host`, which on Docker Desktop shares the Linux VM's network namespace where
#   Keycloak (a container) is reachable at `localhost:8080` and discovery returns `iss=localhost:8080`.
#   The VM cannot reach a macOS-host-bound process via `localhost`, so a `--network host` `socat`
#   sidecar forwards the VM's `localhost:3000` → the macOS host's `:3000` (host.docker.internal). The
#   net effect: harness, server, and Keycloak all agree on `localhost:3000` / `localhost:8080`, the
#   DPoP `htu` matches, and the http issuer resolves to loopback. On a native-Linux engine `--network
#   host` is the literal host netns and the socat hop is a harmless passthrough.
#
# Produces an EARL + HTML + summary report under conformance/reports/.
#
# Result integrity (do NOT regress — the whole point of running this is a trustworthy baseline):
#   - The report dir is CLEARED before every run, so no stale report from a prior run can be mistaken
#     for this run's output.
#   - The harness exit status is CAPTURED (never `|| true`-masked), and the run is only treated as
#     valid if a FRESH EARL report (report.ttl) was actually produced by THIS run.
#   - A non-zero harness exit WITH a fresh report is a REAL result (the CTH exits non-zero when
#     scenarios fail) and is tolerated; a non-zero exit WITHOUT a fresh report is a SCRIPT/HARNESS
#     error and FAILS loudly.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
REPORTS="$HERE/reports"
ENV_FILE="${ENV_FILE:-$HERE/config/solid-server-rs.env}"
IMAGE="${CTH_IMAGE:-pss-cth:ath}"
SERVER_BIN="${SERVER_BIN:-$REPO/target/release/solid-server-rs}"
SPEC_TESTS="${SPEC_TESTS:-$REPO/../prod-solid-server/conformance/specification-tests}"
CERT="$HERE/tls/server-cert.pem"
KEY="$HERE/tls/server-key.pem"

BASE_URL="https://localhost:3000"
AUDIENCE="https://localhost:3000"
ISSUER="http://localhost:8080/realms/solid"
FWD_NAME="srs-conformance-fwd"

# Which SPARQ data-path backend to boot the server with. DEFAULT `memory` (the in-memory double — the
# byte-identical conformance baseline). Set PSS_SPARQ_BACKEND=embedded to run the same conformance
# suite against the IN-PROCESS engine over an EPHEMERAL in-memory graph (no SOLID_SERVER_SPARQ_DIR),
# which requires a release build with `--features embedded-sparq`. The embedded leg seeds an ephemeral
# test instance, so it sets SOLID_SERVER_ALLOW_SEED_NONMEMORY=1 to satisfy the startup seed-guard (the
# guard otherwise refuses to seed a non-memory backend). The default memory leg is unaffected (seeding
# memory is always allowed).
SPARQ_BACKEND="${PSS_SPARQ_BACKEND:-memory}"

# --- pre-flight ---------------------------------------------------------------------------------
[ -x "$SERVER_BIN" ] || { echo "ERROR: server binary not found: $SERVER_BIN (run: cargo build --release)" >&2; exit 1; }
[ -f "$CERT" ] && [ -f "$KEY" ] || { echo "ERROR: TLS cert/key missing in $HERE/tls/ (see conformance/README.md)" >&2; exit 1; }
[ -d "$SPEC_TESTS" ] || { echo "ERROR: specification-tests not found at $SPEC_TESTS (override SPEC_TESTS)" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "ERROR: CTH image '$IMAGE' not present. Build the ath-patched image (see prod-solid-server/conformance/README.md) or set CTH_IMAGE." >&2; exit 1; }
curl -s -m 5 "${ISSUER}/.well-known/openid-configuration" -o /dev/null || { echo "ERROR: Keycloak realm unreachable at ${ISSUER} — is 'docker compose up -d' running?" >&2; exit 1; }

# Clear the report dir so a FAILED run can never leave stale report.ttl/HTML behind that then look
# like a fresh baseline. (`reports/` is gitignored — nothing committed lives here.) The marker file
# pins THIS run's start time; the freshness assertion later requires the EARL report to be newer.
rm -rf "${REPORTS:?REPORTS unset}"
mkdir -p "$REPORTS"
RUN_MARKER="$REPORTS/.run-start"
: > "$RUN_MARKER"
EARL_REPORT="$REPORTS/report.ttl"

# --- boot the server in its OWN session/process-group (load-bearing) -----------------------------
# We launch the server DETACHED into a new session (`setsid` on Linux, an `os.setsid()` python
# wrapper on macOS where `setsid` is absent) instead of a bare `&`. Why: the harness runs as
# `docker run -i --network host …`, and on Docker Desktop that `-i` foreground attach can FORWARD a
# SIGTERM to this script's process group when the container exits — which would reach the
# same-process-group server and (now that the binary handles SIGTERM with a graceful drain — and even
# before, since SIGTERM's default action is to TERMINATE the process) kill it MID-RUN, so the harness's
# very first TLS request races a shutting-down server ("Remote host terminated the handshake"). Putting
# the server in its own session means a TERM delivered to the SCRIPT's group never reaches the server;
# we tear it down explicitly in `cleanup`. (This is a harness-script robustness fix; the binary's
# SIGTERM graceful-drain behaviour is correct and unchanged — it is exercised by the unit/IT tests.)
# The embedded leg seeds an EPHEMERAL test instance, so it must opt past the startup seed-guard
# (which refuses to seed a non-memory backend) with SOLID_SERVER_ALLOW_SEED_NONMEMORY=1. The default
# memory leg leaves it unset (seeding memory is always allowed). NOTE the embedded leg deliberately
# does NOT set SOLID_SERVER_SPARQ_DIR — it uses a fresh in-memory graph (ephemeral on BOTH the index
# and the blob side), so the durable-SPARQ-needs-durable-blob guard does not fire either.
# Export the seed-guard override for the embedded leg ONLY (an `export` is robust — unlike a
# `${VAR:+ASSIGN}` env-prefix expansion, which bash parses as a COMMAND word, not an assignment). The
# server process inherits it; `server_env` passes the backend selection itself. The default memory leg
# leaves SOLID_SERVER_ALLOW_SEED_NONMEMORY UNSET, so seeding memory stays allowed without the override.
if [ "$SPARQ_BACKEND" = "embedded" ]; then
  export SOLID_SERVER_ALLOW_SEED_NONMEMORY=1
  echo ">> SPARQ backend = EMBEDDED (in-process engine, ephemeral graph; seed-guard override set)."
else
  unset SOLID_SERVER_ALLOW_SEED_NONMEMORY
  echo ">> SPARQ backend = ${SPARQ_BACKEND} (default conformance baseline)."
fi

echo ">> Booting solid-server-rs (in-memory doubles, TLS, seeded) at ${BASE_URL} ..."
server_env() {
  SOLID_SERVER_BIND=0.0.0.0:3000 \
  SOLID_SERVER_BASE_URL="$BASE_URL" \
  SOLID_SERVER_AUDIENCE="$AUDIENCE" \
  SOLID_SERVER_ALLOW_LOOPBACK=1 \
  SOLID_SERVER_BIDIRECTIONAL=off \
  SOLID_SERVER_TRUSTED_ISSUER="$ISSUER" \
  SOLID_SERVER_SEED_CONFORMANCE=1 \
  SOLID_SERVER_TLS_CERT="$CERT" \
  SOLID_SERVER_TLS_KEY="$KEY" \
  SOLID_SERVER_RATE_LIMIT_PER_IP=off \
  PSS_SPARQ_BACKEND="$SPARQ_BACKEND" \
  "$@"
}
# ^ SOLID_SERVER_RATE_LIMIT_PER_IP=off — disable the pre-crypto per-IP rate limiter for the harness run.
# The CTH reaches the server through a `--network host` socat sidecar that forwards from a SINGLE
# NON-loopback Docker-VM gateway IP (host.docker.internal), so ALL harness traffic shares ONE source IP.
# The WAC suite's rapid PARALLEL setup bursts (many common.feature callonce iterations + pool threads,
# all one source) would otherwise drain that single IP's token bucket → 429s → false WAC failures. The
# CTH is a TRUSTED single-source load generator, so exempting it is legitimate (the limiter's actual
# per-IP protection is validated by the unit + tests/rate_limit_http.rs suites, NOT the harness). The
# default-on internal-range exemption (SOLID_SERVER_RATE_LIMIT_EXEMPT_INTERNAL) ALSO covers this private
# host.docker.internal hop as defence-in-depth; `off` here is the explicit primary belt.
if command -v setsid >/dev/null 2>&1; then
  server_env setsid "$SERVER_BIN" > "$REPORTS/server.log" 2>&1 &
elif command -v python3 >/dev/null 2>&1; then
  # macOS has no `setsid`; a 1-line python wrapper does the os.setsid()+exec.
  server_env python3 -c 'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$SERVER_BIN" \
    > "$REPORTS/server.log" 2>&1 &
else
  # Last resort: bare background (the original behaviour) — still works when no TERM is forwarded.
  server_env "$SERVER_BIN" > "$REPORTS/server.log" 2>&1 &
fi
LAUNCH_PID=$!

cleanup() {
  # Kill the whole server SESSION (negative PID ⇒ the process group), since the server is its own
  # session leader; fall back to the launcher PID. `|| true` so cleanup never fails the run.
  local srv
  srv="$(pgrep -f "$SERVER_BIN" 2>/dev/null | head -1 || true)"
  [ -n "$srv" ] && kill -TERM "-$srv" 2>/dev/null || true
  kill "$LAUNCH_PID" 2>/dev/null || true
  docker rm -f "$FWD_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Wait for the seeded WebID (server up + seeding done). Probe 127.0.0.1 directly (host-reachable).
for i in $(seq 1 30); do
  if curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:3000/alice/profile/card" 2>/dev/null | grep -q 200; then
    echo ">> Server ready (alice WebID readable)."; break
  fi
  sleep 0.5
  [ "$i" = 30 ] && { echo "ERROR: server did not become ready; log:" >&2; cat "$REPORTS/server.log" >&2; exit 1; }
done

# --- the VM-side socat forwarder: VM localhost:3000 -> macOS host :3000 --------------------------
# So a `--network host` harness reaches the host-bound server at `localhost:3000`. On native Linux this
# forwards localhost:3000 -> host-gateway:3000, a harmless passthrough to the same host process.
echo ">> Starting the localhost:3000 forwarder into the harness network namespace ..."
docker rm -f "$FWD_NAME" >/dev/null 2>&1 || true
docker run -d --name "$FWD_NAME" --network host --add-host host.docker.internal:host-gateway \
  alpine/socat:latest TCP-LISTEN:3000,fork,reuseaddr TCP:host.docker.internal:3000 >/dev/null
sleep 1

# --- run the harness ----------------------------------------------------------------------------
echo ">> Running the harness (${IMAGE}) — protocol + WAC suites ..."
# Capture the harness exit status — do NOT `|| true`-mask it (that swallowed startup/config/mount
# errors and made a broken run look successful). `|| harness_rc=$?` neutralises `set -e` for this one
# command while preserving the real exit code for the validity check below.
#
# --skip-teardown: the harness writes the EARL/HTML report BEFORE its recursive-DELETE teardown, which
# hangs against this server (the published-harness teardown bug — prod-solid-server decisions/0007). The
# in-memory store is discarded with the server on EXIT, so per-resource teardown is dead time.
harness_rc=0
docker run -i --rm \
  --network host \
  -e ALLOW_SELF_SIGNED_CERTS=true \
  -v "$HERE/config:/app/config:ro" \
  -v "$SPEC_TESTS:/data" \
  -v "$REPORTS:/reports" \
  --env-file="$ENV_FILE" \
  "$IMAGE" \
  --output /reports \
  --target solid-server-rs \
  --skip-teardown || harness_rc=$?

# --- validate the result --------------------------------------------------------------------------
# A run is only valid if a FRESH EARL report was produced by THIS invocation: report.ttl must exist
# AND be newer than the run-start marker written just before boot. If the report is missing or stale,
# the run is untrustworthy regardless of the harness exit code.
fresh_report=false
if [ -f "$EARL_REPORT" ] && [ "$EARL_REPORT" -nt "$RUN_MARKER" ]; then
  fresh_report=true
fi

if [ "$fresh_report" != true ]; then
  echo "ERROR: no FRESH EARL report at $EARL_REPORT (harness exit code: ${harness_rc})." >&2
  echo "       The harness did not produce a report for this run — treat the result as INVALID." >&2
  echo "       Server log: $REPORTS/server.log" >&2
  exit 1
fi

# Parse the per-test outcomes from the EARL report (`earl:outcome earl:passed|failed|...`).
count_outcome() { grep -cE "earl:outcome[[:space:]]+earl:$1\b" "$EARL_REPORT" || true; }
passed=$(count_outcome passed)
failed=$(count_outcome failed)
untested=$(count_outcome untested)
inapplicable=$(count_outcome inapplicable)
total=$((passed + failed + untested + inapplicable))

# A non-zero harness exit WITH a fresh report is a REAL result (the CTH exits non-zero when scenarios
# fail) — tolerate it and report the score. A zero exit is a clean pass.
echo ">> Reports in $REPORTS (report.html / report.ttl EARL). Server log: $REPORTS/server.log"
echo ">> CONFORMANCE RESULT: passed=${passed} failed=${failed} untested=${untested} inapplicable=${inapplicable} total=${total} (harness exit code: ${harness_rc})"
