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

# --- pre-flight ---------------------------------------------------------------------------------
[ -x "$SERVER_BIN" ] || { echo "ERROR: server binary not found: $SERVER_BIN (run: cargo build --release)" >&2; exit 1; }
[ -f "$CERT" ] && [ -f "$KEY" ] || { echo "ERROR: TLS cert/key missing in $HERE/tls/ (see conformance/README.md)" >&2; exit 1; }
[ -d "$SPEC_TESTS" ] || { echo "ERROR: specification-tests not found at $SPEC_TESTS (override SPEC_TESTS)" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "ERROR: CTH image '$IMAGE' not present. Build the ath-patched image (see prod-solid-server/conformance/README.md) or set CTH_IMAGE." >&2; exit 1; }
curl -s -m 5 "${ISSUER}/.well-known/openid-configuration" -o /dev/null || { echo "ERROR: Keycloak realm unreachable at ${ISSUER} — is 'docker compose up -d' running?" >&2; exit 1; }

mkdir -p "$REPORTS"

# --- boot the server (in-memory, TLS, seeded) ---------------------------------------------------
echo ">> Booting solid-server-rs (in-memory doubles, TLS, seeded) at ${BASE_URL} ..."
SOLID_SERVER_BIND=0.0.0.0:3000 \
SOLID_SERVER_BASE_URL="$BASE_URL" \
SOLID_SERVER_AUDIENCE="$AUDIENCE" \
SOLID_SERVER_ALLOW_LOOPBACK=1 \
SOLID_SERVER_BIDIRECTIONAL=off \
SOLID_SERVER_TRUSTED_ISSUER="$ISSUER" \
SOLID_SERVER_SEED_CONFORMANCE=1 \
SOLID_SERVER_TLS_CERT="$CERT" \
SOLID_SERVER_TLS_KEY="$KEY" \
"$SERVER_BIN" > "$REPORTS/server.log" 2>&1 &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
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
  --skip-teardown || true

# --skip-teardown: the harness writes the EARL/HTML report BEFORE its recursive-DELETE teardown, which
# hangs against this server (the published-harness teardown bug — prod-solid-server decisions/0007). The
# in-memory store is discarded with the server on EXIT, so per-resource teardown is dead time. `|| true`
# lets a non-zero harness exit (failing scenarios) still surface the report.

echo ">> Reports in $REPORTS (report.html / report.ttl EARL / report.txt summary). Server log: $REPORTS/server.log"
