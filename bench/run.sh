#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Reproducible HTTPS load benchmark for the EXPERIMENTAL Rust solid-server-rs.
#
# Boots solid-server-rs with the IN-MEMORY store doubles (CompositeStore over InMemorySparqClient +
# InMemoryBlobStore — NO S3, NO live SPARQ) terminating TLS in-process (rustls/aws-lc-rs; ALPN
# advertises [h2, http/1.1] so an h2-capable client gets HTTP/2 and an h1-only client negotiates
# down), seeded with the BENCHMARK fixtures (SOLID_SERVER_SEED_BENCH=N): a public RDF document, a
# public listing container with N children, and an owner-private document. It then drives `oha`
# (HTTP/1.1 by default; set BENCH_HTTP2=1 to drive HTTP/2 via `oha --http2`, measuring the
# multiplexing effect) through a concurrency sweep against:
#   (a) GET a public document       — the TLS/pipeline ceiling (no auth, no RDF render);
#   (b) GET the listing container    — the RDF membership render path;
# and records max sustained RPS + p50/p99/p999 latency per concurrency level into bench/results/.
#
# Scenario (c) — GET a private document WITH a valid DPoP token (the auth-verify hot path) — needs a
# Keycloak-minted token and is OUT OF SCOPE of this auth-free harness (see bench/README.md "Authed
# follow-up"). The private fixture IS seeded so a future authed sweep can target it.
#
# Re-run: `./bench/run.sh`. Override knobs via env (see the CONFIG block). The numbers it prints are
# REAL measurements on the box it runs on — record the machine + date in bench/BASELINE.md.
#
# Requirements: a `--release` build of the server (this script builds it if missing) + `oha` on PATH
# (`brew install oha`). `oha` is a local DEV tool, NOT a project dependency.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

# --- CONFIG (override via env) ------------------------------------------------------------------
PORT="${BENCH_PORT:-3210}"
BASE_URL="https://localhost:${PORT}"
# The CONNECT host for the load tool + readiness probes. The server binds IPv4 127.0.0.1, but
# `localhost` resolves to IPv6 `::1` FIRST on macOS — oha connects to `::1` and gets "Connection
# refused" (it does NOT fall back to IPv4 the way curl does). So we drive load at the IPv4 literal
# (the self-signed cert's SAN includes 127.0.0.1, and `--insecure` is set regardless). The server's
# BASE_URL stays `localhost` (the DPoP `htu`/audience identity) — only the dial target differs.
CONNECT_HOST="${BENCH_CONNECT_HOST:-127.0.0.1}"
CONNECT_BASE="https://${CONNECT_HOST}:${PORT}"
CHILDREN="${BENCH_CHILDREN:-100}"             # children in the listing container (>=2; see note)
# NOTE on `BENCH_CHILDREN`: it is forwarded verbatim as `SOLID_SERVER_SEED_BENCH`, whose parser treats
# the bare-truthy `1` as "enable with the DEFAULT count" (= 100), NOT a literal one child (so `1`
# doubles as the on-switch). Use `BENCH_CHILDREN>=2` for an explicit count — a one-child container is
# not a meaningful listing benchmark anyway (the render cost the sweep measures scales with N).
DURATION="${BENCH_DURATION:-10s}"             # oha -z per concurrency level (best-of-N over time)
WARMUP_DURATION="${BENCH_WARMUP:-3s}"         # discarded warm-up before the measured sweep
# The concurrency sweep. Override with a space-separated list, e.g. BENCH_CONCURRENCY="1 16 64".
CONCURRENCY="${BENCH_CONCURRENCY:-1 8 16 32 64 128 256 512}"
# Drive HTTP/2 (oha --http2, multiplexing streams over one connection) when BENCH_HTTP2=1; default is
# HTTP/1.1. The server advertises both via ALPN, so the SAME server/binary serves either — set this to
# measure the h2 multiplexing effect against the h1 baseline on the same box/run.
HTTP2="${BENCH_HTTP2:-0}"
OHA_PROTO_FLAG=""
case "$HTTP2" in 1|true|TRUE|True) OHA_PROTO_FLAG="--http2" ;; esac
SERVER_BIN="${SERVER_BIN:-$REPO/target/release/solid-server-rs}"
CERT="$HERE/tls/server-cert.pem"
KEY="$HERE/tls/server-key.pem"
RESULTS="$HERE/results"

# --- pre-flight ---------------------------------------------------------------------------------
command -v oha >/dev/null 2>&1 || { echo "ERROR: 'oha' not found on PATH. Install: brew install oha (a local dev tool, NOT a project dep)." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required (to parse oha JSON)." >&2; exit 1; }

# ALWAYS (re)build the release binary before benching. A stale binary is the single most insidious
# way to corrupt a before/after delta — measuring code that is NOT the code you just changed. `cargo
# build --release` is a no-op when the binary is already current (cargo's own freshness check), so
# this is cheap on a warm tree and authoritative on a changed one. (Fix for the roborev Medium: the
# old `[ ! -x ]` guard only built when the binary was MISSING, so an edited `src/` benched stale.)
echo ">> Building release binary (cargo build --release; a no-op if already current) ..."
( cd "$REPO" && cargo build --release )

bash "$HERE/gen-cert.sh"

rm -rf "$RESULTS"
mkdir -p "$RESULTS"
RESULTS_TSV="$RESULTS/results.tsv"
printf 'scenario\tconcurrency\trps\tsuccess_rate\tp50_ms\tp99_ms\tp999_ms\tslowest_ms\n' > "$RESULTS_TSV"

# --- boot the server (in-memory, TLS, bench-seeded) ---------------------------------------------
echo ">> Booting solid-server-rs (in-memory, TLS, bench-seeded ${CHILDREN} children) at ${BASE_URL} ..."
SOLID_SERVER_BIND="127.0.0.1:${PORT}" \
SOLID_SERVER_BASE_URL="$BASE_URL" \
SOLID_SERVER_AUDIENCE="$BASE_URL" \
SOLID_SERVER_ALLOW_LOOPBACK=1 \
SOLID_SERVER_BIDIRECTIONAL=off \
SOLID_SERVER_TRUSTED_ISSUER="http://localhost:8080/realms/solid" \
SOLID_SERVER_SEED_BENCH="$CHILDREN" \
SOLID_SERVER_TLS_CERT="$CERT" \
SOLID_SERVER_TLS_KEY="$KEY" \
"$SERVER_BIN" > "$RESULTS/server.log" 2>&1 &
SERVER_PID=$!

cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Wait for readiness (the public bench doc readable). The load URLs dial the IPv4 literal (see
# CONNECT_HOST above) so oha does not hit the IPv6 `::1` connection-refused trap.
PUBLIC_DOC="${CONNECT_BASE}/bench/public/doc"
LISTING="${CONNECT_BASE}/bench/listing/"
for i in $(seq 1 40); do
  if curl -sk -o /dev/null -w '%{http_code}' "$PUBLIC_DOC" 2>/dev/null | grep -q 200; then
    echo ">> Server ready (bench public doc readable)."; break
  fi
  sleep 0.25
  [ "$i" = 40 ] && { echo "ERROR: server did not become ready; log:" >&2; cat "$RESULTS/server.log" >&2; exit 1; }
done

# Verify the fixtures are exactly as expected (fail loudly if not — a wrong fixture invalidates the run).
pub_code=$(curl -sk -o /dev/null -w '%{http_code}' "$PUBLIC_DOC")
lst_code=$(curl -sk -o /dev/null -w '%{http_code}' "$LISTING")
prv_code=$(curl -sk -o /dev/null -w '%{http_code}' "${CONNECT_BASE}/bench/private/doc")
[ "$pub_code" = 200 ] || { echo "ERROR: public doc not 200 (got $pub_code)" >&2; exit 1; }
[ "$lst_code" = 200 ] || { echo "ERROR: listing not 200 (got $lst_code)" >&2; exit 1; }
[ "$prv_code" = 401 ] || { echo "ERROR: private doc must be 401 anonymous (got $prv_code) — fixture ACL broken" >&2; exit 1; }
echo ">> Fixtures verified: public=200 listing=200 private=401(anon)."

# --- the sweep ----------------------------------------------------------------------------------
# Parse oha JSON → a results row. Latencies are in SECONDS in oha; convert to ms.
parse_and_record() {  # $1=scenario $2=concurrency $3=json-file
  python3 - "$1" "$2" "$3" "$RESULTS_TSV" <<'PY'
import json, sys
scenario, conc, jf, tsv = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(jf) as f:
    d = json.load(f)
s = d["summary"]
lp = d.get("latencyPercentiles") or {}
def ms(x):
    # oha emits null for a percentile when it has no sample for it; report -1 (absent) rather than crash.
    return round(x * 1000.0, 3) if isinstance(x, (int, float)) else -1.0
row = [
    scenario, conc,
    f'{s["requestsPerSec"]:.1f}',
    f'{s["successRate"]:.4f}',
    str(ms(lp.get("p50"))), str(ms(lp.get("p99"))), str(ms(lp.get("p99.9"))),
    str(ms(s.get("slowest"))),
]
with open(tsv, "a") as f:
    f.write("\t".join(row) + "\n")
print(f'  [{scenario} c={conc}] rps={s["requestsPerSec"]:.0f} success={s["successRate"]:.3f} '
      f'p50={ms(lp.get("p50"))}ms p99={ms(lp.get("p99"))}ms p999={ms(lp.get("p99.9"))}ms')
PY
}

run_scenario() {  # $1=scenario-name $2=url
  local name="$1" url="$2"
  echo ""
  echo ">> Scenario ($name): $url"
  # One warm-up at mid concurrency (discarded) to prime keep-alive connections + caches.
  oha --no-tui --insecure $OHA_PROTO_FLAG --output-format quiet -c 16 -z "$WARMUP_DURATION" "$url" >/dev/null 2>&1 || true
  for c in $CONCURRENCY; do
    local jf="$RESULTS/${name}-c${c}.json"
    # Cap requests-in-flight at the concurrency; -z drives by duration (best sustained over the window).
    # $OHA_PROTO_FLAG is empty (HTTP/1.1) by default, or `--http2` when BENCH_HTTP2=1.
    oha --no-tui --insecure $OHA_PROTO_FLAG --output-format json -c "$c" -z "$DURATION" "$url" > "$jf" 2>/dev/null
    parse_and_record "$name" "$c" "$jf"
  done
}

# Note the box: core count + model (for the BASELINE doc — these go in the doc by hand, not Date.now).
echo ">> Machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"
echo ">> Transport: $([ -n "$OHA_PROTO_FLAG" ] && echo 'HTTP/2 (oha --http2)' || echo 'HTTP/1.1')"

run_scenario "public-doc" "$PUBLIC_DOC"
run_scenario "listing"    "$LISTING"

echo ""
echo ">> DONE. Per-level JSON in $RESULTS/, summary table in $RESULTS_TSV:"
echo ""
column -t -s $'\t' "$RESULTS_TSV"
echo ""
echo ">> Server log: $RESULTS/server.log"
echo ">> NOTE: scenario (c) authenticated GET is a documented follow-up (needs a Keycloak DPoP token) — see bench/README.md."
