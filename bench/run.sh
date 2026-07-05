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
# Protocol selection. The server advertises BOTH `h2` and `http/1.1` via ALPN (see src/tls.rs), so the
# SAME server/binary serves either — the load tool picks via its own ALPN offer:
#   - BENCH_HTTP2=1            → drive ONLY HTTP/2 (oha --http2, multiplexing streams over one conn);
#   - BENCH_COMPARE_H2=1       → drive BOTH h1 AND h2 over the SAME boot and emit a side-by-side
#                                h2-vs-h1 RPS/latency DELTA (the decisive multiplexing number — this is
#                                the h2 bench arm). Overrides BENCH_HTTP2.
#   - neither (default)        → HTTP/1.1 only (the existing baseline).
HTTP2="${BENCH_HTTP2:-0}"
COMPARE_H2="${BENCH_COMPARE_H2:-0}"
# Resolve the protocol list to sweep. In compare mode we run h1 THEN h2 against the same server boot, so
# the delta is apples-to-apples (same binary, same fixtures, same box, same run). The `oha` flag for
# each: "" = HTTP/1.1 (oha's default), "--http2" = HTTP/2 over the negotiated h2 ALPN.
PROTOCOLS=("h1:")  # default: h1 only ("label:oha-flag")
case "$COMPARE_H2" in 1|true|TRUE|True) PROTOCOLS=("h1:" "h2:--http2") ;; esac
if [ "${#PROTOCOLS[@]}" -eq 1 ]; then
  case "$HTTP2" in 1|true|TRUE|True) PROTOCOLS=("h2:--http2") ;; esac
fi
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
printf 'scenario\tproto\tconcurrency\trps\tsuccess_rate\tp50_ms\tp99_ms\tp999_ms\tslowest_ms\n' > "$RESULTS_TSV"

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
parse_and_record() {  # $1=scenario $2=proto-label $3=concurrency $4=json-file
  python3 - "$1" "$2" "$3" "$4" "$RESULTS_TSV" <<'PY'
import json, sys
scenario, proto, conc, jf, tsv = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
with open(jf) as f:
    d = json.load(f)
s = d["summary"]
lp = d.get("latencyPercentiles") or {}
def ms(x):
    # oha emits null for a percentile when it has no sample for it; report -1 (absent) rather than crash.
    return round(x * 1000.0, 3) if isinstance(x, (int, float)) else -1.0
row = [
    scenario, proto, conc,
    f'{s["requestsPerSec"]:.1f}',
    f'{s["successRate"]:.4f}',
    str(ms(lp.get("p50"))), str(ms(lp.get("p99"))), str(ms(lp.get("p99.9"))),
    str(ms(s.get("slowest"))),
]
with open(tsv, "a") as f:
    f.write("\t".join(row) + "\n")
print(f'  [{scenario}/{proto} c={conc}] rps={s["requestsPerSec"]:.0f} success={s["successRate"]:.3f} '
      f'p50={ms(lp.get("p50"))}ms p99={ms(lp.get("p99"))}ms p999={ms(lp.get("p99.9"))}ms')
PY
}

run_scenario() {  # $1=scenario-name $2=url
  local name="$1" url="$2"
  echo ""
  echo ">> Scenario ($name): $url"
  # Sweep each requested protocol over the SAME server boot (h1 only by default; h1+h2 in compare mode).
  # `entry` is "label:oha-flag" — e.g. "h2:--http2" (label `h2`, flag `--http2`) or "h1:" (label `h1`,
  # no flag = oha's HTTP/1.1 default).
  local entry label proto_flag
  for entry in "${PROTOCOLS[@]}"; do
    label="${entry%%:*}"
    proto_flag="${entry#*:}"
    echo ">>   protocol: ${label} ($([ -n "$proto_flag" ] && echo "$proto_flag" || echo 'HTTP/1.1'))"
    # One warm-up at mid concurrency (discarded) to prime keep-alive connections + caches.
    oha --no-tui --insecure $proto_flag --output-format quiet -c 16 -z "$WARMUP_DURATION" "$url" >/dev/null 2>&1 || true
    for c in $CONCURRENCY; do
      local jf="$RESULTS/${name}-${label}-c${c}.json"
      # Cap requests-in-flight at the concurrency; -z drives by duration (best sustained over the window).
      oha --no-tui --insecure $proto_flag --output-format json -c "$c" -z "$DURATION" "$url" > "$jf" 2>/dev/null
      parse_and_record "$name" "$label" "$c" "$jf"
    done
  done
}

# Note the box: core count + model (for the BASELINE doc — these go in the doc by hand, not Date.now).
echo ">> Machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"
proto_labels=""
for entry in "${PROTOCOLS[@]}"; do proto_labels="${proto_labels}${proto_labels:+, }${entry%%:*}"; done
echo ">> Transport(s): ${proto_labels}  (server ALPN advertises [h2, http/1.1]; oha selects per its ALPN offer)"

run_scenario "public-doc" "$PUBLIC_DOC"
run_scenario "listing"    "$LISTING"

echo ""
echo ">> DONE. Per-level JSON in $RESULTS/, summary table in $RESULTS_TSV:"
echo ""
column -t -s $'\t' "$RESULTS_TSV"

# --- h2-vs-h1 delta (compare mode only) ---------------------------------------------------------
# When BOTH h1 and h2 were swept against the same boot, emit the decisive side-by-side number: per
# (scenario, concurrency), the h2 RPS as a % of the h1 RPS and the p99 latency delta. This is the h2
# bench arm's payoff — the multiplexing effect measured apples-to-apples (same binary/fixtures/box/run).
swept_h2=0; swept_h1=0
for entry in "${PROTOCOLS[@]}"; do
  case "${entry%%:*}" in h2) swept_h2=1 ;; h1) swept_h1=1 ;; esac
done
if [ "$swept_h2" = 1 ] && [ "$swept_h1" = 1 ]; then
  DELTA_TSV="$RESULTS/h2-vs-h1.tsv"
  echo ""
  echo ">> h2-vs-h1 DELTA (same boot; h2 RPS as % of h1, p99 latency delta) → $DELTA_TSV"
  echo ""
  python3 - "$RESULTS_TSV" "$DELTA_TSV" <<'PY'
import csv, sys
src, out = sys.argv[1], sys.argv[2]
rows = {}
with open(src) as f:
    r = csv.DictReader(f, delimiter="\t")
    for row in r:
        rows[(row["scenario"], row["proto"], row["concurrency"])] = row
scenarios, concs = [], []
for (sc, _p, c) in rows:
    if sc not in scenarios: scenarios.append(sc)
    if c not in concs: concs.append(c)
concs.sort(key=lambda x: int(x))
def f(x):
    try: return float(x)
    except Exception: return None
hdr = ["scenario", "concurrency", "h1_rps", "h2_rps", "h2_rps_pct_of_h1", "h1_p99_ms", "h2_p99_ms", "p99_delta_ms"]
lines = ["\t".join(hdr)]
for sc in scenarios:
    for c in concs:
        h1 = rows.get((sc, "h1", c)); h2 = rows.get((sc, "h2", c))
        if not h1 or not h2: continue
        h1r, h2r = f(h1["rps"]), f(h2["rps"])
        pct = f"{(h2r / h1r * 100):.1f}%" if (h1r and h2r is not None and h1r != 0) else "n/a"
        h1p, h2p = f(h1["p99_ms"]), f(h2["p99_ms"])
        dly = f"{(h2p - h1p):+.3f}" if (h1p is not None and h2p is not None) else "n/a"
        lines.append("\t".join([sc, c, h1["rps"], h2["rps"], pct, h1["p99_ms"], h2["p99_ms"], dly]))
with open(out, "w") as fo:
    fo.write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
  echo ""
  echo ">> A value >100% means h2 sustained MORE RPS than h1 at that concurrency (multiplexing win);"
  echo ">> a NEGATIVE p99 delta means h2 was faster at the tail. Record the verdict in bench/BASELINE.md."
fi

echo ""
echo ">> Server log: $RESULTS/server.log"
echo ">> NOTE: scenario (c) authenticated GET is a documented follow-up (needs a Keycloak DPoP token) — see bench/README.md."
