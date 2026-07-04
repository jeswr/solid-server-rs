#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Local performance benchmark harness driver for the EXPERIMENTAL solid-server-rs.
#
# Builds + runs `examples/bench_harness` (in-memory test-double backends; production auth posture) and
# writes a machine-readable JSON report of per-scenario DETERMINISTIC metrics (strict) + TIMING
# percentiles (ADVISORY) at multiple concurrency levels. No live docker/Keycloak/S3/SPARQ needed.
#
# Usage:
#   bench/run-bench.sh [--requests N] [--concurrencies 1,8,32,64] [--out PATH]
# Defaults mirror the example's own defaults. The report path is under bench/results/ (gitignored).
set -euo pipefail
cd "$(dirname "$0")/.."

REQUESTS="600"
CONCURRENCIES="1,8,32,64"
OUT="bench/results/harness/bench-report.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --requests) REQUESTS="$2"; shift 2 ;;
    --concurrencies) CONCURRENCIES="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$(dirname "$OUT")"
echo ">> building bench_harness (release) ..."
cargo build --release --example bench_harness
echo ">> running bench_harness (requests=$REQUESTS concurrencies=$CONCURRENCIES) ..."
./target/release/examples/bench_harness \
  --requests "$REQUESTS" \
  --concurrencies "$CONCURRENCIES" \
  --out "$OUT"
echo ">> report: $OUT"
echo "   (deterministic block = strict/comparable; timing block = ADVISORY, non-gating)"
