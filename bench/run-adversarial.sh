#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Adversarial benchmark suite driver for the EXPERIMENTAL solid-server-rs.
#
# Two halves:
#   1. STRICT invariants — `cargo test --test adversarial_invariants` (the deterministic pass/fail
#      security assertions: existence non-disclosure, replay rejection, cache-bust-doesn't-weaken-auth,
#      bogus-credentials-never-authorize, WAC-holds-after-a-flood). These GATE.
#   2. UNDER-LOAD measurement — `examples/adversarial_bench` drives the same arms as hostile load and
#      writes a JSON report with deterministic `invariant_holds` flags (strict) + ADVISORY timing
#      (existence-non-disclosure timing consistency, replay/cache-bust cost). The example EXITS NON-ZERO
#      if any invariant fails under load.
#
# Usage: bench/run-adversarial.sh [--requests N] [--concurrency C] [--out PATH]
set -euo pipefail
cd "$(dirname "$0")/.."

REQUESTS="500"
CONCURRENCY="32"
OUT="bench/results/adversarial/adversarial-report.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --requests) REQUESTS="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$(dirname "$OUT")"

echo ">> [1/2] strict invariants: cargo test --test adversarial_invariants ..."
cargo test --test adversarial_invariants

echo ">> [2/2] under-load measurement: adversarial_bench (release) ..."
cargo build --release --example adversarial_bench
./target/release/examples/adversarial_bench \
  --requests "$REQUESTS" \
  --concurrency "$CONCURRENCY" \
  --out "$OUT"
echo ">> report: $OUT"
echo "   (invariant_holds flags = strict; timing = ADVISORY, non-gating)"
