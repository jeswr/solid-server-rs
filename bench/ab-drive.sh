#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Drive the interleaved A/B listing bench: REPS interleaved BEFORE/AFTER reps per child-count, print
# a table. Interleaving (B,A,B,A,...) so a transient box-load spike hits both arms roughly equally.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BEFORE="${BEFORE:-/tmp/ssr-BEFORE}"; AFTER="${AFTER:-/tmp/ssr-AFTER}"
REPS="${REPS:-4}"
for N in 100 500; do
  echo "### N=$N children (c=${CONC:-16}, ${DUR:-6s}/rep, $REPS reps interleaved) ###"
  echo -e "rep\tBEFORE_rps\tAFTER_rps"
  for r in $(seq 1 "$REPS"); do
    b=$("$REPO/bench/ab-listing.sh" "$BEFORE" "$N" 3260 | cut -f1)
    a=$("$REPO/bench/ab-listing.sh" "$AFTER" "$N" 3261 | cut -f1)
    echo -e "$r\t$b\t$a"
  done
done
