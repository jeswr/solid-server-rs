<!-- AUTHORED-BY Claude Opus 4.8 -->
# Skip-crypto opt-3 — measured effect

This records the measured effect of **skip-crypto opt 3** (`decisions/0002`): a pre-crypto
public-read skip. The investigation produced an important, honest result: **the win the optimization
was conceived for is not safely realisable**, and what remains is within measurement noise.

## What opt-3 actually does (after the safety scoping)

opt-3 fires ONLY for a GET/HEAD that carries **NO `Authorization` header** (a genuinely anonymous
request), and serves a publicly-readable target directly, short-circuiting the auth middleware. A
**credentialed** read is NEVER short-circuited — see `decisions/0002` for the two decisive reasons
(WAC-Allow `user=` is identity-dependent, and a forged proof is indistinguishable from a legitimate
owner's proof without the crypto). The original "serve any proof-carrying public read as anonymous"
attempt FAILED the WAC-Allow conformance suite (`public-access-{direct,indirect}.feature`) precisely
because it downgraded an authenticated owner's `user=` modes to the public set.

A direct consequence: **opt-3 saves no crypto.** An anonymous request carries no DPoP proof, so the
auth path already does no ES256 work; the skip only avoids constructing one public token + a layer hop
and resolves WAC slightly earlier. So this benchmark measures the ANONYMOUS public-read path, not a
crypto saving.

## What was (and was NOT) confirmed

The dominant cost the optimization targeted — the per-request DPoP ES256 verify, ~93% of CPU on a
proof-carrying read — is paid on AUTHENTICATED reads. opt-3 cannot remove it safely (the credentialed
variant is unsafe). So there is **no proof-carrying lift** to report. An exploratory authed-public
sweep (before the safety scoping) did show a ~22-32% RPS lift, but that configuration was the
conformance-failing one — it is recorded here only as the evidence that the ES256 verify is the cost,
NOT as a shippable result.

## Anonymous public-read — the only path opt-3 changes

`bench/run-skip-crypto.sh` (authed-public, exploratory) and the auth_load client in `AUTH_ANON=1` mode
drive a public-doc sweep against `/bench/public/doc`. BEFORE = `main` @ `00f7f99` (no skip);
AFTER = `feat/skip-crypto-public-read` (skip). Box: Apple M1 (8 cores), macOS 26.4.1, rustc 1.89.0,
`cargo build --release`, 2026-06-24. 10s/level.

Anonymous public GET, RPS (two passes, to expose variance):

| Concurrency | BEFORE pass1 | AFTER pass1 | BEFORE pass2 | AFTER pass2 |
|---|---|---|---|---|
| 16 | 40654 | 45852 | 42661 | 39449 |
| 32 | 44998 | 47768 | 42535 | 41080 |

The sign of the delta FLIPS between passes (+12.8% then −7.5% at c=16). At ~40-47k RPS the path is
dominated by TLS + HTTP framing, and the per-request structural difference (one token construction +
a layer hop) is **smaller than the shared-runner wall-clock variance (±~15%)**. Success rate is 1.000
throughout (no correctness regression).

## Verdict

- **No reliable RPS win.** The anonymous lift is within noise; the proof-carrying win is unsafe and
  not implemented. opt-3 is a small, correct, well-tested fast-path for the anonymous public read with
  no measurable performance benefit — and the durable home for *why* the credentialed variant is
  unsafe (the value the investigation actually produced). The middleware delegates straight to
  `serve_read` with a public token, so it does the SAME single effective-ACL resolution the full
  anonymous path does (an earlier version that pre-checked WAC and then re-served added a redundant
  second ACL pass — fixed, so the skip is at worst neutral, never a regression).
- Per the deterministic-vs-timing gate guidance, the wall-clock RPS here is **advisory** (its variance
  exceeds any useful band); the load-bearing results are the green conformance line (`passed=41
  failed=0 total=41`) and the byte-equivalence + scope-limit unit tests, which ARE deterministic.
- The maintainer may reasonably choose to DROP opt-3 (a review issue records the call): it adds a
  pre-crypto middleware surface for no measured gain. It is retained for now as a correct fast-path +
  the unsafe-variant analysis.

## Re-run

```
# anonymous public-read sweep against a given binary:
SERVER_BIN=<binary> AUTH_OUT_DIR=<dir> AUTH_ANON=1 \
  AUTH_TARGET_PATH=/bench/public/doc AUTH_LISTING_PATH="" \
  AUTH_CONCURRENCY="16 32" AUTH_DURATION_SECS=10 \
  target/release/examples/auth_load   # boot the server first (see bench/run-skip-crypto.sh)
```

Wall-clock RPS is box-dependent; re-measure on the target box. The LIFT (here: none beyond noise), not
the absolute number, is the result.
