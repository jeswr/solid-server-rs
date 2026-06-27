<!-- AUTHORED-BY Claude Opus 4.8 -->
# solid-server-rs — Optimization round 4: a PROFILING round (where does the time actually go?)

> **A measurement/investigation round.** Rounds 0–3 landed the obvious read-path + auth-path wins
> (O(N) container listing, single-pass ACL resolution, the ETag-keyed parsed-ACL cache, the
> verified-access-token cache, the pre-crypto public-read skip). This round PROFILES the current
> server under load to find the NEXT non-crypto lever — or to honestly conclude the per-node path is
> well-optimised. It produces a CPU profile per path, an honest verdict, and ONE small, measured,
> low-risk micro-opt the profile justified. Wall-clock timing is **advisory** per the perf-gate rule;
> the deterministic substance (eliminated per-child Unicode property-table lookups) is the kept part.

## Method

- **Tool:** `samply` (Apple-Silicon sampler, 1000 Hz) launches the release server (built with
  `CARGO_PROFILE_RELEASE_DEBUG=1` for symbols — the COMMITTED release profile is unchanged), and an
  `oha` / the `auth_load` Rust client drives load against it; on SIGINT the server exits gracefully
  and samply writes the profile. Self-time is attributed per LIBRARY and per FUNCTION (atos +
  the binary's dSYM). The driver scripts are `bench/profile-run.sh` (anon) + `bench/profile-auth.sh`
  (DPoP), the analysers `bench/active-split.py` / `bench/symbolicate.py` / `bench/callers.py`.
- **Box:** Apple M1, 8 logical cores, macOS. The box was under variable load (~5–36) during capture.
  A SAMPLING profile's RELATIVE time-distribution is robust to box load (every frame pays the same
  contention tax), so the distribution below is the trustworthy figure — not the absolute RPS.
- **Three paths profiled** at c=16 (the saturation knee): anonymous **public-doc** GET (no crypto,
  no render), anonymous **listing** GET (100 children — the RDF render path), authenticated
  **private-doc** GET (the DPoP/token-verify hot path). The authed sweep held 11.2k RPS @ success
  1.0000 — in line with the round-2 baseline, so the load was representative.

### Park-vs-active correction (load-bearing for reading the numbers)

samply samples ALL threads, including tokio workers PARKED in `pthread_cond_wait` / the mio kqueue
reactor wait (validated via `callers.py`: the busiest kernel leaf is reached 100% from
`libsystem_pthread`, i.e. the worker park — idle, not work). Those idle-park samples (and samply's
own sample-writer `File::write_vectored`) are EXCLUDED to get the **active-CPU** distribution below.

## Where the time goes (active CPU, park excluded)

### (a) public-doc GET — TLS/HTTP ceiling, no crypto, no render
| category | % of active CPU |
|---|---:|
| NET-SYSCALL (kernel recv/send/kqueue dispatch) | 30.3% |
| MALLOC (sys + rust) | 27.2% |
| our-binary OTHER (rustls/h2/hyper framing) | 15.2% |
| tokio/mio/axum runtime | 7.6% |
| memcpy / platform | 6.3% |
| our handler logic | 5.1% |
| HTTP/JSON parse (httparse/url) | 3.7% |
| TLS crypto (AES-GCM record) | 2.0% |

→ The public read is **loopback-syscall + allocator + TLS/HTTP-framing bound**; only ~5% of active
CPU is our handler. Matches the round-0 finding (the server used ~3.4/8 cores while `oha` took the
rest — there is headroom; the ceiling is the loopback round-trip, not server compute). **No per-node
lever here.**

### (b) private-doc GET (DPoP) — the production auth path
| category | % of active CPU |
|---|---:|
| **CRYPTO — ES256 / P-256 ECDSA** (`ecp_nistz256_mul_mont`/`_sqr_mont`/`beeu_mod_inverse`) | **49.9%** |
| NET-SYSCALL (kernel) | 12.3% |
| MALLOC (sys + rust) | 13.4% |
| our-binary OTHER (rustls/h2) | 7.8% |
| HTTP/JSON parse (base64 + serde_json of the JWT/proof + httparse + url) | 5.3% |
| memcpy / platform | 3.5% |
| tokio/mio runtime | 3.3% |
| our auth+WAC orchestration | 3.3% |

→ **Half of the active CPU on the authed path is the ECDSA verify**, and it is INHERENT: the DPoP
proof is fresh per request and MUST be verified every request (the verified-token cache already
removed the *redundant* access-token re-verify — round 3). Our own orchestration (handler + auth +
WAC) is **3.3%** of active CPU. Confirms the round-2/3 conclusion: **the crypto is the floor; there
is no non-crypto per-node throughput lever on the authed path** worth chasing — eliminating ALL of
our orchestration would be a sub-1%-of-all-CPU win, most of it irreducible (`parse_target`,
`modes_for`). The JWT/base64/JSON parse (5.3%) is the only diffuse non-crypto cluster, and it is the
inherent cost of decoding a signed proof.

### (c) listing GET (100 children) — the RDF container-render path (the one server-compute-bound path)
| category | % of active CPU |
|---|---:|
| **our handler logic** | **27.6%** |
| MALLOC (sys + rust) | 25.9% |
| NET-SYSCALL (kernel) | 14.5% |
| our-binary OTHER (rustls/h2) | 10.6% |
| memcpy / platform | 8.1% |
| HTTP/JSON parse | 4.6% |
| tokio/mio runtime | 3.7% |
| TLS crypto | 2.4% |
| RDF serialise (oxttl writer) | 1.5% |

→ The listing is the ONLY path where OUR code is the #1 active-CPU category. Symbolicated, that 27.6%
is dominated by exactly two functions (per-child, called once per member):

1. **`iri_chars_serialisable`** — the per-child structural IRI guard the O(N) render runs before
   `NamedNode::new_unchecked` (the round-1/P1 quick-win replaced the full oxiri RFC-3987 re-parse with
   this cheap guard). It was `iri.chars().any(|c| c.is_control() || …)` — a UTF-8 **char decode +
   per-char Unicode `is_control` property-table lookup** (`core::unicode::unicode_data::cc::lookup`
   shows up as its own ~0.9%-of-all frame). **~8.5% of ALL listing samples** (≈14% of active CPU).
2. **`representation_etag`** — the byte-at-a-time FNV-1a content hash over the whole rendered body
   (a container's validator must track its generated bytes). **~5% of ALL listing samples.**

These two are the only concrete NON-crypto per-node levers the profile surfaced anywhere.

## The micro-opt landed this round: `iri_chars_serialisable` ASCII fast path

**Change** (`src/ldp/handler.rs`): every character RFC-3987 forbids in a serialisable `<…>` term
EXCEPT the C1 control range (U+0080–U+009F) is **ASCII**. A store-minted child IRI is virtually always
all-ASCII (`https://host/c/item-0042`). So the guard now does a **byte scan** for the all-ASCII case —
plain comparisons (`b < 0x20 || b == 0x7F || delimiter`), NO UTF-8 char decode, NO Unicode
property-table lookup — and only falls through to the original `.chars()` predicate (which alone
handles C1) the moment a non-ASCII byte appears. The result is **byte-for-byte identical** to the
prior implementation for every input.

**Correctness (security-relevant — it gates what reaches the RDF serialiser):**
- A new equivalence test (`iri_chars_serialisable_matches_reference_across_inputs`) asserts the
  optimised predicate agrees with the reference `.chars()` predicate across **every ASCII byte
  (0x00–0x7F)** + the C1 controls (U+0080/U+009F via the fallback) + multi-byte ucschar (`café`,
  emoji) + the empty string. The existing accept/reject test gained the C1-control reject cases and a
  4-byte ucschar accept case. Both green.
- The fallback path IS the original code verbatim, so any non-ASCII IRI is decided exactly as before.

**Measured effect (deterministic micro-bench — the trustworthy figure):**
`examples/iri_guard_microbench.rs` times the reference vs optimised predicate over a 100-child
all-ASCII membership, in-process (isolated from network/box noise). Stable across box loads 5→36:

| predicate | ns / child | ns / 100-child render |
|---|---:|---:|
| REFERENCE (`.chars()` + `is_control`) | ~77 | ~7,700 |
| OPTIMISED (ASCII byte-scan) | ~54 | ~5,440 |
| **delta** | **~22 (1.4×)** | **~2,260** |

Deterministically, the change eliminates the **per-child UTF-8 char-decode + Unicode `is_control`
table lookup** for every all-ASCII child IRI (the common case) — `N` Unicode property lookups per
N-child render → 0.

**HTTP throughput (ADVISORY — wall-clock, noise-masked):** an interleaved BEFORE/AFTER `oha` listing
sweep on the loaded box (load ~15) showed AFTER ≈ BEFORE at N=100 (the saturation knee is
syscall/malloc-bound, the guard saving is a small slice masked by run-to-run variance) and a small
nominal lift at N=500 (the render-bound point: AFTER ~12.0k vs BEFORE ~11.4k median RPS, ~+5% — but
with one outlier rep, so within the advisory band). Per the perf-gate rule this RPS figure is
advisory; the kept substance is the deterministic op-count reduction + the 1.4× isolated function
win.

`representation_etag` (the other hotspot) is a candidate for a later round but is left untouched: it
is one lever per change, and changing the hash would change every container's ETag bytes (functionally
fine — ETags are opaque — but a wider-blast-radius change that wants its own conformance pass).

## Honest verdict

- **public-doc + authed-doc paths: well-optimised, no per-node lever.** The time is irreducibly spread
  across loopback syscalls, the allocator, TLS/HTTP framing, and — on the authed path — the inherent
  ES256 verify (HALF of active CPU; the proof must be verified fresh every request). Our own logic is
  ~3–5% of active CPU on each. There is no obvious non-crypto throughput win here; the crypto is the
  floor, exactly as round 2/3 concluded.
- **listing path: ONE real lever existed and is landed** — the per-child IRI guard's Unicode lookup
  (the largest non-crypto our-code hotspot anywhere), now an ASCII byte-scan (1.4× on the function,
  byte-identical output, conformance + full suite green). The remaining listing cost is the allocator
  + the FNV ETag hash + oxttl serialise, all O(body) and close to irreducible.

## Reproduce
```bash
# profiles (samply must be installed; the conformance Keycloak realm must be up for the authed one):
SCENARIO=public  CONC=16 RECORD_SECS=20 ./bench/profile-run.sh   # -> bench/prof-public.json.gz
SCENARIO=listing CONC=16 RECORD_SECS=20 CHILDREN=100 ./bench/profile-run.sh
SCEN=doc         CONC=16 RECORD_SECS=22 ./bench/profile-auth.sh  # -> bench/prof-auth-doc.json.gz
python3 bench/active-split.py bench/prof-auth-doc.json.gz        # active-CPU category split
# the deterministic micro-opt measurement:
cargo run --release --example iri_guard_microbench
```
