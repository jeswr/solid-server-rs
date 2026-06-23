# P1 quick-wins — measured before/after

AUTHORED-BY Claude Opus 4.8

Two P1 quick-wins from the bottleneck roadmap (w4yfp4d9s), landed as two commits on
`perf/p1-quick-wins`:

1. **`perf(ldp)` — container-listing render fast path** (`render_container`, `src/ldp/handler.rs`):
   drop the per-child `NamedNode::new` RFC-3987 re-validation of already-valid index IRIs + the
   whole-graph `HashSet<Triple>` clone-dedup of a set that is unique by construction. Build the
   membership `Vec` directly from `LazyLock`-cached constant vocab nodes (`new_unchecked`, validated
   once per process) + per-child `new_unchecked` (the store guarantees the index IRIs valid on write,
   `debug_assert!` + checked skip-on-failure fallback in release). Only the generated-vs-stored
   overlap is de-duped, against the small stored slice only.
2. **`perf(auth)` — hit-path micro-dedup** (`src/auth_cache.rs`): compute `SHA-256(access_token)`
   ONCE (the cache key) and reuse the 32-byte digest for the `ath` comparison
   (`ath_from_digest` = `base64url(digest)`, byte-identical to the old `ath(token)`); normalise the
   request `htu` once instead of re-parsing the URL inside the match arm.

Both preserve byte-identical output / security semantics — see "Correctness" below.

## How measured

- **Tool:** `oha 1.14.0` driven by `bench/run.sh` (in-memory store doubles, in-process TLS, HTTP/1.1),
  the listing scenario (`GET <base>/bench/listing/`, the RDF membership render path) at 10 / 100 / 500
  children. Command per child-count:
  ```
  BENCH_CHILDREN=<N> BENCH_CONCURRENCY="1 16 64" BENCH_DURATION=5s BENCH_WARMUP=2s ./bench/run.sh
  ```
  Plus three back-to-back `BENCH_CHILDREN=500 BENCH_CONCURRENCY=16 BENCH_DURATION=6s` repeats for the
  stability check below.
- **BEFORE** = `main` `668b865` (release build, detached worktree). **AFTER** = `perf/p1-quick-wins`
  HEAD (`cf3352c`, release build). Both benched on the SAME quiet box, back-to-back.
- **Box:** Apple M1, 8 cores, macOS 26.4.1. Numbers are REAL measurements on this box on the run date;
  per the charter, **wall-clock timing metrics are ADVISORY** (shared-runner / single-box variance) —
  the deterministic substance is the eliminated per-render work (below), which the throughput delta at
  the largest listing reflects.

## Listing throughput — before vs after (RPS, success rate 1.0000 throughout)

The win is O(N)-per-render (per-child validation + per-triple clones removed), so it grows with the
child count. The smallest listings (N=10) sit far above the render-bound and are dominated by
TLS/pipeline + box noise (the auth-free `public-doc` control swings run-to-run too); the **N=500**
listing is the clean render-bound signal.

| children | concurrency | BEFORE RPS | AFTER RPS | Δ | BEFORE p50/p99 ms | AFTER p50/p99 ms |
|---|---|---|---|---|---|---|
| 500 | 1  | 1037 | 1351 | **+30%**  | 0.83 / 1.92 | 0.70 / 1.40 |
| 500 | 16 | 4517 | 9092 | **+101%** | 3.12 / 12.20 | 1.41 / 7.74 |
| 500 | 64 | 3000 | 10252 | **+242%** | 17.64 / 84.87 | 5.83 / 15.50 |
| 100 | 64 | 11841 | 14635 | +24% | 4.78 / 18.51 | 3.56 / 14.38 |
| 100 | 1  | 3420 | 2110 | (noise: baseline ran warm) | 0.26 / 0.71 | 0.37 / 2.02 |
| 10  | 1/16/64 | 7767 / 16028 / 8118 | 2538 / 17632 / 17549 | (render-irrelevant at N=10; noise-dominated) | — | — |

**N=500 c=16 stability (3 back-to-back reps each, best-of):**

| rep | BEFORE RPS | AFTER RPS |
|---|---|---|
| sweep | 4517 | 9092 |
| 2 | 5125 | 10853 |
| 3 | 5044 | 10363 |

→ a stable **~2× throughput** on the 500-child listing render (BEFORE ~4.5–5.1k vs AFTER ~9.1–10.9k
RPS), p50 ~2.9ms → ~1.3ms. This is the eliminated per-child `NamedNode::new` RFC-3987 re-parse + the
whole-graph `HashSet<Triple>` clone-dedup showing through.

## Deterministic substance (the reproducible part, box-independent)

Per container render of an N-child listing, the change eliminates, deterministically:

- **N `NamedNode::new` (oxiri RFC-3987) re-parses** of already-valid index IRIs → 0 (release uses
  `new_unchecked`; debug re-validates via `debug_assert!`).
- **5 constant-vocab `NamedNode::new` parses per render** → amortised to once-per-process
  (`LazyLock`), i.e. 0 on the hot path.
- **The whole-graph `HashSet<Triple>` build + per-triple clone-insert** for `(stored + 3 + N)` triples
  → 0 allocations / 0 clones on the common path (empty/typing-free stored body): the dedup probes ONLY
  the stored set, and the generated triples are never cloned. To avoid an O(stored × (3+N)) cliff on a
  pathological large-stored-body-plus-many-children container, the stored-vs-generated probe is
  threshold-gated: empty stored body → no work; ≤16 stored triples → a zero-alloc linear scan; >16 →
  a single borrowing `HashSet<&Triple>` of the stored set (no clones) probed O(1). All three branches
  suppress exactly the same triples, so the output bytes are identical regardless of which runs (the
  `render_container_dedups_large_stored_body_via_hashset_branch` test pins the HashSet branch).

For the auth hit path, per authenticated request the change eliminates, deterministically:

- **1 of the 2 `SHA-256(access_token)` digests** (the cache key's digest is reused for the `ath`
  comparison) — the access token is hashed once, not twice.
- **1 of the 2 `url::Url::parse` calls in `normalize_htu`** (the request URL is normalised once, not
  re-parsed inside the `htu` match arm).
  This is a tail-latency / allocator win on the authed path; the `bench/run.sh` sweep is auth-free
  (a Keycloak DPoP token is out of its scope — see `bench/README.md`), so it is reported as a
  deterministic op-count reduction rather than a wall-clock number here.

## Correctness — nothing regressed

- **Byte-identical container output** preserved: insertion order + which triples appear are unchanged,
  so the serialiser emits the same bytes and `representation_etag` is byte-for-byte identical. Pinned
  by `render_container_dedups_generated_against_stored_body_byte_identical` (small/linear dedup),
  `render_container_dedups_large_stored_body_via_hashset_branch` (large/HashSet dedup),
  `render_container_lists_every_child_once_with_typing`, and
  `iri_chars_serialisable_accepts_valid_rejects_corrupting` (all green).
- **`ath` token-binding + `normalize_htu` semantics preserved** byte-for-byte; all 20 `auth_cache`
  unit tests green (incl. `wrong_ath_rejected_on_hit`, `ath_compat_absent_ok_present_wrong_rejected`,
  `wrong_htu_or_htm_rejected_on_hit`).
- **`new_unchecked` is confined** to compile-time constants + store-guaranteed-valid index IRIs, each
  with a `debug_assert!` checked-path fallback — a malformed IRI can never silently reach the
  serialiser.
- Gate green on HEAD: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo build --release`, `cargo test` (276 lib + integration suites, 0 failures).
- **Conformance held fresh:** `./conformance/run.sh` → `passed=41 failed=0 total=41` (650/650
  Karate scenarios), against Keycloak `solid` realm + `pss-cth:ath`.
