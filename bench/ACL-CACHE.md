<!-- AUTHORED-BY Claude Opus 4.8 -->
# solid-server-rs — Optimization round 4: ETag-keyed parsed-ACL cache (read path)

> **SECURITY-CRITICAL.** This round caches an **authorization** input — the parsed triples of an ACL
> document. It is correct ONLY because the cache is never authoritative: every served entry is gated
> on an **ETag-equality** check against the ACL's *current* etag, so a rotated/removed ACL can never
> be served stale and the cache **cannot change a decision** (same Allow / 401 / 403, same WAC-Allow,
> same fail-closed). Correctness is established by **exhaustive, adversarial unit tests** (decision
> equivalence + invalidation, run on every gate) and the full **Solid conformance suite (41/41)**.
> The wall-clock number below is the *advisory* timing companion; the **deterministic store.read
> count is the real evidence** (per the suite perf-gate rule — deterministic metrics are the
> substance, timing metrics are advisory because shared-box wall-clock variance exceeds any useful
> band).

## What changed (and why it is safe)

Every anonymous AND authenticated `GET`/`HEAD` resolves the **effective ACL** of the target: a
child→root walk that, at each step, cheaply probes for an `.acl` (a `store.meta` etag/existence
lookup), then for the **nearest** ACL it finds does a `store.read` (byte-fetch of the ACL document)
followed by an `oxttl` parse into triples, then matches the WAC rules. For a **hot** resource whose
ACL is unchanged between reads, that byte-fetch + parse of the nearest ACL is pure waste — the
identical triples come out every time.

Round 4 adds an **ETag-keyed parsed-ACL cache** (`src/acl_cache.rs`, wired in `src/authz/wac.rs` +
`src/ldp/handler.rs` + `src/main.rs`) that caches the **parsed triples** keyed by `(acl-iri, etag)`:

- On each probe the resolver gets the ACL's **current** etag cheaply via `store.meta` — an index
  lookup, **no blob fetch, no parse**.
- A **hit** (entry present AND its etag equals the current etag AND not TTL-stale) reuses the cached
  parse — skipping the byte-fetch and the `oxttl` re-parse entirely.
- A **miss** (no entry / rotated etag / TTL-stale) re-reads + re-parses and refreshes the entry under
  the etag of the bytes actually read.

The cache is **never authoritative** (charter rule). The etag-equality gate means a
rotated/removed ACL can never be served stale, so the cache can never change the WAC decision or the
WAC-Allow output. It is **per-instance only** — a miss on another instance just re-derives the same
answer, so there is no cross-instance coherence hole. It is a **bounded LRU** with a **validation
TTL** (bound by the JWKS cache TTL) so a misbehaving etag can never mask a change indefinitely.
**Default-on**; `SOLID_SERVER_ACL_CACHE_CAPACITY=0` is the explicit disable (byte-identical
pre-cache behaviour). Writes/deletes of an `.acl` explicitly invalidate the entry.

## The measurement

The win is measured by a **deterministic in-process micro-benchmark**,
[`examples/acl_cache_bench.rs`](../examples/acl_cache_bench.rs), which isolates EXACTLY the work the
cache removes — the per-read blob byte-fetch + `oxttl` parse of an UNCHANGED ACL — by driving the WAC
effective-ACL resolution directly against an in-memory `CountingStore` decorator (no HTTP/TLS stack,
no box-load dependence). It counts `store.read` calls (the byte-fetch + the source the resolver
parses) and `store.meta` calls (the cheap etag probe) separately, cache-OFF vs cache-ON, over
**N = 200,000** repeated authenticated reads of the **same** resource (an inherited owner-private
ACL with 40 extra agent grants — a realistically-sized shared-pod ACL, ~the common pod shape where a
resource has no own ACL and inherits the container's).

Run:

```bash
cargo run --release --example acl_cache_bench
# optional: cargo run --release --example acl_cache_bench -- <iterations> <acl_extra_grants>
```

### Result — DETERMINISTIC (reproducible, box-independent — the real evidence)

| metric (over 200,000 repeated reads of an unchanged ACL) | cache OFF | cache ON |
|---|---:|---:|
| `store.read` (ACL **byte-fetch + `oxttl` parse**) | **200,000** | **1** |
| `store.meta` (the cheap etag index probe) | **600,000** | **600,000** *(unchanged — the cache path always does this)* |

- **cache OFF**: 200,000 `store.read` — one ACL byte-fetch + `oxttl` parse per resolve (`iterations`
  resolves × the single governing ACL the fixture exposes).
- **cache ON**: **1** `store.read` — only the cold-miss populate. The fixture seeds exactly ONE ACL
  document (the container's inherited owner-private `acl:default`); the read target has no own ACL, so
  the child→root walk resolves to that single nearest ACL and byte-fetches+parses it ONCE on the
  cold (cache-populating) miss. Every subsequent resolve is a warm hit. After warm-up, **0** further
  byte-fetch+parse operations.
- The `store.meta` count (the cheap etag index probe) is **600,000 in BOTH** — 3 per resolve, the
  child→root walk probing the three candidate ACL IRIs (target.acl → container.acl[found] → root) to
  locate + etag-check the nearest one. It is unchanged OFF vs ON: the cache trades the expensive blob
  read + parse for this already-present cheap probe, it does not add a round-trip.
- ⇒ **100% of the ACL byte-fetch+parse work is eliminated** on repeated reads of an unchanged ACL
  (OFF = `iterations` reads → ON = the single cold populate, then 0), each warm resolve replaced by
  the cheap `store.meta` etag probe the walk already performs + a `HashMap` lookup.

The `store.read` count is a **reproducible integer** — the deterministic substance of the
optimisation, and the metric the perf-gate hard-gates. The `meta` etag-probe count is **unchanged**
between OFF and ON (the cheap index lookup the cache path always performs); the cache trades an
expensive blob read + parse for that already-present cheap probe, it does not add a round-trip.

### Result — ADVISORY (wall-clock — NOT a gated number)

The harness also prints a same-process, back-to-back cold/warm wall-clock ratio, which is far more
robust to contention than two separate HTTP runs:

- warm resolve ≈ **2.19× faster** (351.2 µs → 160.3 µs per resolve).

This reading was taken on a **heavily loaded box**, so the **absolute µs are
advisory only** — they reflect contention, not steady-state latency. The deterministic `store.read`
count above is the real evidence; the wall-clock ratio is the advisory timing companion (per the
suite perf-gate rule: timing metrics are advisory because shared-box wall-clock variance exceeds any
useful band). The harness does **not** call `Date.now`/a clock in the hot path of the counted metric
— the count is derived from atomic operation counters, and the timing is a single `Instant` delta
around the whole loop.

## Security invariants (and the tests that pin them)

The cache touches an authorization input, so the invariant set is the contract. Each is pinned by a
named test (run on every `cargo test` gate):

1. **Decision-equivalence (cold AND warm).** A cached resolve — on both the cold (populating miss)
   pass and the warm (hit) pass — returns the **byte-identical** decision + WAC-Allow as the
   uncached resolve, across **every** ACL shape: public-read / private / no-ACL-anywhere /
   `.acl`-Control-gated / origin match / non-match / absent / **broken-ACL fail-closed** /
   inherited-default. A hit can never turn a 401/403 into a 200, nor change the `EffectivePermissions`
   on an Allow. — `cached_resolve_is_decision_equivalent_across_shapes` (with the
   `assert_cached_authorize_matches_uncached` + `assert_cached_read_matches_uncached` helpers that
   assert cold==warm==uncached for both `authorize` and the `authorize_read` WAC-Allow path).
2. **ACL-write invalidation — no stale grant.** A WRITE that changes the ACL's rules is seen by the
   next cached read. Two mechanisms guarantee it: (a) the rewritten ACL has different bytes ⇒ a
   different etag ⇒ the `(acl, etag)` gate misses and re-parses; (b) the handler also explicitly
   invalidates on an `.acl` write. The test populates with a permissive ACL (Bob may read), rotates
   the same `.acl` to deny Bob, and asserts the next cached read **DENIES** Bob (and now allows
   Alice). — `acl_write_is_seen_by_next_cached_read_no_stale_grant`.
3. **ETag-mismatch re-resolve.** A rotated etag on an existing entry is a MISS that re-reads +
   re-parses (and evicts the stale entry). — `etag_mismatch_misses_and_evicts` (`acl_cache.rs`) +
   exercised end-to-end by invariant 2.
4. **Fail-closed on missing/broken ACL.** A present-but-malformed `.acl` and a no-ACL-anywhere
   orphan resolve to the same fail-closed decision cached as uncached (covered as cases inside
   invariant 1's shape matrix); a DELETE is never resurrected from cache. —
   `cached_resolve_is_decision_equivalent_across_shapes` (broken/orphan cases) +
   `deleted_acl_is_not_resurrected_by_cache`.
5. **`=0` disables (byte-identical to no-cache).** The disabled sentinel never stores and always
   misses, so every read re-resolves with decisions equal to the uncached path exactly. —
   `disabled_cache_is_byte_identical_to_no_cache`, `disabled_cache_never_stores_and_always_misses`,
   `capacity_zero_builds_the_disabled_sentinel`.
6. **Validation TTL bound.** An entry past `inserted_at + max_entry_ttl` is a MISS → full re-resolve,
   so a misbehaving/stuck etag can never mask a change indefinitely (the TTL is bound by the JWKS
   cache TTL). — `validation_ttl_forces_remiss_even_on_etag_match`.
7. **Bounded LRU.** The capacity bound holds under churn; re-inserting the same key does not grow or
   evict. — `lru_capacity_bound_holds`, `reinsert_same_key_does_not_grow_or_evict`,
   `invalidate_removes_the_entry`, `miss_on_empty_then_hit_after_insert_same_etag`.

## Conformance

The cache is gated on the full Solid Conformance Test Harness, which still scores
**`passed=41 failed=0 total=41`** with the cache default-on (Keycloak `solid` realm + the `pss-cth:ath`
DPoP patch). The cache cannot regress conformance precisely because every served entry is
etag-validated to be byte-identical to a fresh read.
