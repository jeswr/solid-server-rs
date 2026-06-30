<!-- AUTHORED-BY Claude Opus 4.8 -->
# solid-server-rs — Optimization round C: cut per-request HEAP ALLOCATIONS on the public-GET path

> **A SAFE-NOW, behaviour-preserving allocation-reduction round.** The round-4 profile
> ([`ROUND4-PROFILE.md`](./ROUND4-PROFILE.md)) attributed **~27% of public-GET active CPU to MALLOC**
> — the single largest non-syscall band on the anonymous read path, and the path is otherwise
> loopback-syscall + TLS/HTTP-framing bound (our handler logic is only ~5% of active CPU). This round
> removes the per-request heap allocations the GET/HEAD read-response **header construction** made,
> keeping the response **BYTE-IDENTICAL**. Stacks on `phase-existence-non-disclosure` (it edits the
> same `src/ldp/handler.rs` read path).

## The bottleneck

The read-response build in `serve_read` (`src/ldp/handler.rs`) re-derived and re-formatted the
**request-INVARIANT** header lines on EVERY request, each allocation pure waste:

- **`HeaderMap::new()`** starts empty and grows-and-rehashes (a realloc) as the ~10 read headers are
  inserted.
- **Discovery `Link`s** (`describedby` + `solid:storageDescription`): `add_discovery_links` called
  `link_headers(base_url)` — a `Vec` + two `format!` `String`s — then a second `format!` +
  `HeaderValue::from_str` per pair. These depend ONLY on the server's fixed `base_url`.
- **Type `Link`s** (`Link: <type>; rel="type"`): a `format!` + `HeaderValue::from_str` per rel, over
  compile-time-constant IRI strings.
- **Method advertisement** (`Allow` / `Accept-Post` / `Accept-Patch`): `HeaderValue::from_str`
  (validate + allocate) over compile-time-constant strings.
- **`Accept-Ranges: bytes`**: `from_str` over a constant.
- **`Content-Length`**: `u64::to_string()` — a heap `String` for the numeral.

None of these vary per resource (the type/method/range values are compile-time constants; the
discovery values vary only with `base_url`, a per-instance constant). So all of them can be computed
ONCE — at process start (for the constants) or at `LdpState` construction (for the `base_url`-derived
discovery values) — and merely `clone`d (a refcount bump on a `HeaderValue`, NOT a heap copy) per
request.

## The change (one lever — per-request response-header allocations)

`src/ldp/handler.rs`:

1. **Intern the request-invariant `Link: <type>; rel="type"` lines** as `from_static` `HeaderValue`
   statics (`HV_LINK_TYPE_*`). `add_type_links` now `clone`s the relevant statics instead of
   `format!` + `from_str`. WHICH rels appear and in WHAT ORDER is unchanged.
2. **Intern the method-advertisement values** (`HV_ALLOW` / `HV_ACCEPT_POST` / `HV_ACCEPT_PATCH`)
   as `from_static` statics; `add_method_advertisement` clones them.
3. **Precompute the discovery `Link` values ONCE per `LdpState`** (`discovery_link_values`, built
   from `base_url` in the constructor via `build_discovery_link_values`). `add_discovery_links` now
   takes the precomputed slice and clones each value.
4. **`Accept-Ranges: bytes`** → `HeaderValue::from_static("bytes")`.
5. **`Content-Length`** → a new `set_u64` helper that formats the integer with **`itoa`** into a
   stack buffer (no heap `String`).
6. **Pre-size the response map** with `HeaderMap::with_capacity(16)` so the ~16 inserts never trigger
   an incremental grow-and-rehash realloc.

`itoa` is added as a direct dependency at `1` — it is ALREADY in the resolved tree (transitively via
`http`/`hyper`/`serde_json`), so naming it directly adds NO new crate.

### The security trap — what is DELIBERATELY left per-request

Interning is applied ONLY to request-INVARIANT lines. The **`.acl` `Link`** (`add_acl_link` /
`acl_url_for`, `format!("{}.acl", target.iri)`) is **derived from the request target** and DIFFERS
per resource. Interning/caching it across requests would leak one resource's `.acl` pointer onto
another's response (a cross-resource ACL-pointer disclosure). It STAYS computed per request, as does
the per-requester `WAC-Allow` value. A unit test
(`acl_link_is_per_target_never_shared_across_resources`) asserts two different targets each receive
their OWN `.acl` Link and that neither carries the other's pointer — so any future attempt to hoist
the `.acl` link into a process-wide intern fails the suite.

## Deterministic measurement — heap allocation COUNT (the trustworthy figure)

Per the perf-gate rule, wall-clock timing is ADVISORY (shared-box variance); the **deterministic**
substance is the allocation OP-COUNT, which is identical run-to-run and machine-to-machine.
`examples/read_response_alloc_microbench.rs` builds the SAME read-response `HeaderMap` the public-GET
path builds, in the BEFORE (pre-round-C) and AFTER (round-C) formulations, under a **counting global
allocator**, and asserts the two emit a **byte-identical header set** before reporting:

```
cargo run --release --example read_response_alloc_microbench
```

| read-response header build (plain resource) | heap alloc/realloc ops |
|---|---:|
| BEFORE (`format!`/`from_str` per line, `to_string` numeral) | **34** |
| AFTER (interned + precomputed invariants + `itoa`, `with_capacity`) | **13** |
| **delta** | **−21 (62% fewer)** |

The remaining 13 are the genuinely per-request values that MUST be built fresh: the per-target `.acl`
Link, the per-requester `WAC-Allow`, plus the Content-Type / ETag insertions and the map's own
backing storage. The 21 eliminated are exactly the request-invariant formatting + the `HeaderMap`
grow reallocs + the `to_string` numeral.

> $ impact: this is a COMPUTE / allocator-pressure reduction on the read hot path (the round-4
> profile's 27.2%-of-active-CPU MALLOC band on public-GET). It lowers per-request allocator work and
> GC-free heap churn under load; it does NOT change S3/QLever request counts, so it is a
> compute-side, not a request-cost, lever. The wall-clock throughput effect is advisory (the path is
> syscall/TLS-framing bound, so the allocator saving is a slice masked by run-to-run variance at the
> saturation knee — exactly as round-4's `iri_chars_serialisable` win was); the kept, reportable
> figure is the deterministic −21 alloc-ops/response.

## Correctness — nothing regressed (BYTE-IDENTICAL output)

- **Byte-identical response headers** — proven three ways: (a) the alloc bench asserts the full
  BEFORE/AFTER header set is identical; (b) `interned_type_link_values_match_reference_formatting`
  pins each interned type-link value equals the prior `format!("<{iri}>; rel=\"type\"")` bytes; (c)
  `precomputed_discovery_link_values_match_reference_formatting` pins the precomputed discovery values
  equal the prior per-request `link_headers` + `format!` bytes; (d)
  `set_u64_emits_same_decimal_as_to_string` pins `Content-Length` equals `to_string` across
  `0..=u64::MAX`.
- **`.acl` link stays per-target** — `acl_link_is_per_target_never_shared_across_resources` (the
  security guard).
- **The discovery contract has ONE home still** — `notifications::ws::link_headers` is consumed once
  into the cache (`build_discovery_link_values`); the well-known doc + the LDP Link headers still
  derive from the same source, so they cannot drift.
- Gate green on HEAD: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo build --release --locked`, `cargo test` (+ `--features redis-replay`) — 334 lib tests
  (+4 new), all integration suites, 0 failures.
- **Conformance:** `./conformance/run.sh` → see `conformance/SCORE.md` (no regression — the emitted
  bytes the CTH reads are unchanged).

## Reproduce
```bash
cargo run --release --example read_response_alloc_microbench   # deterministic alloc-op count
cargo test --release                                           # the byte-equivalence + security tests
./conformance/run.sh                                           # 41/41, no regression
```
