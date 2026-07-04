<!-- AUTHORED-BY Claude Fable 5 -->
# The live-backend read path — round-trip model, caching, and the embedded-SPARQ delta (design proposal)

> **Status: PROPOSAL (proceed-and-document).** The regime-C follow-through of
> [`beyond-50k-throughput.md`](beyond-50k-throughput.md): that doc's conclusion — once the
> in-memory doubles are replaced by a live SPARQ + object store, **backend network round-trips
> dwarf every syscall/CPU saving** — makes the read-path architecture the real scaling lever
> for a live deployment. This doc designs it. Nothing here changes LDP/auth/WAC semantics;
> every phase re-runs the CTH (41/41) + the adversarial invariants before landing.
>
> **Naming note (maintainer directive):** the tracking bead's title says "S3+QLever". That is
> superseded — QLever is never used here. The architecture is **SPARQ-authoritative**
> (existence / metadata / membership / ACL, and eventually the WAC decision itself —
> `jeswr/sparq#992`), with the **object store (`object_store`/S3) holding bytes only**. The
> PSS house invariants carry over verbatim: read paths never fall back to a blob-store
> LIST/HEAD, and **no cache is ever authoritative**.

## 1. The read path BEFORE read-2 (code-verified inventory — the baseline the counters pinned)

> **Status update:** read-1 (the deterministic RTT/await-depth counters, `src/store/counting.rs` +
> `tests/read_path_counters.rs`) and read-2 (the §3.1 combined read-plan query —
> `SparqClient::read_plan` / `Store::read_plan` + the `WacAuthorizer` planned resolve + a minimal
> `Store::read_at` for the target bytes) have **LANDED**. The chain inventoried below is the
> PRE-read-2 baseline, kept because the §1.1 table is the model the read-1 commit pinned (see the
> counter test's git history for the before/after evidence). `serve_read` now issues ONE
> `Store::read_plan` (target meta + the whole ACL-candidate chain), authorizes over it in memory,
> and fetches the target bytes through the plan's held metadata via `read_at`. The O(depth) ACL WALK
> collapses into the plan (warm doc GET **k+2 → 2** queries, depth-independent); the single governing
> ACL is re-confirmed with a live probe for fail-closed-on-delete correctness — see the §3.7 landed
> correction.

`serve_read` (`src/ldp/handler.rs`) for a GET/HEAD — as it stood BEFORE read-2:

1. `parse_target` — CPU only.
2. `authorize_read` → `WacAuthorizer::resolve_effective_acl` (`src/authz/wac.rs`): probe the
   target's own `.acl`, then each ancestor's `.acl` **child→root, stopping at the first
   present one**. Each probe is `Store::meta` = one `SparqClient::get_meta` (one SPARQL
   `SELECT` — `sparql::select_meta`). On an ACL-cache miss for the found ACL, `Store::read`
   fetches it: **another** `get_meta` + one `BlobStore::get`, then an `oxttl` parse (cached
   by `(acl-iri, etag)` — `src/acl_cache.rs`).
3. `Store::read(target)` (`src/store/mod.rs`): `sparq.get_meta` (one `SELECT`) → `blob.get`
   (one blob fetch). Strictly ordered — the blob key comes out of the metadata.
4. Containers only: `render_container` → `Store::list_children` (one `SELECT ?child` —
   already **one query for the whole membership, not per-child**; the render needs only the
   IRIs, so there is no N+1 today. §7 pins the rule so one never appears).

Every step above is **sequential** — each `await` completes before the next starts. On the
in-memory doubles each is ~ns and invisible; on the live backends each is a network RTT.

### 1.1 Round-trips per request (deterministic counts, remote SPARQ + remote blob)

For a document at container depth *d* whose governing ACL sits at ancestor index *k* (0 = own
`.acl`; a typical pod resource inherits the root ACL, so *k* ≈ *d*):

| scenario | SPARQ queries | blob gets | sequential RTT depth |
|---|---:|---:|---:|
| doc GET, **cold** (ACL-cache miss) | (k+1) probes + 1 ACL re-meta + 1 target meta = **k+3** | 1 ACL + 1 target = **2** | **k+5** |
| doc GET, **warm** (ACL-parse hit) | (k+1) probes + 1 target meta = **k+2** | **1** | **k+3** |
| container GET, warm | (k+1) + 1 meta + 1 children = **k+3** | 1 | **k+4** |
| anonymous public read (skip-crypto path) | same as above — the public-read skip (`decisions/0002`) removes *crypto*, not the walk | | |

Three structural findings fall straight out of the table:

- **F1 — the ACL walk is O(depth) sequential SPARQ RTTs on EVERY read, even fully warm.** The
  landed ACL cache (`bench/ACL-CACHE.md`) removes the byte-fetch + parse, but each candidate
  probe is still its own round-trip, serialized because the walk stops at the first hit. At
  depth 3 with a 1 ms internal RTT that is ~4 ms of pure metadata latency before the target
  is even read. This is the dominant remote-mode cost and the headline fix (§3.1).
- **F2 — the ACL-miss path pays a duplicate `get_meta`.** `read_acl` probes `store.meta(acl)`
  for the etag, then on a miss calls `store.read(acl)` — which re-fetches the same metadata
  it just probed. One wasted RTT per ACL rotation/cold entry (§3.3).
- **F3 — the target blob fetch serializes behind the target metadata fetch** (needs
  `blob_key`), and the whole store read serializes behind authorization. The minimum
  achievable cold depth is therefore 2 sequential RTTs (one metadata round, one blob round) —
  §3 gets us there; embedding SPARQ (§5) collapses it to 1.

### 1.2 What does NOT round-trip (already landed)

Warm-path auth is RTT-free: the verified-token cache (`bench/ROUND3.md`) and the verifier's
cached JWKS/WebID fetches keep DPoP verification CPU-only per request (the ES256 floor —
`high-throughput-pop-auth.md`'s budget, not this doc's). The notification fan-out is
in-process (`NotificationHub`). Rate-limit/overload state is in-process.

## 2. Design principles (the invariants this design is built on)

1. **SPARQ is the source of truth** for existence, metadata, membership, and ACL. A read
   path never derives any of those from the blob store or from a cache alone.
2. **The cache is never authoritative — every cache is validate-on-use.** The single
   mandatory per-request SPARQ round-trip (§3.1's combined query) returns the authoritative
   `(exists, etag, blob_key)` for the target and the ACL chain; every cache lookup is keyed
   or gated by what THAT round-trip returned. A cache can therefore never serve a stale
   grant, a stale body, or a resurrected resource — staleness is structurally impossible
   rather than TTL-bounded. (TTLs remain as belt-and-braces, as the ACL cache already does.)
3. **Consequence — deliberately NO metadata/existence cache** on the remote path. Caching
   `ResourceMeta` by IRI would make the cache authoritative for existence and validators
   (404s, ETags, conditional requests, and the validation anchor for every other cache). The
   one metadata round-trip per request is the price of the invariant; §3 makes it exactly
   one, and §5 (embedded) makes it a function call — which is the correct way to eliminate
   it. If this decision is ever revisited (e.g. a read-replica fleet in front of one remote
   SPARQ), it requires an event-driven invalidation feed — a **SPARQ change signal that does
   not exist today** (a new `jeswr/sparq` feature request; see §6 "unknowns") — not a TTL.
4. **Fail closed everywhere.** A backend error on any probe/batch propagates (never "no ACL
   here, keep walking"); a malformed ACL is present-but-granting-nothing; a build error on an
   untrusted IRI is fatal. The batched forms in §3 must preserve exactly these semantics.
5. **Authorization gates the response, and by default gates the byte fetch.** Speculatively
   fetching target bytes before the decision would let unauthenticated floods amplify into
   backend blob traffic (a DoS lever). Overlap is allowed only where §3.2 says so.

## 3. The remote-mode target design

### 3.1 One combined read-plan query (the F1 fix: the walk becomes one RTT)

The ACL-candidate set is **computable up front** from the target IRI alone — but from the
**protected resource**, not the raw target: candidates are
`acl_for(protected_resource(target))` + `ancestors_nearest_first(protected_resource(target))`
(pure string work). The `protected_resource` mapping is load-bearing for `.acl` targets: a
GET of `foo.acl` is governed by `acl:Control` on **`foo`**, so its candidate set starts at
`foo.acl` itself — computing candidates from the raw target would probe the non-existent
`foo.acl.acl` and change ACL-resource authorization. The read plan therefore carries TWO
distinct IRI roles: the **target row** (the raw target, e.g. `foo.acl` — the bytes to
serve) and the **candidate rows** (derived from the protected resource); explicit parity
tests for GET/HEAD on `.acl` resources are part of the read-2 equivalence gate. The walk
only *stops early* as an optimization; probing every candidate is semantically identical
because each probe is an independent read and "nearest present wins" is decided by
ordering, not by sequence. So fold the entire walk **plus the target's own metadata** into
ONE SPARQL query:

```sparql
SELECT ?g ?ct ?bk ?etag WHERE {
  VALUES ?g { <target> <target.acl> <parent/.acl> … <root/.acl> }
  GRAPH ?g { ?rec pss:contentType ?ct ; pss:blobKey ?bk ; pss:etag ?etag }
}
```

(Illustrative — the real builder lives in `src/store/sparql.rs` beside `select_meta`, built
by the same injection-safe IRIREF builders; every candidate IRI is server-constructed.) The
SPARQL 1.1 Protocol permits **exactly one query string per request** (["must include exactly
one SPARQL query string"](https://www.w3.org/TR/sparql11-protocol/#query-operation)), so
protocol-level pipelining/batching is not available — **batching means one richer query**,
which this is. The response rows give, in one RTT:

- the target's `(exists, content_type, blob_key, etag)` — the `Store::read`/`meta` input;
- for every ACL candidate: present-or-absent + current etag — the whole walk's probe set.

The resolver then walks the candidate list **in memory**, nearest-first: first present row
wins; its etag keys the existing ACL-parse cache (`AclCache::get`) unchanged. Absent rows are
authoritatively absent (the query consulted SPARQ, not a cache — invariant 1 intact).
Fail-closed: any transport/backend error on the combined query fails the request; there is no
per-candidate partial-degrade path (invariant 4).

For containers, the same query can carry the membership rows
(`UNION { GRAPH <target> { <target> ldp:contains ?child } }` with a discriminator variable),
folding `list_children` into the same RTT. That is a phase-2 refinement — measure the
two-query container path first; the extra query is parallelizable with nothing (it follows
the read today) but is only worth folding if live-SPARQ per-query overhead dominates.

**New trait surface**: one optional `SparqClient::read_plan(target, acl_candidates) ->
ReadPlan { target: Option<ResourceMeta>, acls: Vec<(iri, Option<Etag>)> }` with a default
implementation that loops `get_meta` (so the in-memory double and the embedded client work
unchanged, and the HTTP client overrides it with the combined query). No handler-visible
semantic change; the equivalence test is "same decision, same headers, same body, same
status for every case in the WAC suite, with the query counter reading 1".

### 3.2 What overlaps, what must not

After the combined query returns (RTT 1):

- **ACL-parse-cache hit (the warm path):** the decision is computed in-CPU; the target blob
  fetch (RTT 2) starts immediately. **Warm authed doc GET = 2 sequential RTTs, flat in
  depth.** With a body-cache hit (§3.4) it is **1 RTT total**.
- **ACL-parse-cache miss:** the ACL blob fetch (RTT 2) must complete before the decision.
  The target blob fetch *could* overlap with it, but that fetches possibly-denied bytes
  (invariant 5). Default: serialize (cold = 3 RTTs). A config flag
  (`SOLID_SERVER_SPECULATIVE_READ=1`, default OFF) may enable the overlap for deployments
  where the blob store is private and cheap; the response itself always awaits the decision,
  so the flag trades backend bandwidth for latency, never correctness.
- The ACL blob fetch reads **through the etag the combined query returned** (fixing F2 —
  no duplicate `get_meta`; see §3.3). A concurrent ACL rotation between the query and the
  blob fetch is handled exactly as `read_acl` documents today: parse-and-cache what was
  actually read, under its own etag.

### 3.3 `read_at(meta)` — kill the duplicate metadata fetch (F2)

Add `Store::read_at(&ResourceMeta) -> Bytes` (or expose `blob.get(&meta.blob_key)` at the
store seam): "I already hold the authoritative metadata from THIS request's SPARQ round;
fetch the bytes it points at." Used by the ACL-miss path and by `serve_read` once the
combined query supplies the target meta. Removes one SPARQ RTT from every cold ACL resolve
and one from every plain read (the current `store.read` re-fetches meta the plan already
holds). The unique-per-write blob keys (`mint_blob_key`) make this safe: the key names an
immutable object, so bytes fetched through a held pointer are exactly the bytes that pointer
committed with — never a torn read of a newer write.

### 3.4 The blob-body cache — immutable by construction

**Key insight: `CompositeStore::mint_blob_key` mints a fresh 128-bit-random key on every
write, so a blob object never changes after creation.** A body cache keyed by
`(blob_key, etag)` (the PSS keying, kept for defence-in-depth even though `blob_key` alone
is already unique) therefore needs **no invalidation protocol at all**:

- a write to the resource commits a **new** key into SPARQ → the next read's combined query
  returns the new key → cache miss → fetch. The old entry is dead weight, evicted by LRU.
- a hit is provably current because the lookup key came from **this request's** SPARQ
  round-trip (invariant 2). The cache cannot serve stale bytes, resurrect a deleted
  resource, or leak across resources.
- deletes need nothing: the combined query reports absence authoritatively.

Sizing/behaviour: byte-budgeted LRU (e.g. `SOLID_SERVER_BODY_CACHE_BYTES`, default a few
hundred MB; `=0` disables), a per-entry size cap so one large media blob cannot evict the
whole hot set (oversize bodies bypass the cache), entries are `Bytes` (cheap to clone into
responses), Range requests slice the cached full body (the handler already slices —
`range::evaluate` runs on the rendered body). ACL bodies flow through the same cache (they
are ordinary resources), which incidentally serves the parse-cache-miss path.

This is the same shape as PSS's S3 LRU ("cache bodies by `(s3Key, etag)`; validate against
the QLever ETag") with one improvement the Rust server's unique keys buy: validation
degenerates to key equality, so there is no revalidation traffic at all.

### 3.5 No WAC-*decision* cache

A `(principal, resource, mode) → allow` cache is rejected: its invalidation is **non-local**
(one ancestor `.acl` write changes the effective decision for every descendant, so
correct invalidation needs a subtree flush keyed by the governing-ACL relationship — exactly
the machinery the etag-gated parse cache avoids). Decisions are recomputed per request from
cached parses — pure CPU over a handful of triples, measured cheap (`bench/ACL-CACHE.md`
banked the win as parse-avoidance, not decision-avoidance). When the decision moves inside
SPARQ (§5.2), the authority computes it and the same reasoning forbids caching it outside
the authority; if remote-`decide` latency ever demands one, the prerequisite is an
ACL-epoch/generation number in the decision response — a `jeswr/sparq#992`-family feature
request, not a server-side TTL.

### 3.6 Request coalescing (single-flight) for hot resources

Concurrent reads of the same target each pay their own combined query + blob fetch. A
single-flight layer keyed by target IRI shares the fetches among concurrent waiters, in two
stages that respect invariant 5:

- **read-plan stage (pre-auth, shareable unconditionally):** the combined query result
  (authoritative metadata + ACL etags) is principal-independent and precedes authorization
  today anyway — concurrent waiters share one in-flight query.
- **blob stage (post-auth only):** the target blob fetch is started — and joined — only by
  waiters whose **own** authorization decision has already allowed the read. An
  unauthorized burst therefore still coalesces the metadata query but never triggers or
  amplifies blob-store traffic (the §3.2 anti-amplification posture is preserved); once one
  authorized waiter has started the fetch, later authorized waiters share it.

Each waiter always computes its **own** decision with its own principal (the shared
artifacts are metadata + bytes — principal-independent; the decision never is, per
`decisions/0002`'s lesson). Deterministic effect: under an N-concurrent same-IRI burst of
authorized reads, backend queries drop from N to 1 per coalescing window. This is a bounded map of in-flight fetches (weak — entries removed on completion),
not a cache; it adds no staleness surface. Worth building only after §3.1/§3.4 land and the
counters (§7) show residual duplicate in-flight fetches on realistic traces.

### 3.7 Read-path RTT model after §3 (remote mode)

> **Landed correction (fail-closed-on-delete).** The aspirational "1 query" warm rows below assumed
> the combined query's plan-time etag could gate the ACL-parse cache directly. It cannot: an ACL
> DELETED between the read-plan query and the in-memory walk would leave the plan reporting present
> with a now-stale etag, and a cached parse under that etag would **authorize from a deleted ACL**
> (a fail-open — invariant 4). So the AS-BUILT read path re-confirms the ONE governing (nearest
> present) ACL with a live index probe (`WacAuthorizer::read_acl_confirmed`) before trusting its
> cache entry; the k *absent* candidate probes stay collapsed into the plan (the real win). Net:
> the warm doc GET is **2 queries** (plan + found-ACL re-confirm), not 1 — still flat in depth. The
> counts below are annotated with the as-built figure.

| scenario | SPARQ queries (design → as-built) | blob gets | sequential RTT depth |
|---|---:|---:|---:|
| doc GET, warm (ACL-parse hit, body-cache miss) | 1 → **2** (plan + found-ACL re-confirm) | 1 | **3** |
| doc GET, warm + body-cache hit | 1 → **2** | 0 | **2** |
| doc GET, cold ACL (speculative off) | 1 → **2** (plan + re-confirm; ACL bytes via `read_at`) | 2 | **3** |
| container GET, warm | 2 → **3** (plan + re-confirm + membership) | 0–1 | **3–4** |

Depth-independence is the point: today's `k+3…k+5` becomes a flat `2–3` (the O(depth) ACL WALK
collapses into the one plan; the single governing ACL is re-confirmed live for correctness). A
future WAC-in-SPARQ decide (§5.2) folds the re-confirm back into the authority.

## 4. Connection pooling + transport to the remote backends

- **SPARQ**: `HttpSparqClient` already rides hyper-util's legacy pooled client
  (`pool_idle_timeout(30s)`, `Arc`-backed, cheap-clone — `src/store/http.rs`). HTTP/1.1
  means one in-flight request per pooled connection; concurrency = pool width. Actions:
  (a) verify reuse under load (connect-count counter — the `perf-p1-backend` bead in
  `beyond-50k-throughput.md` §6 already covers this; the P0.1 syscall harness counts
  `connect`s); (b) make pool limits explicit + configurable rather than default; (c) whether
  `sparq-server` speaks HTTP/2 (which would multiplex the pool away) is **unknown — verify
  against a live instance** (§6). TLS to SPARQ is an M3-next adapter (in-tree note) —
  unchanged here.
- **Blob**: the `object_store` S3 adapter (M2, `Cargo.toml` pins 0.13) maintains its own
  internal pooled HTTP client; its conditional-request surface
  ([`GetOptions`](https://docs.rs/object_store/latest/object_store/struct.GetOptions.html):
  `if_match`/`if_none_match`/`range`/`head`, verified against docs.rs) is available but —
  by design — mostly unneeded on this read path: unique-per-write keys make bodies
  immutable, so plain `get` + the §3.4 cache beats conditional revalidation. `range` is the
  exception: for large non-cached bodies, a client `Range` request can push the byte range
  down to the store instead of fetching the full object (a large-blob follow-up, same family
  as the kTLS phase-2 note in the sibling doc).
- **No protocol-level batching exists to exploit**: one query per SPARQL-protocol request
  (verified, §3.1); updates may join multiple statements with `;` in one request (the write
  path already leans on this for atomicity) — read-side batching is therefore entirely the
  §3.1 combined-query design.

## 5. Embedded SPARQ — the read path when the engine is in-process

`decisions/0001` landed `EmbeddedSparqClient` (opt-in `embedded-sparq` feature): the same
injection-safe SPARQL, executed as an in-process engine call via `spawn_blocking` over
`Arc<Mutex<Graph>>`. For the read path this deletes the entire metadata RTT column:

| scenario (embedded, warm) | engine calls (in-process) | blob gets | sequential **network** RTT depth |
|---|---:|---:|---:|
| doc GET, body-cache hit | 1 (combined plan) | 0 | **0** |
| doc GET, body-cache miss | 1 | 1 | **1** |
| container GET | 1–2 | 0–1 | **0–1** |

Notes that shape the design:

- **The §3 work is NOT wasted under embedding.** The combined read-plan query matters
  remotely (RTT elimination) and still helps embedded (one lock acquisition + one engine
  pass instead of k+2 — the `Mutex<Graph>` serializes engine ops, so fewer calls = less
  serialization; the 0001 follow-up actor/dedicated-thread upgrade raises that ceiling).
  The body cache and `read_at` are transport-independent wins.
- **DEVIATION-1 disappears embedded** (named-graph isolation is real at the engine;
  the live HTTP `/sparql` surface's graph handling is still the open item — §6).
- **Blob stays remote** (S3 backup-only is the architecture) — so the embedded floor is the
  1 blob RTT, and the §3.4 cache is what takes the hot set to zero. A `LocalFileSystem`
  `object_store` backend for single-box deployments makes even that a disk read.
- **Deployment envelope (load-bearing, from 0001):** embedded = single-instance /
  read-replica only until SPARQ has a shared durable backend (`jeswr/sparq#1248`);
  horizontally-scaled active/active stays on the remote/HTTP backend. The read-path design
  must therefore be excellent in BOTH modes — which is why §3 exists and is not skipped in
  favour of "just embed".

### 5.2 WAC evaluation inside SPARQ (`jeswr/sparq#992` — the maintainer-directed integration)

The maintainer's target is that the server **asks SPARQ for the per-resource decision**
rather than evaluating WAC in Rust: FR-1 `decide(principal, resource, mode) → {allow,
granted_modes, governing_acl, scope, status}` + FR-2 (`WAC-Allow` user/public mode sets) +
FR-7 (the `acl:default` inheritance walk materialized inside SPARQ, so a decision is a
lookup, not a walk), surfaced over HTTP as FR-4 `POST /authz/decide` (full design:
`prod-solid-server/docs/design/solid-server-rs-wac.md`; the issue is OPEN — nothing here is
built against shipped API).

Read-path integration when it lands, per mode:

- **Embedded**: `decide()` is a function call. The read plan becomes: one engine call
  (decide + target meta — FR-1's batch form `decide_batch` can carry both, or two cheap
  calls) → blob. The Rust `WacAuthorizer` walk, the ACL-parse cache, and §3.1's ACL-probe
  half of the combined query all **retire** on this path (the parse/materialization cost
  moves to ACL-write time, inside SPARQ — FR-3's re-materialize-on-write).
- **Remote**: `POST /authz/decide` (FR-4) is one RTT that replaces the k+1 probes + ACL
  read + parse entirely. It is **independent of** the target-metadata query, so the two
  issue **concurrently**: `decide ∥ get_meta` (RTT depth 1) → blob (RTT depth 2). Same
  2-RTT warm floor as §3.7, with less server-side machinery and the decision computed at
  the authority. The response is gated on the decide result (invariant 5 unchanged).
- **Fail-closed contract carries over** (FR-6): `status: acl_unavailable` → 500-class
  refusal, never inherit-on-error. The `WAC-Allow` header consumes FR-2's mode sets —
  today's single-resolution `authorize_read` shape (decision + header from one resolution)
  maps 1:1 onto one `decide(+batch)` call.

Seam: extend `SparqClient` with the optional `decide` method family exactly as
`solid-server-rs-wac.md` §5.3 sketches, default-unimplemented (the in-Rust `WacAuthorizer`
remains the fallback + the differential-testing oracle during migration — run both, compare,
alarm on divergence, exactly the parity harness that design doc specifies).

## 6. Honest unknowns — what needs a live SPARQ + object store to validate

Flagged per the charter's over-specification rule; each is a measurement or confirmation
task, not a design blocker:

1. **Live SPARQ `/sparql` latency distribution** (per-query overhead vs result-size cost) —
   determines whether folding container membership into the combined query (§3.1) and the
   two-query container path matter. No number is assumed anywhere above; only RTT *counts*.
2. **`VALUES`-over-graphs combined-query performance in SPARQ** — the engine parses it
   (spargebra; the builders are simple SPARQL 1.1), but whether one N-candidate query beats
   N simple ones on the live server by the expected margin is a measurement. The unpatched
   `spargebra 0.4.6` caveat from `decisions/0001` applies (our queries avoid the W3C edge
   cases; the embedded store-IT proves execution).
3. **DEVIATION-1** — whether the live `sparq-server` `/sparql` surface preserves per-resource
   named-graph isolation (the `#[ignore]` live IT is the confirm point; `src/store/http.rs`
   documents the fallback posture).
4. **`sparq-server` HTTP/2 + keep-alive behaviour** under the pooled client (§4).
5. **`object_store` S3 adapter pool behaviour + latency** under production concurrency (and
   MinIO-vs-S3 delta on the deploy box).
6. **sparq#992 API shape** — FR-1/2/4/6/7 are open feature requests; §5.2 codes to the seam,
   not to a shipped signature. Re-verify against sparq HEAD when picking up that bead.
7. **Body-cache hit rates on real pod traffic** — the LRU byte budget and the per-entry cap
   need a live trace to size; ship config-tunable defaults and measure.
8. **A SPARQ change-feed does not exist today** — only needed if the no-meta-cache decision
   (§2.3) is ever revisited for a read-replica fleet; would be a new `jeswr/sparq` feature
   request (file only when that deployment shape is real).

## 7. Measurement plan (the perf-gate rule applied)

Deterministic (hard-gateable, pinned by tests against counting doubles — the
`InMemorySparqClient`/`InMemoryBlobStore` counters the bench harness already uses):

| metric | pinned floor after §3 (as-built, `tests/read_path_counters.rs`) |
|---|---|
| SPARQ queries per warm authed doc GET | **2** — plan + found-ACL live re-confirm (today: k+2); the walk collapse is depth-independent, the re-confirm is the fail-closed-on-delete probe |
| SPARQ queries per doc GET, cold ACL | **2** — plan + re-confirm; the ACL bytes ride `read_at` (no duplicate `get_meta`) (today: k+3) |
| blob gets per warm doc GET (body-cache hit) | **0** (once the §3.4 body cache lands; today 1 — the target bytes) |
| sequential backend await-depth per op (a critical-path counter at the Store seam) | 2–4 per §3.7 |
| SPARQ queries per container GET | **3** (plan + re-confirm + membership; ≤2 if the membership fold lands) |
| queries per listing **independent of child count** (the no-N+1 rule, pinned so it can never regress) | listing = 1 query at any N |
| backend connects over an M-request run (pool-reuse proof) | ≪ M |
| body/ACL cache hit+miss counters | observability, not gated |

Timing (RPS, p50/p99 against live SPARQ+MinIO on the deploy-class box) is **advisory,
never a merge gate**, reported with run context — unchanged discipline
(`bench/HARNESS.md`, the charter perf-gate rule).

## 8. Phasing → follow-up beads (build-ready)

| id (proposed) | task | depends on | gate class |
|---|---|---|---|
| read-1-counters | **LANDED** — `src/store/counting.rs` (CountingSparqClient/CountingBlobStore + the max-in-flight await-depth witness) + `tests/read_path_counters.rs` pinning the §1.1 baseline, then re-pinned post-read-2 | — | deterministic |
| read-2-readplan | **LANDED** — `sparql::select_read_plan` + `SparqClient::read_plan` (default loop; one-pass in-memory + one-combined-SELECT HTTP overrides) + `WacAuthorizer::read_plan_candidates`/`authorize_read_planned` (differential-tested against the sequential walk over the full WAC matrix, incl. `.acl`-target parity, vanished-ACL, mismatched-plan fail-closed, AND the CACHED delete-after-plan / rotate-after-plan windows) + `Store::read_at`. The O(depth) ACL WALK collapses into the one combined query; the ONE governing ACL is re-confirmed with a LIVE probe (`read_acl_confirmed`) so a delete-after-plan can never grant from a stale cache (fail-closed, bit-for-bit sequential). queries/op **k+2→2** (warm), **k+3→2** (cold) — depth-independent | read-1 | deterministic (queries/op k+2→2, depth-independent) |
| read-3-read-at | LARGELY LANDED with read-2: the planned ACL path already uses `read_at` on the parse-cache miss (no duplicate `get_meta`), and the target read uses `read_at`. The residual per-read cost is the ONE governing-ACL live existence re-confirm (security-required — see §3.7); folding THAT away needs the WAC-in-SPARQ `decide` (§5.2), not another `read_at`. | read-2 | deterministic |
| read-4-bodycache | the §3.4 immutable-key blob-body LRU (`(blob_key, etag)`-keyed, byte-budgeted, per-entry cap, `=0` disables); adversarial tests: stale-serve impossible under write/delete/recreate races | read-1 | deterministic (blob gets/op) |
| read-5-container-fold | fold `list_children` into the read-plan query (measure first — unknown #1) | read-2 + live SPARQ | deterministic |
| read-6-singleflight | §3.6 per-IRI fetch coalescing (only if read-1 counters show duplicate in-flight fetches on realistic load) | read-1,2,4 | deterministic (burst queries N→1) |
| read-7-embedded-bench | run the §7 table + advisory timings on `PSS_SPARQ_BACKEND=embedded` (extends 0001 follow-up (3): full CTH on embedded) | read-2..4 | measurement |
| read-8-decide-seam | `SparqClient::decide` family per §5.2 + differential-oracle harness vs the in-Rust `WacAuthorizer` | **gated on sparq#992** | deterministic + parity |
| read-9-speculative | `SOLID_SERVER_SPECULATIVE_READ` overlap flag (default OFF, §3.2) | read-2..4 | deterministic |
| write-2-planned-authz | **LANDED** — the read-2 walk collapse applied to the WRITE verbs: `WacAuthorizer::authorize_planned` (mode-generic, same planned resolver + LIVE found-ACL re-confirm) + the handler's `authorize_planned_iri` (the shared PUT/POST/DELETE/PATCH authz core; the plan's target-row slot is the FIRST ACL CANDIDATE, never the raw target, so a target-record fault cannot turn the uniform 401/403 denial into a 500 oracle). Full-cross-product differential vs the sequential `authorize` (8 ACL shapes × 4 modes × 3 principals × 3 origins, uncached + cached) + mismatched-plan and cached-delete-after-plan fail-closed tests. Per-op queries pinned in `tests/write_path_counters.rs` (measured before → after in its module doc); each write walk is now flat 2 at any depth | read-2 | deterministic (queries/op, depth-independent) |
| write-3-create-probes | fold the creation paths' remaining per-ancestor EXISTENCE probes (`nearest_existing_container` / `ensure_ancestor_containers`) into one combined round | write-2 | deterministic |

Ordering rationale: read-1..4 are transport-independent and benefit both modes; read-7
promotes embedded with evidence; read-8 is the maintainer's target architecture and retires
the Rust walk when SPARQ ships the API.

## 9. Sources

In-tree (all verified against this checkout): `src/ldp/handler.rs` (`serve_read`,
`render_container`), `src/authz/wac.rs` (`resolve_effective_acl`, `read_acl`),
`src/acl_cache.rs`, `src/store/{mod,sparq,http,sparql,blob}.rs`,
`src/ldp/public_read_skip.rs`, `decisions/0001-embed-sparq-in-process.md`,
`decisions/0002-skip-crypto-when-identity-independent.md`,
`docs/design/beyond-50k-throughput.md`, `docs/design/high-throughput-pop-auth.md`,
`bench/ACL-CACHE.md`, `bench/ROUND3.md`, `bench/HARNESS.md`;
`prod-solid-server/docs/design/solid-server-rs-wac.md` (the FR-1..7 WAC-in-SPARQ design).

External (verified 2026-07-03 against the live source):

- SPARQL 1.1 Protocol — <https://www.w3.org/TR/sparql11-protocol/>: a query operation
  "must include exactly one SPARQL query string" (no request-level batching; POST body
  `application/sparql-query`); an update operation carries exactly one `update` string,
  which MAY contain multiple `;`-joined operations.
- `object_store` `GetOptions` — <https://docs.rs/object_store/latest/object_store/struct.GetOptions.html>
  (docs.rs latest = 0.14.0; the manifest pins 0.13): `if_match`/`if_none_match` (→
  `Error::Precondition`/`Error::NotModified`), `range`, `head`, `version`.
- `jeswr/sparq#992` (OPEN — the FR-1..7 SPARQ-native WAC feature-request set) and
  `jeswr/sparq#1248` (OPEN — shared durable backend for active/active embedding), both
  re-checked via `gh` 2026-07-03.
- Solid Notifications Protocol / WebSocketChannel2023 —
  <https://solidproject.org/TR/notifications-protocol> (referenced only to note it is NOT
  required for cache correctness under the validate-on-use design — §2.3).
