<!-- AUTHORED-BY Claude Fable 5 -->
# Beyond-50k throughput — the three hard cases (analysis + sparq issue drafts)

> **Status: ANALYSIS (proceed-and-document).** Maintainer-requested follow-through of
> [`beyond-50k-throughput.md`](beyond-50k-throughput.md): *"make sure beyond-50k throughput works
> for (1) many concurrent SPARQL queries, (2) large pods, (3) complex access-control rules."*
> The P0.1 syscall baseline ([`bench/syscalls-results/2026-07-04-linux.md`](../../bench/syscalls-results/2026-07-04-linux.md))
> is a **small-response front-door** measurement (116-byte doc, 5.2 KiB listing, in-memory
> doubles) — it deliberately measures NONE of these three cases. This doc traces each case's
> request→WAC→sparq path, splits every bottleneck into **(a) locally optimizable in
> `solid-server-rs`** vs **(b) blocked on SPARQ's design**, drafts the `jeswr/sparq` issues for
> the (b) set (§6 — the orchestrator files them; nothing is filed from here), and gives the
> measurement plan (§7). No code change rides with this doc.
>
> SPARQ-side claims are verified against `jeswr/sparq` `origin/main` @
> `69efb1b6ef2d19fc999f3bc1dcf16657e5ad3e15` (fetched 2026-07-05). sparq moves fast —
> **re-verify file/line claims against current `main` before filing the §6 drafts.**

## 1. The request path these cases stress (code-verified)

An authed LDP GET/HEAD today (`src/ldp/handler.rs`):

1. `serve_read` (`handler.rs`, `pub(crate) async fn serve_read`) → `parse_target` →
   `authorize_read` (`handler.rs`, `LdpState::authorize_read`).
2. `WacAuthorizer::read_plan_candidates` (`src/authz/wac.rs`) derives the ACL-candidate chain
   (pure string work), then **ONE** combined `Store::read_plan` round-trip fetches the target's
   metadata + every candidate's presence/etag (`src/store/http.rs::read_plan` = one
   `VALUES ?g {…}` SELECT; `src/store/embedded.rs::read_plan` = one engine dispatch).
3. `authorize_read_planned` walks the plan in memory; the ONE governing ACL is re-confirmed
   with a live probe (`WacAuthorizer::read_acl_confirmed` — fail-closed on delete-after-plan);
   its parsed triples come from the etag-keyed LRU `AclCache` (`src/acl_cache.rs`), else via
   `read_at` + `oxttl` parse; rule matching is `modes_for` (`src/authz/acl.rs`).
4. 404 decided after auth; bytes via `Store::read_at` (one `BlobStore::get`, full `Bytes`
   buffer). Containers additionally run `render_container` → `Store::list_children` (one more
   SELECT) and serialize the whole listing to compute the representation ETag.

Pinned per-op backend counts (`tests/read_path_counters.rs`, `tests/write_path_counters.rs`):
**warm doc GET = 2 sparq queries + 1 blob get; container GET = 3 queries; every write verb's
ACL walk = flat 2 — all depth-independent** (read-2/write-2, `backend-read-path.md` §3.7).
That flatness means *deep hierarchies are already solved*; the three hard cases stress
different axes: query **concurrency**, result/pod **size**, and **decision cost**.

## 2. Hard case 1 — many concurrent SPARQL queries

Two distinct surfaces, often conflated:

- **1a — the server's own sparq traffic.** Every LDP request issues 2–3 metadata queries; at
  the 50k-RPS ambition that is **100–150k sparq queries/sec** before a single client-authored
  SPARQL query exists.
- **1b — the client-facing access-controlled SPARQL endpoint** (the
  [`solid-sparql-query`](https://github.com/jeswr/solid-sparql-query) editor's-draft surface;
  `sparq#992` FR-4). Not yet built in `solid-server-rs` — but the maintainer's ask covers it,
  and its concurrency shape is decided by SPARQ's `PodStore` API (below).

### 2.1 Embedded backend: ONE global `Mutex<Graph>` serializes everything (the headline)

`EmbeddedSparqClient` holds `Arc<Mutex<Graph>>` and takes the lock inside every
`spawn_blocking` dispatch (`src/store/embedded.rs` — the `graph` field + `lock()`), for
**reads and writes alike**. Effective engine concurrency is **1**: under concurrent load every
tokio blocking thread convoys on one mutex, and a long-running query (a big listing — hard
case 2) stalls every other request's 2-query metadata plan. ADR
[`0001`](../../decisions/0001-embed-sparq-in-process.md) named the dedicated-thread/actor as
the production upgrade; SPARQ has since shipped the better shape:

- `sparq-serve`'s **generation ring** — lock-free `current()` snapshot pinning for N readers,
  a single sequenced group-committing writer, structural `Graph::fork` at **O(pending delta)**
  not O(graph) (verified in `sparq-serve/src/applier.rs` module docs, which record the
  measured commit costs and the superseded O(graph) rebuild); `sparq-server` itself serves on
  exactly this (`sparq-server/src/http.rs`, Wave A1/A2/A4 notes).
- `sparq-core`'s opt-in `shared::SharedGraph` (`sparq#1150`) for the simpler RwLock+snapshot
  shape.

**(a) LOCAL** — the single biggest hard-case-1 lever in this repo: rebuild
`EmbeddedSparqClient` on the ring/embed surface (`sparq#1248` items 1–2 are shipped;
the semver freeze is pending, so pin the rev as `Cargo.toml` already does). Reads
(`get_meta`/`read_plan`/`list_children`/ASKs) pin a generation and run concurrently with zero
locks; writes submit to the sequenced writer. Deterministic gate: the existing round-trip
counters are unchanged; a new test pins "K concurrent readers, no exclusive lock on the read
path". Bead `hc1-embed-ring` (§5).

**(b) SPARQ** — nothing blocks the data-path part; the *access-control* part is §2.3.

### 2.2 Remote backend: HTTP/1.1 pool width + per-query wire overhead

`HttpSparqClient` rides hyper-util's legacy pooled client (`src/store/http.rs`): HTTP/1.1, one
in-flight query per pooled connection, implicit pool limits, 30 s idle timeout. sparq-server's
read side is lock-free (generation pinning), so the engine is not the choke point — the wire
is: per tiny metadata SELECT the server pays HTTP framing + a JSON results parse + an RTT, and
concurrency equals however many connections the implicit pool opens under burst.

**(a) LOCAL:** make pool limits explicit + verify reuse under load (the open
`perf-p1-backend` item — P0.1's `connect` counts are the deterministic check); consider
co-locating sparq on loopback in deployment docs. **(b) SPARQ (confirmation, not design):**
whether `sparq-server` speaks HTTP/2 / its keep-alive behaviour under a pooled client
(`backend-read-path.md` §6 unknown 4) — fold into the §7 measurement, not an issue.

### 2.3 The access-controlled query/decision surface is exclusive-access (`&mut self`)

Verified at sparq `origin/main` @ `69efb1b` (`crates/sparq-solid/src/lib.rs`): the read-side
entry points the AC-SPARQL endpoint and the WAC integration would call —
`accessible`, `accessible_set`, `view_for`, `query_as`, `query_json_as`, `ask_as`,
`wac_allow` — all take **`&mut self`**, because they share one `FxHashMap` session-set cache
(`session_sets`). One `PodStore` therefore admits **one access-controlled query at a time**,
regardless of how concurrent the underlying engine is. `decide`/`decide_batch`/`resolve_acl`
are `&self` but pay a different cost (§4.2). The session cache is also unbounded, keyed
`(agent, client, issuer, now, mode)` — a caller that passes per-request `now` (needed once
time-conditioned grants are in play) gets a **0% hit rate and unbounded growth**.

**(b) SPARQ — design blocker.** Draft issue **A** (§6.1): `&self` read-side entry points over
an interior-mutability (sharded) session cache, bounded, composed with the generation ring so
each published generation carries its immutable auth state. This is also the natural shape for
wiring `sparq-solid` into `sparq-server` (the FR-4 architecture call `sparq#1346` flags).

**(a) LOCAL (interim):** when building the AC-SPARQL endpoint before issue A lands, shard
per-worker `PodStore`s or wrap one in a Mutex and accept serialization — measure, don't guess;
the endpoint itself should reuse the overload/admission stack (`src/overload.rs`) and sparq's
`QueryBudget`-style row caps.

## 3. Hard case 2 — large pods

Depth is solved (§1); **size** is not. Four concrete cliffs, worst first:

### 3.1 Container listings: unbounded, fully buffered, with a hard 16 MiB failure cliff

- `Store::list_children` returns every child in one SELECT; the HTTP client buffers the whole
  SPARQL-results-JSON response and **fails closed at `MAX_RESPONSE_BYTES` = 16 MiB**
  (`src/store/http.rs`). At ~140 bytes/binding row (an ~80-byte child IRI), the cliff sits
  around **~10⁵ children: a large-enough container makes every GET of it a 5xx** on the remote
  backend. Deterministic, reproducible, and currently untested.
- Below the cliff the cost is still O(N) per request: `render_container`
  (`src/ldp/handler.rs`) materializes 3+N triples, serializes the entire body, and hashes it
  for the representation ETag — **HEAD pays the full render too** (the ETag needs the bytes).
  On the embedded backend there is no 16 MiB cap, but the listing query holds the global mutex
  for its whole run (§2.1 interaction: one big listing convoys the entire server).
- There is no paging surface (LDP paging / `Prefer` handling is a protocol decision with a
  conformance guard — `G:ldp-route-completeness`-class change, not a pure perf patch).

**(a) LOCAL:** bead `hc2-listing-page` — page `list_children` (LIMIT/OFFSET loop) so no single
response crosses the bound, stream the render, and add the deterministic cliff test; the
protocol-visible paging decision (cap + `Prefer`/`describedby` affordance) rides the same bead
with an ADR. **(b) SPARQ:** LIMIT/OFFSET across separate requests is only correct against an
unchanging dataset — consistent multi-request pagination needs **snapshot/generation pinning
over the protocol** (draft issue **D**, §6.4; `sparq-server` already pins per-request
`PinnedGen` internally and has `?generation=N` behind the opt-in `time-travel` feature).

### 3.2 Blob bodies: full buffering, Range sliced after the fact

`BlobStore::get` returns `Bytes` (whole object); `range::evaluate` slices the already-buffered
body (`src/ldp/range.rs`; `backend-read-path.md` §3.4 note). A large-media pod pays full-object
memory + latency per request, and concurrent large GETs multiply resident bytes.

**(a) LOCAL:** bead `hc2-blob-streaming` — stream large bodies (`object_store` returns a
stream; `GetOptions.range` pushes a client `Range` down to the store — already flagged in
`backend-read-path.md` §4) with a size threshold below which today's buffered path stays (the
byte-exactness + conditional/ETag semantics are unchanged; streaming must keep the
Range/206/416 behaviour bit-identical). Plus the already-designed bead `read-4-bodycache`
(§3.4 of the read-path doc, not yet landed) so the hot set stops re-fetching at all.
**(b) SPARQ:** none — bytes never touch sparq.

### 3.3 The reconciler's referenced-set is O(pod) in one response

`referenced_blob_keys` fetches every `pss:blobKey` in ONE `SELECT DISTINCT`
(`src/store/http.rs`): the same 16 MiB bound aborts the GC sweep (fail-closed — correct, but
the sweep then **never completes on a large pod**, so orphans accumulate unboundedly).

**(a) LOCAL:** bead `hc2-gc-paged` — page the referenced-set query. **(b) SPARQ:** the same
snapshot-consistent pagination as §3.1 (issue **D**) — an inconsistent page here is not a perf
bug but a *delete-live-bytes* correctness bug, which is why the current code refuses to
shorten silently.

### 3.4 The engine itself is not the large-pod problem (verified)

sparq-core scales: six permutation indexes, structural fork O(pending delta), commit cost
graph-size-independent (measured in `sparq-serve/src/applier.rs` docs), out-of-core mmap
option. Point metadata SELECTs stay index-lookups at any pod size. The large-pod costs that DO
grow with pod size sit in the **decision layer** — §4.2 — and in the embedded `save()`
snapshot (O(graph) under the global lock; subsumed by the ring adoption, whose generations
snapshot off the read path).

## 4. Hard case 3 — complex access-control rules

### 4.1 What the Rust server pays today (in-Rust WAC)

- The walk is flat (2 queries) at any depth/complexity (§1). Parsed ACLs are cached by
  `(acl-iri, etag)` in a bounded LRU+TTL (`src/acl_cache.rs`,
  `DEFAULT_ACL_CACHE_CAPACITY`/`SOLID_SERVER_ACL_CACHE_CAPACITY`).
- Per request, `modes_for` (`src/authz/acl.rs`) linearly scans the parsed authorization
  triples — **O(#authorizations) CPU per request per audience** (user + public on reads). Fine
  at tens of rules; unmeasured at thousands (a sharing-heavy pod: one rule per collaborator).
- `acl:agentGroup` never matches (v1 fail-closed, as PSS) — so group-resolution cost is
  currently zero by construction; groups arrive with the decide integration (§4.2), where
  SPARQ resolves `vcard:hasMember` at materialization time.

**(a) LOCAL:** bead `hc3-modes-memo` (measure-first): if the §7 complex-ACL fixture shows
`modes_for` hot, memoize the pure rule-match by `(governing-acl etag, webid, origin)` — sound
because the plan + live re-confirm already establish *which* `(acl, etag)` governs each
request, so the memo never outlives its ACL revision (this respects the §3.5 no-decision-cache
rationale in `backend-read-path.md`: what was rejected there is a cache whose invalidation is
non-local; an etag-scoped memo of a pure function is local by construction).

### 4.2 The target architecture (WAC-in-SPARQ) has an O(pod-size) decision today

The maintainer's architecture is that SPARQ evaluates WAC (`solid-server-rs-wac.md` in
`prod-solid-server/docs/design/`; `sparq#992`). SPARQ has since **shipped the FR-1..7 library
surface** — `PodStore::decide`/`decide_batch`/`resolve_acl`/`wac_allow` + `put_acl`/
`delete_acl` (per `sparq#992`/`sparq#1210`/`sparq#1346`). Excellent — but the implementation,
verified at `origin/main` @ `69efb1b`, does not yet scale to these hard cases:

1. **`decide` and `resolve_acl` rebuild `AclIndex` from the whole graph on every call** —
   `decide::AclIndex::build(&self.graph)` iterates `graph.named` (every named graph = every
   resource in the store) per decision (`crates/sparq-solid/src/decide.rs`, `AclIndex::build`;
   called per-request from `PodStore::decide`). `decide_batch` amortizes it only *within* one
   batch. Per-request cost is **O(#resources in the store)**.
2. **The per-mode verdict enumerates the full accessible set** — `decide_one`'s mode loop
   calls `AuthIndex::accessible(session, mode)` (which allocates the complete sorted
   `Vec<NamedNode>` of every graph the session may access) and then **linearly scans** it for
   the one resource, ×4 modes, uncached on the `&self` path
   (`decide.rs`, the `modes_held_point` helper). On a pod where a principal can read most of
   1M resources, one decision materializes ~4M `NamedNode`s.
3. **Every ACL write rebuilds the world** — `put_acl`/`materialize_wac` → `reindex()` =
   `AuthIndex::from_graph(&self.graph)` (whole store) + `epoch += 1` + `cache.clear()`
   (`crates/sparq-solid/src/lib.rs`). One tenant toggling a share cold-starts **every**
   session's cached sets across **every** pod in the store, and pays O(all ACLs) per write.
   (`sparq-server`'s own conservative `GLOBAL_POD` invalidation placeholder notes the same
   Wave-B refinement direction for its caches — `crates/sparq-server/src/http.rs`.)

None of this is a *correctness* defect — it is all fail-closed and semantically right, and at
the ~1.1k-graph fixture scale sparq's own docs measure (~0.3 ms cold, ~0.6 µs cached session
set, `lib.rs` docs) it is invisible. It becomes the binding constraint exactly on this doc's
hard cases: **complex ACLs (3) × large pods (2) × decision-per-request QPS (1)**. Draft issues
**B** (decision cost — §6.2) and **C** (incremental materialization/invalidation — §6.3).

**(a) LOCAL:** the `read-8-decide-seam` bead (read-path doc §8) stays gated: adopt
`SparqClient::decide` only once B lands (or embedded-only with `decide_batch` batching per
request), with the differential oracle harness the WAC design specifies. Nothing else to do
locally — the in-Rust evaluator with the etag-keyed parse cache is currently the *more*
scalable path, which is worth stating plainly: **migrating to WAC-in-SPARQ before issues B/C
land would regress hard-case throughput**, not improve it.

## 5. Local optimization beads (prioritized, bead-sized, measurable)

| id | case | change | deterministic gate | expected effect |
|---|---|---|---|---|
| `hc1-embed-ring` | 1 (+2 convoy) | rebuild `EmbeddedSparqClient` on the sparq-serve generation ring / `embed` surface (pinned rev; ADR-0001 follow-up) — lock-free concurrent reads, sequenced writes | round-trip counters unchanged; new "K concurrent readers, zero exclusive read locks" test | removes the global-mutex serialization — the largest single hard-case-1 lever in-repo |
| `read-4-bodycache` | 2 | the already-designed `(blob_key, etag)` LRU (`backend-read-path.md` §3.4) | blob gets/op 1→0 on hit | hot-set reads stop paying the blob RTT |
| `hc2-listing-page` | 2 | page `list_children` + stream the container render + the deterministic 16 MiB-cliff test; protocol cap/paging decision as an ADR | listing of N* children no longer 5xx; queries/listing O(N/page); bytes buffered bounded | removes the large-container failure cliff |
| `hc2-blob-streaming` | 2 | stream large blob bodies + `object_store` Range pushdown above a size threshold | bytes buffered per large GET bounded; Range/206 bit-identical | large-media pods stop buffering whole objects |
| `hc2-gc-paged` | 2 | page `referenced_blob_keys` (consistency per §3.3 / issue D) | referenced-set retrieval works at ≥10⁶ keys | GC functions on large pods |
| `hc1-pool-config` | 1 | explicit `HttpSparqClient` pool limits + reuse verification (extends `perf-p1-backend`) | `connect` counts ≪ requests under the §7 load | predictable remote-backend concurrency |
| `hc3-modes-memo` | 3 | measure-first memo of `modes_for` by `(acl-etag, webid, origin)` | decision identical (differential test); rule-match executions/op ↓ | only if the complex-ACL fixture shows it hot |
| `read-8-decide-seam` | 3 | `SparqClient::decide` family + differential oracle | parity harness | **gated on sparq issues B (+A for concurrency)** |

## 6. Draft `jeswr/sparq` issues (the design blockers — for the orchestrator to file)

> Verified against `origin/main` @ `69efb1b` (2026-07-05); **re-verify before filing** (the
> repo moves fast, and #992's FR surface landed in weeks). Each draft body below is
> self-contained, signs as the PSS agent, tags no one, and defers sequencing to the SPARQ
> agent. They deliberately reference — and do not duplicate — `#992` (FR surface, shipped),
> `#1248` (embedding API), `#1346` (production-readiness meta), `#1150` (SharedGraph),
> `#1210` (put_acl gating).

### 6.1 Draft A — concurrent read-side access control (`&self` PodStore + per-generation auth state)

**Title:** `[feature-request, PSS agent] Concurrent read-side access control: &self PodStore query/decision entry points + per-generation auth state (high-QPS serving)`

**Body:**

> 🤖 **PSS agent** — @jeswr's agent for `prod-solid-server` / the Solid suite (Claude
> Fable 5). Consumer-side feature request from the `solid-server-rs` beyond-50k-throughput
> track (issues-only channel; scope/sequencing is the SPARQ agent's call). Companion analysis:
> `solid-server-rs` `docs/design/throughput-hard-cases.md`.
>
> ### Scenario
>
> The maintainer's throughput target for `solid-server-rs` is "beyond ~50k req/s", explicitly
> including **many concurrent SPARQL queries**. Two consumer paths hit `sparq-solid` per
> request: the WAC decision (every LDP request) and the access-controlled SPARQL endpoint
> (`solid-sparql-query` draft / #992 FR-4; each client query = one `query_as`). Both fan out
> across cores.
>
> ### The blocker (verified `origin/main` @ `69efb1b`, `crates/sparq-solid/src/lib.rs`)
>
> Every read-side session entry point — `accessible`, `accessible_set`, `view_for`,
> `query_as`, `query_json_as`, `ask_as`, `wac_allow` — takes **`&mut self`**, because they
> share the `session_sets` `FxHashMap` cache. One `PodStore` therefore admits **one
> access-controlled read at a time**: N concurrent queries serialize on exclusive access even
> though the underlying engine/read side is lock-free (the sparq-server generation ring).
> Additionally the cache is **unbounded** and keyed `(agent, client, issuer, now, mode)` — a
> server that passes per-request `now` (required once time-conditioned grants matter) gets a
> 0% hit rate *and* unbounded growth.
>
> ### Ask (shape, not prescription)
>
> 1. **`&self` read-side entry points** over an interior-mutability session cache (sharded
>    map / `RwLock`d shards), so one shared `PodStore` serves N concurrent
>    queries/decisions. The engine side already supports concurrent readers; this is only the
>    session-cache surface.
> 2. **Bound the cache** (LRU by principal or total-set-size budget) — a multi-user server
>    holds one entry per distinct `(agent, client, issuer, now, mode)`, each O(accessible-set)
>    in memory.
> 3. **Define the `now` keying policy** (quantize, or key on `now` only when the materialized
>    view contains time-conditioned grants) so per-request timestamps don't defeat the cache.
> 4. **Compose with the generation ring**: publish the auth state (AuthIndex + the #992
>    decision index + session cache) as an immutable per-generation bundle (`Arc`-shared,
>    built once per commit), so a reader pins `(Graph, AuthState)` together. This is the same
>    shape the #1346 P1 "wire sparq-solid into sparq-server" architecture call needs, and what
>    an embedded consumer (solid-server-rs on the #1248 embed surface) would pin per request.
>
> ### Acceptance (suggested)
>
> - Deterministic: the read-side API compiles as `&self` (no exclusive lock on the read
>   path); semantics unchanged (existing WAC/ACP conformance harness green); cache memory
>   bounded by config.
> - Advisory: `query_as`/`decide` throughput scales ~linearly with reader threads on a
>   read-only workload (any fixture; sparq's own bench discipline applies).
>
> Related: #992 (FR surface), #1150 (SharedGraph — the Graph-level analogue of this ask),
> #1248 (embed surface), #1346 (P1 architecture call). 🤖 PSS agent

### 6.2 Draft B — `decide`/`resolve_acl` at large-pod scale (persistent index, indexed membership)

**Title:** `[feature-request, PSS agent] decide/resolve_acl scale: persistent AclIndex + indexed per-resource membership (currently O(store size) per call)`

**Body:**

> 🤖 **PSS agent** — @jeswr's agent for `prod-solid-server` / the Solid suite (Claude
> Fable 5). Consumer-side feature request from the `solid-server-rs` beyond-50k-throughput
> track. Companion analysis: `solid-server-rs` `docs/design/throughput-hard-cases.md`.
>
> First: the #992 FR-1..7 surface shipped fast and the fail-closed semantics
> (`WacDecision`/`AclStatus`) are exactly what the LDP server needs — this issue is purely
> about its **cost model at scale**, which becomes the binding constraint on the maintainer's
> named hard cases (**large pods × complex ACLs × decision-per-request QPS**).
>
> ### The blocker (verified `origin/main` @ `69efb1b`)
>
> 1. **`PodStore::decide` / `resolve_acl` rebuild the structural ACL index per call**:
>    `decide::AclIndex::build(&self.graph)` iterates `graph.named` — every named graph in the
>    store — on **every** decision (`crates/sparq-solid/src/decide.rs`; `lib.rs::decide`).
>    `decide_batch` amortizes only within one batch. An LDP server calls `decide` per request:
>    at a 1M-resource store that is a per-request O(10⁶) scan.
> 2. **The per-mode verdict enumerates the full accessible set**: `decide_one`'s mode loop
>    calls `AuthIndex::accessible(session, mode)` — which allocates the complete sorted
>    `Vec<NamedNode>` of everything the session may access — and then **linearly scans** it
>    for the single resource, ×4 modes, uncached on the `&self` path (`decide.rs`,
>    `modes_held_point`). A principal with broad access on a large pod materializes millions
>    of terms per decision. (`PodStore::wac_allow`'s `modes_held` has the same
>    `.iter().any()` shape over the cached sorted Vec.)
>
> ### Ask (shape, not prescription)
>
> 1. **Persist the `AclIndex`** — build at materialize/reindex time (or per published
>    generation) and maintain incrementally on `put_acl`/`delete_acl`, instead of per-call.
> 2. **Indexed membership instead of enumeration** — answer "does session S hold mode M on
>    resource R" via a hashed/indexed lookup (the `accessible_set` `FxHashSet` shape, or a
>    direct `(principal, mode) → set` structure) without materializing the sorted Vec; let
>    `decide` share the session cache (with issue A's `&self` cache) or an equivalent
>    decision index.
> 3. **Surface an auth epoch/generation in `WacDecision`** — the store already tracks
>    `epoch`; exposing it lets a consumer cache decisions safely keyed on the epoch (the
>    prerequisite `solid-server-rs`'s read-path design names for any server-side decision
>    cache, `backend-read-path.md` §3.5).
>
> ### Acceptance (suggested)
>
> - Deterministic: `decide` performs zero whole-store iterations (pin with an op-count
>   harness the way sparq already pins engine costs); decision results byte-identical to
>   today across the WAC/ACP conformance matrix.
> - Advisory: decisions/sec roughly flat as the store grows 1k → 100k → 1M named graphs
>   (today it degrades linearly by construction).
>
> Consumer note: until this lands, `solid-server-rs` keeps its in-Rust WAC evaluator (flat
> 2-query walk + etag-keyed parse cache) — migrating to `decide` first would *regress* the
> hard cases. This issue is the gate on the read-8-decide-seam integration bead.
>
> Related: #992 (the shipped FR surface this optimizes), #1210 (put_acl), #1346 (P0/P1
> framing). 🤖 PSS agent

### 6.3 Draft C — incremental auth-view materialization + scoped invalidation under ACL-write load

**Title:** `[feature-request, PSS agent] Incremental re-materialization + scoped session-cache invalidation (ACL writes currently rebuild + cold-start the whole store)`

**Body:**

> 🤖 **PSS agent** — @jeswr's agent for `prod-solid-server` / the Solid suite (Claude
> Fable 5). Consumer-side feature request from the `solid-server-rs` beyond-50k-throughput
> track. Companion analysis: `solid-server-rs` `docs/design/throughput-hard-cases.md`.
>
> ### Scenario
>
> A multi-pod store under steady sharing churn: ACL writes are routine (every share/unshare
> is a `put_acl`), while reads run at full QPS. The maintainer's hard cases combine **complex
> ACLs** with **large pods** — many `.acl` graphs, long principal lists, frequent changes.
>
> ### The blocker (verified `origin/main` @ `69efb1b`, `crates/sparq-solid/src/lib.rs`)
>
> `put_acl`/`materialize_wac` → `reindex()` does three whole-store operations on **every ACL
> write**: `AuthIndex::from_graph(&self.graph)` (rebuild over ALL materialized auth triples),
> `epoch += 1`, and `cache.clear()` (drop EVERY session's cached accessible sets). Net effect
> at scale: one tenant toggling one share pays O(all ACLs in the store) on the write path and
> cold-starts every other tenant's cached session sets — post-write decision/query latency
> spikes store-wide, repeated at the ACL-write rate. (#1210 shipped the atomic write-through
> API itself — this issue is about its incremental/scale half. `sparq-server`'s own
> `GLOBAL_POD` invalidation placeholder documents the same "Wave B per-pod visibility"
> refinement direction for its layer.)
>
> ### Ask (shape, not prescription)
>
> 1. **Incremental re-materialization**: `put_acl(acl_iri, …)` re-derives only the auth-view
>    slice governed by that `.acl` (its subtree under `acl:default` inheritance), keeping the
>    existing atomicity/rollback contract.
> 2. **Scoped invalidation**: bump a **per-pod** (or per-governing-ACL-subtree) epoch instead
>    of one global epoch; evict only session-cache entries whose accessible sets could have
>    changed. Aligns with the per-pod PodId direction already noted for sparq-server's caches.
> 3. **(With issue B)** the persistent AclIndex updates incrementally in the same operation.
>
> ### Acceptance (suggested)
>
> - Deterministic: an ACL write for pod X re-derives only X's slice (op-count harness);
>   sessions untouched by X still hit their cache; decisions after the write identical to a
>   full rebuild's (differential test).
> - Advisory: read p99 during sustained ACL-write churn on a multi-pod fixture.
>
> Related: #992 FR-3, #1210, #1346 (P2 operations), issue B (persistent index). 🤖 PSS agent

### 6.4 Draft D — snapshot-consistent pagination over the SPARQL protocol

**Title:** `[feature-request, PSS agent] Snapshot-consistent pagination: expose generation pinning for multi-request LIMIT/OFFSET reads (default build)`

**Body:**

> 🤖 **PSS agent** — @jeswr's agent for `prod-solid-server` / the Solid suite (Claude
> Fable 5). Consumer-side feature request from the `solid-server-rs` beyond-50k-throughput
> track (the **large pods** hard case). Companion analysis: `solid-server-rs`
> `docs/design/throughput-hard-cases.md`.
>
> ### Scenario
>
> Two `solid-server-rs` reads return O(pod)-sized results: a big container's membership
> (`SELECT ?child`, can exceed 10⁵ rows) and the reconciler's referenced-blob-key sweep
> (`SELECT DISTINCT ?bk` over every graph — feeds a fail-closed GC where a silently short
> result would delete live bytes). The client bounds any single HTTP response (16 MiB), so
> both must **page** (LIMIT/OFFSET). But LIMIT/OFFSET across separate protocol requests is
> only correct against an unchanging dataset — an interleaved write can shift row order and
> make pages overlap/skip. For the GC that is a correctness hazard, not just perf.
>
> ### What exists (verified `origin/main` @ `69efb1b`)
>
> `sparq-server` already pins an immutable generation per request (`PinnedGen`, the ring),
> retains K generations, and — behind the opt-in `time-travel` feature — accepts
> `?generation=N`. So the machinery exists; what's missing is a small, default-build,
> documented contract for *multi-request* consistency.
>
> ### Ask (shape, not prescription)
>
> 1. **Expose the committed generation number on query responses** (header or results
>    extension), default build.
> 2. **Accept a generation pin on `/sparql`** within the ring's retention window (or a cursor
>    token equivalent), default build — bounded and best-effort (a pin outside the window is
>    a clean, typed error the client restarts from; no unbounded retention implied).
> 3. Document the ordering guarantee LIMIT/OFFSET pages rely on within one pinned generation
>    (deterministic result order over an immutable snapshot, or a required ORDER BY).
>
> ### Acceptance (suggested)
>
> - Deterministic: two-page LIMIT/OFFSET read with an interleaved write, pinned to one
>   generation, unions to exactly the single-shot result at that generation.
>
> Related: #1416 (wire-contract freeze — this would ride it), #1415 (served-surface
> conformance), the time-travel feature. 🤖 PSS agent

## 7. Benchmark plan — measure the hard cases (extends the P0.1/bench lane)

The committed harnesses measure the small-response front door; none measures these cases.
Extend, in order (all on the EC2 lane per `bench/RUN-ON-EC2.md`; deterministic metrics
hard-gateable, timing advisory — the standing perf-gate rule, `bench/HARNESS.md`):

### 7.1 Fixtures (extend `src/seed.rs` bench seeding — `SOLID_SERVER_SEED_BENCH` already exists)

- **LARGE-POD(P, C, D, b):** P resources total, listing containers of C children, depth D,
  b-byte bodies. Points: P ∈ {10k, 100k, 1M}; C ∈ {100, 10k, 100k}; D ∈ {2, 8, 32}
  (D is a *regression guard* — the flat-2 walk means D must not matter; pin that).
- **COMPLEX-ACL(A, S):** governing ACLs with A ∈ {3, 100, 5 000} `acl:Authorization` rules
  (mix `acl:agent`/`acl:agentClass`/`acl:origin`), exercised by S ∈ {1, 100, 10k} distinct
  principals (S also stresses the verified-token cache here and the session-cache growth in
  sparq — the §6.1/§6.2 acceptance fixtures should mirror it).
- **QUERY-QPS:** the request mix at c ∈ {16, 64, 256}: authed-doc + listing (the server's own
  2–3-query traffic), plus direct `/sparql` load against sparq-server with (i) the
  `read_plan`-shaped combined SELECT and (ii) a client-shaped `GRAPH ?g` query — this is the
  "many concurrent SPARQL queries" case measured *at the backend seam* until the AC-SPARQL
  endpoint exists (then re-run through it).

### 7.2 Deterministic metrics (gate class)

| metric | harness | what it catches |
|---|---|---|
| backend queries/op vs P, C, D, A (must stay flat 2/3) | extend `tests/read_path_counters.rs` / `write_path_counters.rs` with the fixtures | any reintroduced O(depth)/O(size) round-trips |
| engine round-trips/op (embedded) | `EmbeddedSparqClient::engine_round_trips` (`tests/embedded_read_counters.rs`) | same, embedded |
| the 16 MiB listing cliff: GET of a C\*-child container is 200, paged | new IT with LARGE-POD(C=10⁵) | the §3.1 failure cliff (fails today on the remote path — pin the fix) |
| referenced-set retrieval completes at ≥10⁶ keys | reconciler IT | the §3.3 GC cliff |
| blob gets/op = 0 on body-cache hit; bytes buffered per large GET ≤ threshold | `read-4`/`hc2-blob-streaming` gates | large-body buffering regressions |
| allocations/op for listing sizes C | `examples/bench_harness.rs` alloc floor | render-path allocation blowups |
| syscalls/req for new classes `listing-large`, `authed-complex-acl` | extend `bench/syscalls.sh` scenario table | per-request syscall regressions under the hard cases |
| zero exclusive locks on the embedded read path (post `hc1-embed-ring`) | concurrency unit test | the §2.1 convoy |

### 7.3 Advisory (context, never a gate)

RPS/p50/p99/p999 per class per fixture point; peak RSS under LARGE-POD flood
(`examples/adversarial_bench.rs` arm); read p99 during ACL-write churn (the §6.3 scenario);
embedded throughput ratio read-only vs mixed (the mutex-convoy signal, pre/post ring). Report
run context per the house rule; numbers live in `bench/results`/`bench/*.md`, cited from
there.

### 7.4 Sequencing

1. Fixtures + counter extensions (pure test/bench work, no production change) — this makes
   every later claim measurable and pins today's cliffs as failing/ignored tests.
2. `hc1-embed-ring` + `hc2-listing-page` (the two cliffs), each landed on its deterministic
   delta.
3. File §6 drafts (orchestrator); revisit `read-8-decide-seam` when B/C move.

## 8. Sources

In-tree (verified this checkout @ `9735725`): `src/ldp/handler.rs` (`serve_read`,
`authorize_read`, `authorize_planned_iri`, `render_container`), `src/authz/wac.rs`
(`read_plan_candidates`, `authorize_read_planned`, `read_acl_confirmed`), `src/authz/acl.rs`
(`modes_for`), `src/acl_cache.rs`, `src/store/{sparq,http,embedded,mod,blob}.rs`,
`src/seed.rs`, `tests/{read,write}_path_counters.rs`, `tests/embedded_read_counters.rs`,
`bench/syscalls-results/2026-07-04-linux.md`, `bench/{run.sh,HARNESS.md,RUN-ON-EC2.md}`,
`decisions/0001-embed-sparq-in-process.md`, `docs/design/{beyond-50k-throughput,backend-read-path,high-throughput-pop-auth}.md`;
`prod-solid-server/docs/design/solid-server-rs-wac.md`.

`jeswr/sparq` @ `origin/main` `69efb1b6ef2d19fc999f3bc1dcf16657e5ad3e15` (fetched 2026-07-05;
re-verify before filing): `crates/sparq-solid/src/lib.rs` (`session_sets`, `reindex`,
`decide`, `wac_allow`, `query_as`), `crates/sparq-solid/src/decide.rs` (`AclIndex::build`,
`decide_one`), `crates/sparq-server/src/http.rs` (generation ring, `PinnedGen`,
`GLOBAL_POD`), `crates/sparq-serve/src/applier.rs` (structural fork + measured commit costs).
GitHub issues: `sparq#992`, `#1150`, `#1210`, `#1248`, `#1346`, `#1415`, `#1416`, `#1546`;
[`solid-sparql-query`](https://github.com/jeswr/solid-sparql-query).
