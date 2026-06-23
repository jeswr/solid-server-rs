<!-- AUTHORED-BY Claude Opus 4.8 -->
# 0001 — Embed SPARQ in-process as a third `SparqClient` backend

Status: accepted · Date: 2026-06-23

## Context

`solid-server-rs` is **SPARQ-authoritative** for the resource graph + access control (the maintainer
directive: the SPARQ access-control graph is the source of truth, S3/`object_store` is backup-only
for bytes). Until now the authoritative-RDF seam — the [`SparqClient`] trait
(`src/store/sparq.rs`) — had two impls:

- **`InMemorySparqClient`** — the test double + the boot-without-SPARQ default (what conformance
  41/41 runs against);
- **`HttpSparqClient`** (`src/store/http.rs`) — the M3 live client over SPARQ's HTTP `/sparql`
  endpoint (SPARQL 1.1 Protocol), for a **shared-service** deployment.

The HTTP path carries real complexity that exists only because of the HTTP transport:

1. **It cannot return rows from an UPDATE.** So `create_child` / `delete_meta_if_empty` learn their
   outcome (`NotFound` / `NotEmpty` / `Deleted` / created-or-not) only by a **follow-up ASK** after
   the update — which races a concurrent containment mutation unless a per-operation **nonce marker**
   that nothing else touches is written atomically with the guarded update and ASK-ed back
   (`http.rs:400-439`, the create/delete-marker dance).
2. **Named-graph isolation is not yet real over HTTP (DEVIATION-1).** Today's `sparq-server` Graph
   Store read side folds TriG/N-Quads named graphs into one default graph, so the "graph IRI ==
   resource IRI" model the WAC design assumes is enforced at the engine layer but not yet over the
   live HTTP surface (FR-4 in `docs/design/solid-server-rs-wac.md`).

The maintainer steered: **use the SPARQ crate directly, not the HTTP service**, for the in-process
DATA path — feasible against sparq as-is, a net simplification.

## Decision

Add a **third `SparqClient` impl, `EmbeddedSparqClient`** (`src/store/embedded.rs`), that consumes
the SPARQ query engine **as a library**: `sparq-core` (the `Graph` store) + `sparq-engine` (the
`query` / `ask` / `update_in_place` entry points), pinned as a **git dependency on `jeswr/sparq`**
(`git+https`, exact rev — mirroring how `solid-oidc-verifier` is pinned), behind an **opt-in
`embedded-sparq` build feature**.

A config-selected backend — `PSS_SPARQ_BACKEND=memory|http|embedded` — chooses the impl at boot via
a `match` in `main.rs`. `CompositeStore<S>` / `AppState<J,R,S>` / the router are all generic over the
SparqClient `S`, so **each arm monomorphizes the same downstream wiring** (one
`build_app_for_store::<S>` seam: seed → `LdpState` → ACL cache → `AppState` → router) — no
consumer-code changes between backends. **The default is `memory`, UNCHANGED** (boot-without-SPARQ +
conformance byte-identical), and the **HTTP impl is RETAINED** (shared-service deployment).

This is the **in-process DATA-path embed only.** The WAC architecture is **out of scope and
unchanged**: the in-Rust `WacAuthorizer` stays authoritative. Moving WAC evaluation into the engine
(the "SPARQ does efficient WAC eval" / access-controlled query direction) is a separate, later,
gated tranche.

### Why it is a net simplification

- **Same queries, different transport.** Every query/update is built by the SAME injection-safe
  builders in `src/store/sparql.rs` that the HTTP client uses — **verbatim**. So the
  conformance-equivalence to the HTTP/in-mem impls is trivial: identical SPARQL, identical
  named-graph model; only the execution path differs (an in-process engine call vs an HTTP POST).
- **It deletes the HTTP transport + the marker/follow-up-ASK atomicity dance.** In-process, the
  whole operation runs **under one held `Mutex<Graph>` lock**, so `create_child` /
  `delete_meta_if_empty` check-then-act with **no interleaving** and return their outcome
  **directly** — the simpler, correct semantics. No nonce markers, no follow-up ASKs.
- **It fixes DEVIATION-1.** The engine's `query` / `update_in_place` fully support
  `GRAPH <g> { … }` over a single `Graph` holding the default graph **plus** named graphs
  (`update.rs`: "INSERT DATA / DELETE DATA with `GRAPH` blocks, `DELETE/INSERT … WHERE` with graph
  templates"). So the graph-IRI-==-resource-IRI isolation the WAC design assumes is **real** in the
  embedded path, with no HTTP-store fold-into-default-graph caveat.

### The sync↔tokio bridge

The `SparqClient` trait is `#[async_trait]` and the server is tokio, but the engine is a **blocking,
CPU-bound** library (it computes against in-RAM indexes — no async I/O). So every engine call is
dispatched to a blocking thread via **`tokio::task::spawn_blocking`**, mirroring the in-tree
off-reactor precedent — `src/redis_replay.rs`'s dedicated-thread+mpsc pattern and the verifier's
`net.rs`. The `Graph` lives behind `Arc<Mutex<Graph>>` (`Graph` is `Send + Sync`, compile-time
asserted in `sparq-core`); the `Arc` is cloned into the blocking closure, which locks + runs the
engine call there. **No "runtime within a runtime"; no tokio worker is ever blocked on the engine.**
Updates use `update_in_place_atomic` (sparq-engine's request-atomic public default), so a `;`-joined
multi-statement update commits all-or-nothing.

### Persistence

`EmbeddedSparqClient::in_memory()` over a fresh `Graph`, or `::open(dir)` over a directory-backed
graph (`Graph::open`, mmap feature), with `::save(dir)` for the on-disk snapshot. The first slice
keeps the in-memory graph and offers save/open as the durable seam; a WAL-on-every-write story (the
directory-backed `update_in_place` path) is a follow-up.

## Data-sharing constraint (load-bearing)

Embedding **localizes the authoritative RDF + ACL index per-instance** (each process owns its
`Graph`). This is **sound NOW for single-instance and read-replica** deployments. A
**horizontally-scaled active/active embed is GATED** on SPARQ gaining a **shared durable backend** —
the same precondition `decisions/0012` (prod-solid-server) records for the stateless-core /
distributed scaling story. Two active embedded instances would each hold a divergent private graph;
without a shared store, writes on instance A are invisible to instance B. Until then:

- **embedded** is for single-instance / read-replica;
- **http** remains the backend for a shared-service, horizontally-scaled deployment (one SPARQ
  service behind every instance).

Feature-request filed upstream: **`jeswr/sparq#1248`** (shared durable backend for active/active
embedding).

## Dependency / supply-chain notes

- `sparq-core` (`features = ["mmap"]` for `open`/`save`) + `sparq-engine`, pinned to
  `jeswr/sparq@98259ec` (`git+https`, NOT `git+ssh`; `Cargo.lock` committed; 0 `git+ssh://`).
  Re-pin to a tagged release once SPARQ cuts one (follow-up).
- **`spargebra` resolves to the unpatched crates.io `0.4.6`.** SPARQ's workspace root carries a
  `[patch.crates-io] spargebra = { path = "vendor/spargebra" }` (W3C-conformance parser fixes), but a
  consuming crate does NOT inherit a git dependency's own `[patch]` — only the top-level workspace's
  patches apply. The queries this server builds are simple, fully-controlled `ASK`/`SELECT`/
  `DELETE/INSERT … WHERE`/`INSERT DATA` over `GRAPH` blocks — none hit the W3C edge cases the vendored
  patch fixes — and the embedded store-IT (17 data-path cases) executes them correctly against the
  unpatched parser. If a future need arises, replicate the patch in this crate's manifest.
- **Feature unification: the embedded deps turn `oxrdf`/`oxttl`'s `rdf-12` (RDF-star) feature ON for
  the whole build.** That adds a `Term::Triple` / `N3Term::Triple` variant to the two `match`es in
  `src/ldp/patch.rs`; both gain a `#[cfg(feature = "embedded-sparq")]`-gated arm that **rejects
  quoted triples as an unprocessable patch** (correct — RDF-1.2 quoted triples are not part of N3
  Patch). The default (no-feature) build is unaffected (the variant is absent).
- **cargo-deny licenses:** sparq's transitive graph introduces **no new rejected license** — the only
  rejection (`webpki-roots@1.0.8` CDLA-Permissive-2.0) **pre-exists** in the default graph via
  `reqwest → hyper-rustls`, unrelated to this change. No allow-list entry was needed for a sparq dep.

## Consequences

- The binary gains a third storage backend with **no change to the default path** (conformance
  41/41 on `memory` is byte-identical) and no new dependency unless `embedded-sparq` is compiled in.
- The embedded data path is re-proven by `tests/store_embedded.rs` (17 cases, cfg-gated) — the same
  data-path behaviors as `tests/store.rs`, run against the real engine.
- **Follow-ups:** (1) upgrade the `Arc<Mutex<Graph>>` slice to a **dedicated-OS-thread / actor**
  owning the `Graph` and serving ops over an mpsc channel (the production target — `spawn_blocking`
  over a shared mutex serialises engine ops); (2) the **WAC-in-engine** tranche (gated, separate);
  (3) **full CTH on `PSS_SPARQ_BACKEND=embedded`** (this slice proves the store-IT-on-embedded; the
  full conformance boot/seed on embedded is the next step); (4) **durable WAL-on-write** via the
  directory-backed `update_in_place` path; (5) **re-pin** to a tagged SPARQ release.
