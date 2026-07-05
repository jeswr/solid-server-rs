<!-- AUTHORED-BY Claude Fable 5 -->
# 0004 — The flag-gated LWS surface (M1 vertical slice)

**Status:** accepted (M1 landed on `feat/lws`; awaiting maintainer review — the JLWS spec itself
is a personal draft awaiting his steer, `jeswr/lws-spec` DECISIONS.md).

## Context

The maintainer directed: *"create a branch of solid-server-rs which correctly implements LWS."*
The spec implemented is the **JLWS clean-slate LWS design** (`jeswr/lws-spec` — `index.html` core
protocol + `rdf-transform.html` RDF-content-transformation companion), a wire-compatible superset
of the W3C LWS WG's lws10-core WD with the divergences catalogued in that repo's DECISIONS.md
(D-numbers below refer to it). This server already ships a Solid/LDP surface with conformance
pins (41/41 CTH), WAC, and the existence-non-disclosure closures (`decisions/0003`) — the LWS
surface must COMPOSE with it, never regress it.

## Decision

An **additive, runtime-flag-gated** surface in `src/lws/` (`SOLID_SERVER_LWS`), hanging off an
`Option<Arc<LwsConfig>>` on `LdpState`:

1. **Flag-off is byte-identical.** `None` (the default) means: no `/.well-known/lws` route
   mounted, no LWS `Link` headers, no LWS branch executed. Every hook in the existing handlers is
   an `is_some()`-gated branch whose `else` arm is the untouched pre-existing code. An env flag
   (not a cargo feature) was chosen so one binary serves both postures and the tests exercise the
   whole flag matrix in one build; the route-mounting pattern follows the DPoP-SK precedent
   (`app.rs` mounts `/.pop/session` only when that tier is on).

2. **M1 scope** (the coherent vertical slice):
   - *Discovery* (spec §discovery, D5): a CID-shaped storage description at `/.well-known/lws` —
     `conformsTo` protocol-version URIs, the capability registry (including the
     **`ContentNegotiation`** RDF opt-in entries), a self-referential `StorageDescription`
     service; same-bytes conneg across `application/lws+json` / profiled `application/ld+json` /
     `application/json`; bound via `Link rel="…lws#storageDescription"` on GET/HEAD, with
     `rel="up"` containment links (§containment).
   - *Container listing* (§container-representation, D12/D13): the flat server-managed
     `{id, type, totalItems, items[]}` JSON-LD shape, selected by an LWS-profile `Accept`;
     **fail-closed per member** — each child is included only after the same planned WAC
     `acl:Read` walk the read path uses, and `totalItems` counts the visible view only.
   - *RDF content transformation* (`rdf-transform.html`, D18; `SOLID_SERVER_LWS_RDF_TRANSFORM`,
     default on with LWS): stored Turtle/JSON-LD negotiable to N-Triples (+ each other) through
     the existing oxttl/oxjsonld parse path (SSRF-safe: no remote-context fetches by
     construction); per-representation ETags (`"<state>+nt"` …) whose state part the existing
     conditional evaluator already accepts on `If-Match`; authoritative-bytes (stored-type reads
     are byte-exact; no `normalizes`); unparseable-source → 406 problem details; the
     §authoritative-bytes write guard (N-Triples — an advertised target that is not a source —
     over an RDF-readable resource ⇒ 415, so a resource is never stranded).
   - *Idempotent create* (D2): `PUT + If-None-Match: * ` → 201/412 (the existing RFC 9110
     conditional infrastructure already implements it; now pinned as LWS behaviour).

3. **Strict D2/D3 PUT semantics are a second toggle** (`SOLID_SERVER_LWS_STRICT_PUT`, default
   off): 428 on any unconditional PUT, 409 `missing-parent` (no auto-created intermediate
   containers), 400 on a container-PUT body (a container is never a data resource). These
   REPLACE Solid's PUT semantics (auto-intermediates, unconditional PUT — CTH-pinned), so they
   cannot be on by default in a composed Solid+LWS deployment. A pure-LWS deployment turns them
   on. A per-request profile negotiation that could subsume this deployment-level toggle is an
   M2 design question.

   *Existence-disclosure check (decisions/0003 lens):* the strict 409 `missing-parent` vs 201
   split reveals the PARENT container's existence — but only to an agent already authorized to
   create at the target (target-`Write` via the effective ACL + `Append` on the nearest existing
   ancestor, both checked first). That same agent can already learn the same fact through the
   sanctioned V4 bare-`*` channel (`PUT <parent> If-None-Match: *` → 201-created vs 412-exists,
   explicitly exempted for required-mode holders), so the strict branch adds no oracle beyond
   what decisions/0003 already grants that principal class.

4. **LWS errors carry RFC 9457 problem details** (D17) via a dedicated
   `ServerError::LwsProblem { status, type_uri, title }` variant (fixed registry under
   `…/lws/problems/`, never request-derived), constructed ONLY on LWS code paths — the existing
   surface's error bytes are unchanged.

5. **Surface-preserving negotiation is load-bearing and pinned.** The transform negotiation
   resolves IDENTICALLY to `content::negotiate_accept` for any `Accept` not naming
   `application/n-triples` (property-tested over a corpus); the container-shape negotiation
   selects the LWS shape only for `application/lws+json` / profiled `ld+json` at ≥ the best
   existing-producible weight, or plain `application/json` where the request would previously
   have been a 406. Wildcards never select an LWS-only form.

## Consequences / trade-offs

- Flag-ON changes exactly three things a Solid client could notice: `/.well-known/lws` becomes a
  reserved GET-only path (405 on writes, like `/.well-known/solid`), two extra `Link` headers ride
  on reads, and (transform-on) an N-Triples overwrite of an RDF resource is 415 instead of
  silently stored as opaque bytes. All are documented; the CTH posture (flag-off) is untouched.
- The per-member listing filter costs O(children) ACL walks per LWS listing; batching the
  member-visibility plan into one round-trip is an M2 optimisation seam.
- `size` is omitted from member descriptions (SHOULD-level) — `ResourceMeta` records no byte
  length; adding it is an M2 store change. Pagination (SHOULD) likewise deferred.
- M2 — the LWS auth chain (RFC 9728 `resource_metadata` challenge + audience-restricted ≤300 s
  `at+jwt` Bearer validation) — **SHIPPED**; see `decisions/0005-lws-auth-m2.md`. Still deferred
  (M3, seams marked in `src/lws`): RFC 9264 linksets, SSE/WebSocket notification bindings under
  the WD subscription API, pagination/`size`, and the `SparqlQueryService`/AC-SPARQL companion
  (gated on the same SPARQ access-control design as WAC-in-SPARQ, `sparq#992`).
- The `jeswr/lws-spec` `test-vectors/` suite (parallel work) plugs in over plain HTTP against the
  assembled router; `tests/lws_http.rs` is the hand-written pin of the same contract and the
  runner template.
