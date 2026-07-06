<!-- AUTHORED-BY Claude Fable 5 -->
# 0006 — The LWS read-substrate completion (M3): RFC 9264 linksets, pagination + `size`, RFC 9396 narrowing

**Status:** accepted (M3 landed on `feat/lws` atop M1 `decisions/0004` + M2 `decisions/0005`;
the JLWS spec itself remains a personal draft awaiting the maintainer's steer). Spec pinned @
`jeswr/lws-spec` `deb310e`.

## Context

M1 shipped the flag-gated LWS resource surface, M2 the auth chain. Three read-substrate pieces
remained marked as seams: the spec's §metadata linkset model, §pagination, and §rar
`authorization_details`. All three land here — ADDITIVE and flag-gated under the same
`SOLID_SERVER_LWS` invariant (flag-off is byte-identical, pinned). Notifications/SSE/WebSocket,
the DPoP-bound-LWS-audience PoP profile, and the `SparqlQueryService` companion are deliberately
M4 (the last gated on `sparq#992`).

## Decision 1 — RFC 9264 linksets at `<resource>?linkset` (`src/lws/linkset.rs`)

1. **URI choice: the resource's own path + a reserved query** (`?linkset`), not a sibling path
   (`/.linkset/…`) or suffix (`<r>.linkset-…`). Same-path is load-bearing: the WAC walk, the M2
   audience containment, and the M3 narrowing all key on the PATH, so a linkset is authorized
   exactly like its resource (read = `acl:Read`, `acl:Control` for an `.acl`'s metadata; update =
   `acl:Write`/Control) and a token scope covering the resource covers its metadata with NO second
   containment algebra. It is also collision-free with user-mintable names and trivially
   flag-off-invariant (the flag-off surface never inspects query strings — `parse_target` strips
   them; pinned byte-identical). The spec calls linkset URIs server-chosen; pages use the same
   pattern (`?lws-page=N`).
2. **Document shape.** One context object anchored at the resource. System-managed (D13, never
   client-writable): `up`, `type` (`jlws:Container`/`jlws:DataResource`), `acl`, and the
   `…#storageDescription` link (both namespace spellings guarded — the D14 alias). `mediaType`/
   `size`/`modified` stay member-description attributes of the LISTING (the shape that carries
   them in the spec's own example); `items` is the (paginated) listing's job and is NOT
   duplicated into the linkset. User-managed: `describedby`/`title`/`creator` + custom
   ABSOLUTE-URI relations, strictly validated (absolute http(s) `href`s, string-only target
   attributes, bounded counts/sizes — fail-closed 422).
3. **Update discipline (§metadata-updates, all MUSTs):** `PATCH` with
   `application/merge-patch+json` only (advertised via `Accept-Patch`; PUT/POST/DELETE on a
   linkset URI are 405+`Allow` — PUT is spec-OPTIONAL and not offered). No `If-Match` ⇒ 428
   (`…/problems/metadata-precondition-required`); stale ⇒ 412. The patch applies to the CURRENT
   full document (RFC 7386), then every system-managed member must be VALUE-EQUAL to the current
   one — a changed/removed/added system member is a 409 `…/problems/system-managed-metadata`
   (echoing one unchanged is a no-op, so read-modify-write clients work). NB the RFC 7386
   array-replacement semantics mean a client always echoes the full context object; a `null`
   INSIDE the replaced array is a literal (rejected 422), removal = omission — pinned by test.
4. **Persistence: reserved triples in the resource's OWN graph** (`pss:linksetUser` — one
   validated JSON literal — + `pss:linksetRev`), NOT a hidden companion resource. This makes the
   two spec MUSTs structural: DELETE (`DROP GRAPH`) removes resource+linkset **atomically**, and
   a content re-write preserves user metadata (`update_put_meta` never touches the linkset
   predicates — pinned on the real engine). The reserved-term guard already forbids untrusted
   body RDF from writing these predicates.
5. **Concurrency: revision CAS.** Every successful update writes a fresh operation-unique
   revision under a guarded atomic `DELETE/INSERT … WHERE` (`update_set_linkset`): the guard is
   the OBSERVED revision, or — for a never-patched linkset — record-etag equality + rev-absence,
   so a concurrent linkset update, content re-write, or delete between read and write loses the
   CAS ⇒ 412 (never a lost update). The HTTP client confirms via an ASK for the unique new rev
   (the create-marker discipline); the embedded/in-memory impls decide under their single lock.
   The linkset ETag is `"ls-<rev>"` (patched) / `"ls0-<record-etag>"` (never patched — a content
   re-write of an unpatched resource rotates it, conservatively correct since the system links'
   inputs may have shifted). Strong tags; `If-None-Match` 304 on GET.
6. **V4 conditional-channel closure carried over:** the linkset PATCH runs the SAME
   `guard_conditional_requires_read` as every mutating verb, so a Write-without-Read holder
   cannot probe the (state-derived) linkset validator; with that gate in place the post-auth 404
   discloses nothing a permitted GET wouldn't.

## Decision 2 — Pagination + `size` (`src/lws/container.rs`, `ResourceMeta::size`)

1. **`ResourceMeta.size: Option<u64>`**, stamped at write time from the actual body length
   (mirroring `last_modified` end-to-end: `pss:size` integer in the index, OPTIONAL on read, so
   pre-M3 records report `None` and the SHOULD-level member is simply omitted). Never used for
   `Content-Length` or any decision — descriptive only.
2. **Single-response paging.** `?lws-page=N` over the D12-filtered, lexicographically sorted
   visible membership; RFC 8288 links exactly per §pagination (`first` always, `next` on all but
   the last page and OMITTED on the last, `prev`/`last` when meaningful); `totalItems`/`id`/
   `type` describe the whole visible membership on every page; page size =
   `SOLID_SERVER_LWS_PAGE_SIZE` (default 1000; `0` disables). Sorting makes pages a deterministic
   function of the membership (no skip/dup within a snapshot) and the listing ETag
   iteration-order-independent. Each page is its own representation with its own
   rendered-bytes ETag (the existing 304 machinery applies per page unchanged).
3. **Multi-request snapshot consistency — filed as `sparq#1572`, landed as sparq PR #1584, now
   consumed:** each response derives from ONE combined membership+metadata query
   (`Store::list_children_snapshot`); when the backend advertises a generation token (sparq's
   default-build `Sparq-Generation` header), the paged listing's own links carry it as an
   **authenticated `lws-gen` token** (see 3a — never the raw integer) and every follow-up page
   re-reads the SAME immutable snapshot (sparq's `?generation=N` pin) — pages of one walk tile
   exactly one membership+metadata state. Honest bounds (documented in `src/lws/container.rs`):
   the D12 WAC filter stays LIVE (revocation applies immediately — an ACL change mid-walk may
   still shift visible offsets, deliberately); an aged-out/unknown pin is a 410 `snapshot-gone`
   problem (restart from the container URI, never a silent substitute — a pinned response is
   accepted ONLY when the backend echoes exactly the pinned generation); a generation-less
   backend (in-memory, the embedded engine, a pre-#1584 sparq) mints no pinned links and keeps
   the previous single-response-snapshot contract. A past-the-end page is an empty 200 (opaque
   page URIs may outlive shrinkage), an unusable page value or pin token a 400 problem.
3a. **Pinned listings × live WAC — the deleted-member disclosure closure (an adversarial-verify
   HIGH, independently flagged by codex; fixed 2026-07).** Snapshot membership composed with
   LIVE per-member WAC had a hole: a member that existed at the pinned generation under a
   restrictive own-ACL, then was DELETED (its `.acl` with it), stayed in the pinned snapshot
   while the live walk on its IRI fell back to a (possibly permissive) ancestor `acl:default` —
   disclosing the deleted member's IRI + content-type + size + modified to an agent its own ACL
   denied at the snapshot. Closed with two prongs (both regression-tested end-to-end in
   `tests/lws_http.rs`; removing the primary guard reproduces the disclosure — the mutation
   check):
   - **Current-existence guard (primary; `LdpState::authorize_listing_member`):** a listing
     member is disclosed only if it EXISTS at the CURRENT store state AND live WAC grants the
     read mode — one combined `read_plan` with the member in the target slot (no extra backend
     round-trip). Still-existing members keep fully LIVE ACL evaluation (the pin never freezes
     an ACL). Accepted residual (documented at the guard): a delete-and-recreate under the same
     IRI within the pin's TTL can disclose the OLD incarnation's snapshot metadata when the NEW
     incarnation grants Read — closing it needs a store-level resource identity the index does
     not carry.
   - **Authenticated pins (defence-in-depth; `src/lws/pin.rs`):** the backend generation is a
     small guessable integer, so `lws-gen` carries a server-minted HMAC-SHA256 token
     (`<g>.<exp>.<mac>`; aws-lc-rs primitive, per-process 32-byte key, constant-time compare)
     bound to (container IRI, requester WebID/anonymous-class) with a short TTL
     (`SOLID_SERVER_LWS_PIN_TTL_SECS`, default 300 s). Unminted / forged / tampered /
     cross-container / cross-principal ⇒ the opaque 400 `invalid-generation` (MAC verified
     before expiry, so a forgery never learns it named a once-valid pin); an expired genuine
     token ⇒ the 410 restart. Only verified pins ever reach the backend. Per-process key ⇒ a
     pin minted by one replica 400s on another and the walker restarts unpinned (the same
     graceful degradation as retention ageing); a shared operator-provisioned key is a
     documented follow-up seam, deliberately not built.
4. **Existence-non-disclosure preserved:** the WAC filter runs over the WHOLE membership before
   any slicing, so counts/offsets are functions of the visible view only — pagination adds no
   oracle over hidden members. Cost: the same O(children) ACL walks per listing as M1 (the
   batching seam stands).

## Decision 3 — RFC 9396 `authorization_details`, narrowing-only (`src/lws/rar.rs`)

1. **The security property is structural, then tested.** Enforcement is a pure DENY-predicate
   consulted inside `verify_bearer` — the SAME single, non-bypassable chokepoint as the M2
   audience containment (every LWS-authenticated request routes through it; the auth cache never
   serves the LWS path). It runs AFTER full token verification and BEFORE the WAC engine, which
   still runs downstream unchanged on everything admitted. Effective access is therefore the
   intersection `WAC ∩ aud ∩ narrowing` **by construction**: the module has no code path that
   admits anything, so a widening attempt (locations/actions exceeding WAC or aud) cannot relax
   either ceiling — intersection is monotone. Behaviourally pinned end-to-end: a WAC-denied
   agent with a claim "granting" read/modify/delete on the whole storage still gets 403 on
   read/write/delete and mutates nothing; a location wider than the aud still 401s outside the
   aud (the spec's `rar-cannot-widen` vector, over HTTP).
2. **Scope algebra = the audience algebra.** `locations` containment reuses `audience_contains`
   (same-origin, complete `/`-segment boundaries, the `%2e%2e` identity guard) — one containment
   implementation, one test matrix. Because locations are path-prefix scopes and membership is
   path-aligned, a container passing the chokepoint has every member inside the same location:
   the D12 listing filter can never disclose a member outside the narrowed scope (transitivity),
   which is why no per-member narrowing re-check is needed.
3. **Method → action, conservative (every imprecision = a DENY):** GET/HEAD→`read`,
   PUT/PATCH→`modify`, POST→`create`, DELETE→`delete`, OPTIONS exempt (no resource content; CORS
   answers it pre-auth anyway), anything else denied. `modify` implies `create`+`append`
   (`odrl:includedIn`, one-directional); `delete` is implied by NOTHING. Deliberate under-grants
   (documented M4 refinements): PUT-create needs `modify` (not `create` alone — PUT is
   create-or-replace and existence is deliberately not consulted at the authn chokepoint), and an
   insert-only PATCH under an `append`-only grant is denied (patch content unseen there; letting
   `append` pass the chokepoint would let a delete-PATCH through on WAC-Write — a widen).
4. **Fail-closed parsing (401 `invalid_token`):** a present claim that is not a non-empty array
   of well-formed `jlws:AccessRequest` entries — including FOREIGN entry types (with the
   mandatory single storage audience the claim can only be meant for this storage; enforcing
   part of an AS's decision could widen past it) — rejects the token. Two deny-only softenings:
   an entry carrying members beyond `type`/`locations`/`actions` (the spec's OPTIONAL
   `datatypes`/`purposes` are FURTHER constraints this server cannot evaluate) is kept but
   grants NOTHING, and an unknown action STRING grants nothing without poisoning the entry (the
   profile's own "an unknown action grants nothing" rule). Intelligible-but-uncovered requests
   are **403** with the RFC 6750 §3.1 `error="insufficient_scope"` challenge (the token IS
   valid), derived from the request line only — no existence oracle.
5. **Approved-vs-deferred:** the spec names two AS modes but defines no wire discriminator; this
   server treats every AccessRequest entry as enforceable narrowing (the fail-closed reading —
   enforcing a "deferred" entry can only DENY, never widen). Revisit if the spec grows a marker.

## Consequences / trade-offs

- Flag-ON adds to the M1 list of client-observable changes: `?linkset` / `?lws-page=N` query
  strings become meaningful on LWS deployments (flag-off ignores them byte-identically — pinned),
  one more `Link` (`rel="linkset"`) rides on reads and two (`linkset` + `up`) on 201s, and LWS
  listings over the page threshold return pages.
- `update_put_meta` gained a fifth targeted DELETE (`pss:size`) — same single-update shape.
- The narrowing's conservative method mapping under-serves delete-only/append-only/create-only
  tokens for the finer verbs (documented above); nothing is over-served.
- The `notifications` surface is untouched: a narrowed token's subscribe is denied by the
  narrowing (the subscription path is outside any storage location) — fail-closed until M4
  defines the mapping.
- Linkset updates emit NO notification activity (metadata-change activities are an M4 question
  with the notifications binding).

## Tests (the gate)

`rar.rs` (the narrowing matrix: malformed×16 fail-closed, locations/actions narrowing,
segment boundaries, single-resource locations, `modify`⊃`create`/`append` only, long-form IRIs,
unknown-action tolerance, unenforceable-constraint entries, multi-entry union, the method map) +
`auth.rs` (challenge shape incl. `insufficient_scope`) + `linkset.rs` (document build, RFC 7386
semantics, system-managed 409 matrix incl. the WD-alias spoof, 422 validation matrix, ETag/If-Match
strong-compare) + `container.rs` (page-plan tiling/no-skip-no-dup, RFC 8288 link matrix, page-query
fail-closed) + `sparq.rs`/`store_embedded.rs` (linkset CAS first-write/update/lost races,
delete-atomicity, content-rewrite preservation, `size` round-trip — in-memory AND the real engine)
+ `tests/lws_http.rs` (linkset serve/discovery/304/404/406, the full merge-patch flow with
428/415/412/409/422/405, rewrite-survival + delete-death + fresh-recreate, read-gating incl. the
no-existence-oracle 401, pagination end-to-end with the deterministic 3-page walk + Solid-surface
untouched, `size` in listings, and the flag-off byte-invariance pins for every new query surface)
+ `tests/lws_auth.rs` (narrowing end-to-end: covered-allow / location-deny / action-deny with
`insufficient_scope`, **cannot-widen over live WAC**, aud-ceiling composition, malformed-401
matrix, constrained-entry deny, delete-only exactness, absent-claim baseline). Full suites green:
default + `embedded-sparq`, fmt + clippy `-D warnings`.

## M4 (deferred)

SSE/WebSocket notification bindings under the WD subscription API (+ linkset/metadata change
activities), the DPoP-bound LWS-audience PoP profile (§presentation-pop end-to-end),
`SparqlQueryService`/AC-SPARQL (gated on `sparq#992`), operation-precise narrowing (PUT-create /
append-only PATCH), and the batching of per-member listing ACL walks. (Multi-request pagination
snapshot consistency — formerly gated on `sparq#1572` — landed via sparq PR #1584 and is consumed
on the HTTP-backend path; an EMBEDDED-engine pin needs a library-level snapshot/generation API in
sparq, which does not exist yet.)
