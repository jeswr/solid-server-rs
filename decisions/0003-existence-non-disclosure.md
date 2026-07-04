<!-- AUTHORED-BY Claude Opus 4.8 -->
# 0003 — Existence non-disclosure (404 ⇒ you were allowed to know, and it isn't there)

Status: accepted · Date: 2026-06-29

## Context

A Solid/LDP server must not turn its *response codes* into an **existence oracle**: a requester who
is not authorized for the resource must not be able to tell "this resource exists but you may not
touch it" from "this resource does not exist". Either signal — a status split, a header, a returned
validator — lets an unauthorized party enumerate the private names in a pod (file names, child IRIs,
container membership), which is itself a confidentiality leak even when the *bytes* stay protected.

The drop-box is the canonical adversary: a writer with `acl:Append` on a container `/c/` (so it may
POST members) but **no** `acl:Read`/`acl:Write` on the existing members. Such an agent must be able
to create new members, yet must learn NOTHING about which member names already exist.

This server already evaluated authorization BEFORE the existence check on GET/HEAD/DELETE and on a
delete-bearing PATCH (so those paths fold a missing-but-would-be-readable target's denial uniformly,
and the WAC resolver reads only `.acl` resources — never the target's own bytes). This ADR closes the
**remaining five** existence side-channels (V1–V5), all of the "create-rights-on-parent,
no-rights-on-target" shape, and states the invariant that governs all of them.

## Decision — the invariant

> **A `404` is served ONLY to a requester who holds the operation's required mode.** Every other
> requester — anonymous, or authenticated-but-lacking-the-mode — receives their DENIAL code (401 if
> anonymous, 403 if authenticated) for BOTH "forbidden-existing" AND "not-found", **byte-identically**:
> same status, same body, same headers (`Location`, `ETag`, `WWW-Authenticate`). The rule applies
> across GET / HEAD / PUT / POST / PATCH / DELETE **and** the conditional / header channels, so no
> single verb or header is an existence oracle — with ONE narrow, WAC-inherent residual on the
> PUT/PATCH **create-vs-overwrite** membership axis (see "Residual — the create/overwrite membership
> asymmetry" below).

Equivalently: **`404` means "you were allowed to know, and it isn't there."**

### The direction matters — fold `missing → denial`, never `forbidden → 404`, never blanket-403

There are three ways to make missing and forbidden indistinguishable, and only one is correct:

- **`forbidden → 404`** (report a forbidden-existing resource as 404) — WRONG. It would make an
  authorized reader's true 404 and an unauthorized agent's "forbidden" collapse, but it also DESTROYS
  the legitimate 401-vs-403 distinction the WAC spec asserts, and tells an unauthorized agent the
  resource is "absent" when it is not (misleading + still leaks via timing/caches the moment any path
  diverges).
- **blanket-403** (collapse 401 and 403 into one) — WRONG. It denies an anonymous client the 401 +
  `WWW-Authenticate` it needs in order to authenticate, breaking the auth handshake.
- **`missing → denial`** (report a not-found-but-unauthorized target with the SAME denial code as a
  forbidden-existing one) — CORRECT. The under-authorized requester gets their proper 401/403 in BOTH
  cases; only a requester who already holds the required mode (and could learn existence anyway) ever
  sees a 404. This preserves the exact 401-vs-403 split AND the authorized-reader 404.

So the implementation folds *the missing case up into the denial*, never the forbidden case down into
a 404.

## The five closures (V1–V5)

The adversary throughout is the drop-box writer: `acl:Append` on the parent, no `acl:Read`/`Write` on
the target.

### V1 — PUT create-vs-forbidden-overwrite

**Before:** a PUT to an ABSENT name authorized only parent-`acl:Append` (create), returning 201; a PUT
to an EXISTING name the agent could not overwrite returned 403. The 201-vs-403 split on the same name
leaked whether that name existed.

**Fix:** a PUT now requires `acl:Write` on the **target's effective ACL** (inherited via `acl:default`
for a not-yet-existing target) **regardless of whether the target exists** — create and overwrite
authorize the identical mode against the identical (inherited) ACL, so they are indistinguishable. The
authorization runs BEFORE any `meta()`/existence probe.

**Trade-off (documented prominently):** an `acl:Append`-ONLY agent can **no longer PUT-create** a
resource — it must use **POST** (which mints a server-opaque, collision-free name; see V2). This is a
real, intentional WAC-semantics choice: PUT names the exact target IRI, so PUT-create is a
write-the-target operation and is gated on target-Write; the containment-mutating "add a member"
primitive an Append holder is entitled to is POST. (CTH-safe — see "Conformance latitude".)

### Residual — the create/overwrite membership asymmetry (LOW–MEDIUM, accepted; inherent to WAC)

The container-modification half of the create rule — a PUT/PATCH **create** *additionally* requires
`acl:Append` on the **containing container** (via that container's own `acl:accessTo`), because
minting a member mutates the container's `ldp:contains` membership; this is what stops an
`acl:default`-only Write grant (or a Control-holder-pre-provisioned target `.acl`) from letting an
agent with no right over the container create members in it — is **not symmetric** with **overwrite**,
which mutates no membership and so requires no container right. Consequently one narrow principal can
STILL distinguish existence on PUT/PATCH: an agent that holds `acl:Write` on a member **via the
container's `acl:default`** but does **NOT** hold `acl:Append` on the container **via `acl:accessTo`**
gets a **204** overwriting an EXISTING member (only target-Write is checked) versus a **403** creating
a MISSING one (the container-modification `acl:Append` check fails). That 204-vs-403 split reveals
whether the member existed. So the create-vs-overwrite denial is **not** byte-uniform for this one
grant shape — hence the narrowing of the invariant above.

This asymmetry is **inherent to Web Access Control**, not a gap in the closure. Creating a member is a
container-membership mutation and overwriting one is not, so the two operations legitimately require
different rights; and `acl:default` (which flows to members) and `acl:accessTo` on the container are
INDEPENDENTLY grantable, so the "member-Write-without-container-Append" grant that exposes the split is
expressible and cannot be authorized away without either (a) dropping the container-modification check
— reopening the privilege-escalation it exists to close (`acl:default`-only Write minting container
members) — or (b) forbidding overwrite for any principal that could create, which WAC does not support.
The exposure is bounded: it needs that specific split grant (an owner who grants member-Write via
`acl:default` yet withholds container-Append is unusual), it reveals only **existence** — never content
(the V4/V5 ETag closures still hold) — and only to a principal already trusted to write the member's
representation. It is therefore **accepted** rather than closed.

### V2 — POST colliding-Slug `Location` fingerprint

**Before:** a POST always returned 201, but `Location` was the verbatim `…/foo` when the Slug was FREE
versus a mangled `…/foo-<seed>` when it COLLIDED. The `Location` *shape* leaked whether `foo` existed.

**Fix:** the visible `Location` is now **collision-INDEPENDENT** — the sanitised Slug is used ONLY as a
non-binding PREFIX of a server-opaque, collision-free name (`…/foo-<opaque>`), minted the SAME way
whether or not `foo` exists. The `Location` therefore carries no existence signal, while still
*containing* the Slug substring (the Solid Protocol treats `Slug` as a hint). The `.acl`-intent mint
guard now checks the sanitised Slug STEM (not the post-opaque IRI) so an Append-only `Slug: secret.acl`
is still a uniform 403.

### V3 — insert-only PATCH create-vs-forbidden-modify

**Before:** an insert-only create-on-PATCH authorized parent-`acl:Append` (the create path), while an
insert-only modify of an existing target authorized `acl:Append` on the **target's** effective ACL. An
agent with parent-Append but no target-Append got a 2xx on a free name (create) versus a 401/403 on a
taken-but-forbidden name (modify) — an existence oracle.

**Fix:** the create and modify paths are UNIFIED — the content-derived required mode (Append for
insert-only, Write for any delete) is authorized against the **target's** effective ACL in BOTH cases,
BEFORE the target read. Create and forbidden-modify now return byte-identical denials. (An Append
holder that inherits Append on the target via `acl:default` still creates successfully — CTH-safe.)

### V4 — `If-Match` / `If-None-Match` ETag fingerprint (the conditional channel)

**Before:** a conditional precondition is evaluated against the target's current ETag — a CONTENT- (for
a document) or MEMBERSHIP- (for a container) derived validator. A `Write`-without-`Read` holder doing
`PUT … If-Match: "x"` got a 412-vs-2xx outcome (an existence/content probe) and, on success, an `ETag`
fingerprint of a representation it may not GET.

**Fix:** a content/membership-derived validator is treated as REQUIRING `acl:Read`. When the request
carries ANY conditional precondition AND the (already-authorized) requester's granted modes do not
include `Read`, the handler returns the requester's DENIAL code instead of evaluating the precondition
— closing the conditional outcome and suppressing the ETag. Applied to PUT, PATCH and DELETE, BEFORE
the existence probe. A requester WITH Read keeps full conditional semantics; a requester WITHOUT a
conditional header is unaffected.

### V5 — container ETag membership delta

**Before/now:** the container body is generated from live membership, so its ETag (`representation_etag`,
FNV-1a over the rendered listing) shifts on every child add/remove — a listing oracle.

**Fix / invariant:** the container ETag is computed and emitted ONLY on the GET/HEAD read path, which is
gated by `authorize_read` requiring `acl:Read` on the container — so a non-reader never observes it. The
conditional-channel sibling (a non-reader probing the container ETag via a conditional write) is closed
by V4. Together these Read-gate the container ETag end-to-end. The invariant is documented at both the
emission site and `representation_etag`: if a future change emits a container's representation ETag
outside a Read-gated path, the gate MUST be re-established there.

### The coarse timing channel

The under-authorized denial is returned **before** any target-dependent `meta()`/read/existence probe
in every mutating handler (the access decision itself reads only `.acl` resources, never the target's
own bytes/meta). This removes the obvious "did a target lookup happen?" timing difference between the
missing and forbidden branches. **Microsecond-level parity is explicitly OUT OF SCOPE** — ACL
resolution, cache hits, and allocator behaviour all vary; a constant-time guarantee is not attempted and
not claimed. The closure is structural (no target probe on the deny path), not chrono-constant.

## Conformance latitude (why V1–V5 keep the CTH at 41/41)

The Solid Conformance Test Harness leaves exactly the latitude these closures need (see
`solid/specification#311` on the under-determined create/deny status codes):

- The **unauthorized writer/deleter** cells are **set-valued** — e.g. `POST`-fictive is `[403, 404]` /
  `[401, 404]`, `DELETE`-fictive is `[403, 404]` / `[401, 404]`, `PATCH`-fictive deny is
  `[403, 405, 415]` / `[401, 405, 415]`. Returning the denial code (403/401) lands inside every such
  set, so V1/V3's "deny rather than create" passes.
- The **PUT-fictive create** rows that expect a positive (`[201]`) ALWAYS grant the agent inheritable
  `acl:Write` (`write-access-public` / `write-access-bob`, the `W`-inherited fictive rows). **No CTH row
  expects an Append-only PUT-create = 201**, so V1's "PUT-create requires target-Write" breaks nothing.
  (Verified against `web-access-control/protected-operation/write-access-{public,bob}.feature` and
  `read-access-{public,bob,agent}.feature`.)
- The **PATCH-fictive create** rows that expect a positive grant inheritable `acl:Append`/`acl:Write`
  via `acl:default`, which the target's effective-ACL resolution picks up — so V3's unified
  target-Append authorization still admits them.
- The **authorized-reader 404** rows are PRESERVED: `read-access-{public,bob,agent}` (the `R`-inherited
  fictive GET/HEAD rows → 404), `protocol/writing-resource/post-target-not-found.feature` (an authorized
  `clients.alice` GETs/POSTs a missing target → 404), and `containment.feature:122`. Our rule keeps the
  404 for a requester holding the required mode — V1–V5 only change the *under-authorized* requester's
  response.
- The **exact 401-vs-403 split** is unchanged: `write-access-public` GET = 401, `write-access-bob`
  GET = 403; the folded missing→denial uses the requester's own code (401 anon / 403 authenticated).
- V2's opaque `Location` still satisfies `post-uri-assignment-slug.feature` (`Location contains
  '<slug>'`) and `slash-semantics-exclude.feature` (the minted Location must differ from the colliding
  IRI).

**No CTH conflict was hit.** If a future harness revision genuinely required an Append-only-PUT-create =
201, that would conflict with V1 — the resolution is to keep V1 (the security closure) and re-scope the
harness/skip per the standing upstream-blocker rule, NOT to reopen the oracle.

## Security invariants (the adversarial contract)

Each is pinned by a test in `src/ldp/handler.rs` (`mod tests`):

- **byte-identical denial matrix** — for every verb × {anonymous, authenticated-unauthorized} the
  exists-but-forbidden response equals the not-found response in status + body + `Location` + `ETag` +
  `WWW-Authenticate` (`matrix_missing_equals_forbidden_byte_identical_for_every_verb`).
- **authorized-reader 404 preserved** (`authorized_reader_gets_true_404_on_genuinely_missing`).
- **V1** Append-only PUT-create denied (`v1_append_only_put_create_is_denied_not_201`); owner unaffected
  (`v1_owner_put_create_still_succeeds_201`).
- **V2** `Location` collision-independent (`v2_post_location_shape_is_collision_independent`).
- **V3** PATCH-create == PATCH-forbidden-modify byte-identically
  (`v3_append_holder_patch_create_succeeds_but_oracle_is_closed`).
- **V4** Write-without-Read conditional PUT/DELETE folded to denial, no ETag leaked
  (`v4_write_without_read_conditional_put_is_denied_not_412_or_2xx`,
  `v4_write_without_read_conditional_delete_is_denied`); an UNCONDITIONAL write by a Write holder still
  succeeds (`v4_write_without_read_unconditional_put_still_succeeds`).
- **V5** the container membership ETag reaches only a reader (`v5_container_etag_only_reaches_a_reader`).

## Consequences

- An `acl:Append`-only agent uses **POST**, not PUT-create (V1 trade-off). Documented in the handler +
  here. POST mints a collision-free opaque name, so the drop-box workflow is fully supported.
- A POST `Location` is now always opaque-suffixed (`…/<slug>-<opaque>`), never the verbatim Slug. Client
  code must read the `Location` header (it always could; the Slug was only ever a hint).
- Conformance is unchanged at **41/41** (the closures live inside the harness's set-valued / hint
  latitude; re-run `cargo build --release && ./conformance/run.sh`).
- Microsecond timing parity is out of scope (above); the closure is structural.
