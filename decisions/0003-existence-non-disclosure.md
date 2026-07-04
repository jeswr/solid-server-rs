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
existence side-channels of the "create-rights-on-parent, no-rights-on-target" shape (V1–V5), plus the
`acl:default acl:Append` "drop-anywhere" descendant-existence oracle the PR #3 adversarial verify later
execution-proved (V6), and states the invariant that governs all of them.

## Decision — the invariant

> **A `404` is served ONLY to a requester who holds the operation's required mode — and, on a branch
> whose STATUS itself discloses existence, only to one who holds `acl:Read` on the target.** Every other
> requester — anonymous, or authenticated-but-lacking-the-mode — receives their DENIAL code (401 if
> anonymous, 403 if authenticated) for BOTH "forbidden-existing" AND "not-found", **byte-identically**:
> same status, same body, same headers (`Location`, `ETag`, `WWW-Authenticate`). The rule applies
> across GET / HEAD / PUT / POST / PATCH / DELETE **and** the conditional / header channels, so no
> single verb or header is an existence oracle — with TWO narrow, WAC-inherent residuals: one on the
> PUT/PATCH **create-vs-overwrite** membership axis (see "Residual — the create/overwrite membership
> asymmetry" below), and one on the **POST inherited-Read descendant-existence** axis (see "Residual —
> the POST inherited-Read descendant existence asymmetry" below).

The **existence-disclosing STATUS** qualifier is why POST needs the extra `acl:Read` gate (V6 below):
a POST authorizes only `acl:Append`, which for a MISSING target is satisfied via the target's INHERITED
`acl:default` — an Append-holder can therefore NAME a descendant and read its existence out of the
404/405-vs-403 split without ever holding Read. The V4 conditional channel is the exact same shape (a
`Write`-without-`Read` holder reading existence/ETag out of a 412-vs-2xx), and is closed the same way:
**a branch whose status DISCLOSES existence requires `acl:Read`, not merely the operation's write-mode.**
GET/HEAD already require Read intrinsically, so their authorized-reader 404 is unaffected.

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

## The closures (V1–V6)

The adversary throughout is the drop-box writer: `acl:Append` on the parent, no `acl:Read`/`Write` on
the target. V1–V5 close the `acl:accessTo acl:Append` shape; V6 (added after the PR #3 verify) closes the
`acl:default acl:Append` "drop-anywhere" shape that flows to descendants.

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

### V6 — POST descendant-existence via inherited `acl:default` (the drop-anywhere grant)

**Discovered by the PR #3 adversarial verify (execution-proved), after V1–V5 landed.** The matrix's
drop-box adversary holds `acl:accessTo acl:Append` on `/c/` — a grant that does NOT flow to descendants,
so that adversary cannot even NAME a sub-container as a POST target (a POST to `/c/sub/` resolves
`/c/sub/`'s effective ACL via the `acl:default` scope, which an `accessTo`-only rule never matches, so it
is a uniform 403). But a **realistic** "drop a file anywhere under `/c/`" grant is `acl:default acl:Append`
— which DOES flow to every descendant. With it:

**Before:** for an agent (Bob) holding `acl:default acl:Append` on `/c/` (no Read):
- `POST /c/hidden/` where `hidden/` EXISTS with its OWN restrictive `.acl` denying Bob → **403** (the
  child's `accessTo` overrides the inherited default at authorization).
- `POST /c/ghost/` where `ghost/` is MISSING → the inherited `acl:default acl:Append` authorizes the
  POST, then the container-exists check returns **404**.

The 403-vs-404 split lets Bob enumerate which descendant names exist — even ones he may not access. The
identical split exists on the non-container branch (`405` for an existing plain resource he inherits
Append on, `404` for a missing one).

**Fix:** the POST **existence branch** (the 404 for a missing container, and the 404/405 for a
non-container) is an existence DISCLOSURE, so it requires the target's READ-mode — `acl:Read` for a normal
resource, but `acl:Control` for an `.acl` target (reading an `.acl`'s existence is a Control operation;
`Control` does not imply `Read`, so a Control-only holder — who IS entitled to know the `.acl`'s existence
— must not be folded). This is EXACTLY the read-mode the V4 conditional-channel gate
(`guard_conditional_requires_read`) computes, kept in lock-step. When the (already-authorized) requester's
granted modes do NOT include that read-mode, the handler returns the requester's DENIAL (401 anon / 403
authenticated) — byte-identical to an existing-but-forbidden sibling — INSTEAD of the 404/405. A read-mode
holder (the pod owner, or any inheritable-Read holder) keeps the true 404/405: they could GET/read the
target and learn its existence anyway. The **success path is NOT gated** — a POST into an EXISTING
container still returns 201 for an `acl:Append`-only writer, so the drop-box create workflow is intact;
only the existence-disclosing 404/405 branches fold. Enforced in `post_handler` via
`guard_post_existence_requires_read`, BEFORE the existence probe on the non-container branch. NB the
required mode to even REACH each branch differs — POST to a **container** requires `acl:Append`, to a
**non-container** requires `acl:Write`, and to an **`.acl`** requires `acl:Control` — but the gate is
uniform: whatever governs READING that target's existence.

**The backend-fault sub-channel (closed too).** The missing-**container** branch must PROBE existence
(`store.exists`) to decide create-vs-not — it cannot run the gate first, because an EXISTING container is
the 201 success path an Append-only writer is entitled to. That probe is a TARGET-dependent lookup, so a
`store.exists` FAULT would otherwise escape as a 500 to a no-read requester — a 500 an
existing-but-forbidden sibling (denied at authorization, which reads only `.acl` records and never probes
the target) can never produce, i.e. a backend-error existence/state oracle of the same class the
`patch_*_faulting_target_read` tests pin. So the probe folds BOTH its non-create outcomes — the `Ok(false)`
missing case AND an `Err` fault — through the read-mode gate; a read-mode holder (entitled to the target's
state) still gets the true 404 / the surfaced 500. The non-container branch needs no such handling: its
gate runs before the probe, so a no-read requester never reaches the `exists` call.

**Why `acl:Read`, not "`acl:accessTo` on the container" (the discarded distinguisher).** The obvious
alternative — grant the 404 only to a requester with a genuine `acl:accessTo` container-write right, fold
everyone authorized merely by inherited `acl:default` — is WRONG on two counts, both verified against the
CTH:
- It **breaks the CTH.** `protocol/writing-resource/post-target-not-found` POSTs (as the OWNER
  `clients.alice`) to a reserved child of a **freshly `createContainer()`'d** test container that has NO
  own `.acl`; Alice's authorization there is via the pod root's inherited `acl:default`, so she holds NO
  `accessTo` on the nearest existing ancestor. An `accessTo`-based fold would 403 her → the required 404
  fails.
- It **does not even close the oracle.** An agent holding `acl:accessTo acl:Append` on `/c/` (a "genuine
  POSTer" by that distinguisher) but no Read STILL gets 403 on an existing-locked child and would get 404
  on a missing one — the split just moves to a different grant shape. `acl:Read` is the one property that
  the legitimate owner genuinely holds and an existence-probing writer genuinely lacks, and it aligns V6
  with V4/V5 (existence/content disclosure ⇒ Read).

### Residual — the POST inherited-Read descendant existence asymmetry (LOW, accepted; inherent to WAC)

V6 fully closes the oracle for any requester who lacks Read on the target — the proven, realistic drop-box
case. One narrow principal still distinguishes: a requester who holds `acl:Read` on a subtree **via an
ancestor's `acl:default`** but is SEPARATELY denied on a specific EXISTING child by that child's OWN
restrictive `.acl` gets a **403** on that locked child versus a **404** on a missing sibling — revealing
that one child's existence. This is **inherent to Web Access Control**, exactly like the V1
create/overwrite residual: a per-child `.acl` legitimately OVERRIDES inherited access (that is the whole
point of `accessTo`), and `acl:default` (which flows to descendants) and a child's own `accessTo` are
INDEPENDENTLY grantable, so the "inherits Read from the parent, denied by the child's own ACL" shape is
expressible and cannot be authorized away without either (a) dropping the child-`.acl`-overrides-parent
rule — which breaks WAC — or (b) folding the authorized-reader 404 itself — reopening the disclosure for
the very reader the CTH requires it for. The exposure is **bounded**: it needs that specific split (an
owner who grants Read over a subtree via `acl:default` yet writes a child `.acl` that excludes that same
reader — unusual), it reveals only **existence** of that one child (never content — V4/V5 hold), and only
to a principal already trusted to READ the surrounding subtree. It is therefore **accepted** rather than
closed — hence the second narrowing of the invariant above.

### The coarse timing channel

The under-authorized denial is returned **before** any target-dependent `meta()`/read/existence probe
in every mutating handler (the access decision itself reads only `.acl` resources, never the target's
own bytes/meta). This removes the obvious "did a target lookup happen?" timing difference between the
missing and forbidden branches. **Microsecond-level parity is explicitly OUT OF SCOPE** — ACL
resolution, cache hits, and allocator behaviour all vary; a constant-time guarantee is not attempted and
not claimed. The closure is structural (no target probe on the deny path), not chrono-constant.

## Conformance latitude (why V1–V6 keep the CTH at 41/41)

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
- **V6 specifically keeps `post-target-not-found` green.** That scenario POSTs (as the OWNER
  `clients.alice`) to a reserved child of a freshly-created test container → expects 404 (Scenario 1) or
  `[404, 405]` (Scenarios 2–4). Alice holds inheritable `acl:Read` on the test subtree (she is the pod
  owner via the root ACL's `acl:default`), so V6's Read-gate leaves her true 404/405 UNTOUCHED. The
  **POST-fictive deny** rows an under-authorized writer hits are set-valued (`[401, 404]` / `[403, 404]`),
  so V6's fold of a no-Read writer to 401/403 lands inside every such set. No CTH row expects an
  Append-only-without-Read POSTer to receive a 404/405 on a missing/reserved target, so the fold breaks
  nothing.
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
- **V6** an `acl:default acl:Append` (no-Read) writer cannot distinguish a missing sub-container from an
  existing-but-locked one — byte-identical 403 on both, on the container branch
  (`v6_post_default_append_dropbox_existence_oracle_closed`); the non-container branch (which requires
  `acl:Write`) folds a Write-without-Read writer likewise
  (`v6_post_write_without_read_non_container_branch_closed`); the accessTo-Append-without-Read POSTer is
  folded too, so the discarded accessTo-distinguisher cannot reopen it
  (`v6_post_accessto_append_without_read_is_also_folded`); the OWNER (inheritable Read) keeps the true 404
  (`v6_post_owner_still_gets_true_404_on_missing_subcontainer`, the CTH `post-target-not-found` analog); a
  Control-holder POSTing to an `.acl` target keeps the true 404/405 — the gate uses the target's read-mode
  (Control for an `.acl`, not Read), so a Control-only holder is never wrongly folded
  (`v6_post_control_holder_on_acl_target_keeps_true_existence_status`); a `store.exists` fault on the
  missing-container probe folds to the no-read requester's denial rather than leaking a 500, while the
  Read-holding owner still gets the surfaced 500 post-auth
  (`v6_post_no_read_writer_exists_fault_folds_to_denial_not_500`,
  `v6_post_authorized_reader_exists_fault_surfaces_500_post_auth`); and the Append-only drop-box create
  into an EXISTING container still succeeds — the success path is not gated
  (`v6_post_append_only_dropbox_create_into_existing_container_still_201`).

## Consequences

- An `acl:Append`-only agent uses **POST**, not PUT-create (V1 trade-off). Documented in the handler +
  here. POST mints a collision-free opaque name, so the drop-box workflow is fully supported.
- A POST `Location` is now always opaque-suffixed (`…/<slug>-<opaque>`), never the verbatim Slug. Client
  code must read the `Location` header (it always could; the Slug was only ever a hint).
- An `acl:default acl:Append` "drop-anywhere" grant (V6) lets an agent POST members into any EXISTING
  descendant container it inherits Append on (→ 201), but no longer lets it enumerate which descendant
  names exist: a POST to a missing/locked descendant is now the requester's uniform denial unless it also
  holds `acl:Read` on the target.
- Conformance is unchanged at **41/41** (the closures live inside the harness's set-valued / hint
  latitude; V6 preserves `post-target-not-found`'s owner-404 via the Read-gate — re-run
  `cargo build --release && ./conformance/run.sh`, esp. `post-target-not-found`, before final arming).
- Microsecond timing parity is out of scope (above); the closure is structural.
