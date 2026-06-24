<!-- AUTHORED-BY Claude Opus 4.8 -->
# 0002 — Skip crypto when the response is identity-independent (skip-crypto)

Status: accepted · Date: 2026-06-24

## Context

`solid-server-rs` delegates token + DPoP verification to the standalone `solid-oidc-verifier` crate.
On a **proof-carrying** request the dominant CPU cost is the per-request **DPoP proof verification**
— an asymmetric (ES256) signature verify (the access-token signature verify is short-circuited by the
round-3 verified-token cache on a hit, but the DPoP proof is fresh per request and MUST be verified
every time for replay/binding, so it cannot be cached away).

The original "skip-crypto" idea: for a read whose response is **identity-independent** (the effective
`.acl` grants the PUBLIC `acl:Read`), skip the proof verify and serve the read as anonymous — the
resource bytes are the same regardless of the caller. We red-teamed this as four candidate options.
The investigation found that the candidate is **narrower than it first appears**, and this ADR records
both the safe scope and — load-bearingly — **why the broader variants are UNSAFE**.

## Decision

### opt 3 (this change): skip the verify for a GET/HEAD that carries NO `Authorization` header

A thin **pre-crypto middleware** (`src/ldp/public_read_skip.rs`) sits in the **same "cheap reject
before crypto" slot as the rate-limit / overload layers** — just INSIDE CORS, just OUTSIDE the auth
middleware — on the LDP routes (`src/app.rs build_router`). It fires for **GET/HEAD only AND only when
the request carries NEITHER an `Authorization` NOR a `DPoP` header.** For such a request it constructs
`token = VerifiedToken::public()` and delegates STRAIGHT to the SAME `serve_read` the handler uses —
it does NOT run a separate pre-check WAC predicate (which would resolve the ACL twice — a regression
caught in review). `serve_read` does exactly ONE anonymous effective-ACL resolution (`web_id = None`)
and returns: a PUBLIC read → 200 + body; an anonymous denial → the same 401 + `WWW-Authenticate` the
full path returns; a malformed target → the canonical 400 (it calls `parse_target` itself). So the
result is byte-identical to the full anonymous path (it IS the same call), with the SAME single ACL
resolution — the middleware only saves the auth middleware's public-token construction + `AuthRequest`
build + a layer hop. Every other verb and every CREDENTIALED request fall straight through to the
UNCHANGED auth path. (The `DPoP` header is a fall-through trigger too, not just `Authorization`: the
auth middleware rejects a malformed `DPoP` header with a `400` even without `Authorization`, so
falling through whenever a `DPoP` header is present preserves that canonical `400` rather than serving
the request as anonymous — a behaviour divergence caught in review.)

### opt 4 (separate change): jti pre-check

A cheap `jti` replay pre-check before the full proof verify — reject an already-seen `jti` without
paying the signature verify. SAFE (it can only reject *earlier* a proof the full path would also
reject as a replay; it never ADMITS). Implemented separately.

## Why the broader variants are UNSAFE — and NOT implemented

### opt-3 for CREDENTIALED reads (serve ANY proof-carrying public read as anonymous) — UNSAFE

The initial implementation short-circuited **any** proof-carrying public read (it served it as
anonymous, emitting `WAC-Allow user == public`). This **FAILED the WAC-Allow conformance suite**
(`web-access-control/wac-allow/public-access-{direct,indirect}.feature`) — a real, observable defect
the adversarial conformance run surfaced — for two independent, decisive reasons:

1. **`WAC-Allow user=` is identity-DEPENDENT.** The `user` audience advertises what THIS requester may
   do. An authenticated **OWNER** of a public resource holds `read/write/control`, NOT the public
   `read`. Serving such a request as anonymous emits `user="read"` and so **UNDER-REPORTS** the
   owner's access — a wrong response. Computing the correct `user=` requires the VERIFIED WebID, i.e.
   the crypto. So a credentialed read's response is **not** identity-independent — only its body is.
2. **A forged proof is INDISTINGUISHABLE from a legitimate owner's proof without the crypto.** To
   serve a forged-WebID proof harmlessly as anonymous, we would have to serve EVERY proof-carrying
   public read as anonymous — including the legitimate owner's, which is exactly the defect in (1).
   The only thing that tells a forged proof from an owner's is verifying it. So "skip the crypto for a
   credentialed public read" cannot be **both** correct (owner sees full modes) **and** safe (forged
   WebID ignored): the two collapse without the verify.

Therefore opt-3 is scoped to the genuinely-anonymous (no-`Authorization`) case. A consequence — stated
plainly — is that **opt-3 yields NO crypto saving**: an anonymous request carries no proof, so the
auth path already does no ES256 work; the skip only relocates the WAC pass slightly earlier and avoids
constructing one public token. The intended "speed up proof-carrying public reads" win is **not
safely realisable** (see `bench/SKIP-CRYPTO.md` for the measured neutrality). opt-3 is retained as a
small, correct, well-tested fast-path for the anonymous public read, and as the documented home for
*why* the credentialed variant is unsafe; the maintainer may choose to drop it if the marginal benefit
is not worth the surface (a review issue records the call).

### opt 1 / opt 2 (skip crypto for a DENIED / NONEXISTENT resource) — UNSAFE

opt 1 = "skip crypto for an anonymous-DENIED resource (just 401)"; opt 2 = "skip crypto for a
NONEXISTENT resource". Both short-circuit a **proof-carrying** request before the verifier on a
deny/absent target. Rejected for two compounding reasons:

1. **No benefit.** The crypto only runs for a proof-carrying request — an anonymous request already
   skips it. So opt 1/2 save nothing on the anonymous traffic they would supposedly speed up; the only
   requests they touch are proof-carrying ones, on which they are harmful (next point).
2. **A remote 401-vs-403 status oracle + a wrong denial.** For a proof-carrying request to a
   denied/nonexistent resource, only the crypto can tell `Unauthenticated` (401) from `Forbidden`
   (403). Skipping to a blanket 401 **collapses the legitimate 403 into 401** — any authenticated user
   could then distinguish "grants to nobody / does not exist" from "grants to someone else" by the
   status (a remote oracle) — and **wrongly denies a legitimately-but-unauthorized user** the correct
   403 (and denies an owner the 200 the crypto would establish — opt 2 on a "nonexistent" target the
   caller may own). Only the crypto returns the correct identity-dependent 200/403/401. NOT
   implemented; an anonymous-denied / nonexistent read falls through to the full verifier.

## Security invariants (the adversarial contract)

opt 3 holds these, each pinned by a test in `tests/public_read_skip.rs` (full-response byte
comparison through the real router) AND re-validated by the WAC-Allow conformance suite:

- **INV-1 ANONYMOUS-EQUIVALENCE.** When the skip fires (a no-`Authorization` GET/HEAD), the response is
  byte-identical to the genuinely anonymous one — it IS the same `serve_read` call with the same public
  token on a request that carries no credentials.
  (`inv1_skip_fires_only_for_no_authorization_request`.)
- **INV-2 IDENTITY-INDEPENDENCE + SCOPE LIMIT.** The skip fires ONLY for a no-`Authorization` request
  and never reads a claimed WebID. A CREDENTIALED public read is never short-circuited: an
  authenticated OWNER of a public resource sees their FULL `user` modes (the full verify ran), and a
  FORGED token is REJECTED (401), never served as anonymous.
  (`inv2_authenticated_owner_of_public_resource_sees_full_user_modes`,
  `inv2_forged_token_on_public_resource_is_rejected_not_served_as_anonymous`.)
- **INV-3 NO-ORACLE.** `WAC-Allow` advertises `user == public` on the anonymous skip (correct — the
  caller IS the public); a missing publicly-readable child is the same 404 anonymous gets.
  (`inv3_anonymous_public_read_wac_allow_user_equals_public`,
  `inv3_missing_public_resource_is_same_404_as_anonymous`.)
- **INV-6 ORIGIN-FAIL-CLOSED.** An `acl:origin`-scoped public grant is skipped ONLY for a matching
  Origin; a no-Origin / wrong-Origin anonymous caller fails closed (401) —
  `authorize_read(web_id = None, origin)` handles this fail-closed.
  (`inv6_origin_scoped_public_skips_only_for_matching_origin`.)
- **(mutation safety)** GET/HEAD only; a mutation NEVER skips the auth path.
  (`mutation_never_skips_crypto_anonymous_put_is_401`.)
- **(private-resource unchanged)** A private resource still runs the FULL crypto: a valid owner proof
  gets 200, anonymous gets 401, a forged token gets 401.
  (`private_resource_still_runs_full_crypto`.)

## Consequences

- The behaviour change is confined to a **no-`Authorization` GET/HEAD** of a publicly-readable
  resource, which now short-circuits before the (cheap) public-token construction. Conformance is
  byte-identical (CTH `passed=41 failed=0 total=41`).
- **No crypto win** is realised — the credentialed variant that would have saved the ES256 verify is
  unsafe (above). `bench/SKIP-CRYPTO.md` records the measured neutrality and the analysis.
- **Follow-ups:** opt 4 (jti pre-check) lands separately. A maintainer review issue should decide
  whether to keep opt-3's anonymous fast-path or drop it given the marginal benefit; this ADR is the
  durable home for the why-credentialed-is-unsafe analysis regardless.
