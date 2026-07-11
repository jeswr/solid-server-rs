<!-- AUTHORED-BY Claude Fable 5 -->

# WebID hosted outside the pod — the identity host (RSS)

**Status:** accepted; the serving + seed foundation is implemented (`src/identity.rs`, the seed's
identity mode) behind `SOLID_SERVER_IDENTITY_ENABLE` (default **off**). Provisioning does not exist
in RSS yet — the admin provisioning seam is a documented forward reference, not shipped code.
**Source design:** prod-solid-server `decisions/0020-webid-outside-pod.md` (the maintainer security
directive; Inrupt ESS ≥ 2.0 made the same separation — `id.inrupt.com` vs `storage.inrupt.com`).
This document ADAPTS that decision to RSS's architecture (SPARQ-authoritative store, WAC engine,
axum routing) so the invariant is baked in **from the start** rather than retrofitted.

## Problem — the WebID document is the identity trust root, and pods are the wrong place for it

Under Solid-OIDC, the WebID document is what every resource server **on the web** dereferences to
learn which issuers may mint tokens for that WebID (`solid:oidcIssuer`) and where its storage lives
(`pim:storage`). A provider-issued WebID hosted at the conventional `<pod>/profile/card` is a
WAC-governed, owner-writable resource whose subtree routinely receives broad `acl:default` grants to
apps — the *normal* Solid consent pattern. That leaves the identity trust root one over-broad or
accidental grant away from:

| Threat | In-pod WebID | Identity host |
|---|---|---|
| Over-broad/accidental WAC grant reaches the WebID doc | Yes — the card's ACL is owner-Control, grants delegable | **Impossible** — no ACL exists (or can exist) for the reserved namespace; the id route never evaluates WAC |
| Malicious app with pod-wide Write rewrites `oidcIssuer` → ecosystem-wide identity takeover | Yes | No — the demoted in-pod card carries no issuer triple and is no longer the WebID; the id-doc is 405 to every HTTP write |
| Owner deletes/corrupts their own WebID doc (auth lockout) | Yes | No — provider-managed, unreachable from the LDP surface |
| `pim:storage` tampering redirects apps to attacker storage | Yes | No — locked in the id-doc; the demoted card carries no `pim:storage` |
| Handle/route collision shadows the id namespace | — | The dotted `/.identity` segment can never match the handle grammar (no `.` admitted); exact-Host routing; `identity`/`livez`/`readyz` reserved handles |

On RSS itself an attacker-added issuer only wins if it is also in the trusted-issuer allowlist, but
the WebID is a **global** identifier: every *other* Solid server trusts whatever issuers the
dereferenced profile lists. This is the accidental-grant-over-OIDC-statements class the maintainer
flagged; PSS closes it behind `PSS_IDENTITY_ENABLE`, and RSS bakes the same shape in pre-launch.

## Decision

1. **WebID form:** `https://<identity-host>/<handle>#me` (document at
   `https://<identity-host>/<handle>`) — the hash-`#me` form (person ≠ document), matching PSS
   ADR-0020. Default host: `id.<base authority>`, DERIVED from `SOLID_SERVER_BASE_URL` so the server
   stays deployment-agnostic; override with `SOLID_SERVER_IDENTITY_HOST`. The host MUST differ from
   the base authority (boot fails closed otherwise — an identical host would swallow all LDP
   traffic).

2. **Storage — outside the LDP-resource→storage mapping.** Id-docs live in the store under the
   **reserved internal namespace** `<base>/.identity/<handle>`, with three construction-level
   properties (not policy checks):
   - **The LDP surface refuses `/.identity/**` outright** — 404, every method, every origin,
     %-decoded too, **regardless of the identity flag** (so pre-seeded documents can never become
     LDP-addressable — and thus `.acl`-able — when the flag later turns on). Two chokepoints
     enforce it: the identity gate middleware (outermost, before auth/WAC/storage) and
     `ldp::target::parse_target` (belt-and-braces — every handler, plus any internally-constructed
     target re-validated through it). Consequently **no `.acl` exists or can ever be created for
     the namespace, so no WAC grant can ever apply to an id-doc.**
   - **No containment edge is ever recorded** for an id-doc (written via `Store::write`, never
     `create_in_container`), so the namespace appears in no `ldp:contains` listing — it is
     invisible to the LDP resource model, not merely protected.
   - **The WAC engine cannot reach it even in principle:** WAC resolution walks the target's own
     ACL then ancestor `acl:default` ACLs — all LDP-namespace IRIs. The id route never invokes the
     authorizer, and no LDP target can name the namespace (refused above), so no resolution walk
     ever touches a `/.identity/**` IRI.

   **The SPARQ named-graph mapping (forward shape, `sparq#992`).** Today RSS's store doubles key
   resources by IRI in a single index, and the WAC engine evaluates `.acl` documents read through
   the `Store` seam — so the reserved key prefix IS the graph boundary. When the
   SPARQ-authoritative access-control design lands (ACL graph in SPARQ = source of truth, SPARQ
   evaluates the per-resource decision), the id-docs move to a **dedicated SPARQ named graph**
   (e.g. `<base>/.identity/`) that is **excluded from the WAC evaluation scope by construction**:
   the access-control graph and the resource graphs SPARQ evaluates over never include the identity
   graph, and the identity graph is not reachable from the LDP-resource→storage mapping. The
   invariant to preserve verbatim across that migration: *no WAC evaluation — server-side or
   SPARQ-side — may ever take an id-doc as its target or its ACL source.*

3. **Serving — a dedicated, Host-keyed, GET/HEAD-only, no-WAC route.** The identity gate
   (`identity_gate_middleware`, mounted as the OUTERMOST application layer in `app::build_app_routes`)
   exact-Host-matches the configured identity host and answers entirely by itself — an id-host
   request never reaches the auth middleware, the WAC engine, or the LDP handlers:
   - `GET`/`HEAD /{handle}` → the id-doc, with Turtle/JSON-LD content negotiation, `ETag` +
     `If-None-Match` 304, `Cache-Control: public, max-age=300`, an explicit
     `Access-Control-Allow-Origin: *`, and `Vary: Accept`;
   - **no `WWW-Authenticate`, no `.acl`/`describedby` Link, no `WAC-Allow`** — by omission, the
     route runs no auth and no authorization at all (public **by construction**: no ACL exists for
     the namespace, so a WAC pass would fail-closed deny and wrongly break every id-host
     dereference);
   - every other method → `405` + `Allow: GET, HEAD`;
   - anything not exactly one valid non-reserved handle (the root, nested paths, percent-encoded
     or malformed handles) → fail-closed `404`.
   The handle grammar is `[a-z0-9][a-z0-9-]{0,63}`, minus the reserved names (`identity`, and
   `livez`/`readyz`, which the overload-exempt health router — mounted outside the gate —
   shadows). Deliberately in-process, not a separate microservice: the (future) bidirectional
   WebID↔issuer check must read the doc even when everything else is down, and RSS's verifier seam
   can read the reserved key through the store without an HTTP hairpin.

4. **The id-doc content is provider-LOCKED.** Exactly: the `foaf:primaryTopic` wiring, the Person
   type, the locked `solid:oidcIssuer` (the identity trust root), the locked `pim:storage` → the
   pod root, the `<pod> solid:owner <webid>` back-link (asserted per-user in the PUBLIC id-doc,
   never aggregated into one enumerable server-wide document — PSS ADR-0020's user-enumeration
   deviation), and `rdfs:seeAlso` → the in-pod extended profile. Built from `oxrdf` triples and
   serialised with `oxttl` (the house rule — RDF is never hand-concatenated).

5. **The in-pod `profile/card` is DEMOTED** to a user-editable extended profile carrying **no
   `solid:oidcIssuer` and no `pim:storage`** — nothing security-bearing may live in a WAC-governed,
   owner-writable document. The pod-root ACL's owner `acl:agent` is the **id-host WebID**.

6. **Writes to the namespace happen ONLY through the provisioning seam — which does not exist in
   RSS yet.** Honestly: RSS has no provisioner. Today the only writer is the dev/conformance seed
   (`seed::seed_conformance_with_identity`, gated behind `SOLID_SERVER_SEED_CONFORMANCE` +
   `SOLID_SERVER_IDENTITY_ENABLE`), which mints the locked id-doc at the reserved key, binds the
   pod ACL to the id-host WebID, and demotes the card. When RSS grows an admin provisioning
   endpoint (the PSS `POST /admin/provision` analogue), it writes id-docs through the same `Store`
   seam at the same reserved keys — the serving/refusal contract in this document already covers
   it and does not change.

## What this change deliberately does NOT do

- **No provisioning endpoint** — RSS has none at all yet; forward-referenced above.
- **No constrained user edits of the id-doc** (Inrupt-style locked-required-triples + validated
  extras) — PSS ADR-0020 Phase 2; v1 here is read-only + the demoted in-pod extended profile.
- **No broker/IdP wiring** — RSS delegates token verification to `solid-oidc-verifier` and has no
  IdP of its own; the Keycloak `webid`-claim flip is a deployment concern (the PSS broker already
  implements it).
- **No migration tooling** — RSS has no live deployment to migrate; the conformance seed simply
  mints the new shape when the flag is on.

## Conformance / test posture

`SOLID_SERVER_IDENTITY_ENABLE=false` (the default) is byte-for-byte the prior behaviour everywhere
except the unconditional LDP refusal of `/.identity/**`. The existing CTH run (41/41) is unaffected
by default. In identity mode the seed mints id-host WebIDs, so a CTH run against identity mode
needs the harness's test-subject WebIDs (and the Keycloak service-account `webid` claims) pointed
at `https://<identity-host>/<handle>#me`, plus DNS/hosts + TLS for the id host — tracked as the
follow-up conformance leg, exactly as PSS's gates-table requires for any auth-adjacent change.

Tests pinning the contract:
- `src/identity.rs` — config derivation/fail-closed rejection, the reserved-path predicate (raw,
  %-encoded, case variants), the fail-closed handle grammar, the reserved-key mapping.
- `src/seed.rs` — identity mode writes the locked id-doc at the reserved key with NO `.acl` and NO
  containment edge; demotes the card (no issuer/storage); binds the pod ACL to the id-host WebID
  (and NOT the legacy in-pod form).
- `tests/identity_http.rs` — through the assembled router: GET/HEAD serving (conneg, ETag/304,
  `ACAO: *`, no `WWW-Authenticate`, no `.acl` Link, no `WAC-Allow`, anonymous — the no-WAC path);
  405 on every write method; fail-closed 404s; the LDP surface refusing `/.identity/**` for every
  method (raw + %-encoded), flag-ON and flag-OFF, authenticated and anonymous.

## References

- prod-solid-server `decisions/0020-webid-outside-pod.md` (the source decision: threat table,
  id-host convention, locked id-doc, demoted card, migrate-all rationale, Inrupt precedent).
- RSS `decisions/0003-existence-non-disclosure.md` (the fail-closed 404 posture this surface
  matches) and `src/authz` (the WAC engine the namespace is provably outside of).
- `sparq#992` — the SPARQ access-control design the named-graph mapping lands with.
