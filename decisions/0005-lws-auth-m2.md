<!-- AUTHORED-BY Claude Fable 5 -->
# 0005 — The LWS auth chain (M2): RFC 9728 discovery + RFC 9068 at+jwt Bearer validation

**Status:** accepted (M2 landed on `feat/lws` atop the M1 slice, `decisions/0004`; the JLWS spec
itself remains a personal draft awaiting the maintainer's steer).

## Context

The JLWS spec (`jeswr/lws-spec` `index.html` §authorization, pinned @ `deb310e`) specifies the
authorization chain the maintainer's `jeswr/lws-keycloak` prototype established: *authentication
credential → RFC 8693 token exchange at a trusted AS → audience-restricted, short-lived RFC 9068
`at+jwt` → **Bearer** presentation* (RFC 6750 — the MUST-accept baseline; "the use of DPoP is no
longer required"), with AS discovery via an RFC 9728 `resource_metadata` 401 challenge. M1
(`decisions/0004`) shipped the LWS resource surface and left the auth chain as a marked seam,
with the existing Solid-OIDC DPoP path standing in.

## Decision

An **additive, flag-gated** chain under the SAME `SOLID_SERVER_LWS` flag, in `src/lws/auth.rs`,
hanging off an `Option<Arc<LwsBearerAuth>>` on the `AuthContext` (`None` default = every hook
dead, the pre-LWS auth path byte-identical — the M1 invariance rule extended to auth):

1. **The server implements only the VERIFY half.** The RFC 8693 exchange is the AS's job
   (lws-keycloak); this server validates the resulting `at+jwt` per spec §rs-validation and maps
   the verified `sub` onto `VerifiedToken.web_id` — the **existing WAC engine then decides
   access, unchanged** (same 401-anonymous / 403-authenticated split, same ACL walk).

2. **RFC 9728 discovery (§authz-discovery).** A response-mapping middleware (mounted only when
   the chain is on) appends one extra `WWW-Authenticate` value to every 401 leaving the app
   routes: `Bearer realm="<storage root>", resource_metadata="<base>/.well-known/oauth-protected-resource"`,
   plus `error="invalid_token"` iff the request presented an `Authorization` header (RFC 6750
   §3.1 forbids `error` on a credential-less challenge — the spec example pins it). The RFC 9728
   document itself REUSES the existing `pop::sk` builder, extended with the spec-required
   members: `authorization_servers` (the trusted-issuer list), `jlws_storage_description` (the M1
   storage description), and an **honest** `dpop_bound_access_tokens_required` (`false` under the
   Bearer baseline — Bearer accepted, PoP optional; `true` on a PoP-required realm). The PRM
   route is now mounted when ANY of mTLS / DPoP-SK / LWS is on; flag-off keeps the pre-LWS
   bytes verbatim.

3. **at+jwt validation (§rs-validation), fail-closed on every deviation.** Order: trusted-`iss`
   allowlist match FIRST (so an attacker-chosen `iss` never triggers a JWKS/discovery fetch, and
   the `JwksProvider` "issuer already trusted" contract holds) → signature via the VETTED
   `solid_oidc_verifier::jwt::verify_signature` primitive (asymmetric-only allowlist,
   `alg: none`/HS* refused, `typ: at+jwt` enforced in the same call — no new crypto, house rule)
   → **audience containment** (below) → temporal (`exp` future with ≤5 s skew; **remaining
   lifetime `exp − now` ≤ 300 s** by default — the spec's RECOMMENDED window and the
   lws-keycloak issuance posture, operator-adjustable via `SOLID_SERVER_LWS_MAX_TOKEN_TTL_SECS`
   but hard-clamped at the spec's one-hour MUST; `iat` required and not-future; `nbf` honoured,
   present-but-malformed fails closed) → required claims (`sub` an absolute http(s) URI —
   the agent; `client_id`; `jti`) → **bare-PoP refusal**: any `cnf`-bearing token presented via
   Bearer is rejected (§rs-validation step 5 "MUST NOT be accepted bare"), whatever the binding
   flavour — so enabling LWS can never downgrade a DPoP/mTLS-bound token to bearer.

4. **The audience-containment algorithm — the load-bearing check.** Evaluated over PARSED,
   NORMALIZED URIs (`url::Url`: case, default ports, dot-segments — RFC 3986 §6), **never a raw
   string prefix** (the exact High the spec review fixed): same scheme+host+port, audience free
   of query/fragment/userinfo, and the target path equal to the audience path OR prefixed by the
   audience path **slash-terminated** — appending the `/` before comparing is what forces the
   complete-segment boundary, so `…/alice` can never authorize `…/alicemalicious`. Strict in the
   other direction too: `…/alice/` does not contain the distinct sibling resource `…/alice`.
   Every parse/normalization gap denies (never over-grants). `aud` must be **exactly one
   value** — a string, or a singleton array (RFC 9068's array form; multi-valued always
   rejected). Exhaustively unit-tested (the `/alice`-vs-`/alicemalicious` matrix, origins,
   encodings, traversal) plus HTTP-level pins.

   *Target-identity guard (roborev Medium on the first M2 commit).* The `target` handed to the
   check is the server-reconstructed resource IRI — the SAME string the store keys by and WAC
   authorizes (`parse_target`), which rejects LITERAL `.`/`..` segments but PRESERVES
   percent-encoded ones (`%2e%2e`). `url::Url`, however, decodes `%2e%2e` → `..` and removes the
   dot-segment (`…/alice/%2e%2e/bob/x` → `…/bob/x`), so comparing the *normalized* target against
   the audience would let a token scoped to `…/bob/` satisfy containment for a resource whose
   ACTUAL identity is under `…/alice/` — an audience-scope escape (WAC would then serve it if the
   agent has broad WAC rights, defeating the token's confused-deputy scoping). Fix, entirely
   inside `audience_contains` (NOT `parse_target` — changing it would break the flag-off
   byte-invariance): **fail closed whenever the target's `url::Url`-normalized path differs from
   its raw path** — the containment decision is made only on a target whose identity the two
   representations agree on. Legitimate percent-encoding `url::Url` preserves (`%61lice`, `%2f`)
   is unaffected. Executed end-to-end as a regression test (a `/bob/`-scoped token against
   `/alice/%2e%2e/bob/doc` → 401, not a served `/alice/`-subtree resource).

   *Guard-breadth finding closed as false-positive (roborev Medium, job 4727 on the amended M2
   commit).* The review claimed the guard "fails closed for normal URL spellings that `url`
   normalizes, such as percent-encoded unreserved characters (`/%61lice/doc`)", causing avoidable
   401s for valid aliases. Empirically false for the cited example: the `url` crate (WHATWG URL)
   does **not** decode percent-encoded unreserved characters —
   `Url::parse("https://h/%61lice/doc").path()` returns `/%61lice/doc` byte-identical, so the
   guard passes it (unit-pinned in the `aud_containment` tests: `%61lice` is a *different*
   resource from `alice`, denied by ordinary path comparison, not by the guard; `/alice/%61-note`
   under an `/alice/`-scoped audience is allowed). WHATWG renormalizes only full dot-segments
   (`%2e%2e`, `.%2e`, …), `\`→`/` in special URLs, and non-ASCII re-encoding — each an *ambiguous
   identity* between the raw string the store/WAC key by and the parsed URL, exactly the class
   the guard must refuse, and refusal is always a deny (never an over-grant). No code change.

5. **Dispatch: commit on shape, both branches fail-closed.** In the auth middleware, a
   `Bearer`-scheme token whose *unverified* `aud` is a single absolute http(s) URI **and that
   carries no `cnf`** COMMITS to the LWS verifier (final verdict); everything else — DPoP, ANY
   `cnf`-bearing Bearer, non-URI-audience Bearer, anonymous, garbage — falls through to the
   untouched pre-LWS verifier. The `cnf` exclusion keeps a PoP-bound token on the path that
   validates its binding at full strength — in particular the RFC 8705 cert-bound mTLS Bearer
   (PoP Tier-1) keeps working with LWS on (§rs-validation step 5: "validated per the profile in
   use") — while `verify_bearer`'s own bare-`cnf` refusal remains as defence-in-depth on the
   VERIFIED claims. Routing on a peeked claim is not a security decision (the verifier crate's
   own `peek_*` discipline): dodging the exclusion in either direction only lands the token on
   the other fully-verifying, fail-closed branch.

6. **PoP-required realms are a documented toggle, not the default**
   (`SOLID_SERVER_LWS_REQUIRE_POP`, default off — the maintainer's no-DPoP-required baseline and
   the WG design). On: the Bearer path is closed fail-closed, challenges carry the `DPoP` scheme
   only (§presentation-pop: omit Bearer), and the PRM document sets
   `dpop_bound_access_tokens_required: true`. Validating a DPoP-bound **LWS-audience** token
   (so a PoP-required realm can serve LWS clients end-to-end) is a documented M3 seam; the
   Solid-OIDC DPoP surface works on such a realm today.

7. **Wiring keeps the flag-off path untouched.** `main` constructs a SECOND
   `NetworkJwksProvider` instance for the LWS chain (same SSRF-guarded, DNS-pinned class; its own
   cache) rather than re-plumbing the verifier's provider behind a sharing wrapper — the existing
   verifier construction is not touched at all, which is the strongest form of the flag-off
   invariance claim. Cost: one duplicate JWKS fetch per issuer per cache-TTL, only when LWS is
   on. Tests hand both consumers one `StaticJwksProvider` each.

## Security analysis — consequences accepted deliberately

- **Enabling LWS extends what a trusted AS's tokens mean.** With the chain on, ANY unbound
  (`cnf`-less) `at+jwt` from a trusted issuer whose single audience is (a prefix of) this storage
  IS an LWS access token — there is no separate "LWS token type"; `sub` is trusted as the agent
  URI. That is the spec's trust model (the AS validated the client's credential at exchange
  time). Consequences: (a) the trusted-issuer list must contain ONLY ASes whose `sub` is the
  agent URI (lws-keycloak's contract — a Keycloak issuing opaque-UUID `sub`s fails the
  absolute-URI check fail-closed); (b) the DPoP-required posture is relaxed to exactly the
  spec-defined extent, only behind the flag — PoP-bound tokens are never accepted bare, so
  production Solid tokens cannot be replayed as Bearer (pinned by test). The Bearer replay
  exposure is bounded by mandatory audience containment + the ≤300 s window, the spec's own
  §security-considerations analysis.
- **No `jti` replay tracking for access tokens** — deliberate: the spec's Bearer analysis accepts
  within-lifetime replay against the token's own storage as the residual risk PoP profiles close;
  `jti` is required present (RFC 9068) but not tracked. (DPoP proof `jti` replay on the Solid
  path is unchanged.)
- **RFC 9396 `authorization_details` is ignored in M2** — safe by the spec's own rule: the claim
  may only NARROW below the server's policy, never widen, so ignoring it grants exactly the WAC
  baseline. Honouring the narrowing is an M3 seam.
- The valid-token/no-access split stays the existing engine's 403 (some access ⇒ 403; the
  0003 existence-non-disclosure closures are unchanged).

## Tests (the gate)

`src/lws/auth.rs` unit suite (aud-containment matrix incl. `/alice` vs `/alicemalicious` + the
`%2e%2e` identity-guard,
accept + the full reject matrix: forged/tampered signature, alg `none`/HS256, untrusted/missing
issuer, wrong/missing `typ`, aud multi/absent/wrong-origin/sibling, expired/over-window/missing
`exp`, future/missing `iat`, future/malformed `nbf`, missing `client_id`/`sub`/`jti`, opaque
`sub`, bare `cnf` both flavours, PoP-required closure, challenge/PRM shape, TTL clamp) +
`tests/lws_auth.rs` HTTP suite (challenge with/without `error`, PRM members, Bearer
write/read as `sub`, WAC 403, DPoP-flow-unchanged, the sibling-boundary + traversal +
percent-encoding cases over HTTP, PoP-required posture, flag-off + M1-only invariance pins) +
the M1-Low SSRF regression (`tests/lws_http.rs`): a stored hostile remote `@context` yields the
406 `unparseable-source` problem with a live canary listener proving no server-side fetch, and
the LDP write path refuses the document outright.

## M3 (deferred, seams noted)

RFC 9264 linksets, SSE/WebSocket notification bindings under the WD subscription API,
pagination + `size`, the `SparqlQueryService`/AC-SPARQL companion (gated on `sparq#992`),
DPoP-bound LWS-audience tokens for PoP-required realms, and RFC 9396 narrowing.
