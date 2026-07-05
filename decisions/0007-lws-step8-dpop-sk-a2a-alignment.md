<!-- AUTHORED-BY Claude Fable 5 -->
# 0007 — LWS step-8 alignment increments A + B: DPoP-SK over LWS, the a2a-rdf discovery affordance

**Status:** accepted (landed on `feat/lws` atop M1–M3, `decisions/0004`–`0006`). Design source:
the merged spec-alignment design in `jeswr/lws-spec` `docs/alignment/` (`README.md` sequence
table; `dpop-sk.md` verdict (c); `a2a-rdf.md` verdict (d)), spec pinned @ `jeswr/lws-spec`
`f2e081d`.

## Context

Directive step 8 aligned the maintainer's six sibling specs with the now-public JLWS spec. The
alignment design sequenced two increments as buildable-now on `feat/lws`: **A** — DPoP-SK as the
realm's second negotiated PoP presentation profile (an AUTH-layer composition via RFC 9728, not a
storage capability), and **B** — the optional a2a-rdf `AgentInteractionService` extension-service
entry in the storage description (a REFERENCE affordance; JLWS is the extension's document
substrate, and neither spec changes). Both land ADDITIVE and flag-gated under the standing
`SOLID_SERVER_LWS` invariant: flag-off builds are byte-identical, and neither new surface can
appear without the master flag.

## Decision A — DPoP-SK over LWS: one engine, two switches; the composition is structural

1. **No second implementation.** `SOLID_SERVER_LWS_POP_SESSION` (default off, INERT without
   `SOLID_SERVER_LWS` — the conjunction lives inside `lws::auth::pop_session_from_env`, so a
   stray setting on a flag-off build is structurally nothing) enables the SAME `pop::sk` engine
   `SOLID_SERVER_DPOP_SK` enables: `main` ORs the two switches into ONE shared `SkState`
   (establishment endpoint, attestation dispatch, PRM member). The advertisement therefore can
   never be dishonest — `pop_session` present ⇔ the endpoint and verify path are mounted.
2. **PRM: inheritance, not construction.** The base RFC 9728 document
   (`pop::sk::handlers::protected_resource_metadata_json`) already emits the DPoP-SK §discovery
   member set `pop_session{endpoint, algs, channel_bindings, profile}`;
   `LwsBearerAuth::extend_protected_resource_metadata` touches ONLY its three LWS members and
   PRESERVES everything else — so on an SK-enabled LWS realm `pop_session` sits beside
   `jlws_storage_description` exactly as the alignment doc's PRM contract table pins. The
   flavour gating is inherited too: `channel_bindings: ["none"]` behind a TLS-terminating proxy,
   `tls-exporter` only under in-process TLS 1.3 (the DPoP-SK spec's MUST NOT — this was already
   the engine's rule; nothing re-derived).
3. **Verify chokepoint: the M2 dispatch seam already IS the alignment.** A DPoP-SK-established
   token is `cnf`-bound, and the spec's "never bare" rule is JLWS rs-validation step 5:
   `is_lws_candidate` excludes every `cnf`-bearing token from the plain-Bearer LWS path
   (`verify_bearer` independently refuses bare `cnf` on VERIFIED claims as defence-in-depth),
   while the DPoP-SK attestation dispatch in `crate::auth` runs BEFORE any Bearer routing and
   validates attestations at full strength (`pop::sk::verify` — signature, session pin, nonce
   window, token hash). So a DPoP-SK presentation authenticates via the PoP path and can never
   be downgraded onto the Bearer path; **no verification code changed hands** in this increment
   — the deliverable is the wiring (the switch + PRM inheritance) and the adversarial pins
   proving the composition (below).
4. **D9 Bearer baseline preserved.** `dpop_bound_access_tokens_required` ALONE governs the
   realm's posture: a DPoP-SK session is established FROM a DPoP-bound token, so the one
   registered member covers both PoP profiles (the alignment doc's §2.1 finding — no separate
   required-member exists or is minted). Advertising `pop_session` is an additive availability
   signal: on the Bearer baseline the member coexists with an honest
   `dpop_bound_access_tokens_required: false`, and a PoP-required realm shows `true` +
   `pop_session` (the client may then use DPoP or DPoP-SK; Bearer stays refused).

## Decision B — the `AgentInteractionService` storage-description entry

1. **The registry's extension-URI mechanism, no core term minted** (verdict (d)):
   `SOLID_SERVER_LWS_AGENT_CARD_URL`, when set to a valid URL, appends ONE `service` entry —
   `type` = `https://w3id.org/jeswr/a2a-rdf/v1#AgentInteractionService`, `serviceEndpoint` = the
   controller-agent's **A2A Agent Card URL** (the card, not the A2A endpoint — the card carries
   the endpoint + extension declaration), `conformsTo` = the extension URI. It joins `service`
   ONLY: `conformsTo`/`capability` are untouched (a reference affordance is not a protocol
   conformance claim). Unknown-type consumers ignore it per the spec's forward-compatibility
   rule.
2. **Fail-closed validation, loud misconfiguration.** The value must parse as an absolute
   http(s) URL with no userinfo (a `user:pw@host` spelling could cosmetically impersonate an
   origin in a human/agent-read advertisement); anything else collapses to "not advertised" with
   byte-identical description output, and `main` logs a WARNING when the variable is set but
   invalid (an operator must not discover the fail-closure by absence alone). The URL is emitted
   through `serde_json` (escaped) — no injection surface. The entry has zero security weight
   either way: it grants nothing and changes no auth/WAC path.

## Flag-gating / invariance (the standing rule, extended)

`SOLID_SERVER_LWS` off ⇒ neither surface exists: no RFC 9728 route is mounted by the LWS chain
(so no `pop_session` via the LWS switch — the pre-existing `SOLID_SERVER_DPOP_SK` tier is an
unchanged, orthogonal Solid-surface flag), no storage-description route (so no
`AgentInteractionService` anywhere), and both new env knobs are inert by construction
(`pop_session_from_env` conjoins the master flag; `LwsConfig::from_env` returns `None` before
reading the card URL). LWS on with the knobs unset ⇒ the M2 PRM bytes and the M1 description
bytes are unchanged (pinned: the `None` card path is byte-identical, and the extend function
adds no member it didn't before).

## What this increment does NOT do (still M4, honestly)

End-to-end §presentation-pop for an **LWS-audience** token: a webid-less `at+jwt` from the LWS
AS cannot itself establish a DPoP proof or DPoP-SK session today, because establishment runs
through the Solid-OIDC verifier (which requires the `webid` claim and its audience policy).
Step-8 A composes the EXISTING engine with the LWS realm's discovery + dispatch; widening the
establishment token policy to LWS-audience tokens is the deliberately-deferred M4 seam noted in
`src/lws/mod.rs` (unchanged by this ADR, now stated precisely).

## What increment C owns (not this repo)

The five sibling-repo "Relationship to LWS" doc sections (`dpop-sk-spec`, `a2a-rdf-extension`,
`solid-sparql-query`, the webauthn pair, `agentic-solid-note` maturity row) and the
**language-neutral test vectors** (`lws-spec` `test-vectors/vectors/dpop-sk/` — 8 cases — and
the `discovery` + `a2a-rdf` additions, with `manifest.json` + `GAPS.md` bookkeeping). This repo
asserts those vectors' server-observable EXPECTATIONS in Rust where they map
(`prm-carries-pop-session`, `pop-required-single-member`, `sd-agent-interaction-service`); the
establishment/attestation matrices were already pinned byte-for-byte against the DPoP-SK
Appendix-A vectors by the `pop::sk` suites.

## Tests

`src/lws/mod.rs` (SD entry shape + exact members, `None`-path byte-identity, the fail-closed URL
validation matrix incl. userinfo/scheme-relative/js-scheme, the single serialized env-matrix test
proving both knobs inert without the master flag) + `src/lws/auth.rs`
(`prm_extension_preserves_the_pop_session_member` on both postures — the alignment merge point)
+ `tests/lws_step8.rs` end-to-end (PRM coexistence + additive-D9, member absent when the engine
is off, PoP-required realm offering both profiles while refusing Bearer, attested requests at
full strength beside LWS incl. a replayed-nonce denial, `cnf`-bound tokens never dispatched to
the Bearer path — bare ⇒ 401, with proof ⇒ accepted via PoP — M2 Bearer flow unchanged, the SD
agent entry present/absent, and the flag-off build having NEITHER new surface). Full gate:
`cargo fmt` + `clippy -D warnings` + the complete suites on both feature sets (default +
`embedded-sparq`).
