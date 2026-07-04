<!-- AUTHORED-BY Claude Fable 5 -->
# High-throughput proof-of-possession authentication — design proposal

> **Status: DESIGN + PHASED BUILD (proceed-and-document).** Maintainer-requested design; the
> per-bead build status lives in §10 (Tier 1b and the Tier-2 DPoP-SK server side are LANDED,
> both env-gated OFF by default). DPoP as mandated by Solid-OIDC remains the
> untouched interop baseline throughout — everything below is a *negotiated, optional* fast path.
>
> Every RFC/standard claim below was verified against the primary source on 2026-07-03; each is
> cited inline. Measured numbers cite the committed bench records in [`bench/`](../../bench/)
> (per the deterministic-strict / timing-advisory perf rule, wall-clock figures are context, not
> gates).

## 1. The measured problem — what DPoP costs this server per request

`solid-server-rs` reaches ~40–47k RPS on the **anonymous** public-read path but only ~11.7k RPS on
the **authenticated** (DPoP) path on the same box/harness
([`bench/BASELINE.md`](../../bench/BASELINE.md), [`bench/AUTH-BASELINE.md`](../../bench/AUTH-BASELINE.md),
[`bench/SKIP-CRYPTO.md`](../../bench/SKIP-CRYPTO.md)). The round-4 CPU profile
([`bench/ROUND4-PROFILE.md`](../../bench/ROUND4-PROFILE.md)) is unambiguous about why: with the
round-3 verified-token cache already ON, **ES256/P-256 ECDSA is 49.9% of active CPU on the authed
path**, our own auth+WAC orchestration is 3.3%, and the JWT base64/JSON decode is 5.3%. The
round-4 verdict was "the crypto is the floor; there is no non-crypto per-node throughput lever on
the authed path". This proposal is about removing that floor — *without weakening the security
properties DPoP exists to provide*.

### 1.1 Exact per-request work today (grounded in the code)

The axum middleware ([`src/auth.rs`](../../src/auth.rs)) delegates to the
[`solid-oidc-verifier`](https://github.com/jeswr/solid-oidc-verifier) crate
(`verifier.rs::Verifier::verify`), fronted by the round-3 verified-access-token cache
([`src/auth_cache.rs`](../../src/auth_cache.rs)). Per authenticated request:

| # | Step | Where | Cost class | Per-request or amortized? |
|---|---|---|---|---|
| 1 | Parse `Authorization` + `DPoP` headers, peek unverified `iss`, trusted-issuer allowlist | verifier `parse_authorization` / `peek_issuer` | string ops | per-request, negligible |
| 2 | **Access-token verify**: JWS parse, ES256 signature vs issuer JWKS, RFC 9068 `typ=at+jwt` + claims (`sub`/`jti`/`client_id`/`iss`/`aud`/temporal) | verifier `validate_access_token` | 1 asymmetric verify + JSON | **AMORTIZED** since round 3: cache keyed by SHA-256(token), TTL = min(`exp`, 300 s JWKS window) ([`bench/ROUND3.md`](../../bench/ROUND3.md)) |
| 3 | **DPoP proof verify**: base64/JSON decode of a *fresh* JWT, ES256 signature vs the embedded JWK, `typ=dpop+jwt`, asymmetric-alg policy | `auth_cache.rs::verify_fresh_proof` → verifier `verify_proof_with_embedded_jwk` | **1 asymmetric verify + JSON** | **UNAVOIDABLY per-request** — the proof payload (`jti`, `iat`, `htu`) is new every request, so no verification result can be reused |
| 4 | `htm`/`htu` match (URL normalize), `iat` window, `jti` presence | `verify_fresh_proof` | string ops | per-request, cheap |
| 5 | `ath == base64url(SHA-256(access_token))` | `verify_fresh_proof` (digest shared with the cache key) | 1 SHA-256 | per-request, cheap |
| 6 | `cnf.jkt == RFC 7638 thumbprint(proof JWK)` | `Jwk::thumbprint_sha256` | 1 SHA-256 + canonical JSON | per-request, cheap |
| 7 | `jti` replay mark | shared `ReplayStore` (mutex map / Redis) | map insert | per-request state write (bounded window) |
| 8 | WebID↔issuer bidirectional check | verifier `check_bidirectional` (cached resolver) | network | amortized (cache) |

The round-2 baseline attributed **~252 µs/GET to the two ES256 verifies combined**
([`bench/AUTH-BASELINE.md`](../../bench/AUTH-BASELINE.md), [`bench/ROUND3.md`](../../bench/ROUND3.md));
round 3 removed one of them (row 2). **What remains, irreducibly, is row 3** — on the order of
~125 µs of P-256 ECDSA per request on the bench box (one core), i.e. roughly one full CPU core per
~8k authed RPS spent solely on re-proving possession the client already proved on the previous
request one millisecond ago. Rows 4–7 are one or two SHA-256s and string compares — noise next to
row 3.

That is the precise shape of the target: **the per-request *asymmetric* verify is the cost; the
possession being proven is (key, token) — which is constant across a client's whole session.**
Everything below is a standards-grounded way to prove it once and then re-attest it per request
with something cheaper than ECDSA, without losing replay resistance or fail-closed behaviour.

### 1.2 What RFC 9449 itself allows us to cache — and the hard limit

RFC 9449 §4.3 requires the resource server to check, per request, the proof signature, `htm`,
`htu`, `iat` window, `ath`, `nonce` (if used) and the `cnf.jkt` binding
([RFC 9449 §4.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3)). Because the signed
payload is fresh each request, the signature check cannot be memoized. The only cacheables are the
*stable* inputs — the access token's verification (done, round 3) and the JWK→thumbprint mapping
(a SHA-256; not worth a cache). The RFC's own nonce mechanism
([§9](https://www.rfc-editor.org/rfc/rfc9449.html#section-9): `401` +
`WWW-Authenticate: DPoP error="use_dpop_nonce"` + `DPoP-Nonce`) *adds* freshness control (it
defeats pre-generated proofs — [§11.1](https://www.rfc-editor.org/rfc/rfc9449.html)); it does not
reduce verify cost. **Conclusion: within pure RFC 9449 there is no further big win. A cheaper
per-request primitive requires a different (negotiated) PoP method.**

## 2. Researched options (primary sources)

### 2.A RFC 8705 — mutual-TLS certificate-bound access tokens (the service-client win)

[RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) (Standards Track, Feb 2020) binds the
access token to the client's TLS client certificate: the AS embeds
`"cnf":{"x5t#S256":"<base64url(SHA-256(cert DER))>"}` (§3.1), and the RS
"**MUST obtain, from its TLS implementation layer, the client certificate used for mutual TLS and
MUST verify that the certificate matches the certificate associated with the access token**" (§3).
Two AS-side flavours exist — PKI (`tls_client_auth`, §2.1) and **self-signed**
(`self_signed_tls_client_auth`, §2.2, cert registered via `jwks`/`jwks_uri`, chain NOT validated)
— but the *RS-side token binding check is identical and flavour-agnostic*: hash the presented
cert, compare to `cnf.x5t#S256`. AS metadata: `tls_client_certificate_bound_access_tokens`
(§3.3); endpoint isolation via `mtls_endpoint_aliases` (§5).

**Why this is the high-throughput primary candidate.** Proof-of-possession moves to the TLS
handshake: the client proves possession of the private key **once per connection** (the
`CertificateVerify` signature inside the handshake), and every request on that connection is then
attested by TLS's own AEAD record protection. The RS's per-request work is: compare
SHA-256(presented cert) — computable **once per connection** and cached — against the token's
`cnf.x5t#S256`. That is a **32-byte memcmp per request**. Under HTTP/2 (this server already
negotiates h2 via ALPN — [`src/tls.rs`](../../src/tls.rs)) hundreds of thousands of multiplexed
requests amortize one handshake. No replay store is needed for this path at all: TLS 1.3 record
protection already prevents cross-request/cross-connection replay of application data (and
renegotiation no longer exists — [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html): "TLS 1.3
forbids renegotiation").

This is not exotic: **FAPI 2.0 Security Profile (Final, 2025-02-22)** — the highest-assurance
OAuth profile in production use (open banking) — requires sender-constrained access tokens via
exactly "**MTLS as described in [RFC8705] [or] DPoP as described in [RFC9449]**" for AS (§5.3.2.1),
clients (§5.3.3.1) and resource servers (§5.3.4)
([FAPI 2.0](https://openid.net/specs/fapi-security-profile-2_0-final.html)). mTLS-bound tokens are
the regulated-industry baseline; DPoP is the browser-compatible alternative. Our tiering below
mirrors that exact split. **Keycloak — the suite IdP — already implements RFC 8705** on both sides
(X.509 client authenticator + per-client "OAuth 2.0 Mutual TLS Certificate Bound Access Tokens
Enabled", emitting `cnf.x5t#S256`;
[Keycloak discussion #19704](https://github.com/keycloak/keycloak/discussions/19704),
[worked example](https://tech.aufomm.com/how-to-use-certificate-bound-access-token-with-kong-and-keycloak/)).

**Deployment constraint (load-bearing):** RFC 8705 §6.5 leaves cert forwarding across a
TLS-terminating proxy out of scope — the safe posture is **terminate TLS in-process**, which
`solid-server-rs` already does (in-process rustls; the transport-hardening module even documents
that the plain-HTTP path is the degraded one). The mTLS tier is therefore only advertised on the
in-process-TLS serve path.

**Why browsers are excluded from this tier:** browsers technically *can* hold client certs, but
the UX (OS keystore prompts, per-origin cert-picker dialogs, no programmatic provisioning from JS)
makes them unusable for consumer Solid apps; the IETF's browser-based-apps BCP
([draft-ietf-oauth-browser-based-apps-26](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps),
2025-12-04) treats **DPoP as the sender-constraining mechanism for browser apps and does not even
entertain mTLS** there. Hence the tiering.

### 2.B RFC 9421 — HTTP Message Signatures, symmetric variant (the framework for Tier 2)

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) (Standards Track, Feb 2024) is a generic
framework for signing HTTP message components. Relevant facts: it registers **`hmac-sha256`
("HMAC Using SHA-256", §3.3.3)** alongside the asymmetric algorithms in the HTTP Signature
Algorithms registry (§6.2); a signature declares its covered components + parameters in
`Signature-Input` (e.g. `("@method" "@target-uri" "authorization");created=…;keyid=…;nonce=…`,
§2.3/§4.1); **key distribution is explicitly out of scope** (§1.4 — the application must define
"a means of retrieving the key material"); and it does **not** define OAuth access-token binding —
that is left to application profiles. So RFC 9421 gives us the *wire syntax and crypto agility*
for a symmetric per-request attestation, and we must supply the key-establishment + token-binding
profile ourselves (§4 below). Using RFC 9421 syntax rather than a bespoke header keeps the
eventual spec alignable with IETF work.

### 2.C Connection/session-scoped symmetric PoP — one asymmetric proof, then HMAC (the browser win)

Designed concretely in §4. The idea: the client presents ONE ordinary RFC 9449 DPoP proof to a
key-establishment endpoint on the RS; both sides derive a short-lived **symmetric session key**;
subsequent requests carry an RFC 9421 `hmac-sha256` signature instead of a DPoP proof. The
asymmetric verify amortizes from per-request to per-session (or per-connection), and the
per-request primitive becomes one HMAC-SHA256 over a few hundred bytes — of the order of
hundreds of nanoseconds versus ~125 µs for the ECDSA verify (order-of-magnitude figure; to be
measured on this box by the follow-up bench, not asserted as a gate).

Where a TLS channel binding is available to the client (native/service clients), the session key
is additionally bound to the TLS connection via TLS Exported Keying Material
([RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5), [[RFC5705]]), using a
dedicated private-use exporter label `EXPERIMENTAL-dpop-sk-v1` (per RFC 5705 Section 4) — not the
`EXPORTER-Channel-Binding` label from [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html),
which RFC 9266 itself forbids using as secret key material; the exact key-derivation scheme is
specified in the DPoP-SK profile (see §4.1);
rustls exposes exactly this
(`ConnectionCommon::export_keying_material(output, label, context)` —
[rustls docs](https://docs.rs/rustls/latest/rustls/struct.ConnectionCommon.html)). Browser JS has
**no access to TLS exporters** (fetch/XHR expose nothing below the HTTP layer), so the browser
variant is *session-bound* (server-side state + tight TTL) rather than *connection-bound* — the
honest security delta is analysed in §5.

### 2.D DPoP-proof-verification caching — already landed; the residual is bounded

The round-3 verified-access-token cache IS the cacheable half of this option
([`bench/ROUND3.md`](../../bench/ROUND3.md); `src/auth_cache.rs`). What a "cache the verified jkt
per connection" scheme would additionally want to skip is the proof-signature verify itself — and
that is not skippable without abandoning RFC 9449 semantics: the proof is the replay protection,
its payload is fresh per request, and §4.3 requires the full check every time. A server that
accepted "same connection + same jkt ⇒ skip signature" would accept **unsigned** htu/htm/jti
claims from anyone able to write plaintext on that connection — i.e. it silently converts DPoP to
a bearer scheme scoped to the connection, *without the client's consent and while the client
believes DPoP semantics hold*. Rejected. Residual bounded wins in pure DPoP: EdDSA/Ed25519 support
(verify is meaningfully cheaper than P-256 on some stacks — *unverified on this box*; bench
follow-up) and micro-optimizing the base64/serde path (5.3% of active CPU ceiling —
[`bench/ROUND4-PROFILE.md`](../../bench/ROUND4-PROFILE.md)).

### 2.E Token Binding (RFC 8471–8473) — why it is NOT the answer

Token Binding solved this exact problem at the right layer (bind tokens to a
TLS-connection-scoped keypair, prove once per connection). It is dead in practice: **Chrome
removed Token Binding in M70 (Oct 2018)** — before the RFCs even published — and no mainstream
browser ships it ([Intent to Remove: Token Binding](https://groups.google.com/a/chromium.org/g/blink-dev/c/OkdLUyYmY1E/m/w2ESAeshBgAJ),
[Chrome Platform Status](https://chromestatus.com/feature/5097603234529280)). DPoP was created by
the OAuth WG largely as the application-layer replacement. Included here only to show the design
space corner it occupied; not a candidate.

### 2.F TLS 1.3 resumption / 0-RTT — cross-cutting constraints on any connection-amortized PoP

Facts ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)):

- **Resumption (PSK/NewSessionTicket)** does not re-run certificate authentication ("As the server
  is authenticating via a PSK, it does not send a Certificate or a CertificateVerify message",
  §2.2 — symmetrically, the client's cert is not re-presented). The *implementation* carries the
  original handshake's client identity: rustls's `peer_certificates()` returns the client chain
  "for both full and resumed handshakes"
  ([rustls docs](https://docs.rs/rustls/latest/rustls/enum.Connection.html)). So the mTLS tier
  works across resumption **iff we trust rustls's session state** — acceptable (the ticket key is
  ours, in-process), but the design treats "no cert available on this connection" as **fail-closed
  reject** for the mTLS tier, never a downgrade to bearer.
- **A resumed connection is a NEW connection for exporter purposes**: RFC 9266's `tls-exporter`
  derives from the current connection's secrets, so a connection-bound Tier-2 key dies with its
  connection — re-establishment (one asymmetric proof) is required. That is the fail-closed
  behaviour we want.
- **0-RTT early data has "no guarantees of non-replay between connections"** (RFC 8446 §8/E.5).
  Any PoP-authenticated request in early data would be replayable at the connection level.
  rustls disables early data by default (`max_early_data_size` "default is 0" —
  [rustls ServerConfig docs](https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html)),
  and this server never enables it. The design adds a hard invariant: **the fast-path tiers are
  only valid on 1-RTT data; if early data is ever enabled, PoP-fast-path requests arriving in
  early data MUST be rejected with the standard 401 challenge** (DPoP itself keeps its own replay
  defence, so it is the one scheme early data could even be argued for — we still exclude it).

## 3. Per-request cost model — the comparison table

Per **authenticated request** at steady state (connection warm, token cached where applicable).
"ES256 verify" ≈ the dominant ~125 µs-class unit from §1.1; SHA-256/HMAC over request-sized input
is ~2–3 orders of magnitude cheaper (order-of-magnitude engineering estimates for ranking only —
the follow-up bench measures them on this box; the *structural* counts are exact from the code +
specs).

| Cost component (per request) | DPoP today (round-3 cache ON) | DPoP + RS nonce | **mTLS-bound (RFC 8705)** | **Symmetric session PoP (Tier 2)** |
|---|---|---|---|---|
| Asymmetric signature verify | **1 × ES256** (fresh proof) | 1 × ES256 | **0** (handshake-amortized: 1 per connection) | **0** (establishment-amortized: 1 per session) |
| Hashing | 2 × SHA-256 (ath digest shared w/ cache key; JWK thumbprint) | same | **0** (cert digest cached per connection → 32-B compare) | **1 × HMAC-SHA256** (covered components) |
| Parse/decode | JWT: 2 × base64url + serde_json (proof header+claims) | same + nonce bookkeeping | none (token claims already cached) | `Signature-Input` structured-field parse (no JSON, no base64 beyond the 32-B tag) |
| Replay state | `jti` map insert under mutex (or Redis RTT) | jti + nonce window | **none** (TLS AEAD is the anti-replay) | **O(1) sliding-window check** (per-session counter + bitmap, RFC 4303-style) |
| Binding check | `cnf.jkt` ↔ thumbprint (string cmp) | same | `cnf.x5t#S256` ↔ cached cert hash (**32-B memcmp**) | keyid → session lookup (hash map) + token-hash cmp |
| Amortized (NOT per request) | token verify per 300 s window (round 3) | + nonce issuance | TLS handshake w/ client `CertificateVerify`; SHA-256(cert) once/conn | 1 full DPoP verify + HKDF at session establishment; rekey per TTL |
| Expected authed-path ceiling | ES256-bound (~50% of active CPU — [ROUND4-PROFILE](../../bench/ROUND4-PROFILE.md)) | unchanged | **≈ anonymous-path ceiling** (crypto floor removed; TLS/framing-bound) | ≈ anonymous ceiling minus one HMAC + parse |

Under HTTP/2 multiplexing (already negotiated — `src/tls.rs` ALPN `h2,http/1.1`), the mTLS
handshake and the Tier-2 establishment are one-time costs a long-lived agent connection amortizes
over its entire lifetime.

## 4. Tier-2 design — the negotiated symmetric session-PoP profile ("DPoP-SK")

The one piece that needs new protocol design. Kept deliberately close to existing primitives:
RFC 9449 for establishment, HKDF (RFC 5869) for derivation, RFC 9421 for the wire format,
RFC 9266 for the optional channel binding.

### 4.1 Establishment handshake

```
POST /.pop/session HTTP/2
Authorization: DPoP <access-token>            ← the ordinary DPoP-bound token
DPoP: <proof>                                  ← ordinary RFC 9449 proof (htu = this endpoint)
Content-Type: application/json
{ "cb": "tls-exporter" | "none" }              ← client's channel-binding capability

→ 201
{ "session_id": "<opaque, 128-bit random>",
  "key": "<base64url, 32 bytes>",              ← present ONLY when cb=none (browser path)
  "cb": "tls-exporter" | "none",
  "expires_in": 300,
  "alg": "hmac-sha256" }
```

- The RS runs the **full existing DPoP verification** on this one request (verifier untouched).
  Establishment is therefore exactly as strong as today's per-request check.
- **Key derivation.** With `cb=tls-exporter` (native clients): both ends compute
  `EKM = TLS-Exporter("EXPERIMENTAL-dpop-sk-v1", context = "" (zero-length), 32 bytes)` per
  RFC 8446 §7.5 and RFC 5705, then derive using HKDF-SHA256 (RFC 5869):
  ```
  PRK = HKDF-Extract(salt = ASCII(session_id), IKM = EKM)
  K   = HKDF-Expand(PRK, info = ASCII("dpop-sk/v1") || 0x00 || ASCII(ath) || 0x00 || ASCII(jkt), L = 32)
  ```
  No key bytes cross the wire, and K is useless on any other TLS connection (see the DPoP-SK
  specification [[DPOP-SK]] for the complete, normative derivation). With `cb=none` (browsers):
  the RS generates K randomly and returns it in the (TLS-protected) response body; the client
  imports it as a **non-extractable WebCrypto HMAC key** and discards the raw bytes.
- **Server state:** `session_id → { K, sha256(access_token), cnf.jkt, webid/VerifiedToken,
  token_exp, established_at, replay_window (high-water + bitmap), conn_id? }` in a bounded LRU (same discipline as
  `VerifiedTokenCache`; capacity-capped, TTL'd). For `cb=tls-exporter` the session additionally
  pins the connection id and dies with the connection.

### 4.2 Per-request attestation

```
GET /alice/private/doc HTTP/2
Authorization: DPoP <access-token>             ← unchanged (the token still travels)
Signature-Input: sig=("@method" "@target-uri" "authorization");created=1720000000;\
                 keyid="<session_id>";nonce="<counter>";alg="hmac-sha256";tag="dpop-sk"
Signature: sig=:<HMAC-SHA256 over the RFC 9421 signature base>:
```

RS per-request verification (all fail-closed, order mirrors `verify_fresh_proof`):
1. `keyid` → session lookup (miss/expired ⇒ **401 with the standard DPoP challenge** — the client
   falls back to plain DPoP or re-establishes; never an error loop).
2. `sha256(presented access token) == session.token_hash` (the `ath`-equivalent: the session
   cannot be ridden with a different token) and `token_exp > now`.
3. `@method`/`@target-uri` from the *actual request* (htm/htu-equivalent, computed server-side —
   unforgeable by construction, unlike DPoP where the client asserts them and the server compares).
4. `created` within the same `iat` window policy the verifier uses.
5. **Recompute the HMAC over the RFC 9421 signature base; constant-time compare.** This runs
   BEFORE any session-state mutation — an unauthenticated request must not be able to change
   anything (see step 6's ordering note).
6. **Anti-replay: sliding-window check on `nonce` (decimal counter), applied ONLY after the HMAC
   verified.** The required mechanism is the IPsec/DTLS-style window
   ([RFC 4303 §3.4.3](https://www.rfc-editor.org/rfc/rfc4303.html#section-3.4.3): a high-water
   mark + a fixed-size bitmap, e.g. 1024 bits): `nonce > high_water` ⇒ shift window + mark;
   within the window and unmarked ⇒ mark; marked (duplicate) or below the window ⇒ 401. Still
   O(1) integer/bit ops per request — replacing the `jti` map — but, unlike a strictly-increasing
   rule, it accepts the out-of-order completion that HTTP/2 multiplexing makes *normal* for
   concurrent streams (a strict rule would spuriously reject valid in-flight requests; rejected
   as a design option, not deferred). Ordering is load-bearing both ways: verify-then-mark means
   a forged request can neither burn a counter value nor advance/shift the window (state-DoS on
   the session), mirroring the verifier's validate-then-`check_replay` order that
   `auth_cache.rs::verify_fresh_proof` documents ("a proof that fails the binding must not burn
   a jti"). The verify+mark pair executes under the session entry's lock (or an equivalent CAS)
   so two concurrent copies of the same nonce cannot both pass.
7. For `cb=tls-exporter` sessions: request's connection id == session's pinned connection.

On success, the session's stored `VerifiedToken` is injected exactly as `auth.rs` does today —
downstream WAC/LDP is untouched.

### 4.3 Lifetime + revocation

`expires_in ≤ min(token exp, DEFAULT_MAX_ENTRY_TTL_SECS = 300)` — the same JWKS-revocation
propagation bound the round-3 cache enforces (a revoked signing key or token is honoured within
one window, because re-establishment re-runs the full verifier). Logout = session forgotten
(server restart or LRU eviction is safe: worst case is one extra full DPoP round). The server MAY
force early rekey at any time by answering 401 (the DPoP-Nonce philosophy of
[RFC 9449 §9](https://www.rfc-editor.org/rfc/rfc9449.html#section-9): the server controls
freshness by invalidating at times of its choosing).

## 5. Security analysis (per option, fail-closed)

Properties to preserve: (P1) proof-of-possession / stolen-token unusability, (P2) replay
resistance, (P3) MITM resistance, (P4) issuer-agnosticism, (P5) fail-closed on any error.

**DPoP baseline (unchanged, mandatory):** P1 per-request via fresh proof; P2 via `jti` store +
`iat` window (+ optional nonce); P3 via TLS + `htu`/`ath`; P4 via the trusted-issuer list; P5 as
implemented (401/503 paths in the verifier). The known weaknesses (pre-generated proofs —
RFC 9449 §11.1; XSS can use, though not export, the browser key) are inherited, not introduced.

**mTLS-bound (Tier 1).**
- *P1:* stronger than DPoP — a stolen token is unusable without the client's TLS private key, and
  possession is proven inside the handshake (`CertificateVerify`), which no application-layer
  attacker can forge. Self-signed variant (RFC 8705 §2.2) keeps provisioning light: possession of
  the registered key is what's verified, no CA chain trust needed.
- *P2:* per-request replay is impossible below the app layer (TLS 1.3 AEAD, per-record nonces; no
  renegotiation in TLS 1.3). No jti store on this path ⇒ one fewer stateful DoS surface.
  0-RTT: disabled (rustls default 0, asserted by an invariant test) — see §2.F.
- *P3:* mutual TLS is the anti-MITM mechanism itself. Caveat inherited from RFC 8705 §6.5: the
  binding is only sound when the RS sees the real TLS layer ⇒ in-process termination REQUIRED
  (already this server's posture); the mTLS tier is not advertised on any proxied deployment.
- *P4:* preserved — the RS still verifies the token against the trusted-issuer JWKS exactly as
  today; only the *confirmation method* dispatch changes (`cnf.x5t#S256` vs `cnf.jkt`). Any AS
  that can emit RFC 8705 tokens (Keycloak, Authlete, etc.) works.
- *P5:* fail-closed rules — token has `cnf.x5t#S256` but connection has no client cert ⇒ 401;
  hash mismatch ⇒ 401; cert present but token `cnf` is `jkt` ⇒ normal DPoP path (no mixing);
  resumed session without rustls-carried cert ⇒ 401. A cert-bound token is NEVER accepted bare.
- *Residual risks:* client key compromise = full impersonation until cert/registration revoked
  (same class as DPoP key compromise; mitigate with short-lived certs); Keycloak's current
  implementation couples cert-binding to X.509 *client auth* per client
  ([keycloak discussion #36802](https://github.com/keycloak/keycloak/discussions/36802)) — an
  IdP-config constraint to document, not a protocol flaw.

**Symmetric session PoP (Tier 2).**
- *P1:* a stolen access token alone is unusable (requests need K). K itself is the new secret:
  connection-bound flavour never puts K on the wire and K is worthless cross-connection
  (exporter-derived, RFC 9266); browser flavour transmits K once under TLS and holds it
  non-extractable — an XSS attacker can *use* the session while resident exactly as they can use
  a resident DPoP key ([draft-ietf-oauth-browser-based-apps-26](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
  is explicit that DPoP in-browser has the same bound), and a *exfiltrated-at-issuance* K is
  capped by the ≤300 s TTL + token binding. Honest delta vs DPoP: during its TTL, a browser
  session key exfiltrated at the establishment instant is replayable off-device against this RS
  only, for this token only. DPoP with a non-extractable key does not have that instant; DPoP
  with an extractable key (many real apps) is strictly worse. Verdict: acceptable as an
  *opt-in negotiated* profile; apps with the strictest threat model simply don't opt in.
- *P2:* per-session sliding-window counter (verify-then-mark, §4.2 step 6) + `created` window;
  a duplicate or out-of-window nonce is rejected, and a forged request cannot mutate the window
  (HMAC verified first — no state-burn DoS); cross-session
  replay impossible (K differs); cross-connection replay impossible in the `tls-exporter`
  flavour, and in the browser flavour bounded by counter + TTL. Establishment requests are full
  DPoP ⇒ inherit jti protection.
- *P3:* TLS underneath; additionally `@method`/`@target-uri` are computed by the RS from the real
  request (stronger than client-asserted htm/htu).
- *P4:* fully preserved — establishment is ordinary DPoP against the issuer-agnostic verifier;
  the session layer never touches issuer trust. No AS changes required at all (unlike mTLS).
- *P5:* any lookup/verify failure ⇒ the standard 401 DPoP challenge (never silent bearer
  acceptance); unknown `tag`/`alg` ⇒ ignore the signature entirely and require DPoP; session
  state loss ⇒ worst case one extra full DPoP verify.

**Token Binding:** not viable (browser removal — §2.E). **Plain verification caching beyond
round 3:** rejected as a semantic downgrade (§2.D).

## 6. Negotiation — a Solid-OIDC-compatible optional profile

Solid-OIDC **mandates DPoP** — clients "MUST send a DPoP proof JWT" (§8) and the RS must validate
a DPoP proof per RFC 9449 §4.3 (§9.3) ([Solid-OIDC 0.1.0](https://solidproject.org/TR/oidc)); it
permits no other token type. So the fast paths MUST be advertised, opt-in, and individually
refusable, with DPoP always accepted. The standards-correct advertisement surface exists since
April 2025: **RFC 9728 OAuth 2.0 Protected Resource Metadata**
([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)) — `/.well-known/oauth-protected-resource`,
discoverable via the `resource_metadata` parameter in `WWW-Authenticate`, and it already defines
exactly the two standard fields we need: `tls_client_certificate_bound_access_tokens` (bool) and
`dpop_signing_alg_values_supported`, plus `dpop_bound_access_tokens_required` (we set `true` —
that IS the Solid-OIDC mandate, machine-readably).

```jsonc
// GET /.well-known/oauth-protected-resource        (also linked from /.well-known/solid)
{
  "resource": "https://pod.example",
  "authorization_servers": ["https://idp.example"],
  "dpop_bound_access_tokens_required": true,                  // RFC 9728 — the Solid-OIDC baseline
  "dpop_signing_alg_values_supported": ["ES256", "EdDSA"],    // RFC 9728
  "tls_client_certificate_bound_access_tokens": true,         // RFC 9728 — Tier 1 offer
  "pop_session": {                                            // extension member — Tier 2 offer
    "endpoint": "https://pod.example/.pop/session",
    "algs": ["hmac-sha256"],                                  // RFC 9421 registry names
    "channel_bindings": ["tls-exporter", "none"],             // RFC 9266 name or "none"
    "profile": "https://w3id.org/jeswr/pop-session/v1"
  }
}
```

Negotiation flow: (1) client GETs the metadata (or learns it from the 401
`WWW-Authenticate: DPoP … resource_metadata="…"` challenge — both RFC-standard); (2) a service
client that owns a TLS keypair requests a cert-bound token from its AS (Keycloak toggle) and just
connects with its cert — zero extra round trips; (3) a browser/app client optionally POSTs
`/.pop/session`; (4) anything else keeps sending plain DPoP, which always works. Unknown members
are ignored by spec, so the extension is invisible to existing clients. The AS side needs **no
change for Tier 2** and only standard RFC 8705 support (already in Keycloak) for Tier 1 —
issuer-agnosticism is intact.

## 7. Recommended tiered scheme + fit in solid-server-rs

**Recommendation:**

| Tier | Client class | Mechanism | Per-request crypto | Ship order |
|---|---|---|---|---|
| 0 (baseline, mandatory) | everyone | DPoP (RFC 9449) + round-3 token cache | 1 ES256 verify | shipped |
| 1 | services / agents / server-to-server (the A2A + federation + reconciler traffic) | **RFC 8705 cert-bound tokens**, self-signed flavour first | 32-B memcmp | **first** — standards-final, IdP-ready, smallest new code |
| 2 | browser apps + native apps (via `tls-exporter`) | **DPoP-SK symmetric session profile** (§4) | 1 HMAC-SHA256 + O(1) window check | second — needs the small spec + client lib |
| — | micro-win, any | accept `EdDSA` DPoP proofs | 1 Ed25519 verify | opportunistic (bench first) |

**Server integration points (all seams already exist):**

1. **TLS layer** ([`src/tls.rs`](../../src/tls.rs)): build the `ServerConfig` with
   `WebPkiClientVerifier::builder(roots).allow_unauthenticated().build()`
   ([rustls docs](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)) —
   client cert *requested but optional*, so plain-DPoP clients are untouched. For the self-signed
   flavour the verifier is a thin custom `ClientCertVerifier` accepting any well-formed cert
   (trust is NOT the chain — trust is the `cnf.x5t#S256` match; this mirrors RFC 8705 §2.2 where
   the chain is not validated). Env-gated: `SOLID_SERVER_MTLS_BOUND_TOKENS=1`.
2. **Acceptor** ([`src/transport.rs`](../../src/transport.rs) `ConnectionLimitAcceptor`): after
   the inner TLS accept, read `ServerConnection::peer_certificates()` + compute
   `sha256(cert.der())` **once**, allocate a `conn_id`, run `export_keying_material` if a Tier-2
   session will want it, and inject a `ConnPop { cert_x5t_s256: Option<[u8;32]>, conn_id: u64 }`
   into every request on that connection (wrap the tower service the acceptor returns — the same
   pattern axum's `ConnectInfo` uses). Per-connection state, computed once.
3. **Verifier crate** (`solid-oidc-verifier` — separate owner-gated change, flagged): today
   `extract_cnf_jkt` only reads `cnf.jkt` and a cert-bound token would fail with "not DPoP-bound".
   Add a `Confirmation` enum (`Jkt(String) | X5tS256(String)`) on `VerifiedToken`, an
   `AuthRequest.client_cert_x5t_s256: Option<String>` input, and the §3-mandated compare (RFC 8705:
   the RS "MUST verify that the certificate matches"). ~100 lines + exhaustive tests; the crate
   stays issuer-agnostic and dependency-free (no TLS code enters it — it only compares the hash
   the server passes in). This also unblocks the same feature for any other consumer.
4. **Auth middleware** ([`src/auth.rs`](../../src/auth.rs)): dispatch on the token's confirmation
   method — `x5t#S256` ⇒ memcmp against `ConnPop` (cacheable per (conn, token): after the first
   success, subsequent requests with the same token on the same connection are a HashMap hit —
   sound because both inputs are connection/token-constant); `jkt` ⇒ existing path. The
   `VerifiedTokenCache` gains a per-confirmation-type insert guard so a cert-bound token is never
   validated down the jkt path or vice versa.
5. **Tier 2**: a new `src/pop_session.rs` (establishment handler + bounded session store +
   RFC 9421 base reconstruction + HMAC verify via `aws-lc-rs`/`ring` HMAC) and one dispatch arm in
   `auth.rs`. The WAC/LDP layers see the same `VerifiedToken` extension — zero change downstream.
6. **Discovery** (`/.well-known/`): serve the RFC 9728 document (§6) and add the
   `resource_metadata` parameter to the existing single-sourced challenge builder
   (`Verifier::www_authenticate` — one string change).
7. **Conformance guard:** CTH must stay green with every fast path DISABLED and ENABLED (the
   fast paths are additive; a Solid-OIDC client that never reads the metadata must observe an
   unchanged server).

**PSS (TypeScript prod-solid-server) portability:** identical architecture applies (Node
`tls.TLSSocket.getPeerCertificate()` + the same RFC 9728 doc), but PSS terminates TLS at Caddy
today — per RFC 8705 §6.5 the mTLS tier there needs either in-process TLS or a signed
cert-forwarding header contract with the proxy. Out of scope here; noted so the two servers'
metadata stays consistent. Flagged as CORE-PSS follow-up (maintainer approval).

## 8. Honest costs, interop reality, and what could go wrong

- **mTLS provisioning burden.** PKI flavour drags in CA lifecycle — which is why the design leads
  with the **self-signed** flavour (RFC 8705 §2.2): the client mints a keypair + self-signed cert
  and registers it with the AS via `jwks_uri`, no CA at all. Still real: every service client now
  manages a TLS keypair (vs a JWK it already manages for DPoP — a wash in practice), Keycloak
  per-client config is manual, and Keycloak couples cert-binding to X.509 client auth (footgun
  documented in §5). Browsers: effectively excluded (§2.A) — that's what Tier 2 is for.
- **Proxy/CDN reality.** Any TLS-terminating hop kills both Tier 1 (cert invisible) and the
  Tier-2 `tls-exporter` flavour (exporter unavailable). This server's in-process-TLS posture is
  the enabling asset; deployments behind a proxy simply don't advertise those tiers (the
  metadata is the feature flag). Fail-closed by construction: no cert ⇒ 401, never bearer.
- **Tier 2 is a new protocol.** However small, it is state (a bounded session store — a new,
  capacity-capped DoS surface: establishment is rate-limited like any authed write), a new
  endpoint, a client library, and a spec document nobody else implements yet. The browser-flavour
  key-in-response-body is a real (bounded, analysed — §5) weakening vs connection-bound; the spec
  must say so in its own security considerations rather than bury it.
- **Caching (Tier 0) is a bounded win** — already banked in round 3; the remaining ES256 is
  irreducible inside RFC 9449 (§2.D). Anyone promising a "DPoP cache" that skips the proof verify
  is selling a connection-scoped bearer token.
- **Numbers.** The ~125 µs ES256 and ns-class HMAC figures are ranking estimates traceable to
  [`bench/AUTH-BASELINE.md`](../../bench/AUTH-BASELINE.md)/[`ROUND3.md`](../../bench/ROUND3.md)
  and general primitive costs; the follow-up work measures both tiers with the existing committed
  harness (`bench/run-auth.sh` pattern) before any throughput claim is recorded. Per the perf-gate
  rule, timing stays advisory.
- **Interop risk: none for non-adopters.** Every fast path is invisible absent opt-in; DPoP
  remains the only thing a conforming Solid client needs. The negotiation reuses two final RFCs
  (9728, 8705) and one final profile precedent (FAPI 2.0) — we are composing, not inventing,
  except for the one Tier-2 extension member.

## 9. Should this graduate to a spec? Yes — a small one

**Yes, and the boundary is clean.** Tier 1 needs *no* new protocol — "a Solid resource server MAY
support RFC 8705 certificate-bound access tokens, advertised via RFC 9728" is a one-page
profile note. Tier 2 needs a real (short) spec: the establishment exchange, HKDF inputs,
RFC 9421 component set + `tag="dpop-sk"`, counter semantics, TTL/rekey rules, and its security
considerations (§4–§5 are effectively its first draft). Proposed packaging: a **"Solid-OIDC
Proof-of-Possession Negotiation" unofficial draft** (Solid CG-shaped, like the
`solid-webauthn-reauth-spec` precedent) with three sections — (a) RFC 9728 metadata for Solid RSs,
(b) the RFC 8705 profile, (c) DPoP-SK — published under `w3id.org/jeswr/pop-session/v1` until
adopted. It slots directly into the agentic/standards track: high-frequency agent-to-pod traffic
(A2A, federation sync, the accountable-agent runtime) is exactly the service-client class Tier 1
serves, and the eventual IETF home for (c) would be an OAuth WG draft profiling RFC 9421 for
sender-constrained tokens — a gap the WG has not yet filled (RFC 9421 §1.4 verified: it defines
no OAuth binding itself; a search of current OAuth WG documents surfaced no adopted draft filling
it as of 2026-07 — flagged as a search result, not an exhaustive registry audit).

## 10. Build-ready follow-up work (proposed beads)

1. **`solid-oidc-verifier`: `cnf.x5t#S256` confirmation support** — PARTIALLY LANDED (`main@321db01`):
   the READ side ships — `VerifiedToken.cnf_x5t_s256: Option<X5tS256>` (three-state
   `Thumbprint`/`Malformed`) + the `cnf_x5t_s256_thumbprint()` accessor + exhaustive extract tests. The
   VERIFY-PATH admission still to land (the owner-gated remainder): an `AuthRequest.client_cert_x5t_s256`
   input + a path that ACCEPTS a cert-bound token presented as `Bearer` under `require_dpop=true` (today
   `verify()` rejects it at the DPoP-scheme/`must_dpop` gate, so live end-to-end cert-bound acceptance in
   the Solid posture is blocked on this). Security-critical; no new deps.
2. **solid-server-rs Tier 1b** — LANDED (`feat/pop-auth-tier1b`): the optional-client-cert rustls config
   (env-gated `SOLID_SERVER_MTLS_BOUND_TOKENS`, self-signed flavour — requests-not-requires a cert, no
   chain validation, possession still proven by the handshake `CertificateVerify`), the acceptor
   `ConnPop` extension (`src/pop/conn.rs` — cert hashed ONCE per connection, injected via a per-connection
   service wrapper), the auth confirmation dispatch (`AuthContext::authenticate_with_cert` → `pop::dispatch`,
   flag-gated so flag-off is byte-identical, fail-closed on no-cert/wrong-cert/malformed/multi-binding),
   and the fail-closed tests (`tests/pop_mtls.rs` — cert-bound w/o cert, wrong cert, matching cert,
   malformed, multi-binding, DPoP-unchanged, flag-off, resumption re-bind). REMAINING: (a) ~~the RFC 9728
   `/.well-known/oauth-protected-resource` metadata endpoint~~ — LANDED with Tier 2 (bead 6:
   `pop::sk::handlers::protected_resource_metadata_json`, mounted when either PoP tier is enabled;
   advertises `tls_client_certificate_bound_access_tokens` + the `pop_session` member) — the
   `resource_metadata` challenge param remains (the challenge builder is single-sourced in the
   verifier, so it pairs with bead 1's verifier change);
   (b) a live client-cert TLS handshake IT (needs a cert-presenting test client + observing the injected
   `ConnPop` end-to-end, and is only end-to-end-meaningful once bead 1's verify-path admission lands);
   (c) CTH green both toggles (docker-gated locally). The per-(conn,token) match cache is deferred (the
   per-request cost is already a 32-byte memcmp).
3. **Keycloak wiring + IT** — a `conformance`-style service client with self-signed cert,
   cert-bound token mint, end-to-end IT (gated like `PSS_IT_KEYCLOAK`).
4. **Bench: Tier-1 vs DPoP** — extend `bench/run-auth.sh` with an mTLS client; record
   `bench/POP-TIERS.md` (timing advisory).
5. **DPoP-SK spec draft** — DONE (published as the `jeswr/dpop-sk-spec` CG-shaped draft,
   <https://jeswr.github.io/dpop-sk-spec/>, incl. the adversarial review round — see [[DPOP-SK]];
   the key-derivation correction A14 is reflected in §2.C/§4.1 above).
6. **solid-server-rs Tier 2 implementation** — **SERVER SIDE LANDED** (`feat/pop-tier2-dpop-sk`):
   `src/pop/sk/` (derive/window/sig/store/verify/handlers) + the auth-middleware dispatch +
   `POST|DELETE /.pop/session` + the RFC 9728 document, env-gated `SOLID_SERVER_DPOP_SK`
   (default OFF, byte-identical off; mirrors the Tier-1b gating). Both flavours: `cb=none`
   (browser) always when enabled; `cb=tls-exporter` derives from live rustls
   `export_keying_material` under the dedicated `EXPERIMENTAL-dpop-sk-v1` label — TLS 1.3-only,
   in-process-TLS-only (behind the Caddy-terminated deployment it is neither advertised nor
   establishable, fail-closed; the acceptor injects a per-connection `ConnSk` and sessions are
   connection-pinned). The spec's Appendix-A worked example is reproduced byte-for-byte in the
   unit suites, and the negative set (replay in/below window, mutated components, wrong exporter
   label, cross-connection reuse, stripping/downgrade, alg mismatch, dual-mechanism exclusivity)
   is covered in `tests/pop_dpop_sk.rs`. REMAINING: the client helper `@jeswr/…` package for the
   suite apps, a live-TLS exporter IT (pairs with bead 2(b)'s handshake IT), CTH green with the
   flag on (docker-gated), and the bead-4 bench extension measuring the tier.
7. **EdDSA DPoP proof support bench** (verifier already policy-gates algs) — measure Ed25519 vs
   P-256 verify under aws-lc-rs before deciding.
8. **PSS (TS server) counterpart design** — CORE-PSS, maintainer-gated (proxy-termination
   question per RFC 8705 §6.5).

## References

- RFC 9449 (DPoP): https://www.rfc-editor.org/rfc/rfc9449.html — §4.3 RS checks, §9 RS-provided nonce, §11.1 pre-generated proofs
- RFC 8705 (mTLS-bound tokens): https://www.rfc-editor.org/rfc/rfc8705.html — §2.1/2.2 flavours, §3/3.1 `cnf.x5t#S256` + RS MUST-verify, §3.3 metadata, §5 `mtls_endpoint_aliases`, §6.5 termination, §7.2 thumbprint
- RFC 9421 (HTTP Message Signatures): https://www.rfc-editor.org/rfc/rfc9421.html — §3.3.3 `hmac-sha256`, §2.3/4.1 `Signature-Input`, §1.4 key material out of scope, §6.2 registry
- RFC 9728 (Protected Resource Metadata): https://www.rfc-editor.org/rfc/rfc9728.html — well-known URI, `dpop_*` + `tls_client_certificate_bound_access_tokens` members, `resource_metadata` challenge param
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446.html — §2.2 PSK resumption, §7.5 exporters, §8/E.5 0-RTT replay, renegotiation forbidden
- RFC 9266 (tls-exporter channel binding): https://www.rfc-editor.org/rfc/rfc9266.html
- [[DPOP-SK]] DPoP-SK: Negotiated Symmetric Session Keys for DPoP-Bound Requests (specification): https://jeswr.github.io/dpop-sk-spec/ — the normative key-derivation scheme (§4.1), anti-replay window design (§4.2), and adversarial security review (Appendix B)
- RFC 4303 (ESP) §3.4.3 — the sliding-window anti-replay algorithm Tier 2 adopts: https://www.rfc-editor.org/rfc/rfc4303.html#section-3.4.3
- Solid-OIDC 0.1.0: https://solidproject.org/TR/oidc — §8 client DPoP MUST, §9.3 RS validation
- FAPI 2.0 Security Profile (Final, 2025-02-22): https://openid.net/specs/fapi-security-profile-2_0-final.html — §5.3.2.1/§5.3.3.1/§5.3.4 sender-constraining via MTLS or DPoP
- OAuth 2.0 for Browser-Based Apps, draft -26 (2025-12-04): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
- Token Binding removal: https://groups.google.com/a/chromium.org/g/blink-dev/c/OkdLUyYmY1E/m/w2ESAeshBgAJ ; https://chromestatus.com/feature/5097603234529280 ; RFCs 8471–8473
- rustls: `ConnectionCommon::export_keying_material` (https://docs.rs/rustls/latest/rustls/struct.ConnectionCommon.html), `peer_certificates` incl. resumed handshakes (https://docs.rs/rustls/latest/rustls/enum.Connection.html), `WebPkiClientVerifier` + `allow_unauthenticated` (https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html), `ServerConfig::max_early_data_size` default 0 (https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html)
- Keycloak RFC 8705 support: https://github.com/keycloak/keycloak/discussions/19704 ; https://github.com/keycloak/keycloak/discussions/36802 ; https://tech.aufomm.com/how-to-use-certificate-bound-access-token-with-kong-and-keycloak/
- In-repo ground truth: `src/auth.rs`, `src/auth_cache.rs`, `src/tls.rs`, `src/transport.rs`; `solid-oidc-verifier` `src/verifier.rs`/`src/jwt.rs`; `bench/AUTH-BASELINE.md`, `bench/ROUND3.md`, `bench/ROUND4-PROFILE.md`, `bench/SKIP-CRYPTO.md`
