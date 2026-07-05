// AUTHORED-BY Claude Fable 5
//! The **LWS auth chain (M2)** — RFC 9728 authorization-server discovery + RFC 9068 `at+jwt`
//! Bearer validation for the flag-gated LWS surface (`jeswr/lws-spec` `index.html`
//! §authorization: §authz-discovery, §access-token, §presentation, §rs-validation).
//!
//! ## The chain this module implements the SERVER half of
//! *authentication credential → RFC 8693 token exchange at a trusted authorization server →
//! audience-restricted, short-lived RFC 9068 access token → Bearer presentation to the storage
//! server.* The exchange itself is the **authorization server's** job (the maintainer's
//! `jeswr/lws-keycloak` baseline); this server only ever **verifies the resulting `at+jwt`**:
//!
//! 1. **Discovery** (§authz-discovery): every `401` on the LWS surface carries a
//!    `WWW-Authenticate` challenge with `realm` (the storage root — an absolute URI) and
//!    `resource_metadata` (the RFC 9728 protected-resource-metadata document, which this module
//!    extends with `authorization_servers` — the trusted-issuer list — and
//!    `jlws_storage_description`). Per RFC 6750 §3.1 the challenge carries `error="invalid_token"`
//!    ONLY when the request actually presented a token; an anonymous request's challenge has no
//!    `error` parameter (the spec example pins this).
//! 2. **Validation** (§rs-validation, fail-closed on EVERY deviation): trusted `iss` →
//!    signature over the issuer's JWKS via the vetted [`solid_oidc_verifier::jwt`] primitives
//!    (asymmetric-only allowlist, `typ: at+jwt` enforced in the same call — never hand-rolled
//!    crypto) → **audience containment** ([`audience_contains`] — same-origin + complete
//!    `/`-segment-boundary path ancestry, NEVER a raw string prefix) → temporal (`exp` in the
//!    future, bounded remaining lifetime, `iat` not in the future, `nbf` honoured, bounded clock
//!    skew) → required claims (`sub` an absolute http(s) URI, `client_id`, `jti`) → **bare-PoP
//!    refusal** (a token carrying `cnf` MUST NOT be accepted on Bearer presentation —
//!    §rs-validation step 5).
//! 3. **Presentation** (§presentation): Bearer is the MUST-accept baseline. The OPTIONAL PoP
//!    profiles stay advertised through the RFC 9728 document (M1 discovery / the DPoP-SK
//!    metadata); a deployment MAY designate the realm PoP-required via
//!    [`ENV_LWS_REQUIRE_POP`] — then this Bearer path is CLOSED (fail-closed 401; the challenge
//!    lists only the `DPoP` scheme per §presentation-pop) and the RFC 9728 document sets
//!    `dpop_bound_access_tokens_required: true`. Validating a DPoP-bound *LWS-audience* token is
//!    a documented follow-up seam (the Solid-OIDC DPoP surface is unaffected either way).
//!
//! ## Trust model (vs the Solid-OIDC path)
//! The Solid-OIDC verifier confirms the WebID↔issuer relationship (`webid` claim, optional
//! bidirectional check). The LWS chain instead trusts the **configured issuer allowlist**
//! outright: the AS validated the client's authentication credential at exchange time and asserts
//! the agent as `sub` (§access-token). The verified `sub` becomes the WAC agent
//! ([`VerifiedToken::web_id`]) — the existing WAC engine then decides access, unchanged.
//!
//! ## Flag-gating (the M1 invariant, extended)
//! Everything here hangs off [`LwsBearerAuth`] being present on the
//! [`AuthContext`](crate::auth::AuthContext) (`None` default): flag-off builds mount no challenge
//! layer, dispatch no Bearer candidate, and emit byte-identical responses — pinned by tests.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::Value;
use solid_oidc_verifier::config::{JwksError, JwksProvider};
use solid_oidc_verifier::jwt;
use url::Url;

use crate::auth::VerifiedToken;
use crate::error::ServerError;

/// Env flag: designate the LWS realm proof-of-possession-REQUIRED (`1`/`true`; default off —
/// Bearer is the spec's MUST-accept baseline and the maintainer's lws-keycloak posture). On ⇒ the
/// Bearer path is closed fail-closed and challenges/metadata advertise the PoP requirement
/// (spec §presentation-pop).
pub const ENV_LWS_REQUIRE_POP: &str = "SOLID_SERVER_LWS_REQUIRE_POP";
/// Env override for the maximum REMAINING token lifetime accepted (seconds). Default
/// [`DEFAULT_MAX_TOKEN_TTL_SECS`]; hard-capped at [`SPEC_MAX_TOKEN_TTL_SECS`] (the spec's MUST:
/// "tokens with `exp` more than one hour ahead MUST be rejected").
pub const ENV_LWS_MAX_TOKEN_TTL: &str = "SOLID_SERVER_LWS_MAX_TOKEN_TTL_SECS";

/// The default accepted remaining-lifetime window: the spec RECOMMENDS lifetimes of 300 s or less
/// (§access-token) and the maintainer's lws-keycloak baseline issues ≤300 s tokens; enforcing the
/// window on `exp - now` bounds the theft-replay exposure regardless of the asserted `iat`.
pub const DEFAULT_MAX_TOKEN_TTL_SECS: i64 = 300;
/// The spec's absolute ceiling (§rs-validation temporal): `exp` more than one hour ahead MUST be
/// rejected. [`ENV_LWS_MAX_TOKEN_TTL`] can never raise the window past this.
pub const SPEC_MAX_TOKEN_TTL_SECS: i64 = 3600;
/// Clock-skew tolerance (seconds) applied to `exp`/`iat`/`nbf`. The spec RECOMMENDS at most 60;
/// this server uses the same small tolerance as its Solid-OIDC verifier posture.
pub const CLOCK_SKEW_SECS: i64 = 5;

/// The RFC 9728 protected-resource-metadata extension member naming the LWS storage description
/// (spec §authz-discovery: "MUST include the extension member `jlws_storage_description`").
pub const PRM_STORAGE_DESCRIPTION_MEMBER: &str = "jlws_storage_description";

/// The LWS Bearer verifier + challenge builder. Constructed by `main` (or a test harness) ONLY
/// when the LWS surface is on; carried as `Option<Arc<LwsBearerAuth>>` on the
/// [`AuthContext`](crate::auth::AuthContext) so the flag-off auth path is untouched.
pub struct LwsBearerAuth {
    /// The JWKS source for the trusted issuers. Trait-object so `main` can hand it the
    /// network-backed provider and tests the static one without threading another generic through
    /// [`AuthContext`](crate::auth::AuthContext). The [`JwksProvider`] contract holds: this module
    /// calls `keys_for` ONLY with an issuer it has already matched against the trusted list.
    jwks: Arc<dyn JwksProvider>,
    /// The explicit trusted-issuer allowlist (§rs-validation step 2; also the RFC 9728
    /// `authorization_servers` member — "the storage server manages this canonical list").
    trusted_issuers: Vec<String>,
    /// The server's public base URL, no trailing slash (the RFC 9728 document lives under it).
    base_url: String,
    /// The protection-space root (`realm`) — the storage root, an absolute URI (base + `/`).
    realm: String,
    /// Maximum accepted REMAINING lifetime (`exp - now`), seconds. See [`DEFAULT_MAX_TOKEN_TTL_SECS`].
    max_token_ttl_secs: i64,
    /// Whether this realm is designated PoP-required (spec §presentation-pop). Default false.
    require_pop: bool,
    /// Precomputed challenge header values for the append middleware (request-invariant).
    challenge_anonymous: HeaderValue,
    challenge_invalid_token: HeaderValue,
}

impl LwsBearerAuth {
    /// Build the LWS Bearer verifier. `trusted_issuers` must be non-empty (an empty allowlist
    /// would make every token unverifiable — surfaced at boot, not per-request).
    pub fn new(
        jwks: Arc<dyn JwksProvider>,
        trusted_issuers: Vec<String>,
        base_url: &str,
        require_pop: bool,
    ) -> Result<Self, String> {
        if trusted_issuers.is_empty() || trusted_issuers.iter().any(|i| i.trim().is_empty()) {
            return Err("LWS auth requires at least one (non-empty) trusted issuer".into());
        }
        let base = base_url.trim_end_matches('/').to_string();
        let realm = format!("{base}/");
        let scheme = if require_pop { "DPoP" } else { "Bearer" };
        let metadata_url = format!("{base}{}", crate::pop::sk::OAUTH_PROTECTED_RESOURCE_PATH);
        let anonymous = format!("{scheme} realm=\"{realm}\", resource_metadata=\"{metadata_url}\"");
        let invalid = format!("{anonymous}, error=\"invalid_token\"");
        let challenge_anonymous = HeaderValue::from_str(&anonymous)
            .map_err(|_| "LWS challenge is not a valid header value".to_string())?;
        let challenge_invalid_token = HeaderValue::from_str(&invalid)
            .map_err(|_| "LWS challenge is not a valid header value".to_string())?;
        Ok(Self {
            jwks,
            trusted_issuers,
            base_url: base,
            realm,
            max_token_ttl_secs: DEFAULT_MAX_TOKEN_TTL_SECS,
            require_pop,
            challenge_anonymous,
            challenge_invalid_token,
        })
    }

    /// Override the remaining-lifetime window (clamped to `1..=`[`SPEC_MAX_TOKEN_TTL_SECS`] — the
    /// env can tighten or modestly widen the RECOMMENDED window but can NEVER cross the spec's
    /// one-hour MUST).
    pub fn with_max_token_ttl(mut self, secs: i64) -> Self {
        self.max_token_ttl_secs = secs.clamp(1, SPEC_MAX_TOKEN_TTL_SECS);
        self
    }

    /// Whether this realm is designated PoP-required (spec §presentation-pop).
    pub fn require_pop(&self) -> bool {
        self.require_pop
    }

    /// The challenge header value the 401-append middleware attaches: `error="invalid_token"`
    /// iff the request presented credentials (RFC 6750 §3.1 — a no-credential challenge MUST NOT
    /// carry an `error` parameter).
    pub fn challenge_header_value(&self, credentials_presented: bool) -> &HeaderValue {
        if credentials_presented {
            &self.challenge_invalid_token
        } else {
            &self.challenge_anonymous
        }
    }

    /// The `WWW-Authenticate` string for a REJECTED presented token (RFC 6750 §3.1
    /// `error="invalid_token"`), used on the Bearer-verify failure path.
    fn www_authenticate_invalid(&self) -> String {
        self.challenge_invalid_token
            .to_str()
            .unwrap_or_default()
            .to_string()
    }

    /// Extend the RFC 9728 protected-resource-metadata document with the LWS members
    /// (§authz-discovery): `authorization_servers` (the canonical trusted-AS list),
    /// `jlws_storage_description` (the M1 storage description resource), and
    /// `dpop_bound_access_tokens_required` reflecting THIS realm's actual posture — `false` under
    /// the Bearer baseline (Bearer accepted, PoP optional), `true` only when the realm is
    /// designated PoP-required. RFC 9728 requires the member to be honest either way: a client
    /// must be able to distinguish *Bearer-accepted, PoP optional* from *PoP required*.
    pub fn extend_protected_resource_metadata(&self, doc: &mut Value) {
        doc["authorization_servers"] = Value::from(self.trusted_issuers.clone());
        doc[PRM_STORAGE_DESCRIPTION_MEMBER] = Value::from(format!(
            "{}{}",
            self.base_url,
            super::STORAGE_DESCRIPTION_PATH
        ));
        doc["dpop_bound_access_tokens_required"] = Value::from(self.require_pop);
    }

    /// ROUTING (not a security decision): is this Bearer token shaped like an LWS access token —
    /// an unverified `aud` of **exactly one value** that parses as an absolute http(s) URI
    /// (§access-token: an LWS `aud` is the storage URI), and **no `cnf` member**? A candidate
    /// COMMITS to [`verify_bearer`](Self::verify_bearer) — whose verdict is final; a
    /// non-candidate falls through to the untouched pre-LWS verifier path, which is itself fully
    /// fail-closed. Peeking unverified claims for routing mirrors the verifier crate's own
    /// `peek_*` discipline: either branch fully verifies, so a lie in the peeked claim only
    /// selects which fail-closed path rejects it.
    ///
    /// The `cnf` exclusion keeps a PoP-BOUND token on the verifier path, which validates its
    /// binding at full strength — in particular an RFC 8705 cert-bound Bearer on an mTLS
    /// connection (PoP Tier-1) keeps working with LWS on, per §rs-validation step 5 ("validated
    /// per the profile in use") — or rejects it. Dodging the exclusion in either direction only
    /// lands the token on the OTHER fully-verifying branch: omit `cnf` ⇒ the LWS path validates
    /// the (then unbound) token completely; forge a `cnf` ⇒ the stricter verifier path demands
    /// the proof/certificate it names. [`verify_bearer`](Self::verify_bearer)'s own bare-`cnf`
    /// refusal remains as defence-in-depth on the VERIFIED claims.
    pub fn is_lws_candidate(&self, token: &str) -> bool {
        let Some(claims) = jwt::peek_claims(token) else {
            return false;
        };
        if claims.get("cnf").is_some() {
            return false;
        }
        match single_audience(&claims) {
            Some(aud) => parses_as_absolute_http_url(aud),
            None => false,
        }
    }

    /// Verify a Bearer-presented LWS access token per spec §rs-validation, mapping the verified
    /// claims onto the server's [`VerifiedToken`] (the `sub` becomes the WAC agent). `target_htu`
    /// is the SERVER-reconstructed request URL (scheme/host/port/path, query stripped — the same
    /// proxy-independent value the DPoP `htu` check uses); `now` is UNIX seconds.
    ///
    /// FAIL-CLOSED: every deviation is a 401 [`ServerError::Unauthorized`] carrying the RFC 6750
    /// `invalid_token` challenge (+ `realm`/`resource_metadata`). Messages are static and
    /// non-leaky (they name the failed check, never token contents).
    pub fn verify_bearer(
        &self,
        token: &str,
        target_htu: &str,
        now: i64,
    ) -> Result<VerifiedToken, ServerError> {
        // §presentation-pop: a PoP-required realm accepts NO bearer presentation at all — closed
        // before any parsing so the posture is unmissable.
        if self.require_pop {
            return Err(self.reject("This realm requires proof-of-possession presentation."));
        }

        // (2) Issuer FIRST (it selects the verification keys; §rs-validation step 2). Matching the
        // trusted list before `keys_for` preserves the JwksProvider contract (it may assume trust)
        // and means an attacker-chosen `iss` never triggers a JWKS/discovery fetch.
        let iss = jwt::peek_issuer(token).map_err(|_| self.reject("Malformed access token."))?;
        if !self.trusted_issuers.iter().any(|t| t == &iss) {
            return Err(self.reject("Access token issuer is not trusted."));
        }

        // (1) Signature over the trusted issuer's JWKS — the vetted primitive: asymmetric-only
        // allowlist (alg-confusion-safe, `none`/HS* refused), `typ: at+jwt` enforced (RFC 9068
        // §2.1) in the same call. Returns the VERIFIED claims; everything below reads only these.
        let keys = self
            .jwks
            .keys_for(&iss)
            .map_err(|JwksError(_)| self.reject("Access token verification key unavailable."))?;
        let claims = jwt::verify_signature(token, &keys, Some("at+jwt"))
            .map_err(|_| self.reject("Access token signature or typ invalid."))?;
        let claims = Value::Object(claims);

        // Belt-and-braces: the VERIFIED `iss` must equal the issuer whose keys verified the
        // signature (both read the same signed payload, so this cannot differ — but the trust
        // decision must be anchored on the verified claim, not the pre-verification peek).
        if claims.get("iss").and_then(Value::as_str) != Some(iss.as_str()) {
            return Err(self.reject("Access token issuer mismatch."));
        }

        // (3) Audience (§rs-validation step 3 — THE load-bearing check): exactly one value, an
        // absolute URI that logically CONTAINS the target on complete `/`-segment boundaries.
        let Some(aud) = single_audience(&claims) else {
            return Err(self.reject("Access token must carry exactly one audience."));
        };
        if !audience_contains(aud, target_htu) {
            return Err(self.reject("Access token audience does not contain this resource."));
        }

        // (4) Temporal (§rs-validation step 4), bounded skew.
        let Some(exp) = claims.get("exp").and_then(Value::as_i64) else {
            return Err(self.reject("Access token has no exp."));
        };
        if exp <= now - CLOCK_SKEW_SECS {
            return Err(self.reject("Access token is expired."));
        }
        // Bounded remaining lifetime: the ≤300 s window (default) — and never past the spec's
        // one-hour MUST. Enforced on `exp - now` so the replay exposure is bounded regardless of
        // the asserted iat.
        if exp - now > self.max_token_ttl_secs + CLOCK_SKEW_SECS {
            return Err(self.reject("Access token lifetime exceeds the accepted window."));
        }
        let Some(iat) = claims.get("iat").and_then(Value::as_i64) else {
            return Err(self.reject("Access token has no iat."));
        };
        if iat > now + CLOCK_SKEW_SECS {
            return Err(self.reject("Access token iat is in the future."));
        }
        if let Some(nbf) = claims.get("nbf") {
            match nbf.as_i64() {
                Some(nbf) if nbf <= now + CLOCK_SKEW_SECS => {}
                // Present-but-unparseable nbf fails CLOSED (never ignored).
                _ => return Err(self.reject("Access token is not yet valid.")),
            }
        }

        // Required claims (§access-token): sub (absolute URI of the agent), client_id, jti.
        let sub = match claims.get("sub").and_then(Value::as_str) {
            Some(s) if parses_as_absolute_http_url(s) => s.to_string(),
            _ => return Err(self.reject("Access token sub must be an absolute http(s) URI.")),
        };
        let client_id = match claims.get("client_id").and_then(Value::as_str) {
            Some(c) if !c.trim().is_empty() => c.to_string(),
            _ => return Err(self.reject("Access token has no client_id.")),
        };
        match claims.get("jti").and_then(Value::as_str) {
            Some(j) if !j.trim().is_empty() => {}
            _ => return Err(self.reject("Access token has no jti.")),
        }

        // (5) Proof-of-possession (§rs-validation step 5): a `cnf`-bearing token is PoP-BOUND and
        // "MUST NOT be accepted bare". This Bearer path IS bare presentation — refuse, whatever
        // the binding's flavour or well-formedness (fail-closed; the DPoP-bound-LWS-token path is
        // the documented follow-up seam). Normally unreachable via the middleware — the candidate
        // routing already excludes `cnf`-bearing tokens (they stay on the verifier path, which
        // validates the binding) — but that exclusion reads UNVERIFIED claims; this check reads
        // the VERIFIED ones and is the authoritative refusal (defence-in-depth).
        if claims.get("cnf").is_some() {
            return Err(self.reject(
                "A proof-of-possession-bound token cannot be presented as a bare Bearer token.",
            ));
        }

        // The trusted AS asserts the agent (`sub`) — it becomes the WAC identity. No cnf, no
        // scopes semantics defined by the LWS spec (RFC 9396 authorization_details is an M3 seam;
        // per the spec it could only NARROW below WAC, never widen — ignoring it grants exactly
        // the WAC baseline).
        Ok(VerifiedToken {
            web_id: Some(sub),
            issuer: Some(iss),
            client_id: Some(client_id),
            scopes: Vec::new(),
            cnf_jkt: None,
            cnf_x5t_s256: None,
            expiry: Some(exp),
        })
    }

    /// A fail-closed 401 with the RFC 6750 `invalid_token` challenge (+ `realm` /
    /// `resource_metadata`, so the rejected client can (re-)discover the AS per §authz-discovery).
    fn reject(&self, message: &str) -> ServerError {
        ServerError::Unauthorized {
            status: 401,
            message: message.to_string(),
            www_authenticate: self.www_authenticate_invalid(),
        }
    }

    /// The realm (protection-space) URI — the storage root. Exposed for tests/logging.
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

impl std::fmt::Debug for LwsBearerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LwsBearerAuth")
            .field("trusted_issuers", &self.trusted_issuers)
            .field("realm", &self.realm)
            .field("max_token_ttl_secs", &self.max_token_ttl_secs)
            .field("require_pop", &self.require_pop)
            .finish_non_exhaustive()
    }
}

/// Read the spec's "exactly one value" audience (§access-token / §rs-validation step 3): a JSON
/// string, or an array containing EXACTLY one string. Anything else — absent, empty, multi-valued,
/// non-string members — is `None` (⇒ reject).
fn single_audience(claims: &Value) -> Option<&str> {
    match claims.get("aud") {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(Value::Array(a)) if a.len() == 1 => a[0].as_str(),
        _ => None,
    }
}

/// Does `s` parse as an absolute http(s) URL (the shapes an LWS audience / agent URI may take)?
fn parses_as_absolute_http_url(s: &str) -> bool {
    match Url::parse(s) {
        Ok(u) => matches!(u.scheme(), "http" | "https"),
        Err(_) => false,
    }
}

/// **The load-bearing audience-containment check** (spec §rs-validation step 3): does the token's
/// single `aud` logically contain the target resource?
///
/// Evaluated over PARSED, NORMALIZED URIs (RFC 3986 §6 — `url::Url` lowercases scheme/host,
/// resolves default ports via `port_or_known_default`, and removes dot-segments) — **never a raw
/// string prefix**. Containment requires:
/// - both parse as absolute `http(s)` URLs with the SAME scheme, host, and (default-aware) port;
/// - the audience carries no query, fragment, or userinfo (an audience is a storage prefix — any
///   such component fails CLOSED; userinfo could otherwise cosmetically impersonate an origin);
/// - **the target's identity is unambiguous** — its `url::Url`-normalized path is byte-identical
///   to the raw path the server keys the resource by (see below);
/// - the audience's path equals the target's path, OR is an ancestor of it on **complete
///   `/`-delimited segment boundaries**: the target path must start with the audience path
///   *slash-terminated* (appending the `/` before comparing is exactly what forces the segment
///   boundary — `…/alice` can never match `…/alicemalicious`, the raw-prefix flaw the spec review
///   fixed). The check is strict about trailing slashes in the other direction too: an audience
///   of `…/alice/` does NOT contain the distinct sibling resource `…/alice`.
///
/// ## The target-identity guard (roborev Medium, e827448)
/// The `target` passed here is the server-reconstructed resource IRI — the SAME string the store
/// keys by and WAC authorizes (`ldp::target::parse_target`), which rejects LITERAL `.`/`..`
/// segments but PRESERVES percent-encoded ones (`%2e%2e`). `url::Url`, however, decodes `%2e%2e`
/// → `..` and REMOVES the dot-segment: `…/alice/%2e%2e/bob/x` normalizes to `…/bob/x`. Comparing
/// the normalized target against the audience would then let a token scoped to `…/bob/` satisfy
/// containment for a resource whose ACTUAL identity is under `…/alice/` — an audience-scope
/// bypass. So we FAIL CLOSED whenever the target's normalized path differs from its raw path
/// (i.e. it contained a percent-encoded segment `url::Url` renormalizes): the containment
/// decision is only made on a target whose identity the two representations agree on. Legitimate
/// percent-encoding `url::Url` PRESERVES (`%61lice`, `%2f`) passes the guard unchanged.
pub fn audience_contains(aud: &str, target: &str) -> bool {
    let (Ok(a), Ok(t)) = (Url::parse(aud), Url::parse(target)) else {
        return false;
    };
    // Absolute http(s) only, identical scheme.
    if !matches!(a.scheme(), "http" | "https") || a.scheme() != t.scheme() {
        return false;
    }
    // An audience with a query/fragment/userinfo is not a storage prefix — fail closed. (The
    // target is server-reconstructed and never carries these; check anyway.)
    if a.query().is_some() || a.fragment().is_some() {
        return false;
    }
    if !a.username().is_empty() || a.password().is_some() {
        return false;
    }
    if t.query().is_some() || t.fragment().is_some() || !t.username().is_empty() {
        return false;
    }
    // Same origin: host (Url normalizes case) + default-aware port.
    match (a.host_str(), t.host_str()) {
        (Some(ah), Some(th)) if ah == th => {}
        _ => return false,
    }
    if a.port_or_known_default() != t.port_or_known_default() {
        return false;
    }
    if a.cannot_be_a_base() || t.cannot_be_a_base() {
        return false;
    }
    // TARGET-IDENTITY GUARD: refuse a target whose url-normalized path is not byte-identical to
    // the raw path the store/WAC key it by. This closes the `%2e%2e` renormalization mismatch —
    // the containment decision is made ONLY on an unambiguous target identity (see the doc).
    let Some(raw_target_path) = raw_path_of(target) else {
        return false;
    };
    if raw_target_path != t.path() {
        return false;
    }
    let (ap, tp) = (a.path(), t.path());
    if tp == ap {
        return true;
    }
    // Ancestor on complete segment boundaries: slash-terminate the audience path, then prefix.
    let boundary = if ap.ends_with('/') {
        ap.to_string()
    } else {
        format!("{ap}/")
    };
    tp.starts_with(&boundary)
}

/// Extract the RAW (pre-normalization) PATH substring of an absolute `scheme://authority/path`
/// URL string, WITHOUT `url::Url`'s dot-segment/percent-decode normalization, and WITHOUT any
/// query/fragment. Used only by the target-identity guard in [`audience_contains`].
///
/// The guard compares this against `url::Url::path()` (which is path-only). [`audience_contains`]
/// already rejects a target carrying a query/fragment outright (a server-reconstructed LDP target
/// is query-stripped by `ldp::target::parse_target` before it ever reaches here), so in practice
/// the input has none — but this helper is `pub`-adjacent to a `pub fn`, so it stops at the first
/// `?`/`#` defensively to keep its contract (a raw *path*) correct for ANY caller, matching
/// `Url::path()`'s path-only shape. `None` if the string is not shaped like an absolute URL
/// (⇒ the caller fails closed).
fn raw_path_of(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1; // authority[/path][?query][#frag]
    let path_and_rest = match after_scheme.find('/') {
        Some(i) => &after_scheme[i..],
        None => return Some("/"), // no path component ⇒ url::Url reports "/"
    };
    // Trim any query/fragment so the comparison is path-vs-path with `Url::path()`.
    Some(
        path_and_rest
            .split(['?', '#'])
            .next()
            .unwrap_or(path_and_rest),
    )
}

/// The 401 challenge-append middleware (spec §authz-discovery): every `401` leaving the LWS-on
/// application routes MUST advertise the AS-discovery parameters. Appends ONE extra
/// `WWW-Authenticate` value — `Bearer realm="…", resource_metadata="…"` (scheme `DPoP` on a
/// PoP-required realm, which omits Bearer per §presentation-pop) — beside whatever challenge the
/// response already carries (the verifier's DPoP challenge, the WAC anonymous challenge, …);
/// multiple challenges are RFC 9110 §11.6.1-conformant. `error="invalid_token"` rides only when
/// the request presented an `Authorization` header (RFC 6750 §3.1). A response that already
/// advertises `resource_metadata` (the LWS Bearer-verify's own rejection) is left unchanged.
///
/// Mounted by `crate::app` ONLY when the LWS auth chain is configured — a flag-off build has no
/// layer and byte-identical responses.
pub async fn lws_challenge_middleware(
    State(lws): State<Arc<LwsBearerAuth>>,
    req: Request,
    next: Next,
) -> Response {
    let credentials_presented = req.headers().contains_key(header::AUTHORIZATION);
    let mut resp = next.run(req).await;
    if resp.status() == StatusCode::UNAUTHORIZED {
        let already_advertised = resp
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .any(|v| {
                v.to_str()
                    .map(|s| s.contains("resource_metadata="))
                    .unwrap_or(false)
            });
        if !already_advertised {
            resp.headers_mut().append(
                header::WWW_AUTHENTICATE,
                lws.challenge_header_value(credentials_presented).clone(),
            );
        }
    }
    resp
}

/// Read the PoP-required toggle from the environment (see [`ENV_LWS_REQUIRE_POP`]).
pub fn require_pop_from_env() -> bool {
    std::env::var(ENV_LWS_REQUIRE_POP)
        .map(|v| super::is_truthy(&v))
        .unwrap_or(false)
}

/// Read the max-token-TTL override (seconds) from the environment: [`DEFAULT_MAX_TOKEN_TTL_SECS`]
/// when unset/unparseable; always clamped to `1..=`[`SPEC_MAX_TOKEN_TTL_SECS`] (the spec's
/// one-hour MUST is not operator-overridable).
pub fn max_token_ttl_from_env() -> i64 {
    std::env::var(ENV_LWS_MAX_TOKEN_TTL)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(DEFAULT_MAX_TOKEN_TTL_SECS)
        .clamp(1, SPEC_MAX_TOKEN_TTL_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use serde_json::json;
    use solid_oidc_verifier::config::StaticJwksProvider;

    const ISSUER: &str = "https://as.example/realms/lws";
    const BASE: &str = "https://storage.example";
    const AGENT: &str = "https://storage.example/alice/profile#me";

    // --- audience_contains: the exhaustive segment-boundary matrix -----------------------------

    #[test]
    fn aud_containment_segment_boundaries() {
        // THE spec-review case: a raw prefix would authorize the sibling — we must not.
        assert!(!audience_contains(
            "https://storage.example/alice",
            "https://storage.example/alicemalicious"
        ));
        assert!(!audience_contains(
            "https://storage.example/alice/",
            "https://storage.example/alicemalicious"
        ));
        assert!(!audience_contains(
            "https://storage.example/alice",
            "https://storage.example/alicemalicious/notes/x"
        ));
        // The spec's positive example: …/alice/ contains …/alice/notes/x.
        assert!(audience_contains(
            "https://storage.example/alice/",
            "https://storage.example/alice/notes/x"
        ));
        // Slash-less audience is an ancestor on a complete boundary.
        assert!(audience_contains(
            "https://storage.example/alice",
            "https://storage.example/alice/notes"
        ));
        // Exact path equality (both spellings).
        assert!(audience_contains(
            "https://storage.example/alice/",
            "https://storage.example/alice/"
        ));
        assert!(audience_contains(
            "https://storage.example/alice",
            "https://storage.example/alice"
        ));
        // STRICT about the distinct sibling spelling: …/alice/ does not contain …/alice, nor the
        // reverse-as-equality.
        assert!(!audience_contains(
            "https://storage.example/alice/",
            "https://storage.example/alice"
        ));
        // The origin root contains everything on the origin.
        assert!(audience_contains(
            "https://storage.example/",
            "https://storage.example/anything/at/all"
        ));
        assert!(audience_contains(
            "https://storage.example",
            "https://storage.example/anything"
        ));
        // A deeper audience never contains its parent.
        assert!(!audience_contains(
            "https://storage.example/alice/notes/",
            "https://storage.example/alice/"
        ));
    }

    #[test]
    fn raw_path_of_is_path_only() {
        // Query/fragment are trimmed so the guard compares path-vs-path with Url::path().
        assert_eq!(
            raw_path_of("https://storage.example/alice/x"),
            Some("/alice/x")
        );
        assert_eq!(
            raw_path_of("https://storage.example/alice/x?a=1&b=2"),
            Some("/alice/x")
        );
        assert_eq!(
            raw_path_of("https://storage.example/alice/x#frag"),
            Some("/alice/x")
        );
        assert_eq!(raw_path_of("https://storage.example"), Some("/"));
        assert_eq!(raw_path_of("https://storage.example?q"), Some("/"));
        assert_eq!(raw_path_of("not-a-url"), None);
    }

    #[test]
    fn aud_containment_origin_rules() {
        // Scheme mismatch.
        assert!(!audience_contains(
            "http://storage.example/alice/",
            "https://storage.example/alice/x"
        ));
        // Host mismatch; host compare is case-normalized by the parser.
        assert!(!audience_contains(
            "https://other.example/alice/",
            "https://storage.example/alice/x"
        ));
        assert!(audience_contains(
            "https://STORAGE.example/alice/",
            "https://storage.example/alice/x"
        ));
        // Port: explicit-default equals elided default; a different port never matches.
        assert!(audience_contains(
            "https://storage.example:443/alice/",
            "https://storage.example/alice/x"
        ));
        assert!(!audience_contains(
            "https://storage.example:8443/alice/",
            "https://storage.example/alice/x"
        ));
        // Non-http(s) schemes are refused outright.
        assert!(!audience_contains(
            "ftp://storage.example/alice/",
            "ftp://storage.example/alice/x"
        ));
        // Relative / garbage audiences are refused.
        assert!(!audience_contains(
            "/alice/",
            "https://storage.example/alice/x"
        ));
        assert!(!audience_contains(
            "solid",
            "https://storage.example/alice/x"
        ));
    }

    #[test]
    fn aud_containment_hostile_components_fail_closed() {
        // Query/fragment/userinfo on the audience: not a storage prefix.
        assert!(!audience_contains(
            "https://storage.example/alice/?widen=1",
            "https://storage.example/alice/x"
        ));
        assert!(!audience_contains(
            "https://storage.example/alice/#frag",
            "https://storage.example/alice/x"
        ));
        assert!(!audience_contains(
            "https://evil@storage.example/alice/",
            "https://storage.example/alice/x"
        ));
        // The AUDIENCE side is normalized (RFC 3986 §6) — a trusted AS's dot-segment spelling
        // grants exactly its normal form (…/alice/notes/../ ⇒ …/alice/).
        assert!(audience_contains(
            "https://storage.example/alice/notes/../",
            "https://storage.example/alice/x"
        ));
        // Literal dot-segments in the TARGET (url normalizes them) — `parse_target` would already
        // 400 these; the audience check independently denies.
        assert!(!audience_contains(
            "https://storage.example/alice/",
            "https://storage.example/alice/../bob/x" // normalizes to /bob/x — outside
        ));
        // THE roborev-Medium guard: a target with a PERCENT-ENCODED dot-segment renormalizes
        // under url::Url (…/alice/%2e%2e/bob/x ⇒ …/bob/x) but its store/WAC identity stays under
        // …/alice/. The audience check MUST fail closed rather than let a …/bob/-scoped token
        // reach an …/alice/-subtree resource.
        assert!(!audience_contains(
            "https://storage.example/bob/",
            "https://storage.example/alice/%2e%2e/bob/x"
        ));
        assert!(!audience_contains(
            "https://storage.example/bob/",
            "https://storage.example/alice/%2E%2E/bob/x"
        ));
        // Even when the encoded-dot target would land BACK inside the audience, the ambiguity
        // itself is refused (identity must be unambiguous).
        assert!(!audience_contains(
            "https://storage.example/alice/",
            "https://storage.example/alice/notes/%2e%2e/x"
        ));
        // Percent-encoded spellings url::Url PRESERVES do NOT alias and pass the guard: a genuine
        // mismatch denies (never over-grants), a genuine match is allowed.
        assert!(!audience_contains(
            "https://storage.example/alice/",
            "https://storage.example/%61lice/x" // %61lice is a DIFFERENT resource, denied
        ));
        assert!(audience_contains(
            "https://storage.example/alice/",
            "https://storage.example/alice/%61-note" // preserved encoding, inside — allowed
        ));
    }

    // --- verify_bearer: mint helpers -----------------------------------------------------------

    struct Kit {
        signing: SigningKey,
        jwk: solid_oidc_verifier::jwk::Jwk,
    }

    fn b64url(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    impl Kit {
        fn generate() -> Self {
            let signing = SigningKey::random(&mut rand_core::OsRng);
            let point = signing.verifying_key().to_encoded_point(false);
            let jwk = serde_json::from_value(json!({
                "kty": "EC", "crv": "P-256",
                "x": b64url(point.x().unwrap()),
                "y": b64url(point.y().unwrap()),
            }))
            .unwrap();
            Self { signing, jwk }
        }

        fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!(
                "{}.{}",
                b64url(&serde_json::to_vec(header).unwrap()),
                b64url(&serde_json::to_vec(claims).unwrap())
            );
            let sig: Signature = self.signing.sign(input.as_bytes());
            format!("{input}.{}", b64url(&sig.to_bytes()))
        }
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Baseline VALID LWS at+jwt claims (aud = the storage root).
    fn base_claims(now: i64) -> Value {
        json!({
            "iss": ISSUER,
            "sub": AGENT,
            "client_id": "lws-app",
            "aud": format!("{BASE}/"),
            "iat": now,
            "exp": now + 120,
            "jti": "jti-1",
        })
    }

    fn auth_with(kit: &Kit, require_pop: bool) -> LwsBearerAuth {
        let jwks: Arc<dyn JwksProvider> = Arc::new(
            StaticJwksProvider::new().with_issuer(ISSUER.to_string(), vec![kit.jwk.clone()]),
        );
        LwsBearerAuth::new(jwks, vec![ISSUER.to_string()], BASE, require_pop).unwrap()
    }

    fn at_header() -> Value {
        json!({ "alg": "ES256", "typ": "at+jwt" })
    }

    fn expect_reject(auth: &LwsBearerAuth, token: &str, target: &str, now: i64, why: &str) {
        match auth.verify_bearer(token, target, now) {
            Err(ServerError::Unauthorized {
                status,
                www_authenticate,
                ..
            }) => {
                assert_eq!(status, 401, "{why}");
                assert!(
                    www_authenticate.contains("resource_metadata=")
                        && www_authenticate.contains("error=\"invalid_token\""),
                    "{why}: challenge must carry resource_metadata + invalid_token"
                );
            }
            Ok(_) => panic!("{why}: token must be rejected"),
            Err(e) => panic!("{why}: expected 401 Unauthorized, got {e:?}"),
        }
    }

    // --- verify_bearer: accept + the full reject matrix ----------------------------------------

    #[test]
    fn accepts_a_valid_lws_at_jwt_and_maps_sub_to_the_wac_agent() {
        let kit = Kit::generate();
        let auth = auth_with(&kit, false);
        let n = now();
        let token = kit.sign(&at_header(), &base_claims(n));
        let verified = auth
            .verify_bearer(&token, &format!("{BASE}/alice/notes/x"), n)
            .expect("valid token accepted");
        assert_eq!(verified.web_id.as_deref(), Some(AGENT));
        assert_eq!(verified.issuer.as_deref(), Some(ISSUER));
        assert_eq!(verified.client_id.as_deref(), Some("lws-app"));
        assert_eq!(verified.expiry, Some(n + 120));
        assert!(verified.cnf_jkt.is_none() && verified.cnf_x5t_s256.is_none());
        // Singleton-array audience is "exactly one value" too (RFC 9068 allows the array form).
        let mut c = base_claims(n);
        c["aud"] = json!([format!("{BASE}/")]);
        let token = kit.sign(&at_header(), &c);
        assert!(auth.verify_bearer(&token, &format!("{BASE}/x"), n).is_ok());
    }

    #[test]
    fn rejects_forged_signature_and_alg_games() {
        let kit = Kit::generate();
        let forger = Kit::generate();
        let auth = auth_with(&kit, false);
        let n = now();
        let target = format!("{BASE}/x");
        // Signed by a key NOT in the issuer's JWKS.
        let token = forger.sign(&at_header(), &base_claims(n));
        expect_reject(&auth, &token, &target, n, "forged signature");
        // alg: none (empty signature segment shape).
        let header = b64url(br#"{"alg":"none","typ":"at+jwt"}"#);
        let payload = b64url(&serde_json::to_vec(&base_claims(n)).unwrap());
        expect_reject(
            &auth,
            &format!("{header}.{payload}."),
            &target,
            n,
            "alg none",
        );
        expect_reject(
            &auth,
            &format!("{header}.{payload}.sig"),
            &target,
            n,
            "alg none + junk sig",
        );
        // Symmetric alg is outside the asymmetric-only policy (regardless of signature bytes).
        let hs = b64url(br#"{"alg":"HS256","typ":"at+jwt"}"#);
        expect_reject(&auth, &format!("{hs}.{payload}.AAAA"), &target, n, "HS256");
        // Tampered payload under a once-valid signature.
        let good = kit.sign(&at_header(), &base_claims(n));
        let mut parts: Vec<&str> = good.split('.').collect();
        let mut tampered = base_claims(n);
        tampered["sub"] = json!("https://storage.example/mallory#me");
        let tp = b64url(&serde_json::to_vec(&tampered).unwrap());
        parts[1] = &tp;
        expect_reject(&auth, &parts.join("."), &target, n, "tampered payload");
        // Not a JWT at all.
        expect_reject(&auth, "not-a-jwt", &target, n, "garbage");
    }

    #[test]
    fn rejects_wrong_issuer_and_wrong_typ() {
        let kit = Kit::generate();
        let auth = auth_with(&kit, false);
        let n = now();
        let target = format!("{BASE}/x");
        // Untrusted issuer (even though the signature would verify under its own JWKS).
        let mut c = base_claims(n);
        c["iss"] = json!("https://evil-as.example");
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "untrusted issuer",
        );
        // Missing issuer.
        let mut c = base_claims(n);
        c.as_object_mut().unwrap().remove("iss");
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "missing issuer",
        );
        // Wrong / missing typ (RFC 9068 requires at+jwt).
        let token = kit.sign(&json!({ "alg": "ES256", "typ": "JWT" }), &base_claims(n));
        expect_reject(&auth, &token, &target, n, "typ JWT");
        let token = kit.sign(&json!({ "alg": "ES256" }), &base_claims(n));
        expect_reject(&auth, &token, &target, n, "typ absent");
    }

    #[test]
    fn rejects_audience_violations_incl_the_sibling_prefix() {
        let kit = Kit::generate();
        let auth = auth_with(&kit, false);
        let n = now();
        // aud scoped to /alice — the sibling /alicemalicious MUST NOT be authorized.
        let mut c = base_claims(n);
        c["aud"] = json!(format!("{BASE}/alice"));
        let token = kit.sign(&at_header(), &c);
        assert!(auth
            .verify_bearer(&token, &format!("{BASE}/alice/notes"), n)
            .is_ok());
        expect_reject(
            &auth,
            &token,
            &format!("{BASE}/alicemalicious"),
            n,
            "sibling raw-prefix",
        );
        expect_reject(
            &auth,
            &token,
            &format!("{BASE}/alicemalicious/notes"),
            n,
            "sibling subtree",
        );
        // Multi-valued audience: never accepted, even when one member matches.
        let mut c = base_claims(n);
        c["aud"] = json!([format!("{BASE}/"), "https://other.example/"]);
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &format!("{BASE}/x"),
            n,
            "multi-aud",
        );
        // Wrong-origin audience.
        let mut c = base_claims(n);
        c["aud"] = json!("https://other.example/");
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &format!("{BASE}/x"),
            n,
            "wrong origin",
        );
        // Absent / non-string audience.
        let mut c = base_claims(n);
        c.as_object_mut().unwrap().remove("aud");
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &format!("{BASE}/x"),
            n,
            "no aud",
        );
        let mut c = base_claims(n);
        c["aud"] = json!(42);
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &format!("{BASE}/x"),
            n,
            "numeric aud",
        );
    }

    #[test]
    fn rejects_temporal_violations() {
        let kit = Kit::generate();
        let auth = auth_with(&kit, false);
        let n = now();
        let target = format!("{BASE}/x");
        // Expired.
        let mut c = base_claims(n);
        c["exp"] = json!(n - 61);
        expect_reject(&auth, &kit.sign(&at_header(), &c), &target, n, "expired");
        // exp too far ahead (beyond the 300 s window — the ≤300 s enforcement).
        let mut c = base_claims(n);
        c["exp"] = json!(n + 3600);
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "exp beyond window",
        );
        // Just inside the window is accepted.
        let mut c = base_claims(n);
        c["exp"] = json!(n + DEFAULT_MAX_TOKEN_TTL_SECS);
        assert!(auth
            .verify_bearer(&kit.sign(&at_header(), &c), &target, n)
            .is_ok());
        // Missing exp / iat.
        let mut c = base_claims(n);
        c.as_object_mut().unwrap().remove("exp");
        expect_reject(&auth, &kit.sign(&at_header(), &c), &target, n, "no exp");
        let mut c = base_claims(n);
        c.as_object_mut().unwrap().remove("iat");
        expect_reject(&auth, &kit.sign(&at_header(), &c), &target, n, "no iat");
        // iat in the future.
        let mut c = base_claims(n);
        c["iat"] = json!(n + 120);
        expect_reject(&auth, &kit.sign(&at_header(), &c), &target, n, "future iat");
        // nbf in the future; malformed nbf fails closed.
        let mut c = base_claims(n);
        c["nbf"] = json!(n + 120);
        expect_reject(&auth, &kit.sign(&at_header(), &c), &target, n, "future nbf");
        let mut c = base_claims(n);
        c["nbf"] = json!("soon");
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "malformed nbf",
        );
    }

    #[test]
    fn rejects_missing_required_claims_and_bare_pop_tokens() {
        let kit = Kit::generate();
        let auth = auth_with(&kit, false);
        let n = now();
        let target = format!("{BASE}/x");
        // client_id REQUIRED.
        let mut c = base_claims(n);
        c.as_object_mut().unwrap().remove("client_id");
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "no client_id",
        );
        let mut c = base_claims(n);
        c["client_id"] = json!("   ");
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "blank client_id",
        );
        // sub REQUIRED, absolute http(s) URI.
        let mut c = base_claims(n);
        c.as_object_mut().unwrap().remove("sub");
        expect_reject(&auth, &kit.sign(&at_header(), &c), &target, n, "no sub");
        let mut c = base_claims(n);
        c["sub"] = json!("alice");
        expect_reject(&auth, &kit.sign(&at_header(), &c), &target, n, "opaque sub");
        // jti REQUIRED.
        let mut c = base_claims(n);
        c.as_object_mut().unwrap().remove("jti");
        expect_reject(&auth, &kit.sign(&at_header(), &c), &target, n, "no jti");
        // A cnf-bearing (PoP-bound) token MUST NOT be accepted bare — either binding flavour.
        let mut c = base_claims(n);
        c["cnf"] = json!({ "jkt": "some-thumbprint" });
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "bare cnf.jkt",
        );
        let mut c = base_claims(n);
        c["cnf"] = json!({ "x5t#S256": "some-cert-thumbprint" });
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "bare cnf.x5t",
        );
        let mut c = base_claims(n);
        c["cnf"] = json!({});
        expect_reject(
            &auth,
            &kit.sign(&at_header(), &c),
            &target,
            n,
            "bare empty cnf",
        );
    }

    #[test]
    fn pop_required_realm_closes_the_bearer_path() {
        let kit = Kit::generate();
        let auth = auth_with(&kit, true);
        let n = now();
        // Even a fully valid token is refused on a PoP-required realm.
        let token = kit.sign(&at_header(), &base_claims(n));
        match auth.verify_bearer(&token, &format!("{BASE}/x"), n) {
            Err(ServerError::Unauthorized {
                www_authenticate, ..
            }) => {
                // The challenge lists only the DPoP scheme (§presentation-pop: omit Bearer).
                assert!(www_authenticate.starts_with("DPoP "));
                assert!(!www_authenticate.contains("Bearer"));
            }
            other => panic!("PoP-required realm must reject Bearer: {other:?}"),
        }
        // And the metadata advertises the requirement.
        let mut doc = json!({ "resource": BASE, "dpop_bound_access_tokens_required": true });
        auth.extend_protected_resource_metadata(&mut doc);
        assert_eq!(doc["dpop_bound_access_tokens_required"], json!(true));
    }

    // --- candidate routing + challenge/metadata shape -------------------------------------------

    #[test]
    fn candidate_routing_is_aud_shaped_and_excludes_pop_bound_tokens() {
        let kit = Kit::generate();
        let auth = auth_with(&kit, false);
        let n = now();
        // LWS-shaped: single absolute-URI audience (string or singleton array), no cnf.
        assert!(auth.is_lws_candidate(&kit.sign(&at_header(), &base_claims(n))));
        let mut c = base_claims(n);
        c["aud"] = json!([format!("{BASE}/")]);
        assert!(auth.is_lws_candidate(&kit.sign(&at_header(), &c)));
        // Solid-shaped (`aud: "solid"`) is NOT a candidate — it stays on the pre-LWS verifier.
        let mut c = base_claims(n);
        c["aud"] = json!("solid");
        assert!(!auth.is_lws_candidate(&kit.sign(&at_header(), &c)));
        // A PoP-BOUND (`cnf`-bearing) token is NOT a candidate — it stays on the verifier path,
        // which validates its binding at full strength (mTLS cert-bound Bearer keeps working) or
        // rejects it. Any cnf flavour excludes.
        for cnf in [
            json!({ "jkt": "thumb" }),
            json!({ "x5t#S256": "cert-thumb" }),
            json!({}),
        ] {
            let mut c = base_claims(n);
            c["cnf"] = cnf;
            assert!(!auth.is_lws_candidate(&kit.sign(&at_header(), &c)));
        }
        // Multi-valued / absent aud / non-JWT: not candidates.
        let mut c = base_claims(n);
        c["aud"] = json!(["solid", format!("{BASE}/")]);
        assert!(!auth.is_lws_candidate(&kit.sign(&at_header(), &c)));
        assert!(!auth.is_lws_candidate("opaque-token"));
    }

    #[test]
    fn challenge_and_metadata_shape() {
        let kit = Kit::generate();
        let auth = auth_with(&kit, false);
        // Anonymous challenge: realm + resource_metadata, NO error param (RFC 6750 §3.1).
        let anon = auth.challenge_header_value(false).to_str().unwrap();
        assert_eq!(
            anon,
            "Bearer realm=\"https://storage.example/\", \
             resource_metadata=\"https://storage.example/.well-known/oauth-protected-resource\""
        );
        // Presented-token challenge adds error="invalid_token".
        let inv = auth.challenge_header_value(true).to_str().unwrap();
        assert!(inv.starts_with(anon));
        assert!(inv.ends_with(", error=\"invalid_token\""));
        // Metadata extension: authorization_servers + jlws_storage_description + honest PoP member.
        let mut doc = json!({ "resource": BASE, "dpop_bound_access_tokens_required": true });
        auth.extend_protected_resource_metadata(&mut doc);
        assert_eq!(doc["authorization_servers"], json!([ISSUER]));
        assert_eq!(
            doc[PRM_STORAGE_DESCRIPTION_MEMBER],
            json!("https://storage.example/.well-known/lws")
        );
        assert_eq!(doc["dpop_bound_access_tokens_required"], json!(false));
    }

    #[test]
    fn constructor_and_env_guards() {
        let jwks: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider::new());
        assert!(LwsBearerAuth::new(jwks.clone(), vec![], BASE, false).is_err());
        assert!(LwsBearerAuth::new(jwks.clone(), vec!["  ".into()], BASE, false).is_err());
        // TTL clamp: never past the spec's one-hour MUST, never zero/negative.
        let a = LwsBearerAuth::new(jwks.clone(), vec![ISSUER.into()], BASE, false)
            .unwrap()
            .with_max_token_ttl(86_400);
        assert_eq!(a.max_token_ttl_secs, SPEC_MAX_TOKEN_TTL_SECS);
        let a = LwsBearerAuth::new(jwks, vec![ISSUER.into()], BASE, false)
            .unwrap()
            .with_max_token_ttl(0);
        assert_eq!(a.max_token_ttl_secs, 1);
    }
}
