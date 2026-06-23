// AUTHORED-BY Claude Opus 4.8
//! DPoP-bound Solid-OIDC authentication middleware.
//!
//! Auth is **delegated** to the standalone
//! [`solid-oidc-verifier`](https://github.com/jeswr/solid-oidc-verifier) crate — this server does
//! **not** reimplement token/DPoP verification (the spike's load-bearing rule R1). This middleware
//! is the thin axum adapter: it reconstructs the verifier's [`AuthRequest`] from the HTTP request,
//! calls [`Verifier::verify`], and either injects the [`VerifiedToken`] into request extensions for
//! downstream handlers or returns the verifier's own status + `WWW-Authenticate` challenge unchanged.
//!
//! The error contract (401 invalid_token / 503 replay-store-unavailable / the challenge string) is
//! owned entirely by the verifier — this layer never re-derives it. An absent `Authorization` header
//! yields the verifier's public/unauthenticated [`VerifiedToken`] (the LDP layer then enforces that
//! public credentials reach only public resources — M2's WAC step).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use solid_oidc_verifier::config::JwksProvider;
use solid_oidc_verifier::error::{ErrorKind, VerifyError};
use solid_oidc_verifier::replay::ReplayStore;
use solid_oidc_verifier::verifier::{AuthRequest, Verifier};

pub use solid_oidc_verifier::verifier::VerifiedToken;

use crate::auth_cache::{CacheDecision, VerifiedTokenCache};
use crate::error::ServerError;
use crate::ldp::target::parse_target;

/// Everything the auth layer needs: the verifier and the server's public base URL.
///
/// Generic over the verifier's [`JwksProvider`] + [`ReplayStore`] seams so M1 can use the in-memory
/// `StaticJwksProvider` + `InMemoryReplayStore` test doubles, and M2 can swap in the
/// network-backed JWKS (OIDC discovery) + a shared (Redis) replay store with no change here.
pub struct AuthContext<J: JwksProvider, R: ReplayStore> {
    pub verifier: Verifier<J, R>,
    /// The server's public origin (no trailing slash), used to reconstruct the DPoP `htu`.
    pub base_url: String,
    /// The round-3 verified-access-token cache (default-on; see [`crate::auth_cache`]). `None` =>
    /// every authenticated request runs the verifier's full `verify()` (the pre-round-3 behaviour).
    ///
    /// When `Some`, the cache + `replay` MUST share the SAME replay store the `verifier` holds -- the
    /// hit path marks the proof `jti` through `replay`, so it must be the verifier's store or a
    /// replay used on the miss path could be replayed on the hit path. The server wires this by
    /// building one `Arc<InMemoryReplayStore>`, giving the verifier `SharedReplay<_>` over it and the
    /// cache a clone of the same `Arc`. This `replay` handle is exactly that clone.
    cache: Option<TokenCache<R>>,
}

/// The token cache + the shared replay handle it marks `jti`s through (the SAME store the verifier
/// uses). Bundled so they cannot be wired independently (which would split the replay set).
struct TokenCache<R: ReplayStore> {
    cache: VerifiedTokenCache,
    replay: Arc<R>,
}

impl<J: JwksProvider, R: ReplayStore> AuthContext<J, R> {
    /// Construct WITHOUT the verified-token cache -- every authenticated request runs the full verifier
    /// (the pre-round-3 path). Used where no shared replay handle is available (e.g. unit harnesses).
    pub fn new(verifier: Verifier<J, R>, base_url: impl Into<String>) -> Self {
        Self {
            verifier,
            base_url: base_url.into(),
            cache: None,
        }
    }

    /// Construct WITH the round-3 verified-access-token cache. `replay` MUST be a clone of the `Arc`
    /// the `verifier`'s `SharedReplay` wraps (so the hit + miss paths mark the SAME jti set -- the
    /// replay-bypass guard). See [`crate::auth_cache`].
    pub fn with_cache(
        verifier: Verifier<J, R>,
        base_url: impl Into<String>,
        cache: VerifiedTokenCache,
        replay: Arc<R>,
    ) -> Self {
        Self {
            verifier,
            base_url: base_url.into(),
            cache: Some(TokenCache { cache, replay }),
        }
    }

    /// Verify the request and return the caller's [`VerifiedToken`] (possibly public), or the
    /// verifier's error mapped onto a [`ServerError::Unauthorized`] (carrying its status + challenge).
    ///
    /// ## Round-3 verified-access-token cache (when enabled via [`with_cache`](Self::with_cache))
    /// For a `DPoP <token>` request, the cache may already hold the verified result of THIS token.
    /// On a cache HIT the access-token signature + RFC-9068 claims are NOT re-verified (the saving),
    /// but the FRESH DPoP proof + `jti` replay + `cnf.jkt` binding ARE fully verified for this request
    /// (the cache cannot turn a failing proof into a success). On a MISS (or any non-DPoP request) the
    /// full verifier runs, and a successful DPoP-bound result is inserted for the token's `exp` window.
    /// Disabling the cache is byte-identical to the pre-round-3 path.
    pub fn authenticate(
        &self,
        authorization: Option<String>,
        dpop: Option<String>,
        method: &str,
        path: &str,
    ) -> Result<VerifiedToken, ServerError> {
        // Reconstruct the htu the verifier checks the DPoP proof against. A bad target is a 400
        // before we even reach the verifier (it would otherwise reject on htu mismatch as a 401).
        let target = parse_target(&self.base_url, path)?;
        let method_uc = method.to_ascii_uppercase();

        // Cache fast-path: ONLY for a `DPoP <token>` request (the production posture). Everything else
        // -- absent auth (public), Bearer, or an unparseable header -- goes straight to the verifier,
        // which owns those decisions. We extract the bearer token string purely as the cache key + the
        // `ath` input; the verifier remains the sole authority on a miss.
        //
        // Extract the access token as an OWNED `String` (not a borrow of `authorization`) so that on a
        // MISS we can still move `authorization` into the verifier's `AuthRequest` while using the
        // token string for the cache `insert`. The clone is one small string per cache-eligible request
        // -- negligible against the ES256 verify a hit saves, and only paid when the cache is enabled.
        let cache_token: Option<String> = self.cache.as_ref().and(
            authorization
                .as_deref()
                .and_then(dpop_scheme_access_token)
                .map(str::to_string),
        );
        if let (Some(tc), Some(access_token)) = (self.cache.as_ref(), cache_token.as_deref()) {
            match tc.cache.authenticate(
                access_token,
                dpop.as_deref(),
                &method_uc,
                &target.htu,
                now_secs(),
                tc.replay.as_ref(),
            ) {
                CacheDecision::Verified(token) => return Ok(token),
                CacheDecision::Reject(e) => {
                    return Err(ServerError::Unauthorized {
                        status: e.status(),
                        message: e.message().to_string(),
                        www_authenticate: self.verifier.www_authenticate(&e),
                    })
                }
                // Fall through to the full verifier; on success, populate the cache.
                CacheDecision::Miss => {
                    let req = AuthRequest {
                        authorization,
                        dpop,
                        method: method_uc,
                        url: target.htu,
                    };
                    let token =
                        self.verifier
                            .verify(&req)
                            .map_err(|e| ServerError::Unauthorized {
                                status: e.status(),
                                message: e.message().to_string(),
                                www_authenticate: self.verifier.www_authenticate(&e),
                            })?;
                    // Only a SUCCESSFUL full verification reaches here => safe to cache. A non-DPoP-bound
                    // token (no cnf.jkt/exp) is silently not cached by `insert`.
                    tc.cache.insert(access_token, &token, now_secs());
                    return Ok(token);
                }
            }
        }

        // No cache (or a non-DPoP request): the full verifier owns the decision.
        let req = AuthRequest {
            authorization,
            dpop,
            method: method_uc,
            url: target.htu,
        };
        self.verifier
            .verify(&req)
            .map_err(|e| ServerError::Unauthorized {
                status: e.status(),
                message: e.message().to_string(),
                www_authenticate: self.verifier.www_authenticate(&e),
            })
    }

    /// Build the 401 + `WWW-Authenticate` challenge for a request that REQUIRES authentication but
    /// arrived without credentials (a public [`VerifiedToken`]).
    ///
    /// The verifier returns a *public* token (not an error) when no `Authorization` header is present
    /// — that is correct for the auth layer (an anonymous request is a valid, public identity). The
    /// LDP layer then decides whether the target needs auth; when it does and the caller is public, it
    /// must answer 401 with a challenge (Solid Protocol / RFC 6750), NOT a bare 403. This synthesises
    /// the SAME challenge string the verifier emits on a token failure (it names the trusted issuer(s)
    /// and DPoP `algs`), so a client knows where to obtain a token. We route it through the verifier's
    /// own [`Verifier::www_authenticate`] so the challenge format stays single-sourced in the verifier.
    pub fn unauthenticated_error(&self) -> ServerError {
        ServerError::Unauthorized {
            status: 401,
            message: "Authentication required for this resource.".to_string(),
            www_authenticate: self.unauthenticated_challenge(),
        }
    }

    /// The `WWW-Authenticate` challenge string for an anonymous request to a resource that requires
    /// authentication. Single-sourced through the verifier's own challenge builder so the format
    /// (scheme, `error=`, `issuer=`, `algs=`) matches every other challenge this server emits. The LDP
    /// layer caches this once (it does not vary per request) and attaches it to a 401.
    pub fn unauthenticated_challenge(&self) -> String {
        // An `invalid_token` DPoP-scheme error is the canonical "you need a (DPoP-bound) token" signal;
        // `www_authenticate` widens it to `DPoP` + `algs` per the verifier's require_dpop policy.
        let err = VerifyError::new(
            ErrorKind::InvalidToken,
            "Authentication required for this resource.",
        )
        .with_dpop(true);
        self.verifier.www_authenticate(&err)
    }
}

/// An axum middleware layer that authenticates the request and inserts the [`VerifiedToken`] into
/// request extensions. Handlers read it with `Extension<VerifiedToken>`.
///
/// `State` is an `Arc<AuthContext<_, _>>` so the verifier is shared across requests without cloning.
pub async fn auth_middleware<J, R>(
    State(ctx): State<Arc<AuthContext<J, R>>>,
    mut req: Request,
    next: Next,
) -> Response
where
    J: JwksProvider + Send + Sync + 'static,
    R: ReplayStore + Send + Sync + 'static,
{
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    // Distinguish an ABSENT auth header (⇒ public) from one that is PRESENT but unparseable
    // (non-UTF-8 bytes). A present-but-invalid credential must NOT be silently downgraded to public
    // access — that is a fail-open. Reject it as a 400.
    let authorization = match header_string(&req, axum::http::header::AUTHORIZATION) {
        Ok(v) => v,
        Err(()) => {
            return ServerError::BadRequest("malformed Authorization header".into()).into_response()
        }
    };
    // DPoP is a custom header; look it up by its lowercase name.
    let dpop = match header_string(&req, axum::http::HeaderName::from_static("dpop")) {
        Ok(v) => v,
        Err(()) => return ServerError::BadRequest("malformed DPoP header".into()).into_response(),
    };

    match ctx.authenticate(authorization, dpop, &method, &path) {
        Ok(token) => {
            req.extensions_mut().insert(token);
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

/// Read a header as a `String`. `Ok(None)` = absent; `Ok(Some(_))` = a valid value; `Err(())` =
/// present but not valid UTF-8 (a malformed value that must be rejected, never treated as absent).
fn header_string(req: &Request, name: axum::http::HeaderName) -> Result<Option<String>, ()> {
    match req.headers().get(&name) {
        None => Ok(None),
        Some(value) => value.to_str().map(|s| Some(s.to_string())).map_err(|_| ()),
    }
}

/// Extract the access-token string from a `DPoP <token>` Authorization header, returning `None` for
/// any other scheme (Bearer, etc.) or a malformed/empty header.
///
/// This MUST parse the header EXACTLY as the verifier's own `parse_authorization` does -- trim the
/// header, split on the FIRST space, lowercase the scheme, trim the token -- so the cache key is the
/// byte-identical token the verifier verifies on a miss (a divergent parse could key the cache by a
/// different string than the one verified, splitting the cache or, worse, reusing a verification for a
/// token that was never verified). It is consulted ONLY for the cache fast-path; the verifier remains
/// the sole authority on every miss, so this never makes a security decision on its own.
fn dpop_scheme_access_token(header: &str) -> Option<&str> {
    let trimmed = header.trim();
    let sp = trimmed.find(' ')?;
    let scheme = &trimmed[..sp];
    if !scheme.eq_ignore_ascii_case("dpop") {
        return None;
    }
    let token = trimmed[sp + 1..].trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Current UNIX time in seconds (the cache's `now` for token-`exp` + proof-`iat` checks). Matches the
/// verifier's internal clock.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::dpop_scheme_access_token;

    #[test]
    fn extracts_dpop_token_only() {
        assert_eq!(
            dpop_scheme_access_token("DPoP abc.def.ghi"),
            Some("abc.def.ghi")
        );
        // Case-insensitive scheme, trims surrounding + inter-token whitespace exactly like the verifier.
        assert_eq!(dpop_scheme_access_token("  dpop   tok  "), Some("tok"));
        // Non-DPoP schemes are not cache-eligible (verifier decides).
        assert_eq!(dpop_scheme_access_token("Bearer tok"), None);
        // Malformed / empty.
        assert_eq!(dpop_scheme_access_token("DPoP"), None);
        assert_eq!(dpop_scheme_access_token("DPoP "), None);
        assert_eq!(dpop_scheme_access_token(""), None);
    }
}
