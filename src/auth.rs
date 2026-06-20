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
use solid_oidc_verifier::replay::ReplayStore;
use solid_oidc_verifier::verifier::{AuthRequest, Verifier};

pub use solid_oidc_verifier::verifier::VerifiedToken;

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
}

impl<J: JwksProvider, R: ReplayStore> AuthContext<J, R> {
    pub fn new(verifier: Verifier<J, R>, base_url: impl Into<String>) -> Self {
        Self {
            verifier,
            base_url: base_url.into(),
        }
    }

    /// Verify the request and return the caller's [`VerifiedToken`] (possibly public), or the
    /// verifier's error mapped onto a [`ServerError::Unauthorized`] (carrying its status + challenge).
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
        let req = AuthRequest {
            authorization,
            dpop,
            method: method.to_ascii_uppercase(),
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
