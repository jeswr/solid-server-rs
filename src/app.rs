// AUTHORED-BY Claude Opus 4.8
//! Application assembly — wires the auth middleware over the LDP routes.
//!
//! [`build_router`] is generic over the verifier seams and the store seam so the same wiring serves
//! both the M1 in-memory test stack and (M2) the network-backed production stack. The auth layer
//! runs OUTERMOST on the protected routes: a request is authenticated (injecting a [`VerifiedToken`])
//! before it reaches an LDP handler.
//!
//! M2 adds the tower-http middleware stack (CORS, security headers, request-id, trace, body-limit,
//! timeout, rate-limit, load-shed — spike §4) around this, plus the discovery + notification routes.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use solid_oidc_verifier::config::JwksProvider;
use solid_oidc_verifier::replay::ReplayStore;

use crate::auth::{auth_middleware, AuthContext};
use crate::ldp::handler::{get_handler, head_handler, put_handler, LdpState};
use crate::store::Store;

/// The assembled application state — the auth context + the LDP state, each behind an [`Arc`].
pub struct AppState<J: JwksProvider, R: ReplayStore, S: Store> {
    pub auth: Arc<AuthContext<J, R>>,
    pub ldp: Arc<LdpState<S>>,
}

impl<J, R, S> AppState<J, R, S>
where
    J: JwksProvider,
    R: ReplayStore,
    S: Store,
{
    pub fn new(auth: AuthContext<J, R>, ldp: LdpState<S>) -> Self {
        Self {
            auth: Arc::new(auth),
            ldp: Arc::new(ldp),
        }
    }
}

/// Build the axum router: the LDP single-resource routes (GET/HEAD/PUT), wrapped by the DPoP auth
/// middleware. A wildcard path captures the resource target; the handler re-parses it against the
/// base URL.
pub fn build_router<J, R, S>(state: AppState<J, R, S>) -> Router
where
    J: JwksProvider + Send + Sync + 'static,
    R: ReplayStore + Send + Sync + 'static,
    S: Store + 'static,
{
    let AppState { auth, ldp } = state;

    // The protected LDP routes carry the LDP state.
    let protected = Router::new()
        .route(
            "/{*path}",
            get(get_handler::<S>)
                .head(head_handler::<S>)
                .put(put_handler::<S>),
        )
        // The auth middleware carries the AuthContext as ITS state; it runs before the handler and
        // injects the VerifiedToken into request extensions.
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            auth_middleware::<J, R>,
        ))
        .with_state(ldp);

    Router::new().merge(protected)
}
