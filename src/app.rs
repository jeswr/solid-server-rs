// AUTHORED-BY Claude Opus 4.8
//! Application assembly — wires the auth middleware over the LDP routes.
//!
//! [`build_router`] is generic over the verifier seams and the store seam so the same wiring serves
//! both the M1 in-memory test stack and (M2) the network-backed production stack. The auth layer
//! runs OUTERMOST on the protected routes: a request is authenticated (injecting a
//! [`VerifiedToken`](crate::auth::VerifiedToken)) before it reaches an LDP handler.
//!
//! M2 adds the tower-http middleware stack (CORS, security headers, request-id, trace, body-limit,
//! timeout, rate-limit, load-shed — spike §4) around this, plus the discovery + notification routes.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use solid_oidc_verifier::config::JwksProvider;
use solid_oidc_verifier::replay::ReplayStore;

use crate::auth::{auth_middleware, AuthContext};
use crate::ldp::cors::cors_middleware;
use crate::ldp::handler::{
    delete_handler, get_handler, head_handler, options_handler, patch_handler, post_handler,
    put_handler, LdpState,
};
use crate::notifications::ws::{
    receive_handler, storage_description_handler, subscribe_handler, NotifyState, RECEIVE_PATH,
    SUBSCRIPTION_PATH, WELL_KNOWN_SOLID_PATH,
};
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
    pub fn new(auth: AuthContext<J, R>, mut ldp: LdpState<S>) -> Self {
        // Single-source the anonymous-401 challenge: derive it from the verifier (it names the trusted
        // issuer(s) + DPoP algs) and hand it to the LDP layer, which has no verifier handle of its own.
        ldp.set_www_authenticate(auth.unauthenticated_challenge());
        Self {
            auth: Arc::new(auth),
            ldp: Arc::new(ldp),
        }
    }
}

/// Build the axum router: the LDP routes (GET/HEAD/PUT/POST/DELETE/PATCH) + the WebSocketChannel2023
/// notification routes, wrapped by the DPoP auth middleware. A wildcard path captures the resource
/// target; the handler re-parses it against the base URL.
///
/// ## Route precedence (load-bearing)
/// The notification routes use STATIC paths (`/.notifications/…`, `/.well-known/solid`), which axum
/// matches BEFORE the LDP `/{*path}` wildcard — so they intercept correctly without the wildcard
/// shadowing them. They are registered as their own sub-routers carrying [`NotifyState`].
///
/// ## Auth split on the notification surface
/// - `POST /.notifications/WebSocketChannel2023/` is AUTH-GATED (same DPoP middleware as the LDP
///   routes) so it sees a [`VerifiedToken`] and can fail-closed on an anonymous caller.
/// - `GET …/receive` (the WS upgrade) and `GET /.well-known/solid` (discovery) are PUBLIC: a browser
///   WebSocket cannot carry the DPoP header, and discovery is public like a storage description. The
///   receive-token + per-resource WAC seam (`sparq#992`) is documented in `notifications::ws`.
pub fn build_router<J, R, S>(state: AppState<J, R, S>) -> Router
where
    J: JwksProvider + Send + Sync + 'static,
    R: ReplayStore + Send + Sync + 'static,
    S: Store + 'static,
{
    let AppState { auth, ldp } = state;

    // The notification state shares the LDP state's hub + base URL, so a subscriber registered via
    // `…/receive` is the same registry the LDP emit path fans to.
    let notify_state = Arc::new(NotifyState::new(
        ldp.notifications.clone(),
        ldp.base_url.clone(),
    ));

    // The full LDP method set, shared by the wildcard `/{*path}` route AND the explicit `/` (root)
    // route. The `/{*path}` wildcard does NOT match the empty path, so the storage root needs its own
    // route with the same handlers (Cluster-A #1) — otherwise `GET /` is a 404.
    let ldp_methods = || {
        get(get_handler::<S>)
            .head(head_handler::<S>)
            .put(put_handler::<S>)
            .post(post_handler::<S>)
            .delete(delete_handler::<S>)
            .patch(patch_handler::<S>)
            // OPTIONS advertises Allow / Accept-Post / Accept-Patch (and rides the CORS preflight).
            .options(options_handler::<S>)
    };

    // The protected LDP routes carry the LDP state.
    //
    // Layer order (axum/tower applies `.layer()` bottom-up, so the LAST one is OUTERMOST = runs
    // first): the CORS layer is OUTERMOST. That means (a) a CORS preflight OPTIONS is answered by the
    // CORS layer BEFORE auth runs (a browser preflight carries no credentials), and (b) the
    // `Access-Control-*` headers ride on EVERY response — the auth 401, the anonymous-read 401, and
    // the success — because they are added on the way back OUT through the outermost layer.
    let protected = Router::new()
        .route("/", ldp_methods())
        .route("/{*path}", ldp_methods())
        // INNER: the auth middleware authenticates a real (non-preflight) request and injects the
        // VerifiedToken into request extensions.
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            auth_middleware::<J, R>,
        ))
        // OUTER: CORS (preflight short-circuit + the Access-Control-* headers on every response).
        .layer(axum::middleware::from_fn(cors_middleware))
        .with_state(ldp);

    // The AUTH-GATED subscribe route: behind the SAME DPoP middleware so the handler sees a
    // VerifiedToken (fail-closed on anonymous).
    let subscribe = Router::new()
        .route(SUBSCRIPTION_PATH, post(subscribe_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            auth_middleware::<J, R>,
        ))
        .with_state(notify_state.clone());

    // The PUBLIC notification routes: the WS receive upgrade + the discovery document (no auth — see
    // the auth-split note above).
    let public_notify = Router::new()
        .route(RECEIVE_PATH, get(receive_handler))
        .route(WELL_KNOWN_SOLID_PATH, get(storage_description_handler))
        .with_state(notify_state);

    Router::new()
        .merge(subscribe)
        .merge(public_notify)
        .merge(protected)
}
