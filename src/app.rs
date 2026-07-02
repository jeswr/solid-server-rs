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
//!
//! ## Overload protection (admission control + timeout) — the layer ORDER is security-critical
//! [`build_router_with_overload`] wraps the application routes with two overload layers (the
//! [`crate::overload`] backpressure layer):
//! - the **admission-control** middleware ([`crate::overload::admission_middleware`]) is the
//!   **OUTERMOST** layer — it sheds excess load (503 + jittered `Retry-After`) BEFORE auth/WAC/storage
//!   ever run, so a shed request can never bypass authorization (it gets strictly LESS than it would
//!   otherwise — a 503), and the expensive DPoP crypto is never spent on a request about to be
//!   rejected; and
//! - a **request timeout** layer (504 on a stuck request) just inside it.
//!
//! The **health/readiness routes are mounted OUTSIDE these layers** (their own router, merged last)
//! so a load balancer's readiness probe is NEVER shed or timed out — shedding a healthy instance's
//! probe would make the LB pull it, amplifying an overload into an outage.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use solid_oidc_verifier::config::JwksProvider;
use solid_oidc_verifier::replay::ReplayStore;
use tower_http::timeout::TimeoutLayer;

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
use crate::overload::{admission_middleware, AdmissionControl};
use crate::rate_limit::{rate_limit_middleware, RateLimiter};
use crate::store::Store;

/// Path of the liveness probe (process is up). Exempt from admission control + timeout.
pub const LIVEZ_PATH: &str = "/livez";
/// Path of the readiness probe (process is ready to serve). Exempt from admission control + timeout.
pub const READYZ_PATH: &str = "/readyz";

/// Overload-protection configuration for [`build_router_with_overload`]: the admission-control state
/// (the concurrency ceiling + metrics) and the optional per-request timeout. `None` timeout disables
/// the timeout layer.
#[derive(Clone)]
pub struct OverloadConfig {
    /// The admission-control state (concurrency ceiling + in-flight/shed metrics).
    pub admission: AdmissionControl,
    /// The per-request timeout (504 on expiry). `None` ⇒ no timeout layer.
    pub request_timeout: Option<Duration>,
    /// The pre-crypto per-IP rate limiter (429 before auth/crypto on a per-source flood). `None` ⇒ no
    /// rate-limit layer (the `off` sentinel). When present it is the OUTERMOST application layer — see
    /// [`build_router_with_overload`].
    pub rate_limiter: Option<RateLimiter>,
}

impl OverloadConfig {
    /// A config with admission control sized to `max_concurrency` and the given timeout, and NO rate
    /// limiter (back-compat for callers/tests that don't exercise the rate-limit layer).
    pub fn new(max_concurrency: usize, request_timeout: Option<Duration>) -> Self {
        Self {
            admission: AdmissionControl::new(max_concurrency),
            request_timeout,
            rate_limiter: None,
        }
    }
}

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
///
/// This is the no-overload-layer build (the existing default, used by the unit/integration tests). The
/// binary uses [`build_router_with_overload`] to add admission control + a request timeout. The two
/// share the route assembly via a private `build_app_routes` helper; this fn just merges those routes
/// + the (always overload-exempt) health routes with no extra layers.
pub fn build_router<J, R, S>(state: AppState<J, R, S>) -> Router
where
    J: JwksProvider + Send + Sync + 'static,
    R: ReplayStore + Send + Sync + 'static,
    S: Store + 'static,
{
    build_app_routes(state).merge(health_routes())
}

/// Build the router WITH overload protection (the binary's path): admission control (load shedding)
/// as the OUTERMOST layer + an optional request timeout just inside it, wrapping the application
/// routes — but NOT the health routes, which are merged OUTSIDE the layers so a load balancer's
/// readiness probe is never shed/timed-out. See the module's "Overload protection" note for why the
/// layer order is security-critical (a shed request 503s before auth/WAC/storage — never a bypass).
pub fn build_router_with_overload<J, R, S>(
    state: AppState<J, R, S>,
    overload: OverloadConfig,
) -> Router
where
    J: JwksProvider + Send + Sync + 'static,
    R: ReplayStore + Send + Sync + 'static,
    S: Store + 'static,
{
    let mut app = build_app_routes(state);

    // INNER: the request timeout (504 on a stuck request) — applied first so it is INSIDE admission
    // control (a timed-out request still holds its admission permit until it times out; that is
    // correct — the permit models a genuinely in-flight request).
    if let Some(timeout) = overload.request_timeout {
        // tower-http's TimeoutLayer returns a 408 by default; we want 503-family semantics for a
        // server-side stuck request, so use 504 GATEWAY_TIMEOUT (the request did not complete in time).
        app = app.layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            timeout,
        ));
    }

    // ADMISSION: admission control. Sheds (503 + jittered Retry-After) before auth/WAC/storage when at
    // capacity. Applied here so it is OUTSIDE auth but INSIDE the rate limiter (below). Security-
    // critical that this is outside the inner stack (see module docs): a shed request never reaches it,
    // so it can never bypass authorization.
    let mut app = app.layer(axum::middleware::from_fn_with_state(
        overload.admission,
        admission_middleware,
    ));

    // OUTERMOST: the pre-crypto per-IP rate limiter. Applied LAST, so (axum applies layers bottom-up)
    // it is the OUTERMOST application layer — it runs FIRST on every request, BEFORE admission control,
    // auth, WAC, and the expensive DPoP crypto. A per-source flood gets a cheap 429 and NEVER reaches
    // the verifier, so attacker traffic cannot make every bogus proof pay the ES256 verify cost.
    //
    // 🔒 Security: this layer ONLY rejects earlier. A 429 is strictly LESS access than auth would
    // grant, so it can never be a bypass; the limiter has zero authority to ADMIT a request (a
    // limiter bug/missing-ConnectInfo FAILS OPEN to the normal auth stack, which still gates it — see
    // `rate_limit`). It wraps the APP routes only — health routes are added OUTSIDE it (below), and
    // the middleware also skips /livez + /readyz by path as defence-in-depth.
    if let Some(rate_limiter) = overload.rate_limiter {
        app = app.layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ));
    }

    // Health routes are OUTSIDE the overload + rate-limit layers (merged last) — never shed, timed-out,
    // or rate-limited.
    app.merge(health_routes())
}

/// The application routes (LDP + notifications), WITHOUT the overload layers or the health routes —
/// the shared core of [`build_router`] and [`build_router_with_overload`].
fn build_app_routes<J, R, S>(state: AppState<J, R, S>) -> Router
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
        ldp.base_url().to_string(),
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
        // INNERMOST: the auth middleware authenticates a real (non-preflight) request and injects the
        // VerifiedToken into request extensions.
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            auth_middleware::<J, R>,
        ))
        // PRE-CRYPTO PUBLIC-READ SKIP (skip-crypto opt 3, `decisions/0002`): a cheap, identity-
        // independent fast-path BEFORE crypto, in the SAME slot as the rate-limit / overload layers —
        // just INSIDE CORS, just OUTSIDE auth. For a GET/HEAD that carries NO `Authorization`/`DPoP`
        // header it constructs a public token and delegates STRAIGHT to the same `serve_read` the
        // handler uses (one anonymous WAC pass): a PUBLIC read → 200, an anonymous denial → the same
        // 401 + challenge, a malformed target → the canonical 400 — all byte-identical to the full
        // anonymous path. A CREDENTIALED request (Authorization OR DPoP header present), a mutation, or
        // any other verb FALLS THROUGH (`next.run`) to the unchanged auth path. It carries the LDP
        // state (store + base + ACL cache) so the served read uses the SAME `serve_read`.
        // Security-critical (see `crate::ldp::public_read_skip`): it NEVER handles a credentialed
        // request (so an authenticated owner's WAC-Allow user= modes are correct and a forged proof is
        // rejected, not served), NEVER fires for a mutation, and NEVER reads the unverified WebID.
        .layer(axum::middleware::from_fn_with_state(
            ldp.clone(),
            crate::ldp::public_read_skip::public_read_skip_middleware::<S>,
        ))
        // OUTERMOST: CORS (preflight short-circuit + the Access-Control-* headers on every response).
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

/// The health/readiness routes: `GET /livez` (process up) + `GET /readyz` (ready to serve). Both are
/// cheap, public, and ALWAYS overload-EXEMPT (merged outside the admission/timeout layers), so a load
/// balancer's probe is never shed/timed-out — shedding a healthy instance's readiness probe would make
/// the LB pull a still-good node and amplify an overload into an outage.
///
/// `/livez` and `/readyz` return 200 + a tiny `text/plain` body. They are deliberately NOT auth-gated
/// (a probe carries no credentials) and expose no state. They are kept distinct so an operator can map
/// them to a k8s `livenessProbe` vs `readinessProbe`: today both are a static "the process is up";
/// `/readyz` is the seam to add a real backend-reachability check (SPARQ/S3) when the live store lands
/// — at which point a not-ready instance can 503 its `/readyz` to deregister cleanly behind the LB.
fn health_routes() -> Router {
    Router::new()
        .route(LIVEZ_PATH, get(|| async { (StatusCode::OK, "live\n") }))
        .route(READYZ_PATH, get(|| async { (StatusCode::OK, "ready\n") }))
}
