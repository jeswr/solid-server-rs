// AUTHORED-BY Claude Fable 5
//! **JLWSC-HG-5 / D17 — problem details on every error response (flag-gated).**
//!
//! The JLWS core spec (`jeswr/lws-spec` `index.html` §http-general, statement JLWSC-HG-5) requires:
//! "All 4xx and 5xx responses MUST carry an RFC 9457 problem details body
//! (`application/problem+json`), except where HTTP semantics do not permit response content."
//! The LWS code paths already mint their fixed-registry problems ([`crate::error::ServerError::LwsProblem`],
//! D17), but the GENERIC `ServerError` responses (404, 401, 409, …) — shared with the flag-off
//! Solid surface — are short `text/plain` bodies. This middleware closes that gap **only when the
//! LWS surface is enabled**: it is applied by the router builders iff `LdpState::lws()` is `Some`,
//! so the flag-off response bytes are byte-identical to pre-LWS (the flag-off invariance rule).
//!
//! Behaviour:
//! - Non-error responses (1xx–3xx) pass through untouched.
//! - **HEAD carve-out** (the statement's "except where HTTP semantics do not permit response
//!   content"): a HEAD response passes through untouched — its error metadata mirrors the GET's
//!   headers (RFC 9110 §9.3.2) and it carries no content to replace.
//! - A response that is **already `application/problem+json`** (the D17 fixed-registry problems)
//!   passes through untouched — which also makes the mapping idempotent if it is ever layered
//!   twice.
//! - Everything else with a 4xx/5xx status has its entity swapped for the fixed RFC 9457 shape
//!   `{"type":"about:blank","title":<canonical reason phrase>,"status":<code>}` — exactly RFC 9457
//!   §4.2.1's rule for a problem that adds no semantics beyond the status code. **Nothing
//!   request-derived rides in the body** (the non-leaky-errors rule holds), and **all headers are
//!   preserved** (`WWW-Authenticate`, `Allow`, `Accept-Post`/`Accept-Patch`, `Retry-After`, the
//!   CORS set) — only the entity and its `Content-Type`/`Content-Length` change.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;

/// Response-mapping middleware: give every content-bearing 4xx/5xx an RFC 9457
/// `application/problem+json` body. Applied by the router builders ONLY when the LWS surface is
/// enabled — see the module docs for the carve-outs and invariance argument.
pub async fn problem_details_middleware(req: Request, next: Next) -> Response {
    let is_head = req.method() == Method::HEAD;
    let resp = next.run(req).await;
    let status = resp.status();
    if is_head || !(status.is_client_error() || status.is_server_error()) {
        return resp;
    }
    let already_problem = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.trim_start()
                .to_ascii_lowercase()
                .starts_with("application/problem+json")
        })
        .unwrap_or(false);
    if already_problem {
        return resp;
    }
    let (mut parts, _discarded_generic_body) = resp.into_parts();
    // RFC 9457 §4.2.1: `about:blank` + title = the status code's reason phrase, for a problem
    // with no semantics beyond the code itself. Fixed strings only — never request-derived.
    let title = status.canonical_reason().unwrap_or("error");
    let body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
    });
    // The old entity's framing headers no longer apply; hyper recomputes Content-Length.
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    Response::from_parts(parts, Body::from(body.to_string()))
}
