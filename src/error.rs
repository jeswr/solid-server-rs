// AUTHORED-BY Claude Opus 4.8
//! The server's error type and its mapping onto HTTP status codes.
//!
//! Auth failures carry the verifier's own status + `WWW-Authenticate` challenge through unchanged
//! (the verifier owns the auth error contract — RFC 6750/9449); the rest are the LDP/store errors.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// The crate-wide result alias.
pub type ServerResult<T> = Result<T, ServerError>;

/// A server error, mapped to an HTTP status in [`IntoResponse`].
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The target URL could not be parsed / is not a valid LDP target.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// An authentication failure surfaced from the verifier. Carries the exact status the verifier
    /// chose (401 / 503) and the `WWW-Authenticate` challenge value, so the auth error contract is
    /// owned by the verifier, not re-derived here.
    #[error("unauthorized: {message}")]
    Unauthorized {
        status: u16,
        message: String,
        www_authenticate: String,
    },

    /// The caller is authenticated but not permitted.
    ///
    /// M2: this is produced by the full WAC engine once it lands; the M1 slice never authorizes
    /// beyond authentication, so this is here for the seam, not yet emitted on a real ACL decision.
    #[error("forbidden")]
    Forbidden,

    /// The requested resource does not exist (per SPARQ, the authoritative index).
    #[error("not found")]
    NotFound,

    /// A request that conflicts with the current state of the target — e.g. DELETE of a non-empty
    /// container, or a PUT whose path collides with an existing resource of the opposite slash-kind.
    #[error("conflict: {0}")]
    Conflict(String),

    /// The method is not allowed on this target — e.g. POST to a plain (non-container) resource. Maps
    /// to 405 Method Not Allowed (RFC 9110 §15.5.6).
    #[error("method not allowed")]
    MethodNotAllowed,

    /// A conditional request's precondition (`If-Match` / `If-None-Match`) was not met (RFC 9110
    /// §13). A failed `If-None-Match: *` create-guard, or an `If-Match` ETag mismatch, maps here.
    #[error("precondition failed")]
    PreconditionFailed,

    /// A `Range` request whose range(s) cannot be satisfied for the resource (RFC 9110 §15.5.17).
    #[error("range not satisfiable")]
    RangeNotSatisfiable,

    /// No representation acceptable per the request's `Accept` header (RFC 9110 §15.5.7).
    #[error("not acceptable")]
    NotAcceptable,

    /// The PATCH document or media type is unsupported / malformed (RFC 5789 §2.2 → 422 for a
    /// well-formed but unprocessable patch, 415 for an unsupported media type — see [`Self::status`]).
    #[error("unprocessable patch: {0}")]
    UnprocessablePatch(String),

    /// An unsupported or unparseable RDF content type.
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),

    /// An RFC 9457 problem-details error minted by the **flag-gated LWS surface** (`crate::lws`;
    /// DECISIONS.md D17: LWS 4xx responses carry machine-readable problem details). Only LWS code
    /// paths construct this variant, so the flag-off Solid surface's error bytes are unchanged.
    /// `status` is the HTTP status (e.g. 406/409/415/428); `type_uri` is a problem-type URI under
    /// `https://w3id.org/jeswr/lws/problems/`; `title` is the human-readable summary. Both are
    /// `&'static str` — LWS problems are a fixed registry, never request-derived (no leak surface).
    #[error("{title}")]
    LwsProblem {
        status: u16,
        type_uri: &'static str,
        title: &'static str,
    },

    /// A failure in the storage layer (SPARQ index or blob store).
    #[error("storage error: {0}")]
    Storage(String),
}

impl ServerError {
    /// The HTTP status this error maps to.
    pub fn status(&self) -> StatusCode {
        match self {
            ServerError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ServerError::Unauthorized { status, .. } => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::UNAUTHORIZED)
            }
            ServerError::Forbidden => StatusCode::FORBIDDEN,
            ServerError::NotFound => StatusCode::NOT_FOUND,
            ServerError::Conflict(_) => StatusCode::CONFLICT,
            ServerError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ServerError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            ServerError::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
            ServerError::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            ServerError::UnprocessablePatch(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ServerError::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ServerError::LwsProblem { status, .. } => {
                // The status is one of the fixed registry values the LWS code paths mint; an
                // out-of-range value (unreachable) falls back to 400 rather than panicking.
                StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_REQUEST)
            }
            ServerError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = self.status();
        // LWS problem details (D17): an `application/problem+json` body carrying the fixed
        // registry `type` + `title` + `status`. Flag-gated paths only — see the variant doc.
        if let ServerError::LwsProblem {
            status: s,
            type_uri,
            title,
        } = self
        {
            let body = serde_json::json!({
                "type": type_uri,
                "title": title,
                "status": s,
            });
            let mut resp = (status, body.to_string()).into_response();
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/problem+json"),
            );
            return resp;
        }
        // Preserve the verifier's WWW-Authenticate challenge on auth failures (RFC 6750 §3).
        if let ServerError::Unauthorized {
            ref www_authenticate,
            ..
        } = self
        {
            let mut resp = (status, "unauthorized").into_response();
            if let Ok(value) = www_authenticate.parse() {
                resp.headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
            return resp;
        }
        // Non-leaky bodies: never echo internal detail to the client (spike §8 — non-leaky errors).
        let public_body = match status {
            StatusCode::INTERNAL_SERVER_ERROR => "internal server error",
            StatusCode::NOT_FOUND => "not found",
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::METHOD_NOT_ALLOWED => "method not allowed",
            StatusCode::CONFLICT => "conflict",
            StatusCode::PRECONDITION_FAILED => "precondition failed",
            StatusCode::RANGE_NOT_SATISFIABLE => "range not satisfiable",
            StatusCode::NOT_ACCEPTABLE => "not acceptable",
            StatusCode::UNPROCESSABLE_ENTITY => "unprocessable entity",
            StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported media type",
            _ => "bad request",
        };
        (status, public_body).into_response()
    }
}
