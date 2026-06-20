// AUTHORED-BY Claude Opus 4.8
//! The LDP request handlers — the M1 slice: GET / HEAD / PUT on a single resource.
//!
//! These are the axum handlers over the [`Store`] seam. They are deliberately thin: target parsing
//! ([`crate::ldp::target`]) and content-type handling ([`crate::ldp::content`]) are pure modules, so
//! the handler is just the HTTP glue + the store call.
//!
//! M2 plugs in here: POST (container-creating slug logic), DELETE, PATCH (the N3-Patch engine),
//! Range + conditional requests (If-None-Match/If-Match CAS over the ETag), and full conneg.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;

use crate::auth::VerifiedToken;
use crate::error::ServerError;
use crate::ldp::content::{classify, validate_rdf};
use crate::ldp::target::parse_target;
use crate::store::Store;

/// Shared state for the LDP handlers: the store + the server's public base URL.
pub struct LdpState<S: Store> {
    pub store: S,
    pub base_url: String,
}

impl<S: Store> LdpState<S> {
    pub fn new(store: S, base_url: impl Into<String>) -> Self {
        Self {
            store,
            base_url: base_url.into(),
        }
    }
}

/// `GET /{path}` — read a resource's bytes + content type.
///
/// M2: WAC `read` authorization is enforced here once the WAC engine lands; in M1 the resource is
/// returned to any authenticated-or-public caller (no ACLs exist in the slice). The `_token` arg is
/// the seam where that decision plugs in.
pub async fn get_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(_token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
) -> Result<Response, ServerError> {
    let target = parse_target(&state.base_url, uri.path())?;
    let resource = state.store.read(&target.iri).await?;
    let mut headers = HeaderMap::new();
    set_str(
        &mut headers,
        header::CONTENT_TYPE,
        &resource.meta.content_type,
    );
    set_str(&mut headers, header::ETAG, &resource.meta.etag);
    Ok((StatusCode::OK, headers, resource.body).into_response())
}

/// `HEAD /{path}` — the GET response headers without the body.
pub async fn head_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(_token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
) -> Result<Response, ServerError> {
    let target = parse_target(&state.base_url, uri.path())?;
    let resource = state.store.read(&target.iri).await?;
    let mut headers = HeaderMap::new();
    set_str(
        &mut headers,
        header::CONTENT_TYPE,
        &resource.meta.content_type,
    );
    set_str(&mut headers, header::ETAG, &resource.meta.etag);
    set_str(
        &mut headers,
        header::CONTENT_LENGTH,
        &resource.body.len().to_string(),
    );
    // HEAD: status + headers, empty body.
    Ok((StatusCode::OK, headers).into_response())
}

/// `PUT /{path}` — create-or-replace an RDF resource (Turtle / JSON-LD).
///
/// The body is validated as well-formed RDF in the declared content type before storage; an
/// unsupported type is 415, a malformed body is 400. M2 adds the conditional-write CAS
/// (If-None-Match/If-Match) + non-RDF binary resources.
pub async fn put_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(_token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ServerError> {
    let target = parse_target(&state.base_url, uri.path())?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let format = classify(content_type)?;
    // Relative IRIs in the body resolve against the resource's own IRI (the LDP/RDF convention).
    validate_rdf(format, &body, &target.iri)?;

    // Whether this is a create (201) or a replace (200) — the authoritative existence check.
    let existed = state.store.exists(&target.iri).await?;
    let meta = state
        .store
        .write(&target.iri, body, format.media_type())
        .await?;

    let status = if existed {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    let mut out = HeaderMap::new();
    set_str(&mut out, header::ETAG, &meta.etag);
    if !existed {
        set_str(&mut out, header::LOCATION, &target.iri);
    }
    Ok((status, out).into_response())
}

/// Insert a header value, silently skipping a value that cannot be encoded (never panics).
fn set_str(headers: &mut HeaderMap, name: header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}
