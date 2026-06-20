// AUTHORED-BY Claude Opus 4.8
//! The LDP request handlers — GET / HEAD / PUT / POST / DELETE / PATCH over the [`Store`] seam.
//!
//! These are the axum handlers over the [`Store`] seam. They stay thin: target parsing
//! ([`crate::ldp::target`]), content classification + negotiation ([`crate::ldp::content`]),
//! precondition evaluation ([`crate::ldp::conditional`]), range computation ([`crate::ldp::range`]),
//! and the N3-Patch engine ([`crate::ldp::patch`]) are pure modules; the handler is the HTTP glue +
//! the store call.
//!
//! ## The authorization seam (M2-next — fail-closed today)
//!
//! Full WAC authorization needs the SPARQ access-control design, which does not yet exist — so this
//! slice does NOT evaluate ACLs. Reads are served to any caller (no ACLs ⇒ nothing private exists);
//! **mutations (PUT/POST/DELETE/PATCH) require an authenticated caller and are otherwise rejected
//! (403)** — the conservative fail-closed posture (never fail open on a write). The `token` argument
//! on each mutating handler is the seam where the per-resource WAC `write`/`append`/`control`
//! decision plugs in. See `require_authenticated`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;

use crate::auth::VerifiedToken;
use crate::error::ServerError;
use crate::ldp::conditional::{self, evaluate as eval_preconditions};
use crate::ldp::content::{
    classify, negotiate_accept, parse_to_triples, serialize_triples, validate_rdf, RdfFormat,
};
use crate::ldp::patch::{apply_patch, classify_patch_media_type, parse_n3_patch};
use crate::ldp::range::{self, RangeOutcome};
use crate::ldp::target::{parse_target, LdpTarget};
use crate::store::{ResourceMeta, Store};

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

/// `GET /{path}` — read a resource, with `Accept`-driven content negotiation + `Range` support.
///
/// Content negotiation: an RDF resource stored as Turtle is re-serialised to JSON-LD (or vice
/// versa) when the client's `Accept` prefers it; a non-RDF body is served verbatim (its `Accept`
/// is honoured only as `*/*`). `Range: bytes=…` yields a 206 + `Content-Range` (single range), or a
/// 416 when unsatisfiable. Conditional GET preconditions are not applied here (this slice scopes
/// conditional handling to the mutating verbs — see [`conditional`]).
pub async fn get_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(_token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    serve_read::<S>(&state, &uri, &headers, true).await
}

/// `HEAD /{path}` — the GET response headers without the body.
pub async fn head_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(_token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    serve_read::<S>(&state, &uri, &headers, false).await
}

/// Shared GET/HEAD read path. `with_body` distinguishes GET (send bytes) from HEAD (headers only).
async fn serve_read<S: Store>(
    state: &Arc<LdpState<S>>,
    uri: &axum::http::Uri,
    req_headers: &HeaderMap,
    with_body: bool,
) -> Result<Response, ServerError> {
    let target = parse_target(&state.base_url, uri.path())?;
    let resource = state.store.read(&target.iri).await?;

    // Decide the response bytes + content type via content negotiation (RDF only).
    let accept = header_str(req_headers, header::ACCEPT);
    let (body, content_type) = negotiate_body(
        &resource.body,
        &resource.meta.content_type,
        accept,
        &target.iri,
    )?;

    let total_len = body.len() as u64;
    // `Range` is defined for GET (RFC 9110 §14.2); ignore it for HEAD so a HEAD never returns 206.
    let outcome = if with_body {
        range::evaluate(header_str(req_headers, header::RANGE), total_len)
    } else {
        RangeOutcome::Full
    };

    let mut out = HeaderMap::new();
    set_str(&mut out, header::CONTENT_TYPE, &content_type);
    set_str(&mut out, header::ETAG, &resource.meta.etag);
    // Advertise byte-range support (RFC 9110 §14.3).
    set_str(&mut out, header::ACCEPT_RANGES, "bytes");

    match outcome {
        RangeOutcome::Unsatisfiable => {
            // 416 + a Content-Range stating the full length (RFC 9110 §15.5.17). Build the response
            // directly so the Content-Range header rides along (the error type carries only a body).
            set_str(
                &mut out,
                header::CONTENT_RANGE,
                &format!("bytes */{total_len}"),
            );
            Ok((
                StatusCode::RANGE_NOT_SATISFIABLE,
                out,
                "range not satisfiable",
            )
                .into_response())
        }
        RangeOutcome::Satisfied { start, end } => {
            let slice = body.slice(start as usize..=end as usize);
            set_str(
                &mut out,
                header::CONTENT_RANGE,
                &format!("bytes {start}-{end}/{total_len}"),
            );
            set_str(&mut out, header::CONTENT_LENGTH, &slice.len().to_string());
            if with_body {
                Ok((StatusCode::PARTIAL_CONTENT, out, slice).into_response())
            } else {
                Ok((StatusCode::PARTIAL_CONTENT, out).into_response())
            }
        }
        RangeOutcome::Full => {
            set_str(&mut out, header::CONTENT_LENGTH, &total_len.to_string());
            if with_body {
                Ok((StatusCode::OK, out, body).into_response())
            } else {
                Ok((StatusCode::OK, out).into_response())
            }
        }
    }
}

/// `PUT /{path}` — create-or-replace an RDF resource (Turtle / JSON-LD), with conditional-write
/// support (`If-Match` / `If-None-Match`).
///
/// Fail-closed: a mutation from a public caller is a 403 (the WAC seam is M2-next). The body is
/// validated as well-formed RDF in its declared type (415 unsupported / 400 malformed). The
/// `If-None-Match: *` create-guard and `If-Match` overwrite-guard are evaluated against the current
/// ETag (412 on mismatch).
pub async fn put_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ServerError> {
    require_authenticated(&token)?;
    let target = parse_target(&state.base_url, uri.path())?;

    let content_type = header_str(&headers, header::CONTENT_TYPE);
    let format = classify(content_type)?;
    // Relative IRIs in the body resolve against the resource's own IRI (the LDP/RDF convention).
    validate_rdf(format, &body, &target.iri)?;

    // Conditional write: evaluate preconditions against the CURRENT representation's ETag.
    let current = state.store.meta(&target.iri).await?;
    let current_etag = current.as_ref().map(|m| m.etag.as_str());
    conditional::require(eval_preconditions(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        current_etag,
    ))?;

    let existed = current.is_some();
    let meta = state
        .store
        .write(&target.iri, body, format.media_type())
        .await?;

    Ok(write_response(existed, &meta, &target.iri))
}

/// `POST /{path}` — create a child resource inside a container.
///
/// Honours the `Slug` header (sanitised) and mints a server URI when absent or colliding. POST to a
/// non-container is a 409 Conflict; POST to a container that does not exist is a 404. Returns 201 +
/// `Location`. Fail-closed (public ⇒ 403).
pub async fn post_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ServerError> {
    require_authenticated(&token)?;
    let container = parse_target(&state.base_url, uri.path())?;

    // POST creates a CHILD in a CONTAINER — the target must be a container (trailing-slash path).
    // A POST to a plain resource is a 409.
    if !container.is_container {
        return Err(ServerError::Conflict(
            "POST target is not a container".into(),
        ));
    }
    // The container must exist (the authoritative index check) — never create a child + a containment
    // edge under a missing container. A missing container is a 404.
    if !state.store.exists(&container.iri).await? {
        return Err(ServerError::NotFound);
    }

    let content_type = header_str(&headers, header::CONTENT_TYPE);
    let format = classify(content_type)?;

    // Mint the child IRI: Slug-derived if present + free, else a server-generated opaque name.
    let slug = header_str(&headers, HeaderName::from_static("slug"));
    let child_iri = mint_child_iri(&state.store, &container.iri, slug).await?;

    // Validate the body resolves relative IRIs against the MINTED child IRI.
    validate_rdf(format, &body, &child_iri)?;

    let meta = state
        .store
        .create_in_container(&container.iri, &child_iri, body, format.media_type())
        .await?;

    let mut out = HeaderMap::new();
    set_str(&mut out, header::ETAG, &meta.etag);
    set_str(&mut out, header::LOCATION, &child_iri);
    Ok((StatusCode::CREATED, out).into_response())
}

/// `DELETE /{path}` — delete a resource.
///
/// A non-existent target is a 404. A non-empty container is a 409 (LDP refuses to delete a container
/// with members — recursive delete is M2-next). `If-Match` is honoured (412 on mismatch). On success
/// returns 204. Fail-closed (public ⇒ 403).
pub async fn delete_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    require_authenticated(&token)?;
    let target = parse_target(&state.base_url, uri.path())?;

    let current = state.store.meta(&target.iri).await?;
    let current = current.ok_or(ServerError::NotFound)?;

    // Conditional delete: honour If-Match / If-None-Match against the current ETag.
    conditional::require(eval_preconditions(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        Some(current.etag.as_str()),
    ))?;

    // An empty-container refusal: a container with members cannot be deleted (LDP).
    if target.is_container {
        let children = state.store.list_children(&target.iri).await?;
        if !children.is_empty() {
            return Err(ServerError::Conflict(
                "cannot delete a non-empty container".into(),
            ));
        }
    }

    let parent = parent_container(&target);
    state.store.delete(&target.iri, parent.as_deref()).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `PATCH /{path}` — apply a Solid N3 Patch (`text/n3`).
///
/// The patch is parsed (insert/delete subset; a templated `where`/variable patch is a clear 422 —
/// see [`patch_handler`]), applied to the target's existing graph (a missing `deletes` triple ⇒ 409), and
/// the result re-serialised in the resource's stored format. PATCH on a missing resource that only
/// inserts creates it (the LDP "create on PATCH" convention); a PATCH with deletes on a missing
/// resource is a 409. `If-Match` is honoured. Fail-closed (public ⇒ 403).
pub async fn patch_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ServerError> {
    require_authenticated(&token)?;
    let target = parse_target(&state.base_url, uri.path())?;

    // Only text/n3 is supported; any other PATCH media type is a 415 (never a silent accept).
    classify_patch_media_type(header_str(&headers, header::CONTENT_TYPE))?;
    let patch = parse_n3_patch(&body, &target.iri)?;

    // Load the current representation (if any) + apply preconditions.
    let current = state.store.read(&target.iri).await.ok();
    let current_etag = current.as_ref().map(|r| r.meta.etag.clone());
    conditional::require(eval_preconditions(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        current_etag.as_deref(),
    ))?;

    // Determine the existing triples + the stored format (default Turtle for a new resource).
    let (existing_triples, stored_format) = match &current {
        Some(res) => {
            let fmt = classify(Some(&res.meta.content_type)).unwrap_or(RdfFormat::Turtle);
            (parse_to_triples(fmt, &res.body, &target.iri)?, fmt)
        }
        None => {
            // Create-on-PATCH: only an insert-only patch can create a resource. A delete on a missing
            // resource is a 409 (apply_patch enforces the missing-delete precondition).
            (Vec::new(), RdfFormat::Turtle)
        }
    };

    let patched = apply_patch(&existing_triples, &patch)?;
    let new_body = serialize_triples(stored_format, &patched)?;

    let existed = current.is_some();
    let meta = state
        .store
        .write(
            &target.iri,
            Bytes::from(new_body),
            stored_format.media_type(),
        )
        .await?;

    Ok(write_response(existed, &meta, &target.iri))
}

// --- helpers -----------------------------------------------------------------------------------

/// Reject a mutation from a public/unauthenticated caller (fail-closed — the WAC seam is M2-next).
fn require_authenticated(token: &VerifiedToken) -> Result<(), ServerError> {
    if token.is_public() {
        return Err(ServerError::Forbidden);
    }
    Ok(())
}

/// The shared 201/204 + ETag (+ Location on create) response for PUT / PATCH writes.
fn write_response(existed: bool, meta: &ResourceMeta, iri: &str) -> Response {
    let status = if existed {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    let mut out = HeaderMap::new();
    set_str(&mut out, header::ETAG, &meta.etag);
    if !existed {
        set_str(&mut out, header::LOCATION, iri);
    }
    (status, out).into_response()
}

/// Content-negotiate the response body for an RDF resource. For a non-RDF stored type the body is
/// returned verbatim. For an RDF type, the stored bytes are re-serialised into the negotiated format
/// when it differs from the stored one. A client that accepts NEITHER producible type ⇒ 406.
fn negotiate_body(
    stored_body: &Bytes,
    stored_content_type: &str,
    accept: Option<&str>,
    base_iri: &str,
) -> Result<(Bytes, String), ServerError> {
    let stored_format = match classify(Some(stored_content_type)) {
        Ok(f) => f,
        // Non-RDF stored content (binary): no RDF conneg — serve verbatim. (A future slice can do
        // generic media-type matching; for now any Accept is satisfied by the stored bytes.)
        Err(_) => return Ok((stored_body.clone(), stored_content_type.to_string())),
    };

    let chosen = negotiate_accept(accept, stored_format).ok_or(ServerError::NotAcceptable)?;
    if chosen == stored_format {
        return Ok((stored_body.clone(), stored_content_type.to_string()));
    }
    // Re-serialise into the chosen format.
    let triples = parse_to_triples(stored_format, stored_body, base_iri)?;
    let bytes = serialize_triples(chosen, &triples)?;
    Ok((Bytes::from(bytes), chosen.media_type().to_string()))
}

/// Mint a child IRI within `container`, honouring a `Slug` (sanitised) when present and free, else a
/// server-generated opaque name (the `buildTaskUri`-style mint). Guarantees the returned IRI does
/// not currently exist (collision-avoiding).
async fn mint_child_iri<S: Store>(
    store: &S,
    container_iri: &str,
    slug: Option<&str>,
) -> Result<String, ServerError> {
    let base = container_iri.trim_end_matches('/');

    // Try the sanitised Slug first.
    if let Some(raw) = slug {
        if let Some(name) = sanitise_slug(raw) {
            let candidate = format!("{base}/{name}");
            if !store.exists(&candidate).await? {
                return Ok(candidate);
            }
            // Slug collided — fall through to a generated name (with the slug as a stem).
            return generate_unique(store, base, Some(&name)).await;
        }
    }
    generate_unique(store, base, None).await
}

/// Generate a unique child IRI under `base`, optionally seeded by `stem`. Deterministic-but-unique:
/// a monotonic counter + the stem, retried until the index reports it free.
async fn generate_unique<S: Store>(
    store: &S,
    base: &str,
    stem: Option<&str>,
) -> Result<String, ServerError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let prefix = stem.unwrap_or("resource");
    // Seed with a coarse timestamp so names are unique across process restarts too.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    for attempt in 0..64u64 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = format!("{base}/{prefix}-{seed:x}-{n:x}-{attempt:x}");
        if !store.exists(&candidate).await? {
            return Ok(candidate);
        }
    }
    Err(ServerError::Storage(
        "could not mint a unique child IRI".into(),
    ))
}

/// Sanitise a `Slug` into a safe single path segment: keep `[A-Za-z0-9._-]`, drop everything else
/// (including `/`, `:`, `%`, whitespace, `.`/`..`). Returns `None` if nothing usable remains. This
/// is defence-in-depth — the minted IRI is also re-validated by [`parse_target`]'s traversal guard.
fn sanitise_slug(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    // Reject path-traversal-ish remnants and empties.
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return None;
    }
    Some(cleaned)
}

/// Derive the parent container IRI of a target (for detaching containment on DELETE). The parent is
/// the IRI up to and including the last interior slash. The root has no parent.
fn parent_container(target: &LdpTarget) -> Option<String> {
    // Strip a trailing slash for a container target so we find its PARENT, not itself.
    let iri = target.iri.trim_end_matches('/');
    // Find the last '/' that is part of the path (after the scheme's "//").
    let scheme_end = iri.find("://").map(|i| i + 3).unwrap_or(0);
    let path_part = &iri[scheme_end..];
    match path_part.rfind('/') {
        Some(rel) => {
            let abs = scheme_end + rel;
            // Include the slash so the parent is itself a container IRI.
            Some(iri[..=abs].to_string())
        }
        None => None,
    }
}

/// Read a header value as `&str`, or `None` if absent / not valid UTF-8.
fn header_str(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Insert a header value, silently skipping a value that cannot be encoded (never panics).
fn set_str(headers: &mut HeaderMap, name: header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}
