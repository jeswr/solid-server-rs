// AUTHORED-BY Claude Opus 4.8
//! The LDP request handlers — GET / HEAD / PUT / POST / DELETE / PATCH over the [`Store`] seam.
//!
//! These are the axum handlers over the [`Store`] seam. They stay thin: target parsing
//! ([`crate::ldp::target`]), content classification + negotiation ([`crate::ldp::content`]),
//! precondition evaluation ([`crate::ldp::conditional`]), range computation ([`crate::ldp::range`]),
//! and the N3-Patch engine ([`crate::ldp::patch`]) are pure modules; the handler is the HTTP glue +
//! the store call.
//!
//! ## The authorization seam (pre-WAC — Cluster B, gated on sparq#992)
//!
//! Full per-resource WAC authorization needs the SPARQ access-control design, which does not yet
//! exist — so this slice does NOT evaluate `.acl` documents. Instead it runs a coarse, fail-closed
//! PRE-WAC posture that is correct for the Solid Protocol authentication scenarios:
//!
//! - **Mutations (PUT/POST/DELETE/PATCH) require an authenticated caller.** An anonymous mutation is a
//!   401 + `WWW-Authenticate` challenge (NOT a bare 403, NOT a fail-open write).
//! - **Reads (GET/HEAD) also require an authenticated caller, EXCEPT a public WebID profile
//!   document** (`…/profile/card`), which any Solid client (and the conformance harness) dereferences
//!   UNAUTHENTICATED to find `pim:storage`/`solid:oidcIssuer`. Every other anonymous read is a 401 +
//!   challenge.
//!
//! The `token` argument on each handler is the seam where the per-resource WAC
//! `read`/`write`/`append`/`control` decision plugs in. See `require_auth` + `is_public_readable`;
//! the WAC engine, when it lands, SUPERSEDES this coarse gate.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;

use oxrdf::{NamedNode, Triple};

use crate::auth::VerifiedToken;
use crate::error::ServerError;
use crate::ldp::conditional::{self, evaluate as eval_preconditions};
use crate::ldp::content::{
    classify, negotiate_accept, parse_to_triples, serialize_triples, validate_rdf, RdfFormat,
};
use crate::ldp::patch::{
    apply_patch, classify_patch_media_type, parse_n3_patch, parse_sparql_update, PatchKind,
};
use crate::ldp::range::{self, RangeOutcome};
use crate::ldp::target::{parse_target, LdpTarget};
use crate::notifications::ws::link_headers;
use crate::notifications::{ActivityType, NotificationHub};
use crate::store::{DeleteOutcome, ResourceMeta, Store};

/// LDP/RDF vocabulary IRIs used to synthesise a container's `ldp:contains` representation.
const RDF_TYPE_IRI: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const LDP_RESOURCE_IRI: &str = "http://www.w3.org/ns/ldp#Resource";
const LDP_CONTAINER_IRI: &str = "http://www.w3.org/ns/ldp#Container";
const LDP_BASIC_CONTAINER_IRI: &str = "http://www.w3.org/ns/ldp#BasicContainer";
const LDP_CONTAINS_IRI: &str = "http://www.w3.org/ns/ldp#contains";

/// Shared state for the LDP handlers: the store + the server's public base URL + the notification hub.
///
/// The hub is the SINGLE emit seam: after a successful mutation the handler calls
/// [`NotificationHub::notify`] (the only notification coupling in the write path — no handler
/// refactor). The hub is cheap to clone (an `Arc` inside) and shared with the notification routes.
pub struct LdpState<S: Store> {
    pub store: S,
    pub base_url: String,
    pub notifications: NotificationHub,
    /// The `WWW-Authenticate` challenge to emit on a 401 for an anonymous request to a resource that
    /// requires authentication. Populated from the [`AuthContext`](crate::auth::AuthContext) at router
    /// assembly ([`AppState::new`](crate::app::AppState::new)) so the LDP layer can answer 401 +
    /// challenge WITHOUT a handle to the verifier; a default Bearer/DPoP challenge is used if unset.
    pub www_authenticate: String,
}

/// The fallback `WWW-Authenticate` challenge used when no verifier-derived one was injected (e.g. a
/// test that builds an `LdpState` directly). The verifier-derived challenge additionally names the
/// trusted issuer(s); this fallback is a minimal, spec-shaped DPoP challenge.
const DEFAULT_WWW_AUTHENTICATE: &str = "DPoP error=\"invalid_token\", scope=\"webid\"";

impl<S: Store> LdpState<S> {
    /// Build an LDP state with a fresh, isolated notification hub.
    pub fn new(store: S, base_url: impl Into<String>) -> Self {
        Self::with_hub(store, base_url, NotificationHub::new())
    }

    /// Build an LDP state sharing an EXISTING notification hub (so the LDP emit path and the
    /// notification receive routes register against the same registry).
    pub fn with_hub(store: S, base_url: impl Into<String>, notifications: NotificationHub) -> Self {
        Self {
            store,
            base_url: base_url.into(),
            notifications,
            www_authenticate: DEFAULT_WWW_AUTHENTICATE.to_string(),
        }
    }

    /// Set the `WWW-Authenticate` challenge emitted on a 401 (the verifier-derived one). Called by
    /// [`AppState::new`](crate::app::AppState::new) so the LDP layer's anonymous-401 names the same
    /// issuer(s)/algs as every other challenge.
    pub fn set_www_authenticate(&mut self, challenge: impl Into<String>) {
        self.www_authenticate = challenge.into();
    }

    /// Build the 401 `Unauthorized` error (with the cached challenge) for an anonymous request to a
    /// resource that requires authentication.
    fn unauthenticated(&self) -> ServerError {
        ServerError::Unauthorized {
            status: 401,
            message: "Authentication required for this resource.".to_string(),
            www_authenticate: self.www_authenticate.clone(),
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
    Extension(token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    serve_read::<S>(&state, &token, &uri, &headers, true).await
}

/// `HEAD /{path}` — the GET response headers without the body.
pub async fn head_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    serve_read::<S>(&state, &token, &uri, &headers, false).await
}

/// Shared GET/HEAD read path. `with_body` distinguishes GET (send bytes) from HEAD (headers only).
async fn serve_read<S: Store>(
    state: &Arc<LdpState<S>>,
    token: &VerifiedToken,
    uri: &axum::http::Uri,
    req_headers: &HeaderMap,
    with_body: bool,
) -> Result<Response, ServerError> {
    let target = parse_target(&state.base_url, uri.path())?;

    // Pre-WAC read authorization (the 401-vs-anonymous posture, NOT full WAC — that is Cluster B,
    // gated on sparq#992). A read needs an authenticated caller, EXCEPT a WebID profile document,
    // which is public by design: the conformance harness (and any Solid client) dereferences a WebID
    // UNAUTHENTICATED to find `pim:storage`/`solid:oidcIssuer`, so the profile card must stay readable
    // anonymously. Everything else, when requested anonymously, answers 401 + `WWW-Authenticate` —
    // matching the `authentication-header` + CORS-simple scenarios. (Once the WAC engine lands it
    // SUPERSEDES this coarse gate with per-resource `acl:Read` decisions + the public-read class.)
    if token.is_public() && !is_public_readable(&target.iri, &state.base_url) {
        return Err(state.unauthenticated());
    }

    let resource = state.store.read(&target.iri).await?;

    // Decide the response bytes + content type. For a CONTAINER, synthesise the LDP representation
    // (`ldp:contains` listing + container typing) from the authoritative membership; for a plain
    // resource, content-negotiate its stored bytes. Both honour the `Accept` header.
    let accept = header_str(req_headers, header::ACCEPT);
    let (body, content_type) = if target.is_container {
        render_container(
            state,
            &target.iri,
            &resource.body,
            &resource.meta.content_type,
            accept,
        )
        .await?
    } else {
        negotiate_body(
            &resource.body,
            &resource.meta.content_type,
            accept,
            &target.iri,
        )?
    };

    let total_len = body.len() as u64;
    // `Range` is defined for GET (RFC 9110 §14.2); ignore it for HEAD so a HEAD never returns 206.
    let outcome = if with_body {
        range::evaluate(header_str(req_headers, header::RANGE), total_len)
    } else {
        RangeOutcome::Full
    };

    let mut out = HeaderMap::new();
    set_str(&mut out, header::CONTENT_TYPE, &content_type);
    // ETag: a CONTAINER's body is GENERATED from LIVE membership (the `ldp:contains` listing), so its
    // validator MUST be derived from the FINAL RENDERED representation — not the stored-metadata ETag,
    // which never changes when a child is added/removed (the stale-validator bug: the body would
    // change while the ETag did not, breaking conditional requests / caches). A strong hash of the
    // negotiated, serialised body changes whenever the membership/body or the negotiated format
    // changes. GET and HEAD compute the SAME `body` here, so they agree on this validator. A plain
    // resource keeps its stored-metadata ETag (its bytes ARE the stored representation).
    let etag = if target.is_container {
        representation_etag(&body)
    } else {
        resource.meta.etag.clone()
    };
    set_str(&mut out, header::ETAG, &etag);
    // Advertise byte-range support (RFC 9110 §14.3).
    set_str(&mut out, header::ACCEPT_RANGES, "bytes");
    // Method advertisement on the read response: `Allow` (the LDP verb set — `read-method-allow`
    // asserts GET/HEAD responses carry `Allow` listing GET + HEAD) + `Accept-Post` (containers only)
    // + `Accept-Patch`. (OPTIONS itself is answered by the CORS layer, which short-circuits every
    // OPTIONS; the `options_handler` is the non-CORS fallback.)
    add_method_advertisement(&mut out, target.is_container);
    // Notification discovery: advertise the storage-description doc via `describedby` +
    // `solid:storageDescription` Link rels so a client can HEAD a resource and find the subscription
    // service (the values live in `notifications::ws::link_headers`, the single discovery home).
    add_discovery_links(&mut out, &state.base_url);
    // LDP/Solid type advertisement (`Link: <type>; rel="type"`): a container advertises
    // `ldp:BasicContainer` (+ `ldp:Container`/`ldp:Resource`), and the STORAGE ROOT additionally
    // advertises `pim:Storage` (Solid Protocol §4.1). The conformance harness REQUIRES the
    // `pim:Storage` rel=type header on the pod root to recognise an accessible storage at bootstrap.
    add_type_links(&mut out, &target, &state.base_url);
    // ACL discovery (`Link: <…>; rel="acl"`, Solid Protocol §4.3.1): every resource advertises the URL
    // of its access-control document (the conventional `<resource>.acl` / `<container>/.acl`). The
    // conformance harness reads this at bootstrap to locate where to write the test container's ACL.
    // NB the ACL is NOT yet ENFORCED (WAC is gated on sparq#992) — advertising + storing the .acl
    // document lets the harness proceed; the WAC scenarios still fail until the engine lands.
    add_acl_link(&mut out, &target);

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
    require_auth(&token, state.as_ref())?;
    let target = parse_target(&state.base_url, uri.path())?;

    // Slash-semantics: a trailing-slash IRI (a container) and the same IRI without the slash (a plain
    // resource) MUST NOT co-exist (Solid Protocol — "with and without trailing slash cannot
    // co-exist"). Refuse a PUT whose URI collides with an EXISTING resource of the opposite kind.
    reject_slash_semantics_conflict(state.as_ref(), &target).await?;

    // A write MUST carry a Content-Type (Solid Protocol §writing — `content-type-reject`). An ABSENT
    // Content-Type is a 400 Bad Request.
    let content_type = require_content_type(&headers)?;
    // Validate + select the stored media type. An RDF type is parse-validated (400 on malformed); a
    // NON-RDF type (e.g. `text/plain`, an image) is stored VERBATIM as an opaque binary resource —
    // the Solid Protocol stores any content type, and a read serves a binary body unchanged (see
    // `negotiate_body`). The stored media type is the (sanitised) declared one.
    let stored_type = validate_writable(&content_type, &body, &target.iri)?;

    // Conditional write: evaluate preconditions against the CURRENT representation's ETag.
    let current = state.store.meta(&target.iri).await?;
    let current_etag = current.as_ref().map(|m| m.etag.as_str());
    conditional::require(eval_preconditions(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        current_etag,
    ))?;

    let existed = current.is_some();
    let parent = parent_container(&target);

    let meta = if existed {
        // A replace: rewrite the bytes in place; containment is unchanged.
        state.store.write(&target.iri, body, &stored_type).await?
    } else {
        // A CREATE via PUT must create intermediate containers (Solid Protocol §writing-resource —
        // "Creating a resource using PUT … must create intermediate containers") AND wire the new
        // resource into its parent's `ldp:contains` membership (so the container GET lists it). An
        // ancestor that already exists as a NON-container is a conflict (a resource cannot have a
        // child) → handled by `ensure_ancestor_containers`.
        ensure_ancestor_containers(state.as_ref(), &target.iri).await?;
        match &parent {
            Some(p) => {
                state
                    .store
                    .create_in_container(p, &target.iri, body, &stored_type)
                    .await?
            }
            // No parent (a root-level write): a plain write mints the record.
            None => state.store.write(&target.iri, body, &stored_type).await?,
        }
    };

    // EMIT (the single notification hook on the PUT path): a replace ⇒ Update, a create ⇒ Create. A
    // PUT-created resource also grows its container's membership, so pass the parent (the hub derives
    // the parent `Add`); a replace passes no parent (no membership change).
    let activity = if existed {
        ActivityType::Update
    } else {
        ActivityType::Create
    };
    let emit_parent = if existed { None } else { parent.clone() };
    state
        .notifications
        .notify(&target.iri, activity, emit_parent.as_deref())
        .await;

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
    require_auth(&token, state.as_ref())?;
    let container = parse_target(&state.base_url, uri.path())?;

    // POST creates a CHILD in a CONTAINER — the target must be a container (trailing-slash path).
    // A POST to a non-container target is NOT a containment operation: per the Solid Protocol
    // `post-target-not-found` scenarios it is `[404, 405]` — 404 when nothing exists at that URI,
    // 405 Method-Not-Allowed when a plain resource is there (POST does not create a child of a
    // resource). (This supersedes the earlier 409 — a 409 is not the spec-accepted status here.)
    if !container.is_container {
        return if state.store.exists(&container.iri).await? {
            Err(ServerError::MethodNotAllowed)
        } else {
            Err(ServerError::NotFound)
        };
    }
    // The container must exist (the authoritative index check) — never create a child + a containment
    // edge under a missing container. A missing container is a 404 (`post-target-not-found`).
    if !state.store.exists(&container.iri).await? {
        return Err(ServerError::NotFound);
    }

    // A POST write MUST carry a Content-Type (Solid Protocol — `content-type-reject`): ABSENT ⇒ 400.
    let content_type = require_content_type(&headers)?;

    // Container-intent: a `Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"` (or
    // `ldp:Container`) on a POST asks the server to create a CONTAINER child (LDP §5.2.3.4) — the
    // minted child IRI then ends in `/` and is created as a container. Without the type Link, a plain
    // resource child is created.
    let wants_container = wants_container_via_link(&headers);

    // Mint the child IRI: Slug-derived if present + free, else a server-generated opaque name. A
    // container child gets a trailing slash.
    let slug = header_str(&headers, HeaderName::from_static("slug"));
    let child_iri = mint_child_iri(&state.store, &container.iri, slug, wants_container).await?;

    // Validate + select the stored media type, resolving relative IRIs against the MINTED child IRI.
    // RDF is parse-validated; a non-RDF type is stored verbatim as an opaque binary resource. A
    // container's body is conventionally empty/RDF; we still validate whatever was sent.
    let stored_type = validate_writable(&content_type, &body, &child_iri)?;

    let meta = state
        .store
        .create_in_container(&container.iri, &child_iri, body, &stored_type)
        .await?;

    // EMIT: a POST always CREATES the child and GROWS the container's membership — Create on the child
    // + a derived Add on the container (the hub fans both from this one call).
    state
        .notifications
        .notify(&child_iri, ActivityType::Create, Some(&container.iri))
        .await;

    let mut out = HeaderMap::new();
    set_str(&mut out, header::ETAG, &meta.etag);
    set_str(&mut out, header::LOCATION, &child_iri);
    Ok((StatusCode::CREATED, out).into_response())
}

/// `DELETE /{path}` — delete a resource OR a container.
///
/// A non-existent target is a 404. `If-Match` / `If-None-Match` are honoured (412 on mismatch). On
/// success returns 204. Fail-closed (public ⇒ 403).
///
/// **Container-delete semantics (the spec choice — documented per the standing make-the-call rule).**
/// A DELETE on a container path (trailing slash) is permitted ONLY when the container is empty: a
/// container with members is a **409 Conflict**, never a cascade. This is the conservative choice the
/// LDP spec permits (LDP §5.2.5.1 lets a server refuse to delete a non-empty container) and what CSS
/// does by default — it avoids a single request silently destroying an arbitrarily large subtree.
/// Deleting an empty container removes its own resource record AND its (empty) `ldp:contains` set in
/// SPARQ (the live store `DROP`s the container's named graph; the in-memory double clears its
/// children entry), and detaches it from its parent's containment. Recursive / cascade delete is
/// intentionally NOT offered (an opt-in recursive delete is a possible future slice — file an issue
/// if a client needs it).
pub async fn delete_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    require_auth(&token, state.as_ref())?;
    let target = parse_target(&state.base_url, uri.path())?;

    let current = state.store.meta(&target.iri).await?;
    let current = current.ok_or(ServerError::NotFound)?;

    // Conditional delete: honour If-Match / If-None-Match against the current ETag.
    conditional::require(eval_preconditions(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        Some(current.etag.as_str()),
    ))?;

    let parent = parent_container(&target);

    if target.is_container {
        // A container DELETE goes through the ATOMIC empty-check+delete (no TOCTOU): the empty check
        // and the delete are ONE store operation, so a child POSTed concurrently can never slip in
        // between a separate empty-check and a separate delete and be orphaned. A non-empty container
        // is a 409; an absent one a 404 (the precondition load above already 404'd a fully-absent
        // target, but the atomic op is the authoritative existence+empty decision).
        match state
            .store
            .delete_container_if_empty(&target.iri, parent.as_deref())
            .await?
        {
            DeleteOutcome::Deleted => {
                // EMIT only on an actual delete: Delete on the container + a derived Remove on its
                // parent (membership shrank). NotEmpty/NotFound deleted nothing ⇒ no notification.
                state
                    .notifications
                    .notify(&target.iri, ActivityType::Delete, parent.as_deref())
                    .await;
                Ok(StatusCode::NO_CONTENT.into_response())
            }
            DeleteOutcome::NotEmpty => Err(ServerError::Conflict(
                "cannot delete a non-empty container".into(),
            )),
            DeleteOutcome::NotFound => Err(ServerError::NotFound),
        }
    } else {
        // A plain resource: the (non-atomic) removal is fine — there is no empty-check to race.
        state.store.delete(&target.iri, parent.as_deref()).await?;
        // EMIT: Delete on the resource + a derived Remove on its parent container.
        state
            .notifications
            .notify(&target.iri, ActivityType::Delete, parent.as_deref())
            .await;
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

/// `PATCH /{path}` — apply a Solid N3 Patch (`text/n3`).
///
/// The patch is parsed (insert/delete plus the `solid:where` variable solver — see
/// [`crate::ldp::patch`] for the BGP-matching + exactly-one-solution semantics), applied to the
/// target's existing graph (a missing `deletes` triple ⇒ 409; a non-empty `where` with zero or
/// multiple solutions ⇒ 409), and the result re-serialised in the resource's stored format. PATCH on
/// a missing resource that only inserts creates it (the LDP "create on PATCH" convention); a PATCH
/// with deletes on a missing resource is a 409. `If-Match` is honoured. Fail-closed (public ⇒ 403).
pub async fn patch_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    Extension(token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ServerError> {
    require_auth(&token, state.as_ref())?;
    let target = parse_target(&state.base_url, uri.path())?;

    // Select the PATCH language from the Content-Type (ABSENT ⇒ 400, unsupported ⇒ 415) and parse the
    // document. `text/n3` is the Solid N3 Patch; `application/sparql-update` is the INSERT/DELETE DATA
    // subset. Both reduce to an `N3Patch` the shared engine applies.
    let patch = match classify_patch_media_type(header_str(&headers, header::CONTENT_TYPE))? {
        PatchKind::N3 => parse_n3_patch(&body, &target.iri)?,
        PatchKind::SparqlUpdate => parse_sparql_update(&body, &target.iri)?,
    };

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
    let parent = parent_container(&target);

    let meta = if existed {
        state
            .store
            .write(
                &target.iri,
                Bytes::from(new_body),
                stored_format.media_type(),
            )
            .await?
    } else {
        // Create-on-PATCH: like PUT, create intermediate containers + wire the new resource into its
        // parent's `ldp:contains` (so the containment scenario's container GET lists it). An ancestor
        // that exists as a non-container is a conflict (`ensure_ancestor_containers`).
        ensure_ancestor_containers(state.as_ref(), &target.iri).await?;
        match &parent {
            Some(p) => {
                state
                    .store
                    .create_in_container(
                        p,
                        &target.iri,
                        Bytes::from(new_body),
                        stored_format.media_type(),
                    )
                    .await?
            }
            None => {
                state
                    .store
                    .write(
                        &target.iri,
                        Bytes::from(new_body),
                        stored_format.media_type(),
                    )
                    .await?
            }
        }
    };

    // EMIT (same shape as PUT): a patch that edited an existing resource ⇒ Update; a create-on-PATCH
    // ⇒ Create + a parent membership Add.
    let activity = if existed {
        ActivityType::Update
    } else {
        ActivityType::Create
    };
    let emit_parent = if existed { None } else { parent.clone() };
    state
        .notifications
        .notify(&target.iri, activity, emit_parent.as_deref())
        .await;

    Ok(write_response(existed, &meta, &target.iri))
}

/// `OPTIONS /{path}` — advertise the methods + write media types for a target (RFC 9110 §9.3.7 +
/// the Solid Protocol `Accept-Post`/`Accept-Patch`).
///
/// Returns **204 No Content** (an empty body) with:
/// - `Allow`: the LDP verb set the server supports (`OPTIONS, HEAD, GET, PUT, POST, DELETE, PATCH`);
/// - `Accept-Post`: the container POST media types (`text/turtle`, `application/ld+json`);
/// - `Accept-Patch`: the PATCH media types (`text/n3`, `application/sparql-update`).
///
/// OPTIONS is NOT auth-gated (it is metadata about the surface, not a read of content) and is the
/// path the CORS preflight rides on — the `CorsLayer` adds the `Access-Control-*` headers to this
/// response. The `read-method-support` / `read-method-allow` scenarios require OPTIONS ≠ 405 and an
/// `Allow` listing GET + HEAD.
pub async fn options_handler<S: Store>(
    State(_state): State<Arc<LdpState<S>>>,
    Extension(_token): Extension<VerifiedToken>,
    uri: axum::http::Uri,
) -> Result<Response, ServerError> {
    let is_container = uri.path().ends_with('/');
    let mut out = HeaderMap::new();
    add_method_advertisement(&mut out, is_container);
    Ok((StatusCode::NO_CONTENT, out).into_response())
}

/// The LDP method-advertisement headers (`Allow` + `Accept-Post` on containers + `Accept-Patch`),
/// shared by the OPTIONS handler and the GET/HEAD read response.
///
/// - `Allow`: the full LDP verb set.
/// - `Accept-Post` (Solid Protocol — containers accept POST): the container POST media types. Only a
///   container advertises it (POST to a non-container is not a containment op).
/// - `Accept-Patch`: the PATCH media types (`text/n3`, `application/sparql-update`).
fn add_method_advertisement(headers: &mut HeaderMap, is_container: bool) {
    set_str(
        headers,
        header::ALLOW,
        "OPTIONS, HEAD, GET, PUT, POST, DELETE, PATCH",
    );
    if is_container {
        set_str(
            headers,
            HeaderName::from_static("accept-post"),
            "text/turtle, application/ld+json",
        );
    }
    set_str(
        headers,
        HeaderName::from_static("accept-patch"),
        "text/n3, application/sparql-update",
    );
}

// --- helpers -----------------------------------------------------------------------------------

/// Reject a request from a public/unauthenticated caller that requires authentication: a 401 with the
/// server's `WWW-Authenticate` challenge (NOT a bare 403).
///
/// This is the pre-WAC posture (full per-resource WAC is Cluster B, gated on sparq#992): every
/// mutation, and every read except a public WebID profile document, needs an authenticated caller.
/// An anonymous caller gets a spec-shaped 401 + challenge so a client knows to obtain a token.
fn require_auth<S: Store>(token: &VerifiedToken, state: &LdpState<S>) -> Result<(), ServerError> {
    if token.is_public() {
        return Err(state.unauthenticated());
    }
    Ok(())
}

/// Require a non-empty `Content-Type` on a write (Solid Protocol — `content-type-reject`). An ABSENT
/// or empty Content-Type is a **400 Bad Request**. Distinguishing absent (400) from
/// present-but-unsupported (handled by [`validate_writable`]) is the point of this helper.
fn require_content_type(headers: &HeaderMap) -> Result<String, ServerError> {
    match header_str(headers, header::CONTENT_TYPE) {
        Some(ct) if !ct.trim().is_empty() => Ok(ct.to_string()),
        _ => Err(ServerError::BadRequest(
            "a write request must declare a Content-Type".into(),
        )),
    }
}

/// Validate a write body for its declared `content_type` and return the media type to store it under.
///
/// - An **RDF** type (`text/turtle` / `application/ld+json`) is parse-validated (a malformed body is a
///   400) so the index/byte stores never hold a non-parseable "RDF" resource.
/// - A **NON-RDF** type (`text/plain`, an image, …) is stored VERBATIM as an opaque binary resource —
///   the Solid Protocol permits storing any content type, and a read serves a binary body unchanged
///   (`negotiate_body`). The CORS scenarios create `text/plain` resources, so this path is required.
///
/// The returned media type is the declared one's essence (parameters trimmed) for an RDF type, or the
/// declared value verbatim for a binary type.
fn validate_writable(
    content_type: &str,
    body: &Bytes,
    base_iri: &str,
) -> Result<String, ServerError> {
    match classify(Some(content_type)) {
        Ok(format) => {
            // RDF: validate the body parses in its declared format (relative IRIs against base_iri).
            validate_rdf(format, body, base_iri)?;
            Ok(format.media_type().to_string())
        }
        // A non-RDF type is an opaque binary resource — store the declared content type verbatim.
        Err(ServerError::UnsupportedMediaType(_)) => Ok(content_type.trim().to_string()),
        Err(e) => Err(e),
    }
}

/// Whether `iri` is PUBLIC-readable without authentication. Pre-WAC, the only public-read class is a
/// **WebID profile document** (the `…/profile/card` the conformance harness — and any Solid client —
/// dereferences UNAUTHENTICATED to find `pim:storage`/`solid:oidcIssuer`). Everything else requires a
/// token until the WAC engine lands (which will replace this with per-resource `acl:Read` + the
/// public-read agent class).
///
/// **The exception is the EXACT direct WebID-profile shape only** — `<base>/{user}/profile/card`,
/// where `{user}` is a SINGLE top-level path segment (exactly two interior segments before the final
/// `profile/card`: the user dir + `profile/card`). It is NOT a suffix/`ends_with` match: a nested
/// `<base>/{user}/private/profile/card` (or any deeper `…/profile/card`) is private data and MUST
/// require authentication — an `ends_with` test let any such nested path bypass the auth gate (the
/// HIGH this closes). This whole posture is interim; the WAC engine (Cluster B) supersedes it with
/// per-resource ACL.
fn is_public_readable(iri: &str, base_url: &str) -> bool {
    let base = base_url.trim_end_matches('/');
    let Some(rest) = iri.strip_prefix(base) else {
        return false;
    };
    // The seeded WebID profile document is EXACTLY `/{user}/profile/card`. Match the precise shape —
    // a single top-level `{user}` segment, then `profile`, then `card` — and nothing else. Splitting
    // on '/' over the leading-slash-trimmed path yields exactly `["{user}", "profile", "card"]` for a
    // direct profile card; a nested `…/private/profile/card` yields four+ segments and is rejected.
    let segments: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
    matches!(segments.as_slice(), [user, "profile", "card"] if !user.is_empty())
}

/// Synthesise a container's LDP representation and content-negotiate it.
///
/// The body MERGES two triple sources, built from `oxrdf` triples (never hand-concatenated — the
/// house rule) and serialised with the server's own RDF serialiser:
/// - **The container's OWN stored RDF** (whatever was PUT to the container, or POSTed as its body):
///   parsed from `stored_body` in its stored format and carried through, so RDF written to a
///   container stays retrievable on GET. A non-RDF / unparseable stored body contributes no triples
///   (a container's body is conventionally RDF or empty).
/// - **The generated LDP containment triples** — `<container> rdf:type ldp:Resource, ldp:Container,
///   ldp:BasicContainer` and `<container> ldp:contains <child>` for each authoritative
///   `store.list_children` member.
///
/// The two sets are de-duplicated (a stored triple identical to a generated one is not repeated). The
/// negotiated format honours the `Accept` header (Turtle / JSON-LD), defaulting to the container's
/// stored format when it is RDF (else Turtle); an Accept that admits neither is a 406.
async fn render_container<S: Store>(
    state: &Arc<LdpState<S>>,
    container_iri: &str,
    stored_body: &Bytes,
    stored_content_type: &str,
    accept: Option<&str>,
) -> Result<(Bytes, String), ServerError> {
    // The container's stored bytes default to a Turtle representation; if the stored type is RDF, use
    // it as the conneg default (most faithful) and parse the stored body for its own triples.
    let stored_format = classify(Some(stored_content_type)).ok();
    let default_format = stored_format.unwrap_or(RdfFormat::Turtle);
    let format = negotiate_accept(accept, default_format).ok_or(ServerError::NotAcceptable)?;

    let subject = NamedNode::new(container_iri)
        .map_err(|e| ServerError::Storage(format!("invalid container IRI {container_iri}: {e}")))?;
    let rdf_type = nn(RDF_TYPE_IRI)?;
    let contains = nn(LDP_CONTAINS_IRI)?;

    let mut triples: Vec<Triple> = Vec::new();

    // 1) The container's OWN stored RDF (whatever was written to the container itself). Parse it in
    // its stored format, resolving relative IRIs against the container IRI. If the stored body is
    // non-RDF or unparseable, it contributes nothing (a container body is conventionally RDF/empty) —
    // we never fail the listing over a stored body the server itself stored.
    if let Some(fmt) = stored_format {
        if let Ok(stored) = parse_to_triples(fmt, stored_body, container_iri) {
            triples.extend(stored);
        }
    }

    // 2) The generated LDP typing + containment triples (de-duped against the stored set so an
    // identical triple is not repeated).
    push_unique(
        &mut triples,
        Triple::new(subject.clone(), rdf_type.clone(), nn(LDP_RESOURCE_IRI)?),
    );
    push_unique(
        &mut triples,
        Triple::new(subject.clone(), rdf_type.clone(), nn(LDP_CONTAINER_IRI)?),
    );
    push_unique(
        &mut triples,
        Triple::new(subject.clone(), rdf_type, nn(LDP_BASIC_CONTAINER_IRI)?),
    );

    for child in state.store.list_children(container_iri).await? {
        // A child IRI comes from the authoritative index; if it is somehow not a valid IRI, skip it
        // rather than fail the whole listing (defence-in-depth — the store mints valid IRIs).
        if let Ok(child_node) = NamedNode::new(&child) {
            push_unique(
                &mut triples,
                Triple::new(subject.clone(), contains.clone(), child_node),
            );
        }
    }

    let bytes = serialize_triples(format, &triples)?;
    Ok((Bytes::from(bytes), format.media_type().to_string()))
}

/// Push `triple` onto `triples` only if not already present (set-union semantics; the graphs are
/// small per resource so a linear scan is correct and adequate — `oxrdf::Triple` is `Eq` but not
/// `Ord`).
fn push_unique(triples: &mut Vec<Triple>, triple: Triple) {
    if !triples.contains(&triple) {
        triples.push(triple);
    }
}

/// A `NamedNode` from a server-constructed IRI (well-formed by construction; map an unexpected error
/// to a storage error rather than panic).
fn nn(iri: &str) -> Result<NamedNode, ServerError> {
    NamedNode::new(iri).map_err(|e| ServerError::Storage(format!("invalid IRI {iri}: {e}")))
}

/// A STRONG ETag computed from a rendered representation's BYTES — `"<len>-<hash>"`.
///
/// Used for a container response, whose body is generated from live membership (not stored bytes), so
/// the validator must track the actual representation: it changes whenever the serialised body changes
/// (a child added/removed, or the negotiated format differs). The same body computed for GET and HEAD
/// yields the same validator, so the two methods agree. This is a non-cryptographic content hash
/// (FNV-1a over the bytes), sufficient for a cache validator — collisions across distinct
/// representations are vanishingly unlikely and the length prefix further disambiguates.
fn representation_etag(body: &[u8]) -> String {
    // FNV-1a 64-bit over the serialised representation.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in body {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("\"{}-{:x}\"", body.len(), hash)
}

/// Ensure every ANCESTOR container of `iri` exists, creating any that are missing and wiring each into
/// its own parent's `ldp:contains` (Solid Protocol — PUT/PATCH create intermediate containers). The
/// resource `iri` itself is NOT created here (the caller does that). Walks ROOT→down so a parent
/// always exists before its child is wired.
///
/// **Conflict:** if an ancestor PATH already exists as a NON-container resource (a plain resource
/// cannot have children — the slash-semantics invariant), this is a 409 Conflict (`containment`
/// "conflicts when … turning resource into container"). The conflict is detected by the
/// trailing-slash container record being absent while the slash-less resource record is present.
async fn ensure_ancestor_containers<S: Store>(
    state: &LdpState<S>,
    iri: &str,
) -> Result<(), ServerError> {
    let base = state.base_url.trim_end_matches('/');
    let Some(rest) = iri.strip_prefix(base) else {
        return Ok(());
    };

    // The storage ROOT container `<base>/` is the ancestor of EVERYTHING; ensure it exists first (a
    // parentless write mints its record) so the walk below can wire each child into a present parent.
    let root = format!("{base}/");
    if !state.store.exists(&root).await? {
        state
            .store
            .write(&root, Bytes::new(), RdfFormat::Turtle.media_type())
            .await?;
    }

    // Interior path segments, excluding the resource's own final segment. e.g. for
    // `/a/b/c.txt` the ancestor containers are `/`, `/a/`, `/a/b/`.
    let path = rest.trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() <= 1 {
        // Resource is a direct child of the base root — only the root container is its ancestor, and it
        // now exists.
        return Ok(());
    }

    // Build each ancestor container IRI incrementally and ensure it exists.
    let mut prefix = String::from(base);
    let mut parent = root.clone();
    // Ancestor containers are all segments EXCEPT the last (the resource name).
    for seg in &segments[..segments.len() - 1] {
        prefix.push('/');
        prefix.push_str(seg);
        let container = format!("{prefix}/");

        // A pre-existing NON-container at this path (the slash-less form) ⇒ conflict.
        let slashless = prefix.clone();
        if state.store.exists(&slashless).await? && !state.store.exists(&container).await? {
            return Err(ServerError::Conflict(
                "an ancestor path already exists as a non-container resource".into(),
            ));
        }

        if !state.store.exists(&container).await? {
            // Create the missing intermediate container, wired into its parent's containment.
            state
                .store
                .create_in_container(
                    &parent,
                    &container,
                    Bytes::new(),
                    RdfFormat::Turtle.media_type(),
                )
                .await?;
        }
        parent = container;
    }
    Ok(())
}

/// Reject a PUT whose URI collides with an existing resource of the OPPOSITE slash-kind: a
/// trailing-slash container IRI and the slash-less resource IRI MUST NOT co-exist (Solid Protocol —
/// "with and without trailing slash cannot co-exist"). A collision is a **409 Conflict**.
async fn reject_slash_semantics_conflict<S: Store>(
    state: &LdpState<S>,
    target: &LdpTarget,
) -> Result<(), ServerError> {
    let opposite = if target.is_container {
        // Container `…/foo/` collides with resource `…/foo`.
        target.iri.trim_end_matches('/').to_string()
    } else {
        // Resource `…/foo` collides with container `…/foo/`.
        format!("{}/", target.iri)
    };
    if state.store.exists(&opposite).await? {
        return Err(ServerError::Conflict(
            "a resource and a container cannot share the same path (trailing-slash semantics)"
                .into(),
        ));
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

/// Whether a POST asks for a CONTAINER child via `Link: <ldp#BasicContainer>; rel="type"` (or
/// `ldp:Container`) — LDP §5.2.3.4 container creation. Matched across (possibly multiple) `Link`
/// header lines, case-insensitively on the rel + the LDP container type IRI.
fn wants_container_via_link(headers: &HeaderMap) -> bool {
    headers.get_all(header::LINK).iter().any(|v| {
        let Ok(s) = v.to_str() else { return false };
        let lower = s.to_ascii_lowercase();
        lower.contains("rel=\"type\"")
            && (lower.contains("ldp#basiccontainer") || lower.contains("ldp#container"))
    })
}

/// Mint a child IRI within `container`, honouring a `Slug` (sanitised) when present and free, else a
/// server-generated opaque name (the `buildTaskUri`-style mint). Guarantees the returned IRI does
/// not currently exist (collision-avoiding). When `as_container` is set, the minted IRI ends in `/`
/// (an LDP container child) and collision is checked against that trailing-slash form.
async fn mint_child_iri<S: Store>(
    store: &S,
    container_iri: &str,
    slug: Option<&str>,
    as_container: bool,
) -> Result<String, ServerError> {
    let base = container_iri.trim_end_matches('/');
    let suffix = if as_container { "/" } else { "" };

    // Try the sanitised Slug first.
    if let Some(raw) = slug {
        if let Some(name) = sanitise_slug(raw) {
            let candidate = format!("{base}/{name}{suffix}");
            // Free iff NEITHER slash-form exists — a resource `…/name` and a container `…/name/` MUST
            // NOT co-exist (the trailing-slash invariant), so a Slug colliding with the OPPOSITE form
            // is a collision too and must not be used (else the POST would create a sibling of the
            // opposite kind at the same name). On any collision, fall through to a generated name.
            if !slash_form_taken(store, base, &name).await? {
                return Ok(candidate);
            }
            return generate_unique(store, base, Some(&name), as_container).await;
        }
    }
    generate_unique(store, base, None, as_container).await
}

/// Whether EITHER slash-form of a child name (`<base>/<name>` resource OR `<base>/<name>/` container)
/// already exists — the trailing-slash co-existence guard for child minting.
async fn slash_form_taken<S: Store>(
    store: &S,
    base: &str,
    name: &str,
) -> Result<bool, ServerError> {
    let resource = format!("{base}/{name}");
    let container = format!("{base}/{name}/");
    Ok(store.exists(&resource).await? || store.exists(&container).await?)
}

/// Generate a unique child IRI under `base`, optionally seeded by `stem`. Deterministic-but-unique:
/// a monotonic counter + the stem, retried until the index reports it free. A container child gets a
/// trailing slash.
async fn generate_unique<S: Store>(
    store: &S,
    base: &str,
    stem: Option<&str>,
    as_container: bool,
) -> Result<String, ServerError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let prefix = stem.unwrap_or("resource");
    let suffix = if as_container { "/" } else { "" };
    // Seed with a coarse timestamp so names are unique across process restarts too.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    for attempt in 0..64u64 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = format!("{base}/{prefix}-{seed:x}-{n:x}-{attempt:x}{suffix}");
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

/// Append the notification-discovery `Link` headers (`describedby` + `solid:storageDescription`,
/// both → the storage description doc) to a read response. Uses `append` (not `insert`) so multiple
/// rels coexist as separate `Link` header lines. A value that cannot be header-encoded is skipped.
fn add_discovery_links(headers: &mut HeaderMap, base_url: &str) {
    for (rel, target) in link_headers(base_url) {
        let value = format!("<{target}>; rel=\"{rel}\"");
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.append(header::LINK, v);
        }
    }
}

/// Append the LDP/Solid `Link: <type>; rel="type"` advertisement headers for a read response.
///
/// - Any resource advertises `ldp:Resource`.
/// - A container additionally advertises `ldp:Container` + `ldp:BasicContainer` (the LDP type a Solid
///   container exposes).
/// - The STORAGE ROOT container additionally advertises `pim:Storage` — the Solid Protocol §4.1
///   storage-advertisement the conformance harness reads at bootstrap to recognise the pod. With the
///   in-memory/seeded layout the storage root is the per-user pod container `…/{user}/`; treat any
///   container that is a direct child of the server base (`<base>/{seg}/`) as a storage root.
///
/// Uses `append` so each rel is its own `Link` header line; values that cannot be header-encoded are
/// skipped (never panics).
fn add_type_links(headers: &mut HeaderMap, target: &LdpTarget, base_url: &str) {
    const LDP_RESOURCE: &str = "http://www.w3.org/ns/ldp#Resource";
    const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
    const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
    const PIM_STORAGE: &str = "http://www.w3.org/ns/pim/space#Storage";

    let mut types: Vec<&str> = vec![LDP_RESOURCE];
    if target.is_container {
        types.push(LDP_CONTAINER);
        types.push(LDP_BASIC_CONTAINER);
        if is_storage_root(&target.iri, base_url) {
            types.push(PIM_STORAGE);
        }
    }
    for t in types {
        let value = format!("<{t}>; rel=\"type\"");
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.append(header::LINK, v);
        }
    }
}

/// Append the `Link: <acl-url>; rel="acl"` ACL-discovery header (Solid Protocol §4.3.1).
///
/// The ACL URL follows the conventional sibling-document layout: a container `…/c/` → `…/c/.acl`; a
/// plain resource `…/r` → `…/r.acl`. Skipped if the value cannot be header-encoded.
fn add_acl_link(headers: &mut HeaderMap, target: &LdpTarget) {
    let acl_url = acl_url_for(target);
    let value = format!("<{acl_url}>; rel=\"acl\"");
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.append(header::LINK, v);
    }
}

/// The conventional ACL document URL for a target: `…/c/.acl` for a container `…/c/` (its IRI ends in
/// `/`, so `{iri}.acl` is `…/c/.acl`), and `…/r.acl` for a resource `…/r`. The same `{iri}.acl`
/// suffix yields both.
fn acl_url_for(target: &LdpTarget) -> String {
    format!("{}.acl", target.iri)
}

/// Whether `iri` is a storage-root container: a container that is a DIRECT child of the server base
/// (`<base>/<segment>/`, exactly one interior path segment). The seeded per-user pods (`…/alice/`,
/// `…/bob/`) are storage roots; deeper containers (`…/alice/profile/`) are not.
fn is_storage_root(iri: &str, base_url: &str) -> bool {
    let base = base_url.trim_end_matches('/');
    let Some(rest) = iri.strip_prefix(base) else {
        return false;
    };
    // rest is the absolute path, e.g. "/alice/". A storage root has exactly one non-empty segment
    // and a trailing slash.
    let inner = rest.trim_start_matches('/').trim_end_matches('/');
    !inner.is_empty() && !inner.contains('/') && rest.ends_with('/')
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

#[cfg(test)]
mod tests {
    use super::*;

    fn target(iri: &str) -> LdpTarget {
        LdpTarget {
            htu: iri.to_string(),
            iri: iri.to_string(),
            is_container: iri.ends_with('/'),
        }
    }

    fn link_values(headers: &HeaderMap) -> Vec<String> {
        headers
            .get_all(header::LINK)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn storage_root_is_a_direct_base_child_container() {
        let base = "https://localhost:3000";
        assert!(is_storage_root("https://localhost:3000/alice/", base));
        assert!(is_storage_root("https://localhost:3000/bob/", base));
        // Nested containers are NOT storage roots.
        assert!(!is_storage_root(
            "https://localhost:3000/alice/profile/",
            base
        ));
        assert!(!is_storage_root("https://localhost:3000/alice/test/", base));
        // The base root itself is not a per-user storage root.
        assert!(!is_storage_root("https://localhost:3000/", base));
        // A plain resource (no trailing slash) is not a storage root.
        assert!(!is_storage_root("https://localhost:3000/alice", base));
    }

    #[test]
    fn acl_url_is_the_dot_acl_sibling() {
        // Container: …/c/ → …/c/.acl
        assert_eq!(
            acl_url_for(&target("https://localhost:3000/alice/test/")),
            "https://localhost:3000/alice/test/.acl"
        );
        // Resource: …/r → …/r.acl
        assert_eq!(
            acl_url_for(&target("https://localhost:3000/alice/profile/card")),
            "https://localhost:3000/alice/profile/card.acl"
        );
    }

    #[test]
    fn storage_root_advertises_pim_storage_and_ldp_types() {
        let mut h = HeaderMap::new();
        let base = "https://localhost:3000";
        let t = target("https://localhost:3000/alice/");
        add_type_links(&mut h, &t, base);
        let links = link_values(&h);
        assert!(links
            .iter()
            .any(|l| l.contains("ldp#Resource") && l.contains("rel=\"type\"")));
        assert!(links.iter().any(|l| l.contains("ldp#Container")));
        assert!(links.iter().any(|l| l.contains("ldp#BasicContainer")));
        assert!(
            links.iter().any(|l| l.contains("pim/space#Storage")),
            "the storage root MUST advertise pim:Storage (harness bootstrap requirement): {links:?}"
        );
    }

    #[test]
    fn nested_container_advertises_ldp_types_but_not_pim_storage() {
        let mut h = HeaderMap::new();
        let base = "https://localhost:3000";
        add_type_links(
            &mut h,
            &target("https://localhost:3000/alice/profile/"),
            base,
        );
        let links = link_values(&h);
        assert!(links.iter().any(|l| l.contains("ldp#BasicContainer")));
        assert!(!links.iter().any(|l| l.contains("pim/space#Storage")));
    }

    #[test]
    fn plain_resource_advertises_only_ldp_resource_type() {
        let mut h = HeaderMap::new();
        let base = "https://localhost:3000";
        add_type_links(
            &mut h,
            &target("https://localhost:3000/alice/profile/card"),
            base,
        );
        let links = link_values(&h);
        assert!(links.iter().any(|l| l.contains("ldp#Resource")));
        assert!(!links.iter().any(|l| l.contains("ldp#Container")));
        assert!(!links.iter().any(|l| l.contains("pim/space#Storage")));
    }

    #[test]
    fn acl_link_header_is_emitted() {
        let mut h = HeaderMap::new();
        add_acl_link(&mut h, &target("https://localhost:3000/alice/test/"));
        let links = link_values(&h);
        assert!(
            links
                .iter()
                .any(|l| l.contains("/alice/test/.acl") && l.contains("rel=\"acl\"")),
            "the ACL-discovery Link rel=acl must be emitted: {links:?}"
        );
    }

    #[test]
    fn only_webid_profile_documents_are_public_readable() {
        let base = "https://localhost:3000";
        // A WebID profile card is public (the harness/clients dereference it anonymously).
        assert!(is_public_readable(
            "https://localhost:3000/alice/profile/card",
            base
        ));
        assert!(is_public_readable(
            "https://localhost:3000/bob/profile/card",
            base
        ));
        // Everything else requires auth pre-WAC.
        assert!(!is_public_readable("https://localhost:3000/alice/", base));
        assert!(!is_public_readable(
            "https://localhost:3000/alice/profile/",
            base
        ));
        assert!(!is_public_readable(
            "https://localhost:3000/alice/test/data",
            base
        ));
        assert!(!is_public_readable("https://localhost:3000/", base));
        // A path that merely ENDS in profile/card but is outside the base is not matched.
        assert!(!is_public_readable(
            "https://evil.example/profile/card",
            base
        ));
    }

    /// REGRESSION (the HIGH): the public-read exception must match the EXACT direct profile-card shape
    /// only — `<base>/{user}/profile/card` — and NOT any nested `…/profile/card`. A
    /// `<base>/a/private/profile/card` is private data and must require auth; the old `ends_with`
    /// test let it bypass the gate.
    #[test]
    fn nested_profile_card_path_is_not_public_readable() {
        let base = "https://localhost:3000";
        // The exact direct WebID-profile card stays public.
        assert!(is_public_readable(
            "https://localhost:3000/alice/profile/card",
            base
        ));
        // A NESTED `…/profile/card` (one extra interior segment) MUST require auth — not a suffix match.
        assert!(!is_public_readable(
            "https://localhost:3000/a/private/profile/card",
            base
        ));
        // Deeper nesting is likewise private.
        assert!(!is_public_readable(
            "https://localhost:3000/alice/private/profile/card",
            base
        ));
        assert!(!is_public_readable(
            "https://localhost:3000/alice/x/y/profile/card",
            base
        ));
        // A trailing-slash container ending in `profile/card/` is not the profile document.
        assert!(!is_public_readable(
            "https://localhost:3000/alice/profile/card/",
            base
        ));
    }

    #[test]
    fn wants_container_link_is_detected() {
        let mut h = HeaderMap::new();
        assert!(!wants_container_via_link(&h));
        h.append(
            header::LINK,
            HeaderValue::from_static("<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\""),
        );
        assert!(wants_container_via_link(&h));

        // ldp:Container also counts.
        let mut h2 = HeaderMap::new();
        h2.append(
            header::LINK,
            HeaderValue::from_static("<http://www.w3.org/ns/ldp#Container>; rel=\"type\""),
        );
        assert!(wants_container_via_link(&h2));

        // A non-type Link (e.g. an acl rel) does NOT request a container.
        let mut h3 = HeaderMap::new();
        h3.append(
            header::LINK,
            HeaderValue::from_static("<https://pod.example/x.acl>; rel=\"acl\""),
        );
        assert!(!wants_container_via_link(&h3));
    }

    #[test]
    fn require_content_type_distinguishes_absent_from_present() {
        // Absent ⇒ 400 (content-type-reject).
        let empty = HeaderMap::new();
        assert_eq!(
            require_content_type(&empty).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        // Whitespace-only ⇒ also 400.
        let mut blank = HeaderMap::new();
        blank.insert(header::CONTENT_TYPE, HeaderValue::from_static("   "));
        assert_eq!(
            require_content_type(&blank).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        // Present (even an unsupported value) ⇒ Ok (415 is decided later by `classify`).
        let mut present = HeaderMap::new();
        present.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(require_content_type(&present).unwrap(), "text/plain");
    }
}
