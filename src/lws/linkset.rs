// AUTHORED-BY Claude Fable 5
//! **RFC 9264 linkset metadata (M3)** — the standalone linkset resource the JLWS spec mandates for
//! every storage resource (`jeswr/lws-spec` `index.html` §metadata / §metadata-categories /
//! §metadata-updates), flag-gated under the same `SOLID_SERVER_LWS` invariant as M1/M2.
//!
//! ## The linkset resource and its URI
//! Each resource's metadata is served as an `application/linkset+json` document at
//! **`<resource>?linkset`** — a server-chosen (spec: opaque) URI on the SAME path as the resource.
//! Same-path is load-bearing three ways:
//! - **authorization**: the WAC walk and the M2 audience containment key on the path, so reading a
//!   linkset requires `acl:Read` on ITS resource (Control for an `.acl` — its metadata is as
//!   Control-gated as its content) and a token audience/`authorization_details` scope covering the
//!   resource covers its linkset — no second scope algebra;
//! - **discovery**: every LWS-on GET/HEAD carries `Link: <…?linkset>; rel="linkset"` (§metadata),
//!   and 201 creates carry the same (+`rel="up"`) per §http-create;
//! - **flag-off invariance**: the flag-off surface never inspects query strings, so these URIs
//!   simply serve the resource as before — byte-identical (pinned).
//!
//! ## Document shape (RFC 9264 §4.2)
//! One context object anchored at the resource. **System-managed** links (server-derived, never
//! client-writable — §metadata-categories, D13): `up` (the parent container; absent on the storage
//! root), `type` (`jlws:Container`/`jlws:DataResource`), `acl` (the resource's access-control
//! document), and the `…lws#storageDescription` link. `mediaType`/`size`/`modified` remain
//! attributes of the container-listing member description (the shape that carries them); `items`
//! is the container listing's job (paginated there) and is deliberately not duplicated into the
//! linkset. **User-managed** links (`describedby`, `title`, `creator`, custom ABSOLUTE-URI
//! relations) are persisted as one validated JSON literal in the resource's own graph
//! ([`crate::store::sparql::p_linkset_json`]) — so a resource DELETE drops its linkset atomically
//! (§metadata: "deleting a resource MUST delete its linkset resource") and a content re-write
//! preserves it.
//!
//! ## Update discipline (§metadata-updates — the strict conditional contract)
//! `PATCH … ?linkset` with `application/merge-patch+json` (RFC 7386, advertised via
//! `Accept-Patch`) is the ONLY write:
//! - no `If-Match` ⇒ **428 Precondition Required**; a stale one ⇒ **412**;
//! - the patch is applied to the CURRENT full document, then every system-managed member must be
//!   UNCHANGED — else **409** with problem type `…/problems/system-managed-metadata` (a no-op
//!   echo of a system link is fine; changing one is not);
//! - the resulting user-managed links are strictly validated (shape, absolute-URI hrefs,
//!   string-only target attributes, bounded counts/sizes) — fail-closed **422**;
//! - persistence is a COMPARE-AND-SWAP against the observed linkset revision (or, for a
//!   never-patched linkset, the resource record's etag) — a lost race is a **412**, never a lost
//!   update — and every success mints a fresh revision, so the ETag rotates (MUST).
//!
//! PUT/POST/DELETE on a linkset URI are **405** (PUT is spec-OPTIONAL and not offered; the
//! linkset's lifecycle is its resource's).
//!
//! Every 4xx here carries RFC 9457 problem details (D17), like the rest of the LWS surface.

use axum::body::Body;
use axum::http::{
    header, HeaderMap, HeaderName, HeaderValue, Response as HttpResponse, StatusCode,
};
use axum::response::Response;
use bytes::Bytes;
use serde_json::{json, Map, Value};
use std::sync::Arc;

use crate::authz::AccessMode;
use crate::error::ServerError;
use crate::ldp::conditional;
use crate::ldp::handler::{parent_container_of, LdpState};
use crate::ldp::target::LdpTarget;
use crate::store::{LinksetCas, Store};

use solid_oidc_verifier::verifier::VerifiedToken;

use super::{
    JLWS_NS, LWS_WD_NS, PROBLEM_INVALID_LINKSET_PATCH, PROBLEM_LINKSET_NOT_ACCEPTABLE,
    PROBLEM_LINKSET_PRECONDITION_FAILED, PROBLEM_LINKSET_TOO_LARGE, PROBLEM_METADATA_PRECONDITION,
    PROBLEM_NOT_FOUND, PROBLEM_SYSTEM_MANAGED, PROBLEM_UNSUPPORTED_PATCH_TYPE,
    STORAGE_DESCRIPTION_PATH,
};

/// The linkset media type (RFC 9264 §4.2).
pub const MEDIA_LINKSET_JSON: &str = "application/linkset+json";
/// The one PATCH format the spec REQUIRES for linkset updates (RFC 7386).
pub const MEDIA_MERGE_PATCH: &str = "application/merge-patch+json";
/// The query string that selects a resource's linkset (server-chosen; spec: opaque).
const LINKSET_QUERY: &str = "linkset";
/// The methods a linkset resource supports.
const ALLOW: &str = "GET, HEAD, PATCH, OPTIONS";

/// Caps on the user-managed half (fail-closed policy bounds, not spec numbers): relations per
/// linkset / targets per relation / members per target object / value byte length / serialized
/// total. Oversized ⇒ 413/422, never truncated.
const MAX_USER_RELS: usize = 32;
const MAX_TARGETS_PER_REL: usize = 32;
const MAX_MEMBERS_PER_TARGET: usize = 16;
const MAX_STRING_LEN: usize = 2048;
const MAX_USER_JSON_BYTES: usize = 16 * 1024;

/// Does this request's query string select the linkset resource? (Exactly `?linkset` — any other
/// query keeps the existing behaviour, so nothing pre-existing changes shape.)
pub fn selects_linkset(query: Option<&str>) -> bool {
    query == Some(LINKSET_QUERY)
}

/// The linkset URI for a resource.
pub fn linkset_uri(resource_iri: &str) -> String {
    format!("{resource_iri}?{LINKSET_QUERY}")
}

/// Append the `Link: <…?linkset>; rel="linkset"` discovery header (§metadata) for `resource_iri`.
pub fn add_linkset_link(headers: &mut HeaderMap, resource_iri: &str) {
    if let Ok(v) =
        HeaderValue::from_str(&format!("<{}>; rel=\"linkset\"", linkset_uri(resource_iri)))
    {
        headers.append(header::LINK, v);
    }
}

/// Append the spec-required create-response links (§http-create: a 201 MUST carry `rel="up"` +
/// `rel="linkset"`): called by the PUT/POST create paths when the LWS flag is on.
pub fn append_create_links(headers: &mut HeaderMap, created_iri: &str) {
    add_linkset_link(headers, created_iri);
    if let Some(parent) = parent_container_of(created_iri) {
        if let Ok(v) = HeaderValue::from_str(&format!("<{parent}>; rel=\"up\"")) {
            headers.append(header::LINK, v);
        }
    }
}

/// The linkset resource's method-advertisement headers (`Allow` + `Accept-Patch`) — shared by the
/// linkset GET/HEAD response and the OPTIONS handler's linkset branch (roborev Low on 53296c0: an
/// `OPTIONS …?linkset` must advertise the LINKSET surface, not the LDP verb set).
pub fn add_method_advertisement(headers: &mut HeaderMap) {
    headers.insert(header::ALLOW, HeaderValue::from_static(ALLOW));
    headers.insert(
        HeaderName::from_static("accept-patch"),
        HeaderValue::from_static(MEDIA_MERGE_PATCH),
    );
}

/// A `405 Method Not Allowed` for a write verb on a linkset URI — with the RFC 9110-required
/// `Allow` header and the D17 problem-details body (which `ServerError` cannot carry together).
pub fn method_not_allowed() -> Response {
    let body = json!({
        "type": super::PROBLEM_LINKSET_METHOD,
        "title": "a linkset resource supports GET/HEAD/PATCH only; its lifecycle is its resource's",
        "status": 405,
    });
    problem_response(
        StatusCode::METHOD_NOT_ALLOWED,
        body,
        &[(header::ALLOW, ALLOW)],
    )
}

/// `GET`/`HEAD` a resource's linkset. Runs the SAME single-pass read authorization as the
/// resource itself (`acl:Read`; Control for an `.acl`), 404s only after an Allow, honours
/// `If-None-Match` (304), and serves the RFC 9264 document with a rotating strong ETag.
pub async fn serve<S: Store>(
    state: &Arc<LdpState<S>>,
    target: &LdpTarget,
    token: &VerifiedToken,
    origin: Option<&str>,
    req_headers: &HeaderMap,
    with_body: bool,
) -> Result<Response, ServerError> {
    // Authorization first (the same 401/403-before-existence discipline as every read); the plan's
    // target row doubles as the existence check + the etag input.
    let (_perms, meta) = state
        .authorize_read(
            if with_body { "GET" } else { "HEAD" },
            target,
            token,
            origin,
        )
        .await?;
    let Some(meta) = meta else {
        return Err(not_found());
    };

    // Conneg: the linkset is available as application/linkset+json (MUST). Absent Accept or a
    // wildcard is served; anything that cannot accept it is a 406 problem.
    let accept = req_headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok());
    if !accepts_linkset(accept) {
        return Err(ServerError::LwsProblem {
            status: 406,
            type_uri: PROBLEM_LINKSET_NOT_ACCEPTABLE,
            title: "a linkset resource is available as application/linkset+json only",
        });
    }

    let stored = state.store.get_linkset(&target.iri).await?;
    let user = parse_stored_user(stored.as_ref())?;
    let etag = linkset_etag(stored.as_ref().map(|(_, rev)| rev.as_str()), &meta.etag);
    let doc = build_document(state.base_url(), target, user.as_ref());

    let mut out = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&etag) {
        out.insert(header::ETAG, v);
    }
    add_method_advertisement(&mut out);
    // `Vary: Accept` (RFC 9110 §12.5.5 — the roborev Medium on 53296c0): the linkset's BYTES never
    // vary by `Accept`, but its STATUS does (a non-accepting `Accept` is a 406 above), so a shared
    // cache must key on `Accept` or it could serve a cached 200 to a client that negotiated a 406.
    // On the shared header map, so the 200, HEAD, and 304 all carry it.
    out.insert(header::VARY, HeaderValue::from_static("Accept"));

    // Conditional GET: If-None-Match (weak comparison) against the linkset's own validator. The
    // linkset has no advertised Last-Modified, so If-Modified-Since does not participate.
    let inm = req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if conditional::evaluate_read(inm, None, &etag, None)
        == conditional::ReadPrecondition::NotModified
    {
        return Ok((StatusCode::NOT_MODIFIED, out).into_response2());
    }

    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(MEDIA_LINKSET_JSON),
    );
    let body = serde_json::to_vec(&doc)
        .map_err(|e| ServerError::Storage(format!("linkset serialise: {e}")))?;
    if with_body {
        Ok((StatusCode::OK, out, Bytes::from(body)).into_response2())
    } else {
        // HEAD: GET's headers (incl. Content-Length) without the body.
        if let Ok(v) = HeaderValue::from_str(&body.len().to_string()) {
            out.insert(header::CONTENT_LENGTH, v);
        }
        Ok((StatusCode::OK, out).into_response2())
    }
}

/// `PATCH … ?linkset` — the §metadata-updates merge-patch, under the strict If-Match/428
/// discipline and the system-managed guard. See the module doc for the full sequence.
pub async fn patch<S: Store>(
    state: &Arc<LdpState<S>>,
    target: &LdpTarget,
    token: &VerifiedToken,
    origin: Option<&str>,
    req_headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, ServerError> {
    // (1) The one supported patch format (spec MUST; further formats would be advertised via
    // Accept-Patch). Checked BEFORE any state so the 415 leaks nothing.
    let content_type = req_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        });
    if content_type.as_deref() != Some(MEDIA_MERGE_PATCH) {
        let body = json!({
            "type": PROBLEM_UNSUPPORTED_PATCH_TYPE,
            "title": "linkset updates use application/merge-patch+json",
            "status": 415,
        });
        return Ok(problem_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            body,
            &[(HeaderName::from_static("accept-patch"), MEDIA_MERGE_PATCH)],
        ));
    }

    // (2) Authorization: writing user-managed metadata is a WRITE on the resource (`acl:Control`
    // for an `.acl` — the authorize_mode override), decided before any existence probe.
    let granted = state
        .authorize_mode(target, AccessMode::Write, token, origin)
        .await?;
    // V4 (decisions/0003): the If-Match evaluation below discloses a validator derived from the
    // resource's state — the SAME conditional-channel Read-gate as every mutating verb applies.
    state.guard_conditional_requires_read(&target.iri, req_headers, &granted, token)?;

    // (3) The spec's 428: a linkset update without If-Match is rejected BEFORE any state probe
    // (header-only — leaks nothing).
    let Some(if_match) = req_headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return Err(ServerError::LwsProblem {
            status: 428,
            type_uri: PROBLEM_METADATA_PRECONDITION,
            title: "a linkset update must carry If-Match (fetch the linkset, then update against \
                    its ETag)",
        });
    };

    // (4) Existence — after auth + the Read-gate (a reader is entitled to the 404).
    let Some(meta) = state.store.meta(&target.iri).await? else {
        return Err(not_found());
    };
    let stored = state.store.get_linkset(&target.iri).await?;
    let user = parse_stored_user(stored.as_ref())?;
    let current_etag = linkset_etag(stored.as_ref().map(|(_, rev)| rev.as_str()), &meta.etag);

    // (5) Strong If-Match comparison (RFC 9110 §13.1.1; `*` = any current representation).
    if !if_match_matches(if_match, &current_etag) {
        return Err(precondition_failed());
    }

    // (6) The patch document itself (RFC 5789: an unparseable patch body is a 400-class error).
    let patch_doc: Value = serde_json::from_slice(&body).map_err(|_| ServerError::LwsProblem {
        status: 400,
        type_uri: PROBLEM_INVALID_LINKSET_PATCH,
        title: "the merge-patch body is not valid JSON",
    })?;

    // (7) RFC 7386: apply to the CURRENT full document, then re-validate everything.
    let current_doc = build_document(state.base_url(), target, user.as_ref());
    let merged = merge_patch(&current_doc, &patch_doc);
    let new_user = extract_user_relations(&current_doc, &merged, target)?;

    // (8) Persist under CAS; serialisation is deterministic (serde_json's BTreeMap ordering).
    let new_json = serde_json::to_string(&Value::Object(new_user))
        .map_err(|e| ServerError::Storage(format!("linkset serialise: {e}")))?;
    if new_json.len() > MAX_USER_JSON_BYTES {
        return Err(ServerError::LwsProblem {
            status: 413,
            type_uri: PROBLEM_LINKSET_TOO_LARGE,
            title: "the user-managed linkset exceeds the size bound",
        });
    }
    let new_rev = mint_rev()?;
    let cas = match &stored {
        Some((_, rev)) => LinksetCas::ExpectRev(rev),
        None => LinksetCas::ExpectNone {
            record_etag: &meta.etag,
        },
    };
    let applied = state
        .store
        .set_linkset(&target.iri, &new_json, &new_rev, cas)
        .await?;
    if !applied {
        // The CAS lost (a concurrent linkset update, content re-write, or delete moved the state
        // we validated against) — the client re-fetches and retries: exactly a 412.
        return Err(precondition_failed());
    }

    // (9) 204 + the ROTATED ETag (spec MUST: successful updates rotate it).
    let mut out = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&linkset_etag(Some(&new_rev), &meta.etag)) {
        out.insert(header::ETAG, v);
    }
    Ok((StatusCode::NO_CONTENT, out).into_response2())
}

// --- document construction ----------------------------------------------------------------------

/// The system-managed relation names of the linkset context object (§metadata-categories, plus
/// `anchor` itself and the storage-description rel in both namespace spellings — D14 alias). A
/// merge-patch may echo these unchanged; it may never alter them.
fn is_system_member(name: &str) -> bool {
    matches!(
        name,
        "anchor" | "up" | "type" | "acl" | "linkset" | "mediaType" | "size" | "modified" | "items"
    ) || name == storage_description_rel(JLWS_NS)
        || name == storage_description_rel(LWS_WD_NS)
}

fn storage_description_rel(ns: &str) -> String {
    format!("{ns}storageDescription")
}

/// Build the FULL RFC 9264 document for `target`: the system-managed links derived from the
/// resource's identity + the validated user-managed relations merged in.
fn build_document(base_url: &str, target: &LdpTarget, user: Option<&Map<String, Value>>) -> Value {
    let mut ctx = Map::new();
    ctx.insert("anchor".into(), json!(target.iri));
    if let Some(parent) = parent_container_of(&target.iri) {
        ctx.insert("up".into(), json!([{ "href": parent }]));
    }
    let type_iri = if target.is_container {
        format!("{JLWS_NS}Container")
    } else {
        format!("{JLWS_NS}DataResource")
    };
    ctx.insert("type".into(), json!([{ "href": type_iri }]));
    ctx.insert(
        "acl".into(),
        json!([{ "href": format!("{}.acl", target.iri) }]),
    );
    ctx.insert(
        storage_description_rel(JLWS_NS),
        json!([{ "href": format!("{}{}", base_url.trim_end_matches('/'), STORAGE_DESCRIPTION_PATH) }]),
    );
    if let Some(user) = user {
        for (k, v) in user {
            // Stored user relations were validated at write; system names can never be among them
            // (extract_user_relations refuses them), but skip defensively anyway.
            if !is_system_member(k) {
                ctx.insert(k.clone(), v.clone());
            }
        }
    }
    json!({ "linkset": [Value::Object(ctx)] })
}

/// Parse the STORED user-relations JSON (written by [`patch`], so structurally valid; a corrupt
/// value is a backend fault, surfaced — never silently dropped).
fn parse_stored_user(
    stored: Option<&(String, String)>,
) -> Result<Option<Map<String, Value>>, ServerError> {
    match stored {
        None => Ok(None),
        Some((json_str, _rev)) => match serde_json::from_str::<Value>(json_str) {
            Ok(Value::Object(map)) => Ok(Some(map)),
            _ => Err(ServerError::Storage(
                "stored linkset user relations are corrupt".into(),
            )),
        },
    }
}

/// Validate the MERGED document and extract its user-managed relations.
///
/// Fail-closed on every deviation:
/// - the document must be exactly `{"linkset": [one context object]}` (422);
/// - every system-managed member must be VALUE-EQUAL to the current document's (409 — the spec's
///   `system-managed-metadata` problem; adding or removing one counts as modifying it);
/// - every other member must be a permitted user relation (`describedby`/`title`/`creator` or an
///   absolute http(s) extension relation) whose value is a bounded, non-empty array of link
///   target objects with an absolute http(s) `href` and string-only attributes (422).
fn extract_user_relations(
    current: &Value,
    merged: &Value,
    target: &LdpTarget,
) -> Result<Map<String, Value>, ServerError> {
    let invalid = |title: &'static str| ServerError::LwsProblem {
        status: 422,
        type_uri: PROBLEM_INVALID_LINKSET_PATCH,
        title,
    };
    let system_managed = ServerError::LwsProblem {
        status: 409,
        type_uri: PROBLEM_SYSTEM_MANAGED,
        title: "system-managed linkset members (anchor/up/type/acl/storage-description/…) cannot \
                be modified",
    };

    // Shape: {"linkset": [exactly one object]} and nothing else at the top level.
    let Some(top) = merged.as_object() else {
        return Err(invalid("the merged linkset document must be a JSON object"));
    };
    if top.len() != 1 {
        return Err(invalid(
            "the linkset document carries exactly the \"linkset\" member",
        ));
    }
    let Some(contexts) = top.get("linkset").and_then(Value::as_array) else {
        return Err(invalid("the \"linkset\" member must be an array"));
    };
    let [Value::Object(ctx)] = contexts.as_slice() else {
        return Err(invalid(
            "this linkset carries exactly one context object (the resource anchor)",
        ));
    };
    let current_ctx = current
        .get("linkset")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_object)
        .expect("build_document shape");

    let mut user = Map::new();
    for (k, v) in ctx {
        if is_system_member(k) {
            // Echoing a system member UNCHANGED is a no-op; anything else modifies it — 409.
            if current_ctx.get(k) != Some(v) {
                return Err(system_managed);
            }
            continue;
        }
        // A user relation: registered user-managed names, or an absolute-URI extension relation
        // (RFC 9264 extension discipline — also collision-proof against future system names).
        let named_ok =
            matches!(k.as_str(), "describedby" | "title" | "creator") || is_absolute_http_url(k);
        if !named_ok {
            return Err(invalid(
                "custom linkset relations must be absolute http(s) URIs",
            ));
        }
        validate_targets(v).map_err(invalid)?;
        user.insert(k.clone(), v.clone());
    }
    // Every CURRENT system member must survive in the merged doc (a merge-patch `null` removing
    // one is also a modification).
    for k in current_ctx.keys() {
        if is_system_member(k) && !ctx.contains_key(k) {
            return Err(ServerError::LwsProblem {
                status: 409,
                type_uri: PROBLEM_SYSTEM_MANAGED,
                title: "system-managed linkset members cannot be removed",
            });
        }
    }
    if user.len() > MAX_USER_RELS {
        return Err(invalid("too many user-managed relations"));
    }
    // The anchor is system-managed and always present; sanity-pin it (unreachable — equality was
    // enforced above — but the anchor's identity is the whole document's, so double-check).
    debug_assert_eq!(ctx.get("anchor"), Some(&json!(target.iri)));
    Ok(user)
}

/// One relation's link-target array: non-empty, bounded, each an object with an absolute http(s)
/// `href` and OPTIONAL string-only target attributes (RFC 9264 §4.2.4 shapes like `type`/`title`;
/// nested structures are refused — fail closed).
fn validate_targets(v: &Value) -> Result<(), &'static str> {
    let Some(targets) = v.as_array() else {
        return Err("a linkset relation's value must be an array of link target objects");
    };
    if targets.is_empty() {
        return Err("a linkset relation must have at least one target (remove it with null)");
    }
    if targets.len() > MAX_TARGETS_PER_REL {
        return Err("too many link targets for one relation");
    }
    for t in targets {
        let Some(obj) = t.as_object() else {
            return Err("each link target must be an object");
        };
        if obj.len() > MAX_MEMBERS_PER_TARGET {
            return Err("too many members on a link target object");
        }
        match obj.get("href").and_then(Value::as_str) {
            Some(href) if is_absolute_http_url(href) && href.len() <= MAX_STRING_LEN => {}
            _ => return Err("each link target needs an absolute http(s) href"),
        }
        for (k, v) in obj {
            if k == "href" {
                continue;
            }
            match v.as_str() {
                Some(s) if s.len() <= MAX_STRING_LEN && k.len() <= MAX_STRING_LEN => {}
                _ => return Err("link target attributes must be bounded strings"),
            }
        }
    }
    Ok(())
}

// --- validators / small helpers ------------------------------------------------------------------

/// The linkset resource's STRONG entity tag: revision-derived once patched; derived from the
/// resource record's etag before any patch (so a content re-write of a never-patched resource
/// also rotates it — the system links' inputs may have changed).
fn linkset_etag(rev: Option<&str>, resource_etag: &str) -> String {
    match rev {
        Some(rev) => format!("\"ls-{}\"", rev.trim_matches('"')),
        None => format!("\"ls0-{}\"", resource_etag.trim_matches('"')),
    }
}

/// Strong `If-Match` evaluation (RFC 9110 §13.1.1): `*` matches any current representation; a
/// listed tag must equal the current one byte-for-byte (a `W/`-prefixed tag never strong-matches).
fn if_match_matches(header_value: &str, current_etag: &str) -> bool {
    header_value.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || (!candidate.starts_with("W/") && candidate == current_etag)
    })
}

/// RFC 7386 JSON merge patch.
fn merge_patch(target: &Value, patch: &Value) -> Value {
    match patch {
        Value::Object(patch_obj) => {
            let mut out = match target {
                Value::Object(o) => o.clone(),
                _ => Map::new(),
            };
            for (k, v) in patch_obj {
                if v.is_null() {
                    out.remove(k);
                } else {
                    let base = out.get(k).cloned().unwrap_or(Value::Null);
                    out.insert(k.clone(), merge_patch(&base, v));
                }
            }
            Value::Object(out)
        }
        _ => patch.clone(),
    }
}

/// Does the Accept header (if any) accept `application/linkset+json`? Wildcards and an absent
/// header do; an explicit list must name it (or a covering wildcard) with q > 0.
fn accepts_linkset(accept: Option<&str>) -> bool {
    let Some(raw) = accept else { return true };
    if raw.trim().is_empty() {
        return true;
    }
    for part in raw.split(',') {
        let (media, q, _) = super::parse_accept_part(part);
        if q > 0.0 && matches!(media.as_str(), MEDIA_LINKSET_JSON | "application/*" | "*/*") {
            return true;
        }
    }
    false
}

fn is_absolute_http_url(s: &str) -> bool {
    match url::Url::parse(s) {
        Ok(u) => matches!(u.scheme(), "http" | "https"),
        Err(_) => false,
    }
}

/// Mint an operation-unique linkset revision (16 CSPRNG bytes, hex). FAILS CLOSED if the OS RNG
/// is unavailable (the update errors; a weak or colliding revision could break the CAS confirm).
fn mint_rev() -> Result<String, ServerError> {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf)
        .map_err(|e| ServerError::Storage(format!("OS RNG unavailable for linkset rev: {e}")))?;
    Ok(buf.iter().fold(String::with_capacity(32), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    }))
}

fn not_found() -> ServerError {
    ServerError::LwsProblem {
        status: 404,
        type_uri: PROBLEM_NOT_FOUND,
        title: "no such resource",
    }
}

fn precondition_failed() -> ServerError {
    ServerError::LwsProblem {
        status: 412,
        type_uri: PROBLEM_LINKSET_PRECONDITION_FAILED,
        title: "the If-Match precondition does not match the linkset's current entity tag",
    }
}

/// Build an RFC 9457 problem response with extra headers (`ServerError::LwsProblem` cannot carry
/// headers; used for the Allow-bearing 405 and the Accept-Patch-bearing 415).
fn problem_response(
    status: StatusCode,
    body: Value,
    extra: &[(HeaderName, &'static str)],
) -> Response {
    let mut builder = HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/problem+json");
    for (name, value) in extra {
        builder = builder.header(name, *value);
    }
    builder
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response2())
}

/// A local `IntoResponse` shim: axum's trait method name (`into_response`) collides with nothing
/// here, but importing the trait broadly shadows nothing either — this tiny extension keeps the
/// call sites uniform without a glob import.
trait IntoResponse2 {
    fn into_response2(self) -> Response;
}
impl<T: axum::response::IntoResponse> IntoResponse2 for T {
    fn into_response2(self) -> Response {
        self.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(iri: &str) -> LdpTarget {
        LdpTarget {
            iri: iri.to_string(),
            htu: iri.to_string(),
            is_container: iri.ends_with('/'),
        }
    }

    const BASE: &str = "https://pod.example";
    const DOC: &str = "https://pod.example/alice/notes/a.txt";

    fn ctx_of(doc: &Value) -> &Map<String, Value> {
        doc["linkset"][0].as_object().unwrap()
    }

    // --- document shape ---------------------------------------------------------------------

    #[test]
    fn system_links_are_derived_from_the_resource_identity() {
        let doc = build_document(BASE, &target(DOC), None);
        let ctx = ctx_of(&doc);
        assert_eq!(ctx["anchor"], json!(DOC));
        assert_eq!(
            ctx["up"],
            json!([{ "href": "https://pod.example/alice/notes/" }])
        );
        assert_eq!(
            ctx["type"],
            json!([{ "href": format!("{JLWS_NS}DataResource") }])
        );
        assert_eq!(ctx["acl"], json!([{ "href": format!("{DOC}.acl") }]));
        assert_eq!(
            ctx[&storage_description_rel(JLWS_NS)],
            json!([{ "href": "https://pod.example/.well-known/lws" }])
        );
        // A container types as Container; the storage root has no `up`.
        let cdoc = build_document(BASE, &target("https://pod.example/alice/"), None);
        assert_eq!(
            ctx_of(&cdoc)["type"],
            json!([{ "href": format!("{JLWS_NS}Container") }])
        );
        let root = build_document(BASE, &target("https://pod.example/"), None);
        assert!(!ctx_of(&root).contains_key("up"), "the root has no parent");
    }

    #[test]
    fn user_relations_ride_beside_the_system_links() {
        let mut user = Map::new();
        user.insert(
            "describedby".into(),
            json!([{ "href": "https://pod.example/alice/meta/a" }]),
        );
        let doc = build_document(BASE, &target(DOC), Some(&user));
        assert_eq!(
            ctx_of(&doc)["describedby"],
            json!([{ "href": "https://pod.example/alice/meta/a" }])
        );
    }

    // --- merge patch ------------------------------------------------------------------------

    #[test]
    fn rfc7386_merge_patch_semantics() {
        let base = json!({ "a": { "b": 1, "c": 2 }, "d": [1, 2] });
        // Nested merge, null removal, array replacement.
        let merged = merge_patch(&base, &json!({ "a": { "b": null, "e": 3 }, "d": [9] }));
        assert_eq!(merged, json!({ "a": { "c": 2, "e": 3 }, "d": [9] }));
        // A non-object patch replaces wholesale.
        assert_eq!(merge_patch(&base, &json!("x")), json!("x"));
    }

    // --- patch validation (extract_user_relations) -------------------------------------------

    fn patched(patch: Value) -> Result<Map<String, Value>, ServerError> {
        let t = target(DOC);
        let current = build_document(BASE, &t, None);
        let merged = merge_patch(&current, &patch);
        extract_user_relations(&current, &merged, &t)
    }

    fn status_of(e: &ServerError) -> u16 {
        match e {
            ServerError::LwsProblem { status, .. } => *status,
            other => panic!("expected an LWS problem, got {other:?}"),
        }
    }

    #[test]
    fn adding_a_describedby_is_accepted() {
        let user = patched(json!({
            "linkset": [{
                "anchor": DOC,
                "up": [{ "href": "https://pod.example/alice/notes/" }],
                "type": [{ "href": format!("{JLWS_NS}DataResource") }],
                "acl": [{ "href": format!("{DOC}.acl") }],
                storage_description_rel(JLWS_NS): [{ "href": "https://pod.example/.well-known/lws" }],
                "describedby": [{ "href": "https://pod.example/alice/meta/a", "type": "text/turtle" }],
                "https://example.org/rel/source": [{ "href": "https://upstream.example/x" }],
            }]
        }))
        .expect("valid patch");
        assert_eq!(user.len(), 2);
        assert!(user.contains_key("describedby"));
        // Note the merged doc REPLACED the whole context object (RFC 7386 array semantics), so the
        // client echoed the system links unchanged — accepted as a no-op on them.
    }

    #[test]
    fn modifying_or_removing_system_links_is_a_409() {
        // Changing `up` (the §http-move mechanism is NOT offered — no MoveResource capability).
        let e = patched(json!({
            "linkset": [{
                "anchor": DOC,
                "up": [{ "href": "https://pod.example/elsewhere/" }],
                "type": [{ "href": format!("{JLWS_NS}DataResource") }],
                "acl": [{ "href": format!("{DOC}.acl") }],
                storage_description_rel(JLWS_NS): [{ "href": "https://pod.example/.well-known/lws" }],
            }]
        }))
        .unwrap_err();
        assert_eq!(status_of(&e), 409);
        // Removing `acl` (absent from the replaced context object).
        let e = patched(json!({
            "linkset": [{
                "anchor": DOC,
                "up": [{ "href": "https://pod.example/alice/notes/" }],
                "type": [{ "href": format!("{JLWS_NS}DataResource") }],
                storage_description_rel(JLWS_NS): [{ "href": "https://pod.example/.well-known/lws" }],
            }]
        }))
        .unwrap_err();
        assert_eq!(status_of(&e), 409);
        // Changing the anchor.
        let e = patched(json!({
            "linkset": [{
                "anchor": "https://pod.example/alice/notes/b.txt",
                "up": [{ "href": "https://pod.example/alice/notes/" }],
                "type": [{ "href": format!("{JLWS_NS}DataResource") }],
                "acl": [{ "href": format!("{DOC}.acl") }],
                storage_description_rel(JLWS_NS): [{ "href": "https://pod.example/.well-known/lws" }],
            }]
        }))
        .unwrap_err();
        assert_eq!(status_of(&e), 409);
        // The WD-alias spelling of the storage-description rel is system-managed too (D14).
        let e = patched(json!({
            "linkset": [{
                "anchor": DOC,
                "up": [{ "href": "https://pod.example/alice/notes/" }],
                "type": [{ "href": format!("{JLWS_NS}DataResource") }],
                "acl": [{ "href": format!("{DOC}.acl") }],
                storage_description_rel(JLWS_NS): [{ "href": "https://pod.example/.well-known/lws" }],
                storage_description_rel(LWS_WD_NS): [{ "href": "https://evil.example/desc" }],
            }]
        }))
        .unwrap_err();
        assert_eq!(status_of(&e), 409);
    }

    #[test]
    fn malformed_user_relations_are_a_422() {
        let sys = |extra: Value| {
            let mut ctx = json!({
                "anchor": DOC,
                "up": [{ "href": "https://pod.example/alice/notes/" }],
                "type": [{ "href": format!("{JLWS_NS}DataResource") }],
                "acl": [{ "href": format!("{DOC}.acl") }],
                storage_description_rel(JLWS_NS): [{ "href": "https://pod.example/.well-known/lws" }],
            });
            for (k, v) in extra.as_object().unwrap() {
                ctx[k] = v.clone();
            }
            json!({ "linkset": [ctx] })
        };
        for (bad, why) in [
            (json!({ "describedby": "not-an-array" }), "non-array value"),
            (json!({ "describedby": [] }), "empty target list"),
            (
                json!({ "describedby": [{ "no_href": true }] }),
                "missing href",
            ),
            (
                json!({ "describedby": [{ "href": "/relative" }] }),
                "relative href",
            ),
            (
                json!({ "describedby": [{ "href": "ftp://x/" }] }),
                "non-http href",
            ),
            (
                json!({ "describedby": [{ "href": "https://x.example/", "attrs": { "nested": 1 } }] }),
                "non-string attribute",
            ),
            (
                json!({ "customrel": [{ "href": "https://x.example/" }] }),
                "bare custom rel name",
            ),
        ] {
            let e = patched(sys(bad)).unwrap_err();
            assert_eq!(status_of(&e), 422, "{why}");
        }
        // Shape violations at the document level.
        for bad in [
            json!([]),                                      // not an object
            json!({ "linkset": {} }),                       // linkset not an array
            json!({ "linkset": [] }),                       // no context object
            json!({ "linkset": [{}, {}] }),                 // two context objects
            json!({ "linkset": [{}], "profile": "extra" }), // extra top-level member
        ] {
            let t = target(DOC);
            let current = build_document(BASE, &t, None);
            let e = extract_user_relations(&current, &bad, &t).unwrap_err();
            assert_eq!(status_of(&e), 422, "{bad}");
        }
    }

    // --- validators ---------------------------------------------------------------------------

    #[test]
    fn etag_derivation_and_if_match() {
        // Never patched: derived from the resource record etag (rotates on content re-write).
        assert_eq!(linkset_etag(None, "\"abc\""), "\"ls0-abc\"");
        // Patched: revision-derived (rotates on every successful update).
        assert_eq!(linkset_etag(Some("r1"), "\"abc\""), "\"ls-r1\"");
        assert!(if_match_matches("*", "\"ls-r1\""));
        assert!(if_match_matches("\"ls-r1\"", "\"ls-r1\""));
        assert!(if_match_matches("\"x\", \"ls-r1\"", "\"ls-r1\""));
        assert!(!if_match_matches("\"ls-r2\"", "\"ls-r1\""));
        // A weak tag never strong-matches (RFC 9110 §13.1.1).
        assert!(!if_match_matches("W/\"ls-r1\"", "\"ls-r1\""));
    }

    #[test]
    fn linkset_selection_and_conneg() {
        assert!(selects_linkset(Some("linkset")));
        assert!(!selects_linkset(None));
        assert!(!selects_linkset(Some("linkset=1")));
        assert!(!selects_linkset(Some("other")));
        assert!(accepts_linkset(None));
        assert!(accepts_linkset(Some("*/*")));
        assert!(accepts_linkset(Some("application/*")));
        assert!(accepts_linkset(Some(MEDIA_LINKSET_JSON)));
        assert!(accepts_linkset(Some(
            "text/html, application/linkset+json;q=0.5"
        )));
        assert!(!accepts_linkset(Some("text/html")));
        assert!(!accepts_linkset(Some("application/linkset+json;q=0")));
    }
}
