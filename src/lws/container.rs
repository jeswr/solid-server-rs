// AUTHORED-BY Claude Fable 5
//! The **LWS container representation** (`index.html` §container-representation; DECISIONS.md
//! D12/D13): the flat, server-managed JSON-LD listing —
//! `{"@context", "id", "type": "Container", "totalItems", "items": [...]}`.
//!
//! Distinct from the Solid LDP `ldp:contains` graph the existing surface renders: containment is
//! server-managed METADATA here, not client-authored RDF, so the LWS shape carries ONLY the
//! listing (D3: a container is never a data resource — client RDF stored on the container does
//! NOT appear in this representation; it stays reachable through the Solid-surface rendering).
//!
//! ## Which representation a request gets (the composition rule)
//! [`negotiate_container`] selects the LWS shape only when the request UNAMBIGUOUSLY asks for it:
//! `application/lws+json`, or `application/ld+json` carrying the
//! `profile="https://w3id.org/jeswr/lws/v1"` parameter, at a weight at least equal to every other
//! producible type — or plain `application/json` when nothing the Solid surface can produce is
//! acceptable (rescuing the plain-JSON client that previously got a 406, without ever shadowing an
//! existing response). Every other `Accept` resolves exactly as before, so the Solid LDP container
//! surface is unchanged even with the flag ON.
//!
//! ## Fail-closed membership (D12 — divergence from the WD)
//! `items` MUST NOT include members the requesting agent has no access to, and `totalItems` counts
//! only the caller-visible view — the listing must not be a weaker existence-oracle than the
//! derived views. Implemented as a per-child WAC `acl:Read` check through the SAME planned
//! authorization walk the read path uses; a denied child is silently omitted (a backend FAULT
//! still fails the whole request — fail-closed never silently masks a storage error as an empty
//! listing). This is O(children) ACL walks per listing; batching the member-visibility plan into
//! one round-trip is an M2 optimisation seam.
//!
//! Member descriptions carry `id` + `type` (MUST), `mediaType` for data resources (MUST), and
//! `modified` when known (SHOULD). `size` is omitted — `ResourceMeta` does not yet record byte
//! length (an M2 `ResourceMeta` field); the spec rates it SHOULD. Pagination (SHOULD) is likewise
//! an M2 item — every listing is single-page.

use serde_json::{json, Map, Value};

use crate::auth::VerifiedToken;
use crate::authz::wac::Decision;
use crate::authz::AccessMode;
use crate::error::ServerError;
use crate::ldp::handler::LdpState;
use crate::ldp::target::LdpTarget;
use crate::store::timestamp::to_xsd_datetime;
use crate::store::Store;

use super::{MEDIA_LWS_JSON, MEDIA_PROFILED_JSONLD};

/// Which LWS-selecting form the request named — decides the response `Content-Type` (the payload
/// bytes are IDENTICAL across all three, per the WD conneg rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerVariant {
    /// `application/lws+json`.
    LwsJson,
    /// `application/ld+json;profile="https://w3id.org/jeswr/lws/v1"`.
    ProfiledJsonLd,
    /// `application/json` (the plain-JSON rescue path).
    PlainJson,
}

impl ContainerVariant {
    /// The response `Content-Type` for this variant.
    pub fn content_type(self) -> &'static str {
        match self {
            ContainerVariant::LwsJson => MEDIA_LWS_JSON,
            ContainerVariant::ProfiledJsonLd => MEDIA_PROFILED_JSONLD,
            ContainerVariant::PlainJson => "application/json",
        }
    }
}

/// Decide whether a container GET's `Accept` selects the LWS representation, and under which
/// `Content-Type`. `None` ⇒ the existing Solid LDP rendering (the flag-off behaviour).
///
/// Selection rules (surface-preserving — see the module doc):
/// 1. `application/lws+json` or PROFILED `application/ld+json` at a weight `>=` the best weight of
///    any type the existing surface can produce (Turtle / plain JSON-LD, incl. wildcard coverage)
///    ⇒ the LWS shape (these two forms are unambiguous LWS requests; ties resolve in their favour
///    because the profile/media type is the more specific ask).
/// 2. Else plain `application/json` at q > 0 when NOTHING the existing surface produces is
///    acceptable (the request would previously have been a 406) ⇒ the LWS shape as
///    `application/json`.
/// 3. Else ⇒ `None` (existing behaviour, byte-identical).
pub fn negotiate_container(accept: Option<&str>) -> Option<ContainerVariant> {
    let raw = accept?;
    if raw.trim().is_empty() {
        return None;
    }

    let mut q_lws = 0.0f32; // application/lws+json (explicit)
    let mut q_profiled = 0.0f32; // application/ld+json + the LWS profile param
    let mut q_json = 0.0f32; // application/json (explicit)
    let mut q_turtle: Option<f32> = None;
    let mut q_jsonld: Option<f32> = None;
    let mut q_text_star: Option<f32> = None;
    let mut q_app_star: Option<f32> = None;
    let mut q_any: Option<f32> = None;
    fn bump(slot: &mut Option<f32>, q: f32) {
        *slot = Some(slot.unwrap_or(0.0).max(q));
    }

    for part in raw.split(',') {
        let (media, q, profiled) = super::parse_accept_part(part);
        match media.as_str() {
            MEDIA_LWS_JSON => q_lws = q_lws.max(q),
            "application/json" => q_json = q_json.max(q),
            "application/ld+json" => {
                if profiled {
                    q_profiled = q_profiled.max(q);
                }
                // A profiled part still counts toward plain JSON-LD too (the existing parser sees
                // the same media essence), keeping the "best existing q" honest.
                bump(&mut q_jsonld, q);
            }
            "text/turtle" => bump(&mut q_turtle, q),
            "text/*" => bump(&mut q_text_star, q),
            "application/*" => bump(&mut q_app_star, q),
            "*/*" => bump(&mut q_any, q),
            _ => {}
        }
    }

    // The best weight of anything the EXISTING surface can produce (same effective-q resolution as
    // `content::negotiate_accept`).
    let turtle = q_turtle.or(q_text_star).or(q_any).unwrap_or(0.0);
    let jsonld = q_jsonld.or(q_app_star).or(q_any).unwrap_or(0.0);
    let best_existing = turtle.max(jsonld);

    let q_strong = q_lws.max(q_profiled);
    if q_strong > 0.0 && q_strong >= best_existing {
        return Some(if q_lws >= q_profiled {
            ContainerVariant::LwsJson
        } else {
            ContainerVariant::ProfiledJsonLd
        });
    }
    if q_json > 0.0 && best_existing <= 0.0 {
        return Some(ContainerVariant::PlainJson);
    }
    None
}

/// Render the LWS container listing for `target` as the requesting agent sees it.
///
/// Fail-closed per D12: each authoritative child is included only when the agent holds `acl:Read`
/// on it (via the same planned WAC walk the read path uses); a denial omits the child, a backend
/// FAULT fails the request (never a silently-shorter listing). A listed child whose metadata row
/// is missing (a byte/index inconsistency window) is likewise omitted — `mediaType` is a MUST on
/// data-resource members, so emitting a member we cannot describe would violate the shape.
pub(crate) async fn render<S: Store>(
    state: &LdpState<S>,
    target: &LdpTarget,
    token: &VerifiedToken,
    origin: Option<&str>,
) -> Result<Vec<u8>, ServerError> {
    let children = state.store.list_children(&target.iri).await?;
    let mut items: Vec<Value> = Vec::with_capacity(children.len());
    for child in children {
        let iri = child.as_str();
        // D12: only members the requesting agent can read are disclosed. A deny (401/403-class
        // decision) omits the member; a backend error propagates (fail-closed on faults).
        match state
            .authorize_planned_iri(iri, AccessMode::Read, token, origin)
            .await?
        {
            Decision::Allow(_) => {}
            Decision::Unauthenticated | Decision::Forbidden => continue,
        }
        let is_container = iri.ends_with('/');
        let Some(meta) = state.store.meta(iri).await? else {
            // Listed but meta-less (an index inconsistency window): omit — a data-resource member
            // without its MUST-level mediaType would be malformed.
            continue;
        };
        let mut item = Map::new();
        item.insert("id".into(), json!(iri));
        item.insert(
            "type".into(),
            json!(if is_container {
                "Container"
            } else {
                "DataResource"
            }),
        );
        if !is_container {
            item.insert("mediaType".into(), json!(meta.content_type));
        }
        if let Some(modified) = meta.last_modified.and_then(to_xsd_datetime) {
            item.insert("modified".into(), json!(modified));
        }
        items.push(Value::Object(item));
    }

    let doc = json!({
        "@context": super::JLWS_CONTEXT,
        "id": target.iri,
        "type": "Container",
        "totalItems": items.len(),
        "items": items,
    });
    serde_json::to_vec(&doc)
        .map_err(|e| ServerError::Storage(format!("lws container serialise: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lws_shape_selected_only_on_unambiguous_ask() {
        // The unambiguous forms select it…
        assert_eq!(
            negotiate_container(Some("application/lws+json")),
            Some(ContainerVariant::LwsJson)
        );
        assert_eq!(
            negotiate_container(Some(
                "application/ld+json;profile=\"https://w3id.org/jeswr/lws/v1\""
            )),
            Some(ContainerVariant::ProfiledJsonLd)
        );
        // …and win ties against equally-weighted existing types (the more specific ask).
        assert_eq!(
            negotiate_container(Some("text/turtle, application/lws+json")),
            Some(ContainerVariant::LwsJson)
        );
        // A STRICTLY higher existing weight keeps the Solid rendering.
        assert_eq!(
            negotiate_container(Some("text/turtle;q=0.9, application/lws+json;q=0.5")),
            None
        );
        // q=0 refuses the LWS form.
        assert_eq!(negotiate_container(Some("application/lws+json;q=0")), None);
    }

    #[test]
    fn existing_accepts_keep_the_solid_rendering() {
        for accept in [
            None,
            Some(""),
            Some("*/*"),
            Some("text/turtle"),
            Some("application/ld+json"),
            Some("text/*"),
            Some("application/*"),
            Some("text/turtle;q=0.5, application/ld+json;q=0.9"),
        ] {
            assert_eq!(
                negotiate_container(accept),
                None,
                "accept={accept:?} must keep the existing rendering"
            );
        }
    }

    #[test]
    fn plain_json_rescues_only_a_previous_406() {
        // application/json alone: previously 406 ⇒ the LWS shape as plain JSON.
        assert_eq!(
            negotiate_container(Some("application/json")),
            Some(ContainerVariant::PlainJson)
        );
        // With an acceptable existing type present, the Solid rendering wins (surface-preserving).
        assert_eq!(
            negotiate_container(Some("application/json, text/turtle;q=0.5")),
            None
        );
        // A wildcard also keeps the existing rendering (it covers the Solid types).
        assert_eq!(
            negotiate_container(Some("application/json;q=0.1, */*;q=0.1")),
            None
        );
    }

    #[test]
    fn variant_content_types() {
        assert_eq!(
            ContainerVariant::LwsJson.content_type(),
            "application/lws+json"
        );
        assert_eq!(
            ContainerVariant::ProfiledJsonLd.content_type(),
            "application/ld+json;profile=\"https://w3id.org/jeswr/lws/v1\""
        );
        assert_eq!(
            ContainerVariant::PlainJson.content_type(),
            "application/json"
        );
    }
}
