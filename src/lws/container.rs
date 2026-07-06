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
//! `modified` + `size` when known (SHOULD — `size` reads the M3 `ResourceMeta::size` byte length
//! stamped at write time; a pre-M3 record simply omits it).
//!
//! ## Pagination (M3 — spec §pagination)
//! A listing whose VISIBLE membership exceeds the configured page size
//! ([`LwsConfig::page_size`](super::LwsConfig)) is paged, link-based per RFC 8288: `rel="first"`
//! always, `rel="next"` on all but the last page (omitted on the last), `rel="prev"`/`rel="last"`
//! when meaningful; page URIs are `?lws-page=N` (opaque to clients — only the server's own
//! emitted links are meaningful). Per §container-properties, a page's `items` is the CURRENT page
//! while `id`/`type`/`totalItems` describe the WHOLE visible membership; every page is a 200.
//!
//! **Determinism**: members are sorted lexicographically by IRI before slicing, so page contents
//! are a deterministic function of the (visible) membership — no member is skipped or duplicated
//! across the pages of one snapshot, and the representation ETag is iteration-order-independent.
//!
//! ## Multi-request snapshot consistency (sparq#1572 — landed as sparq PR #1584)
//! Each response is built from ONE combined membership+metadata query
//! ([`Store::list_children_snapshot`]). When the backend advertises a **generation token** for
//! that snapshot (sparq's default-build `Sparq-Generation` header), a paged listing's own
//! `first`/`next`/`prev`/`last` links carry it as `lws-gen=<token>`, and every follow-up page
//! request **re-reads the SAME immutable snapshot** (sparq's `?generation=N` pin) — so a member
//! created/deleted between page fetches can no longer shift the sorted offsets: the pages of one
//! walk tile exactly one membership+metadata state (the sparq#1572 acceptance property).
//!
//! The honest bounds of that claim:
//! - **Authorization stays LIVE — deliberately.** The D12 per-member WAC filter always evaluates
//!   at REQUEST time, never at the pinned snapshot (pinning ACL reads would keep serving revoked
//!   access — security over consistency). An ACL change mid-walk may therefore still shift the
//!   VISIBLE offsets; that residual is the security-correct behaviour, not a gap.
//! - **The pin is retention-bounded.** sparq keeps only its concurrency-retention window (the
//!   last K generations, default 4); a pin that ages out fails as a **410**
//!   `snapshot-gone` problem and the walker restarts from the container URI (an unpinned first
//!   page — a fresh snapshot). Never a silent substitute of a different snapshot.
//! - **Graceful degradation.** A backend with no generation concept (the in-memory double, the
//!   embedded engine — no library-level snapshot API yet — or a pre-#1584 sparq) yields
//!   `generation: None`: links carry no `lws-gen`, and behaviour is exactly the previous
//!   single-response-snapshot contract (the spec's §pagination requires no more).
//!
//! ## Pinned listings × live WAC — the deleted-member disclosure closure (two prongs)
//! Snapshot membership + LIVE authorization compose into a hole unless guarded: a member that
//! existed at the pinned generation under a RESTRICTIVE own-ACL, then was DELETED (its `.acl`
//! with it), is still in the pinned snapshot — but the LIVE walk on its IRI now finds no own-ACL
//! and falls back to an ancestor's (possibly more permissive) `acl:default`. Unguarded, an agent
//! that member's own ACL denied at the snapshot would be handed its IRI + content-type + size +
//! modified out of the pin. Closed with two independent prongs:
//!
//! 1. **The current-existence + incarnation re-bind guard (primary —
//!    `LdpState::authorize_listing_member`).** A member is disclosed ONLY if it (a) EXISTS at the
//!    CURRENT store state and (b) live WAC grants Read **on the incarnation that exists**: a
//!    positive Allow is served only after a full confirm re-plan, read strictly AFTER the ACL
//!    resolution completes, comes back IDENTICAL to the plan the decision consumed (the target's
//!    `ResourceMeta` carries the per-write-unique `blob_key`, so any delete + same-IRI recreate
//!    is a visible incarnation change that forces a re-walk against the recreated own-ACL). A
//!    since-deleted member is excluded fail-closed, regardless of what the ancestor-`acl:default`
//!    fallback would grant — including one deleted mid-decision (the T0/T2 TOCTOU) or deleted and
//!    RECREATED under the same IRI inside the decision window (the round-4 recreate race, closed
//!    by the re-bind); still-existing members keep the deliberate LIVE evaluation above (fresh
//!    revocation applies immediately — the pin never freezes an ACL). See that method's doc for
//!    the full invariant + the re-bind loop.
//! 2. **Authenticated pins (defence-in-depth — [`super::pin`]).** The backend generation is a
//!    small guessable integer, so raw `lws-gen=<u64>` would let ANY requester rewind ANY
//!    container to an arbitrary retained state. Instead `lws-gen` carries a server-MINTED
//!    HMAC token bound to (container, requester) with a short expiry, emitted only in the
//!    server's own pagination links; anything else is the opaque 400 `invalid-generation`
//!    problem (an expired genuine token is the 410 restart). Only verified pins ever reach the
//!    backend.
//!
//! ## Fail-closed membership × pagination
//! The D12 per-member WAC filter runs over the WHOLE membership BEFORE slicing (`totalItems` and
//! the page boundaries are functions of the visible view only), so page arithmetic can never leak
//! the existence of hidden members through counts or offsets.

use serde_json::{json, Map, Value};

use crate::auth::VerifiedToken;
use crate::authz::wac::Decision;
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

/// A rendered LWS listing: the (page's) JSON-LD bytes + the RFC 8288 pagination `Link` header
/// values to append (empty when the listing is single-page).
pub(crate) struct Listing {
    pub body: Vec<u8>,
    pub page_links: Vec<axum::http::HeaderValue>,
}

/// Parse the requested page + RAW snapshot-pin token from the query string: absent ⇒ page 1,
/// unpinned; `lws-page=N` (N ≥ 1) ⇒ page N; `lws-gen=<token>` ⇒ the raw pin token, extracted
/// UNINTERPRETED here — every judgement about it (shape, authenticity, binding, expiry) lives in
/// the ONE verification chokepoint ([`super::LwsConfig::verify_pin`], called by [`render`]), so a
/// forged/malformed/expired pin cannot be told apart by WHERE it was rejected. An unusable
/// `lws-page` is a 400 problem (page URIs are opaque — only the server's own links count).
pub(crate) fn page_from_query(query: Option<&str>) -> Result<(usize, Option<String>), ServerError> {
    let Some(query) = query else {
        return Ok((1, None));
    };
    let mut page: usize = 1;
    let mut pin: Option<String> = None;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("lws-page=") {
            page = match v.parse::<usize>() {
                Ok(n) if n >= 1 => n,
                _ => {
                    return Err(ServerError::LwsProblem {
                        status: 400,
                        type_uri: super::PROBLEM_INVALID_PAGE,
                        title: "lws-page must be a positive integer (follow the server's own \
                                first/next/prev/last links)",
                    })
                }
            };
        } else if let Some(v) = pair.strip_prefix("lws-gen=") {
            // Opaque at this layer — verification (incl. the empty/garbage 400) is `verify_pin`'s.
            pin = Some(v.to_string());
        }
    }
    Ok((page, pin))
}

/// The [0-based) slice bounds + the link set for `page` of a `total`-member visible listing under
/// `page_size`. Pure + deterministic — the pagination arithmetic in one testable place.
#[derive(Debug, PartialEq, Eq)]
struct PagePlan {
    start: usize,
    end: usize,
    /// Total pages (≥ 1). A requested page past the end yields an EMPTY page (start == end) with
    /// the same deterministic links (no `next`), never an error — page URIs are opaque and the
    /// membership may legitimately have shrunk since a link was minted.
    pages: usize,
    paged: bool,
}

fn page_plan(total: usize, page: usize, page_size: Option<std::num::NonZeroUsize>) -> PagePlan {
    let Some(size) = page_size else {
        return PagePlan {
            start: 0,
            end: total,
            pages: 1,
            paged: false,
        };
    };
    let size = size.get();
    if total <= size {
        // At or under the threshold: single-page, no pagination links (`?lws-page=1` included —
        // the whole listing IS page 1).
        return PagePlan {
            start: 0,
            end: total,
            pages: 1,
            paged: false,
        };
    }
    let pages = total.div_ceil(size);
    let start = (page - 1).saturating_mul(size).min(total);
    let end = start.saturating_add(size).min(total);
    PagePlan {
        start,
        end,
        pages,
        paged: true,
    }
}

/// Render the LWS container listing for `target` as the requesting agent sees it — `page` of a
/// `page_size`-paged listing (see the module doc; `page_size: None` ⇒ single-page), optionally
/// **pinned** to the snapshot generation a prior page of the same walk was served at (`raw_pin` —
/// the `lws-gen` token from the server's own links; the sparq#1572 consistency, module doc above).
/// The raw token is verified HERE, before any backend work, at the one chokepoint
/// ([`super::LwsConfig::verify_pin`]): unminted/forged/mismatched ⇒ the 400 `invalid-generation`
/// problem, expired ⇒ the 410 restart — only a verified pin ever reaches the backend (prong 2 of
/// the module doc's disclosure closure).
///
/// Fail-closed per D12: each authoritative child is included only when it EXISTS at the CURRENT
/// store state AND the agent holds `acl:Read` on it — both checked LIVE, never at the pinned
/// snapshot, by [`LdpState::authorize_listing_member`] (the same planned WAC walk the read path
/// uses, plus the current-existence + incarnation re-bind guard that is prong 1 of the module
/// doc's disclosure closure); a denial omits the child, a backend FAULT fails the request (never a
/// silently-shorter listing). A listed child whose metadata row is missing at the snapshot (a
/// byte/index inconsistency window) is likewise omitted — `mediaType` is a MUST on data-resource
/// members, so emitting a member we cannot describe would violate the shape. The filter runs over
/// the WHOLE membership (never just the page) so `totalItems` and the page boundaries are
/// functions of the visible view only.
pub(crate) async fn render<S: Store>(
    state: &LdpState<S>,
    target: &LdpTarget,
    token: &VerifiedToken,
    origin: Option<&str>,
    page: usize,
    raw_pin: Option<&str>,
    page_size: Option<std::num::NonZeroUsize>,
) -> Result<Listing, ServerError> {
    let requester = token.web_id.as_deref();
    // Prong 2 (module doc): verify the presented pin token BEFORE any backend work — only a pin
    // this server minted for exactly this (container, requester) is forwarded as a backend
    // generation. The flag-off surface never reaches here; a missing config inside the LWS render
    // is unreachable, but fails CLOSED as the same opaque 400 rather than trusting the raw value.
    let pin: Option<u64> = match raw_pin {
        None => None,
        Some(raw) => match state.lws() {
            Some(cfg) => Some(cfg.verify_pin(&target.iri, requester, raw)?),
            None => return Err(super::invalid_generation_problem()),
        },
    };
    // ONE combined membership+metadata read from ONE backend state (pinned when the walker
    // presented a verified server-minted `lws-gen` token). A no-longer-servable pin surfaces as
    // the 410 `snapshot-gone` problem from the store — the walker restarts unpinned.
    let snapshot = state.store.list_children_snapshot(&target.iri, pin).await?;
    let generation = snapshot.generation;
    let mut children = snapshot.members;
    // Deterministic member order (M3): lexicographic by IRI, so page slicing is a pure function
    // of the visible membership (and the representation ETag is iteration-order-independent).
    children.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));

    // The VISIBLE view first (D12), across the whole membership. Membership + metadata come from
    // the snapshot; the disclosure decision is LIVE (deliberate — see the module doc's honest
    // bounds): current existence AND live WAC Read, per member (prong 1 — the deleted-member
    // guard lives inside `authorize_listing_member`).
    let mut visible: Vec<(String, crate::store::ResourceMeta)> = Vec::with_capacity(children.len());
    for (child, meta) in children {
        let iri = child.as_str();
        // D12: only members that currently exist AND that the requesting agent can read are
        // disclosed. A deny (401/403-class decision) — including the nonexistent-at-current-state
        // case — omits the member; a backend error propagates (fail-closed on faults).
        match state.authorize_listing_member(iri, token, origin).await? {
            Decision::Allow(_) => {}
            Decision::Unauthenticated | Decision::Forbidden => continue,
        }
        visible.push((iri.to_string(), meta));
    }

    let total = visible.len();
    let plan = page_plan(total, page, page_size);
    let mut items: Vec<Value> = Vec::with_capacity(plan.end - plan.start);
    for (iri, meta) in &visible[plan.start..plan.end] {
        let is_container = iri.ends_with('/');
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
            // SHOULD-level: the byte length stamped at write time (absent on pre-M3 records).
            if let Some(size) = meta.size {
                item.insert("size".into(), json!(size));
            }
        }
        if let Some(modified) = meta.last_modified.and_then(to_xsd_datetime) {
            item.insert("modified".into(), json!(modified));
        }
        items.push(Value::Object(item));
    }

    // §container-properties: `id`/`type`/`totalItems` describe the WHOLE visible membership;
    // `items` is the current page only when paginated.
    let doc = json!({
        "@context": super::JLWS_CONTEXT,
        "id": target.iri,
        "type": "Container",
        "totalItems": total,
        "items": items,
    });
    let body = serde_json::to_vec(&doc)
        .map_err(|e| ServerError::Storage(format!("lws container serialise: {e}")))?;
    // Mint the authenticated pin token the links carry (prong 2): only when the backend
    // advertised a generation AND pins are enabled (a key exists). `None` ⇒ unpinned links — the
    // graceful degradation shared by generation-less backends and the disabled-pins posture.
    let pin_token = generation
        .and_then(|g| state.lws().and_then(|cfg| cfg.mint_pin(&target.iri, requester, g)));
    Ok(Listing {
        body,
        page_links: page_links(&target.iri, page, &plan, pin_token.as_deref()),
    })
}

/// The RFC 8288 pagination `Link` values for `page` under `plan` (§pagination): `first` always,
/// `next` on all but the last page (omitted on the last — a MUST both ways), `prev`/`last` when
/// meaningful. Empty when the listing is single-page.
///
/// When the caller minted a snapshot-pin token ([`super::pin`] — the backend advertised a
/// generation and pins are enabled), every link carries it as `lws-gen=<token>` so the walker's
/// follow-up requests re-read the SAME snapshot (the sparq#1572 consistency — module doc).
/// `None` ⇒ plain unpinned links (the graceful-degradation contract).
fn page_links(
    container_iri: &str,
    page: usize,
    plan: &PagePlan,
    pin_token: Option<&str>,
) -> Vec<axum::http::HeaderValue> {
    if !plan.paged {
        return Vec::new();
    }
    let link = |n: usize, rel: &str| {
        let uri = match pin_token {
            Some(t) => format!("{container_iri}?lws-page={n}&lws-gen={t}"),
            None => format!("{container_iri}?lws-page={n}"),
        };
        axum::http::HeaderValue::from_str(&format!("<{uri}>; rel=\"{rel}\"")).ok()
    };
    let mut out = Vec::with_capacity(4);
    out.extend(link(1, "first"));
    if page > 1 {
        out.extend(link((page - 1).min(plan.pages), "prev"));
    }
    if page < plan.pages {
        out.extend(link(page + 1, "next"));
    }
    out.extend(link(plan.pages, "last"));
    out
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
    fn page_plan_is_deterministic_with_no_skip_or_dup() {
        let size = std::num::NonZeroUsize::new(2);
        // Under/at the threshold: single-page, unpaged (no links).
        assert_eq!(
            page_plan(2, 1, size),
            PagePlan {
                start: 0,
                end: 2,
                pages: 1,
                paged: false
            }
        );
        // 5 members, size 2 ⇒ 3 pages; the slices tile the membership exactly (no skip/dup).
        let plans: Vec<PagePlan> = (1..=3).map(|p| page_plan(5, p, size)).collect();
        assert_eq!(
            plans[0],
            PagePlan {
                start: 0,
                end: 2,
                pages: 3,
                paged: true
            }
        );
        assert_eq!(
            plans[1],
            PagePlan {
                start: 2,
                end: 4,
                pages: 3,
                paged: true
            }
        );
        assert_eq!(
            plans[2],
            PagePlan {
                start: 4,
                end: 5,
                pages: 3,
                paged: true
            }
        );
        let covered: usize = plans.iter().map(|p| p.end - p.start).sum();
        assert_eq!(covered, 5, "pages tile the membership exactly");
        // A page past the end: EMPTY, same page count, never an error.
        assert_eq!(
            page_plan(5, 9, size),
            PagePlan {
                start: 5,
                end: 5,
                pages: 3,
                paged: true
            }
        );
        // Pagination disabled: everything on one page.
        assert_eq!(
            page_plan(5000, 1, None),
            PagePlan {
                start: 0,
                end: 5000,
                pages: 1,
                paged: false
            }
        );
    }

    #[test]
    fn page_links_follow_rfc8288() {
        let c = "https://pod.example/alice/";
        let strs = |page: usize, plan: &PagePlan| -> Vec<String> {
            page_links(c, page, plan, None)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect()
        };
        let plan = page_plan(5, 1, std::num::NonZeroUsize::new(2));
        // Page 1: first + next + last; NO prev.
        assert_eq!(
            strs(1, &plan),
            vec![
                format!("<{c}?lws-page=1>; rel=\"first\""),
                format!("<{c}?lws-page=2>; rel=\"next\""),
                format!("<{c}?lws-page=3>; rel=\"last\""),
            ]
        );
        // Middle page: all four.
        assert_eq!(
            strs(2, &plan),
            vec![
                format!("<{c}?lws-page=1>; rel=\"first\""),
                format!("<{c}?lws-page=1>; rel=\"prev\""),
                format!("<{c}?lws-page=3>; rel=\"next\""),
                format!("<{c}?lws-page=3>; rel=\"last\""),
            ]
        );
        // Last page: `next` MUST be omitted.
        let last = strs(3, &plan);
        assert!(!last.iter().any(|l| l.contains("rel=\"next\"")));
        assert!(last.iter().any(|l| l.contains("rel=\"first\"")));
        // Single-page: no links at all.
        let single = page_plan(2, 1, std::num::NonZeroUsize::new(2));
        assert!(strs(1, &single).is_empty());
    }

    #[test]
    fn page_links_carry_the_snapshot_pin_when_a_generation_is_known() {
        // The sparq#1572 consistency wiring: the caller-minted authenticated pin token (prong 2 —
        // never the raw generation integer) rides EVERY link as `lws-gen=<token>`, so a walker
        // following the server's own links re-reads the SAME snapshot.
        let c = "https://pod.example/alice/";
        let plan = page_plan(5, 2, std::num::NonZeroUsize::new(2));
        let t = "42.1000.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let links: Vec<String> = page_links(c, 2, &plan, Some(t))
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            links,
            vec![
                format!("<{c}?lws-page=1&lws-gen={t}>; rel=\"first\""),
                format!("<{c}?lws-page=1&lws-gen={t}>; rel=\"prev\""),
                format!("<{c}?lws-page=3&lws-gen={t}>; rel=\"next\""),
                format!("<{c}?lws-page=3&lws-gen={t}>; rel=\"last\""),
            ]
        );
        // No pin token ⇒ plain unpinned links (graceful degradation — asserted exactly in
        // `page_links_follow_rfc8288` above).
        assert!(page_links(c, 2, &plan, None)
            .iter()
            .all(|l| !l.to_str().unwrap().contains("lws-gen")));
    }

    #[test]
    fn page_query_parsing_fails_closed() {
        assert_eq!(page_from_query(None).unwrap(), (1, None));
        assert_eq!(page_from_query(Some("")).unwrap(), (1, None));
        assert_eq!(page_from_query(Some("lws-page=3")).unwrap(), (3, None));
        assert_eq!(page_from_query(Some("a=b&lws-page=2")).unwrap(), (2, None));
        // Other queries are ignored (page 1) — the surface-preserving default.
        assert_eq!(page_from_query(Some("foo=bar")).unwrap(), (1, None));
        for bad in ["lws-page=0", "lws-page=-1", "lws-page=abc", "lws-page="] {
            assert!(page_from_query(Some(bad)).is_err(), "{bad} must be a 400");
        }
    }

    #[test]
    fn generation_pin_is_extracted_raw_for_the_verify_chokepoint() {
        // The pin token is OPAQUE here: `page_from_query` extracts the raw value uninterpreted —
        // ALL judgement (shape, authenticity, binding, expiry) belongs to the ONE chokepoint
        // (`LwsConfig::verify_pin`, exercised in `lws::pin`'s tests + the HTTP suite), so a
        // rejected pin cannot be fingerprinted by WHERE it failed. Nothing here is a silent unpin:
        // whatever was presented is carried to the verifier, which fails closed.
        assert_eq!(
            page_from_query(Some("lws-page=2&lws-gen=42.99.ff")).unwrap(),
            (2, Some("42.99.ff".to_string()))
        );
        assert_eq!(
            page_from_query(Some("lws-gen=7")).unwrap(),
            (1, Some("7".to_string())),
            "a pin without an explicit page applies to page 1 (and still must verify)"
        );
        // Garbage — including the legacy bare-int and empty forms — is still EXTRACTED (never
        // dropped), so the verifier is the one to refuse it with the 400 problem.
        for (q, raw) in [
            ("lws-gen=", ""),
            ("lws-gen=abc", "abc"),
            ("lws-gen=-1", "-1"),
            ("lws-page=2&lws-gen=1.5", "1.5"),
        ] {
            assert_eq!(
                page_from_query(Some(q)).unwrap().1,
                Some(raw.to_string()),
                "{q} must be carried raw to the verifier"
            );
        }
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
