// AUTHORED-BY Claude Fable 5
//! The **LWS (Linked Web Storage) surface** — an ADDITIVE, FLAG-GATED implementation of the JLWS
//! clean-slate spec (`jeswr/lws-spec`: `index.html` core + `rdf-transform.html` companion) beside
//! the existing Solid/LDP surface.
//!
//! ## Flag-gating (the load-bearing invariant)
//! The whole surface hangs off [`LwsConfig`]: when it is `None` on the
//! [`LdpState`](crate::ldp::handler::LdpState) (the default — no `SOLID_SERVER_LWS`), **no LWS
//! route is mounted, no LWS header is emitted, and no LWS branch runs** — the Solid LDP + auth +
//! WAC + conditional behaviour is byte-identical to a build without this module. Every hook in the
//! existing handlers is a `state.lws()`-gated branch whose flag-off arm is the pre-existing code
//! path, unchanged.
//!
//! ## What M1 ships (spec section → code)
//! - **Discovery / storage description** (`index.html` §discovery; DECISIONS.md D5): a CID-shaped
//!   JSON-LD document at [`STORAGE_DESCRIPTION_PATH`] advertising `conformsTo` protocol-version
//!   URIs + the capability registry — including the **`ContentNegotiation`** entries (the RDF
//!   opt-in, `rdf-transform.html` §capability) when the transform is on. Bound to every LDP
//!   GET/HEAD response via `Link rel="https://w3id.org/jeswr/lws#storageDescription"`
//!   (§discovery-binding). Served with the WD conneg contract: `application/lws+json`,
//!   `application/ld+json` (profiled), and `application/json` all return the **identical bytes**,
//!   only `Content-Type` varies (§container-media-type applies to the description too).
//! - **Container-as-JSON-LD listing** (`index.html` §container-representation; D12/D13): a
//!   container GET whose `Accept` selects the LWS profile ([`container`]) is served the flat
//!   server-managed `{id, type, totalItems, items[]}` shape — **fail-closed**: `items` lists only
//!   members the requesting agent can read, and `totalItems` counts only that visible view (D12).
//!   A non-LWS `Accept` gets the existing Solid LDP `ldp:contains` graph, unchanged. `rel="up"`
//!   containment metadata rides as a `Link` header on every LWS-enabled GET/HEAD (§containment).
//! - **The RDF content-transformation opt-in** (`rdf-transform.html`; D18): with the
//!   `ContentNegotiation` capability on, a stored `text/turtle`/`application/ld+json` resource can
//!   be read as any advertised target (`text/turtle` / `application/ld+json` /
//!   `application/n-triples`) via [`transform`] — per-representation entity-tags
//!   (`"<state>+nt"` etc.), `Vary: Accept`, authoritative-bytes (the stored byte stream wins;
//!   reads in the stored type return it verbatim), If-Match accepted against either
//!   representation's tag (the existing state-part comparison), and the §authoritative-bytes
//!   write guard (a write in an advertised-target-but-not-source type over an RDF-readable
//!   resource is a 415, so a resource is never stranded in a type the server cannot transform
//!   from). Opt-in OFF ⇒ byte-native only: `application/n-triples` is not negotiable (406) and
//!   the capability is not advertised.
//! - **Idempotent create via `PUT + If-None-Match: *`** (`index.html` §http-create-put; D2):
//!   201-on-create / 412-on-exists — pinned by tests over the EXISTING conditional infrastructure
//!   (which already implements RFC 9110 §13.1.2). The STRICT D2 semantics that would change the
//!   Solid surface — every PUT must be conditional (428 otherwise), no auto-created intermediate
//!   containers (409 `missing-parent`), containers are never data resources (400 on a
//!   container-PUT body, D3) — sit behind the additional [`LwsConfig::strict_put`] deployment
//!   toggle (`SOLID_SERVER_LWS_STRICT_PUT`), because a composed Solid+LWS deployment must keep
//!   Solid's PUT semantics (auto-intermediate-containers, unconditional PUT). A pure-LWS
//!   deployment turns it on. The per-request negotiation that could replace this deployment-level
//!   toggle is an M2 seam.
//!
//! ## Error shape (D17)
//! LWS-minted 4xx errors carry RFC 9457 problem details ([`crate::error::ServerError::LwsProblem`])
//! with problem-type URIs under `https://w3id.org/jeswr/lws/problems/`. Retro-fitting problem
//! details onto the EXISTING surface's errors is deliberately out of M1 scope (it would change
//! flag-off bytes).
//!
//! ## Where the lws-spec test vectors plug in
//! The `jeswr/lws-spec` repo's `test-vectors/` suite (being generated in parallel) drives a server
//! over plain HTTP. This surface is fully reachable through the assembled [`axum::Router`]
//! (`build_router` with an [`LwsConfig`] set), so a vector-runner needs only
//! `tower::ServiceExt::oneshot` per vector — `tests/lws_http.rs` is the hand-written pin of the
//! same request/response contract and the template for the runner. Vector families covered by M1
//! code paths: discovery/storage-description, container listing (flat `items`, visible-only
//! counts), RDF-transform round-trip + per-representation ETags + `normalizes`-absent byte-exact
//! read-back, conditional create (`If-None-Match: *` / 412 / strict-428).
//!
//! ## What M2 ships (the LWS auth chain — [`auth`])
//! The server half of the spec's authorization chain (§authz-discovery / §access-token /
//! §presentation / §rs-validation): the RFC 9728 `resource_metadata` + `realm` 401 challenge
//! (appended by [`auth::lws_challenge_middleware`], reusing the RFC 9728 document built by
//! [`crate::pop::sk::handlers::protected_resource_metadata_json`] and extended with
//! `authorization_servers` + `jlws_storage_description`), and RFC 9068 `at+jwt` **Bearer**
//! validation ([`auth::LwsBearerAuth`]) — trusted-issuer allowlist, vetted signature path,
//! single-valued audience with same-origin + `/`-segment-boundary containment, bounded ≤300 s
//! lifetime, required `client_id`/`sub`/`jti`, bare-`cnf` refusal — mapping the verified `sub`
//! onto the existing WAC decision path. The RFC 8693 exchange itself is the authorization
//! server's job (lws-keycloak); this server only verifies the resulting token. Bearer is the
//! MUST-accept baseline; a deployment MAY designate the realm PoP-required
//! ([`auth::ENV_LWS_REQUIRE_POP`]).
//!
//! ## What M3 ships (the read-substrate completion — `decisions/0006`)
//! - **RFC 9264 linkset metadata** ([`linkset`]; spec §metadata/§metadata-updates): every
//!   resource's typed-link metadata as a standalone `application/linkset+json` resource at
//!   `<resource>?linkset` — system-managed `up`/`type`/`acl`/storage-description links +
//!   user-managed relations, updated ONLY via `application/merge-patch+json` under the strict
//!   `If-Match`/428 discipline (412 on stale, 409 on any system-managed modification, CAS-backed
//!   lost-update protection, ETag rotation), discovered via `Link rel="linkset"` on every GET/HEAD
//!   and on 201 creates (+`rel="up"`). The user half persists as reserved triples in the
//!   resource's OWN graph, so DELETE drops resource+linkset atomically.
//! - **Paginated container listings + member `size`** ([`container`]; spec §pagination): a
//!   listing whose VISIBLE membership exceeds [`LwsConfig::page_size`] is paged with the RFC 8288
//!   `first`/`next`/`prev`/`last` links (`?lws-page=N`), deterministic lexicographic order, page
//!   arithmetic strictly over the D12-filtered visible view; `items[]` members now carry the
//!   SHOULD-level `size` (the `ResourceMeta::size` byte length stamped at write time). Each
//!   response is a single-query snapshot; cross-request snapshot consistency is gated on
//!   `sparq#1572` (documented in [`container`]).
//! - **RFC 9396 `authorization_details` — narrowing-only** ([`rar`]; spec §rar): the LWS `at+jwt`
//!   claim is enforced at the same single verify-chokepoint as the audience containment, as a
//!   pure DENY-gate — effective access = WAC ∩ aud ∩ narrowing, so it can only ever reduce (a
//!   widening attempt changes nothing: WAC remains the ceiling). Intelligible-but-uncovered ⇒
//!   403 `insufficient_scope`; unintelligible ⇒ 401 fail-closed.
//!
//! ## M4 (deferred, seams noted)
//! Notification bindings (SSE + WebSocket under the WD subscription API), DPoP-bound
//! LWS-audience token validation for a PoP-required realm (§presentation-pop end-to-end), the
//! `SparqlQueryService`/AC-SPARQL companion (a gated increment on `sparq#992`), multi-request
//! pagination snapshot-consistency (`sparq#1572`), operation-precise narrowing for
//! PUT-create/append-only-PATCH (today conservatively under-granted — [`rar`]), and the
//! container `application/json`-vs-`text/turtle` preference refinement.

pub mod auth;
pub mod container;
pub mod linkset;
pub mod rar;
pub mod transform;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use std::sync::Arc;

use crate::ldp::handler::LdpState;
use crate::store::Store;

/// The JLWS vocabulary namespace (DECISIONS.md D14 — never `w3.org/ns/lws#`, which this personal
/// surface must not squat; the `w3.org` form is accepted as an ALIAS where a jlws URI is required).
pub const JLWS_NS: &str = "https://w3id.org/jeswr/lws#";
/// The Working Draft's namespace, accepted as an equivalent alias in link-relation/type positions
/// (the D14 alias rule).
pub const LWS_WD_NS: &str = "https://www.w3.org/ns/lws#";
/// The normative JSON-LD context URI (doubles as the `profile` parameter value that selects the
/// LWS container representation).
pub const JLWS_CONTEXT: &str = "https://w3id.org/jeswr/lws/v1";
/// The core-protocol conformance URI advertised in the storage description's `conformsTo`.
pub const JLWS_CORE_CONFORMS: &str = "https://w3id.org/jeswr/lws/protocol/core/1.0";
/// The RDF content-transformation profile URI (`rdf-transform.html`): pins the `rdf-1` round-trip
/// semantics on `ContentNegotiation` capability entries and joins `conformsTo` when the opt-in is
/// on.
pub const RDF_TRANSFORM_PROFILE: &str = "https://w3id.org/jeswr/lws/transform/rdf-1";
/// Where the storage description resource is served (the binding Link header points here).
pub const STORAGE_DESCRIPTION_PATH: &str = "/.well-known/lws";
/// The LWS media type: `application/lws+json` ≡ `application/ld+json;
/// profile="https://w3id.org/jeswr/lws/v1"`.
pub const MEDIA_LWS_JSON: &str = "application/lws+json";
/// The profiled JSON-LD content type the LWS representation is served under by default.
pub const MEDIA_PROFILED_JSONLD: &str =
    "application/ld+json;profile=\"https://w3id.org/jeswr/lws/v1\"";

/// Problem-type URIs (D17 — the registry root is `https://w3id.org/jeswr/lws/problems/`).
pub const PROBLEM_UNPARSEABLE_SOURCE: &str =
    "https://w3id.org/jeswr/lws/problems/unparseable-source";
/// Strict-PUT (D2): the parent container of a `PUT + If-None-Match: *` create must already exist.
pub const PROBLEM_MISSING_PARENT: &str = "https://w3id.org/jeswr/lws/problems/missing-parent";
/// Strict-PUT (D2): every PUT is explicitly conditional; an unconditional PUT is a 428.
pub const PROBLEM_UNCONDITIONAL_PUT: &str = "https://w3id.org/jeswr/lws/problems/unconditional-put";
/// Strict-PUT (D3): a container is not a data resource — a container PUT must carry no body.
pub const PROBLEM_CONTAINER_BODY: &str = "https://w3id.org/jeswr/lws/problems/container-body";
/// rdf-transform §authoritative-bytes: a write in an advertised-target-but-not-source media type
/// over an RDF-readable resource would strand it — 415 with the accepted types named.
pub const PROBLEM_NOT_A_SOURCE: &str = "https://w3id.org/jeswr/lws/problems/not-a-source-type";
/// Linkset (M3, §metadata-updates): a linkset PUT/PATCH without `If-Match` is a 428.
pub const PROBLEM_METADATA_PRECONDITION: &str =
    "https://w3id.org/jeswr/lws/problems/metadata-precondition-required";
/// Linkset (M3, §metadata-updates — the spec-named registry entry): an attempt to modify a
/// system-managed link is rejected.
pub const PROBLEM_SYSTEM_MANAGED: &str =
    "https://w3id.org/jeswr/lws/problems/system-managed-metadata";
/// Linkset (M3): a merge-patch producing an invalid linkset document / user relation — 400/422.
pub const PROBLEM_INVALID_LINKSET_PATCH: &str =
    "https://w3id.org/jeswr/lws/problems/invalid-linkset-patch";
/// Linkset (M3): a PATCH in any format other than `application/merge-patch+json` — 415.
pub const PROBLEM_UNSUPPORTED_PATCH_TYPE: &str =
    "https://w3id.org/jeswr/lws/problems/unsupported-patch-type";
/// Linkset (M3): an `Accept` that cannot take `application/linkset+json` — 406.
pub const PROBLEM_LINKSET_NOT_ACCEPTABLE: &str =
    "https://w3id.org/jeswr/lws/problems/not-acceptable";
/// Linkset (M3): a stale `If-Match` (or a lost update CAS) — 412.
pub const PROBLEM_LINKSET_PRECONDITION_FAILED: &str =
    "https://w3id.org/jeswr/lws/problems/precondition-failed";
/// Linkset (M3): the user-managed relations exceed the server's size bound — 413.
pub const PROBLEM_LINKSET_TOO_LARGE: &str = "https://w3id.org/jeswr/lws/problems/linkset-too-large";
/// LWS-surface 404 with problem details (the linkset of a missing resource).
pub const PROBLEM_NOT_FOUND: &str = "https://w3id.org/jeswr/lws/problems/not-found";
/// Linkset (M3): a write verb on a linkset URI (its lifecycle is its resource's) — 405.
pub const PROBLEM_LINKSET_METHOD: &str = "https://w3id.org/jeswr/lws/problems/method-not-allowed";
/// Pagination (M3, §pagination): an unusable `lws-page` value — 400 (page URIs are opaque; only
/// the server's own emitted links are meaningful).
pub const PROBLEM_INVALID_PAGE: &str = "https://w3id.org/jeswr/lws/problems/invalid-page";

/// Env flag that enables the LWS surface (`1`/`true`).
pub const ENV_LWS: &str = "SOLID_SERVER_LWS";
/// Env flag for the RDF content-transformation opt-in (`rdf-transform.html`). Default **on** when
/// the LWS surface is enabled (it is the surface's flagship capability); set `=0`/`false` for a
/// byte-native-only storage that advertises no `ContentNegotiation` capability.
pub const ENV_LWS_RDF_TRANSFORM: &str = "SOLID_SERVER_LWS_RDF_TRANSFORM";
/// Env flag for the STRICT D2/D3 PUT semantics (pure-LWS deployments only — changes Solid PUT
/// behaviour, see the module doc). Default **off**.
pub const ENV_LWS_STRICT_PUT: &str = "SOLID_SERVER_LWS_STRICT_PUT";
/// Env knob for the LWS container-listing PAGE SIZE (M3, spec §pagination — the "server-determined
/// threshold"): a membership larger than this is paged. Default [`DEFAULT_LWS_PAGE_SIZE`]; `0`
/// disables pagination (every listing single-page); unparseable values keep the default.
pub const ENV_LWS_PAGE_SIZE: &str = "SOLID_SERVER_LWS_PAGE_SIZE";
/// The default pagination threshold/page size (members per page).
pub const DEFAULT_LWS_PAGE_SIZE: usize = 1000;

/// The LWS surface configuration. Present on the [`LdpState`] ⇒ the surface is ON; absent (the
/// default) ⇒ every LWS hook is dead code and the Solid surface is byte-identical to pre-LWS.
#[derive(Debug, Clone)]
pub struct LwsConfig {
    /// The RDF content-transformation opt-in (`rdf-transform.html`). On ⇒ `ContentNegotiation`
    /// capability entries are advertised and derived representations (incl.
    /// `application/n-triples`) are negotiable; off ⇒ byte-native only.
    pub rdf_transform: bool,
    /// The strict D2/D3 PUT semantics (every PUT conditional / no auto-intermediate containers /
    /// no container bodies). Off by default — see the module doc's composition note.
    pub strict_put: bool,
    /// The container-listing page size (M3, spec §pagination): a listing whose VISIBLE membership
    /// exceeds this is paged (`Link` rel first/next/prev/last; `items` = the current page;
    /// `totalItems` = the whole visible membership). `None` ⇒ pagination off (every listing
    /// single-page). Default `Some(`[`DEFAULT_LWS_PAGE_SIZE`]`)`.
    pub page_size: Option<std::num::NonZeroUsize>,
    /// The precomputed storage-description document bytes (request-invariant per boot).
    description_body: Bytes,
    /// The precomputed `Link: <…/.well-known/lws>; rel="…#storageDescription"` header value
    /// (request-invariant; derived from `base_url` only — never from a request target, so caching
    /// it leaks nothing, mirroring `LdpState::discovery_link_values`).
    storage_description_link: Option<HeaderValue>,
}

impl LwsConfig {
    /// Build a config for `base_url` (the server's public base URL, no trailing slash needed).
    pub fn new(base_url: &str, rdf_transform: bool, strict_put: bool) -> Self {
        let base = base_url.trim_end_matches('/');
        let description_body = Bytes::from(build_storage_description(base, rdf_transform));
        let storage_description_link = HeaderValue::from_str(&format!(
            "<{base}{STORAGE_DESCRIPTION_PATH}>; rel=\"{JLWS_NS}storageDescription\""
        ))
        .ok();
        Self {
            rdf_transform,
            strict_put,
            page_size: std::num::NonZeroUsize::new(DEFAULT_LWS_PAGE_SIZE),
            description_body,
            storage_description_link,
        }
    }

    /// Override the container-listing page size (M3): `None` disables pagination. Builder-style so
    /// every existing `new` caller keeps the default.
    pub fn with_page_size(mut self, page_size: Option<std::num::NonZeroUsize>) -> Self {
        self.page_size = page_size;
        self
    }

    /// Read the LWS configuration from the environment: `None` (surface off — the default) unless
    /// [`ENV_LWS`] is truthy; the transform defaults ON and strictness OFF per the constants' docs;
    /// the page size per [`ENV_LWS_PAGE_SIZE`] (`0` = off, unset/unparseable = the default).
    pub fn from_env(base_url: &str) -> Option<Self> {
        if !env_truthy(ENV_LWS) {
            return None;
        }
        // Transform: default ON when LWS is on; an explicit falsy value turns it off.
        let rdf_transform = match std::env::var(ENV_LWS_RDF_TRANSFORM).ok() {
            None => true,
            Some(v) => is_truthy(&v),
        };
        let strict_put = env_truthy(ENV_LWS_STRICT_PUT);
        let page_size = match std::env::var(ENV_LWS_PAGE_SIZE)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
        {
            Some(n) => std::num::NonZeroUsize::new(n), // 0 ⇒ None ⇒ pagination off
            None => std::num::NonZeroUsize::new(DEFAULT_LWS_PAGE_SIZE),
        };
        Some(Self::new(base_url, rdf_transform, strict_put).with_page_size(page_size))
    }

    /// The precomputed storage-description bytes (identical for every conneg variant — the WD
    /// same-bytes rule).
    pub fn description_body(&self) -> Bytes {
        self.description_body.clone()
    }

    /// Append the storage-description binding `Link` header (§discovery-binding) to a response.
    pub(crate) fn add_storage_description_link(&self, headers: &mut HeaderMap) {
        if let Some(v) = &self.storage_description_link {
            headers.append(header::LINK, v.clone());
        }
    }
}

/// `"1"`/`"true"` (case-insensitive, trimmed) ⇒ true. Mirrors the binary's `env_flag` semantics
/// (kept local so the library crate has no dependency on `main.rs`).
fn env_truthy(key: &str) -> bool {
    std::env::var(key).map(|v| is_truthy(&v)).unwrap_or(false)
}

fn is_truthy(v: &str) -> bool {
    matches!(v.trim(), "1" | "true" | "TRUE" | "True")
}

/// Build the CID-shaped storage-description JSON (spec §discovery-model; D5): `id` + `type:
/// Storage` + `conformsTo` version URIs + the capability registry entries + the `service` set
/// (which MUST include a `StorageDescription` entry pointing at the document's own URL).
///
/// `verificationMethod` is OPTIONAL (REQUIRED only for notification servers — an M2 concern) and
/// deliberately absent here. The `ContentNegotiation` capability entries appear iff the RDF
/// transform opt-in is on, one entry per advertised SOURCE type, each pinned to the `rdf-1`
/// profile URI (`rdf-transform.html` §capability); `normalizes` is omitted (default `false`) —
/// this store is byte-preserving (stored bytes are returned verbatim in the stored type).
fn build_storage_description(base: &str, rdf_transform: bool) -> Vec<u8> {
    use serde_json::{json, Value};

    let storage_root = format!("{base}/");
    let description_url = format!("{base}{STORAGE_DESCRIPTION_PATH}");

    let mut conforms_to = vec![Value::String(JLWS_CORE_CONFORMS.to_string())];
    let mut capability: Vec<Value> = Vec::new();
    if rdf_transform {
        conforms_to.push(Value::String(RDF_TRANSFORM_PROFILE.to_string()));
        // One entry per advertised SOURCE media type. Targets are every OTHER RDF serialisation
        // this server derives (rdf-transform §capability — each target MUST encode the same
        // abstract syntax; §round-trip). `application/n-triples` is target-only: not a source, so
        // a resource stored as N-Triples is byte-native (no transform expectations), and the
        // §authoritative-bytes write guard keeps an RDF-readable resource from being rewritten
        // INTO it (see `transform::write_type_guard`).
        capability.push(json!({
            "type": "ContentNegotiation",
            "source": "text/turtle",
            "target": ["application/ld+json", "application/n-triples"],
            "profile": RDF_TRANSFORM_PROFILE,
        }));
        capability.push(json!({
            "type": "ContentNegotiation",
            "source": "application/ld+json",
            "target": ["text/turtle", "application/n-triples"],
            "profile": RDF_TRANSFORM_PROFILE,
        }));
    }

    let doc = json!({
        "@context": JLWS_CONTEXT,
        "id": storage_root,
        "type": "Storage",
        "conformsTo": conforms_to,
        "capability": capability,
        "service": [{
            "type": "StorageDescription",
            "serviceEndpoint": description_url,
        }],
    });
    // `serde_json`'s default map is a BTreeMap, so the serialisation is deterministic — the
    // same-bytes-across-conneg-variants rule holds trivially.
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// `GET /.well-known/lws` — the storage description resource.
///
/// PUBLIC, like the Solid storage description at `/.well-known/solid` (the spec: readable by any
/// agent that can read the storage root, MAY be public; discovery must work for unauthenticated
/// clients so they can find the authorization server — M2's RFC 9728 flow starts here). Mounted
/// ONLY when the LWS flag is on (`app::build_app_routes`), so the flag-off route table is
/// byte-identical.
///
/// Conneg (§container-media-type, applied to the description): requests for
/// `application/lws+json`, profiled/plain `application/ld+json`, and `application/json` all
/// receive the IDENTICAL payload bytes — only `Content-Type` varies. Any other/absent `Accept`
/// gets the default profiled JSON-LD type (the document IS JSON-LD; a stricter 406 would only
/// hurt discovery).
pub async fn description_handler<S: Store>(
    State(state): State<Arc<LdpState<S>>>,
    headers: HeaderMap,
) -> Response {
    let Some(lws) = state.lws() else {
        // Unreachable: the route is only mounted when the config is present. Fail closed anyway.
        return StatusCode::NOT_FOUND.into_response();
    };
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let content_type = description_content_type(accept);
    let mut out = HeaderMap::new();
    if let Ok(ct) = HeaderValue::from_str(content_type) {
        out.insert(header::CONTENT_TYPE, ct);
    }
    // The representation varies only in Content-Type by Accept — still a Vary dependency.
    out.insert(header::VARY, HeaderValue::from_static("Accept"));
    (StatusCode::OK, out, lws.description_body()).into_response()
}

/// Choose the description's `Content-Type` from the request's `Accept` (bytes never change).
/// Highest-q named variant wins; default = the profiled JSON-LD form.
fn description_content_type(accept: &str) -> &'static str {
    let mut q_lws = 0.0f32;
    let mut q_json = 0.0f32;
    let mut q_ldjson = 0.0f32;
    for part in accept.split(',') {
        let (media, q, _profiled) = parse_accept_part(part);
        match media.as_str() {
            MEDIA_LWS_JSON => q_lws = q_lws.max(q),
            "application/json" => q_json = q_json.max(q),
            "application/ld+json" => q_ldjson = q_ldjson.max(q),
            _ => {}
        }
    }
    if q_lws > 0.0 && q_lws >= q_json && q_lws >= q_ldjson {
        MEDIA_LWS_JSON
    } else if q_json > 0.0 && q_json > q_ldjson {
        "application/json"
    } else {
        MEDIA_PROFILED_JSONLD
    }
}

/// Parse one comma-separated `Accept` part into `(media-essence-lowercase, q, has-lws-profile)`.
///
/// Parameter NAMES are matched case-insensitively (RFC 9110 §5.6.6 — the roborev Low on c3eb4da:
/// `Profile=`/`Q=` mixed-case variants must negotiate identically). For `q` this is
/// behaviour-identical to [`crate::ldp::content::negotiate_accept`]'s `q=`/`Q=` matching (the
/// single-letter name has no other case), so the q handling still mirrors the existing negotiator
/// exactly (default 1.0; a malformed q is 0 — "not accepted"; clamped to `[0,1]`) and LWS-side
/// negotiation can never disagree with it about a part's weight. `has-lws-profile` is true when a
/// `profile` parameter names [`JLWS_CONTEXT`] (quoted or bare) — the profiled-JSON-LD selector for
/// the container representation.
pub(crate) fn parse_accept_part(part: &str) -> (String, f32, bool) {
    let mut it = part.split(';');
    let media = it.next().unwrap_or("").trim().to_ascii_lowercase();
    let mut q: f32 = 1.0;
    let mut profiled = false;
    for param in it {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("q") {
            q = value.trim().parse::<f32>().unwrap_or(0.0).clamp(0.0, 1.0);
        } else if name.eq_ignore_ascii_case("profile") {
            let v = value.trim().trim_matches('"');
            if v == JLWS_CONTEXT {
                profiled = true;
            }
        }
    }
    (media, q, profiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_advertises_core_and_transform_when_on() {
        let cfg = LwsConfig::new("https://pod.example", true, false);
        let doc: serde_json::Value = serde_json::from_slice(&cfg.description_body()).unwrap();
        assert_eq!(doc["id"], "https://pod.example/");
        assert_eq!(doc["type"], "Storage");
        let conforms: Vec<&str> = doc["conformsTo"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(conforms.contains(&JLWS_CORE_CONFORMS));
        assert!(conforms.contains(&RDF_TRANSFORM_PROFILE));
        // The ContentNegotiation capability entries — the RDF opt-in — per source type.
        let caps = doc["capability"].as_array().unwrap();
        let ld = caps
            .iter()
            .find(|c| c["source"] == "application/ld+json")
            .expect("ld+json source entry");
        assert_eq!(ld["type"], "ContentNegotiation");
        assert_eq!(ld["profile"], RDF_TRANSFORM_PROFILE);
        let targets: Vec<&str> = ld["target"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(targets, vec!["text/turtle", "application/n-triples"]);
        // `normalizes` is omitted (default false — this store is byte-preserving).
        assert!(ld.get("normalizes").is_none());
        // The service set includes the self-referential StorageDescription entry.
        let services = doc["service"].as_array().unwrap();
        assert!(services.iter().any(|s| s["type"] == "StorageDescription"
            && s["serviceEndpoint"] == "https://pod.example/.well-known/lws"));
    }

    #[test]
    fn description_omits_transform_when_off() {
        let cfg = LwsConfig::new("https://pod.example", false, false);
        let doc: serde_json::Value = serde_json::from_slice(&cfg.description_body()).unwrap();
        let conforms: Vec<&str> = doc["conformsTo"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(conforms, vec![JLWS_CORE_CONFORMS]);
        assert_eq!(doc["capability"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn description_content_type_negotiation() {
        assert_eq!(description_content_type(""), MEDIA_PROFILED_JSONLD);
        assert_eq!(description_content_type("*/*"), MEDIA_PROFILED_JSONLD);
        assert_eq!(
            description_content_type("application/lws+json"),
            MEDIA_LWS_JSON
        );
        assert_eq!(
            description_content_type("application/json"),
            "application/json"
        );
        assert_eq!(
            description_content_type("application/ld+json"),
            MEDIA_PROFILED_JSONLD
        );
        // Highest q wins across the named variants.
        assert_eq!(
            description_content_type("application/lws+json;q=0.2, application/json;q=0.9"),
            "application/json"
        );
    }

    #[test]
    fn accept_part_parser_reads_q_and_profile() {
        let (m, q, p) = parse_accept_part(" application/ld+json;q=0.5 ");
        assert_eq!(m, "application/ld+json");
        assert!((q - 0.5).abs() < 1e-6);
        assert!(!p);
        let (_, _, p) =
            parse_accept_part("application/ld+json;profile=\"https://w3id.org/jeswr/lws/v1\"");
        assert!(p);
        let (_, _, p) =
            parse_accept_part("application/ld+json;profile=https://w3id.org/jeswr/lws/v1");
        assert!(p);
        // Parameter NAMES are case-insensitive (RFC 9110 §5.6.6 — the roborev Low on c3eb4da):
        // mixed-case `Profile=` / `Q=` parse identically.
        let (_, _, p) =
            parse_accept_part("application/ld+json;Profile=\"https://w3id.org/jeswr/lws/v1\"");
        assert!(p);
        let (_, q, p) =
            parse_accept_part("application/ld+json;PrOfIlE=https://w3id.org/jeswr/lws/v1;Q=0.4");
        assert!(p);
        assert!((q - 0.4).abs() < 1e-6);
        let (_, _, p) = parse_accept_part("application/ld+json;profile=\"https://other.example/\"");
        assert!(!p);
        // Malformed q ⇒ 0 (not accepted) — mirrors the existing negotiator.
        let (_, q, _) = parse_accept_part("application/json;q=abc");
        assert_eq!(q, 0.0);
    }

    #[test]
    fn storage_description_link_is_well_formed() {
        let cfg = LwsConfig::new("https://pod.example/", true, false);
        let mut headers = HeaderMap::new();
        cfg.add_storage_description_link(&mut headers);
        let v = headers.get(header::LINK).unwrap().to_str().unwrap();
        assert_eq!(
            v,
            "<https://pod.example/.well-known/lws>; rel=\"https://w3id.org/jeswr/lws#storageDescription\""
        );
    }
}
