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
//!   response is a single-query snapshot; a MULTI-REQUEST page walk is additionally
//!   snapshot-PINNED (`lws-gen` in the server's own links) when the backend advertises a
//!   generation token — the sparq#1572 ask, landed as sparq PR #1584 and consumed via
//!   [`crate::store::Store::list_children_snapshot`] (documented in [`container`]).
//! - **RFC 9396 `authorization_details` — narrowing-only** ([`rar`]; spec §rar): the LWS `at+jwt`
//!   claim is enforced at the same single verify-chokepoint as the audience containment, as a
//!   pure DENY-gate — effective access = WAC ∩ aud ∩ narrowing, so it can only ever reduce (a
//!   widening attempt changes nothing: WAC remains the ceiling). Intelligible-but-uncovered ⇒
//!   403 `insufficient_scope`; unintelligible ⇒ 401 fail-closed.
//!
//! ## What step 8 A/B ship (the spec-alignment increments — `decisions/0007`)
//! - **A — DPoP-SK over LWS** (`lws-spec` `docs/alignment/dpop-sk.md`, verdict (c) AUTH-profile):
//!   [`auth::ENV_LWS_POP_SESSION`] enables the SAME DPoP-SK engine [`crate::pop::sk`] ships (one
//!   engine, two switches — never a second implementation), so the LWS-extended RFC 9728 document
//!   carries the `pop_session` member (endpoint/algs/channel_bindings/profile) beside
//!   `jlws_storage_description`, and an attested request authenticates via the PoP dispatch that
//!   ALREADY precedes the Bearer paths in [`crate::auth`]. The composition is structural: a
//!   `cnf`-bound token is never an LWS Bearer candidate (rs-validation step 5 — "never bare"),
//!   and `dpop_bound_access_tokens_required` alone governs the PoP-required posture (the D9
//!   Bearer baseline; `pop_session` is an additive availability signal, not a requirement flip).
//! - **B — the a2a-rdf discovery affordance** (`docs/alignment/a2a-rdf.md`, verdict (d)
//!   REFERENCE + optional extension service): [`ENV_LWS_AGENT_CARD_URL`] advertises the storage
//!   controller's A2A agent as an [`A2A_AGENT_INTERACTION_SERVICE`] `service` entry in the
//!   storage description (the registry's extension-URI mechanism — no core registry term is
//!   minted). Emitted ONLY when the URL is configured AND validates (absolute http(s), no
//!   userinfo — fail-closed to "not advertised"); it adds no `conformsTo`/`capability` entry.
//!
//! ## M4 (deferred, seams noted)
//! Notification bindings (SSE + WebSocket under the WD subscription API), DPoP-bound
//! LWS-audience token validation for a PoP-required realm (§presentation-pop end-to-end for an
//! LWS-audience `at+jwt` — a webid-less token from the LWS AS cannot yet establish a DPoP proof
//! or DPoP-SK session through the Solid-OIDC verifier path; step-8 A composes the EXISTING
//! engine with the LWS realm, it does not widen the establishment token policy), the
//! `SparqlQueryService`/AC-SPARQL companion (a gated increment on `sparq#992`), operation-precise
//! narrowing for PUT-create/append-only-PATCH (today conservatively under-granted — [`rar`]), and
//! the container `application/json`-vs-`text/turtle` preference refinement. (Multi-request
//! pagination snapshot-consistency — formerly gated on `sparq#1572` — LANDED via sparq PR #1584
//! and is consumed on the HTTP-backend path; see [`container`].)

pub mod auth;
pub mod container;
pub mod linkset;
pub mod pin;
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
/// Pagination snapshot pinning: an unusable `lws-gen` value — 400 (the generation token is opaque;
/// only the server's own emitted pinned links are meaningful).
pub const PROBLEM_INVALID_GENERATION: &str =
    "https://w3id.org/jeswr/lws/problems/invalid-generation";
/// Pagination snapshot pinning: the pinned snapshot can no longer be served (it aged out of the
/// backend's retention window, or the backend instance no longer knows the token) — 410; the
/// walker restarts from the container's own URI (an unpinned first page — a fresh snapshot).
/// Never a silent substitute.
pub const PROBLEM_SNAPSHOT_GONE: &str = "https://w3id.org/jeswr/lws/problems/snapshot-gone";

/// Env flag that enables the LWS surface (`1`/`true`).
pub const ENV_LWS: &str = "SOLID_SERVER_LWS";
/// Env flag for the RDF content-transformation opt-in (`rdf-transform.html`). Default **on** when
/// the LWS surface is enabled (it is the surface's flagship capability); set `=0`/`false` for a
/// byte-native-only storage that advertises no `ContentNegotiation` capability.
pub const ENV_LWS_RDF_TRANSFORM: &str = "SOLID_SERVER_LWS_RDF_TRANSFORM";
/// Env flag for the STRICT D2/D3 PUT semantics (pure-LWS deployments only — changes Solid PUT
/// behaviour, see the module doc). Default **off**.
pub const ENV_LWS_STRICT_PUT: &str = "SOLID_SERVER_LWS_STRICT_PUT";
/// Env flag for the STRICT container-LISTING discipline (pure-LWS deployments only —
/// `index.html` §container-media-type, JLWSC-CMT-1/2). Default **off**. When ON, the LWS
/// server-managed JSON-LD listing IS the container representation: a container GET with **no
/// Accept**, or `application/ld+json` / `application/json` (in addition to the always-on
/// `application/lws+json` / profiled ld+json), all serve the IDENTICAL listing bytes with only
/// `Content-Type` varying (the same-bytes conneg rule). OFF (the composed default) keeps the
/// existing Solid LDP `ldp:contains` rendering for every non-LWS Accept — so the additive
/// invariant (an LWS-composed Solid deployment is byte-identical for the Solid surface) holds
/// unless a deployment explicitly opts into the pure-LWS listing.
pub const ENV_LWS_STRICT_LISTING: &str = "SOLID_SERVER_LWS_STRICT_LISTING";
/// Env knob for the LWS container-listing PAGE SIZE (M3, spec §pagination — the "server-determined
/// threshold"): a membership larger than this is paged. Default [`DEFAULT_LWS_PAGE_SIZE`]; `0`
/// disables pagination (every listing single-page); unparseable values keep the default.
pub const ENV_LWS_PAGE_SIZE: &str = "SOLID_SERVER_LWS_PAGE_SIZE";
/// The default pagination threshold/page size (members per page).
pub const DEFAULT_LWS_PAGE_SIZE: usize = 1000;
/// Env knob for the pagination snapshot-pin TTL in SECONDS (the server-minted `lws-gen` token's
/// lifetime — see [`pin`]): how long a page walk may keep re-using one pinned snapshot. Default
/// [`DEFAULT_LWS_PIN_TTL_SECS`]; unset/unparseable keeps the default. (The backend's own
/// generation-retention window still applies underneath — an aged-out pin is a 410 either way.)
pub const ENV_LWS_PIN_TTL: &str = "SOLID_SERVER_LWS_PIN_TTL_SECS";
/// The default pagination snapshot-pin TTL (seconds). Generous for a human-speed page walk, small
/// against the retention of anything the walker didn't just see.
pub const DEFAULT_LWS_PIN_TTL_SECS: u64 = 300;
/// Env knob for the step-8-B a2a-rdf discovery affordance (`lws-spec` `docs/alignment/a2a-rdf.md`):
/// the **A2A Agent Card URL** of the agent that speaks for this storage's controller. Set (to a
/// valid absolute http(s) URL) ⇒ the storage description advertises an
/// [`A2A_AGENT_INTERACTION_SERVICE`] extension-service entry pointing at it; unset/invalid (the
/// default) ⇒ the entry is not emitted and the description bytes are unchanged. Purely a
/// discovery advertisement — it grants nothing and changes no auth/WAC behaviour.
pub const ENV_LWS_AGENT_CARD_URL: &str = "SOLID_SERVER_LWS_AGENT_CARD_URL";

/// The A2A RDF extension URI (`jeswr/a2a-rdf-extension`) — the `conformsTo` value of the
/// [`A2A_AGENT_INTERACTION_SERVICE`] entry (the extension defines the term; the JLWS core
/// capability registry mints nothing — alignment verdict (d)).
pub const A2A_RDF_EXTENSION: &str = "https://w3id.org/jeswr/a2a-rdf/v1";
/// The extension-service `type` advertising the storage controller's A2A agent
/// (`serviceEndpoint` = the agent's **Agent Card URL** — the card, not the A2A endpoint: the card
/// carries the endpoint + the `capabilities.extensions` declaration). Consumers that don't
/// recognise the type ignore the entry (spec §discovery-model forward-compatibility).
pub const A2A_AGENT_INTERACTION_SERVICE: &str =
    "https://w3id.org/jeswr/a2a-rdf/v1#AgentInteractionService";

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
    /// The strict container-LISTING discipline (§container-media-type / JLWSC-CMT-1/2): when on,
    /// the LWS JSON-LD listing IS the container representation — a no-Accept / `application/ld+json`
    /// / `application/json` container GET serves the identical listing bytes (only `Content-Type`
    /// varies), rather than the composed Solid `ldp:contains` rendering. Off by default (composed
    /// mode preserved — see [`ENV_LWS_STRICT_LISTING`] + the module doc's composition note).
    pub strict_listing: bool,
    /// The container-listing page size (M3, spec §pagination): a listing whose VISIBLE membership
    /// exceeds this is paged (`Link` rel first/next/prev/last; `items` = the current page;
    /// `totalItems` = the whole visible membership). `None` ⇒ pagination off (every listing
    /// single-page). Default `Some(`[`DEFAULT_LWS_PAGE_SIZE`]`)`.
    pub page_size: Option<std::num::NonZeroUsize>,
    /// The per-process MAC key authenticating `lws-gen` snapshot-pin tokens (see [`pin`]): only a
    /// pin THIS server minted — bound to (container, requester) and expiring — is ever forwarded
    /// to the backend. `None` (an OS-RNG failure at construction — effectively unreachable) FAILS
    /// CLOSED: no pinned links are minted and every presented pin is refused with the 400
    /// `invalid-generation` problem; page walks degrade to unpinned, exactly the generation-less
    /// backend posture.
    pin_key: Option<pin::PinKey>,
    /// The snapshot-pin token TTL in seconds ([`ENV_LWS_PIN_TTL`], default
    /// [`DEFAULT_LWS_PIN_TTL_SECS`]). Expiry is exclusive — a zero TTL means every minted pin is
    /// already expired (used by tests to drive the 410 restart path deterministically).
    pin_ttl_secs: u64,
    /// The server's public base URL (trailing slash trimmed) — kept so the builder-style setters
    /// can rebuild the precomputed description body.
    base: String,
    /// The step-8-B a2a-rdf affordance: the controller-agent's Agent Card URL, VALIDATED
    /// (absolute http(s), no userinfo). `None` (the default) ⇒ no
    /// [`A2A_AGENT_INTERACTION_SERVICE`] entry and byte-identical description output.
    agent_card_url: Option<String>,
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
        let base = base_url.trim_end_matches('/').to_string();
        let description_body = Bytes::from(build_storage_description(&base, rdf_transform, None));
        let storage_description_link = HeaderValue::from_str(&format!(
            "<{base}{STORAGE_DESCRIPTION_PATH}>; rel=\"{JLWS_NS}storageDescription\""
        ))
        .ok();
        Self {
            rdf_transform,
            strict_put,
            strict_listing: false,
            page_size: std::num::NonZeroUsize::new(DEFAULT_LWS_PAGE_SIZE),
            // Fresh per-process entropy; `None` on RNG failure ⇒ pins disabled fail-closed (the
            // field's doc). Never minted from a weak fallback.
            pin_key: pin::PinKey::generate(),
            pin_ttl_secs: DEFAULT_LWS_PIN_TTL_SECS,
            base,
            agent_card_url: None,
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

    /// Enable the strict container-LISTING discipline ([`ENV_LWS_STRICT_LISTING`]; JLWSC-CMT-1/2):
    /// the LWS JSON-LD listing becomes the default container representation. Builder-style so every
    /// existing `new` caller keeps the composed default (off).
    pub fn with_strict_listing(mut self, strict_listing: bool) -> Self {
        self.strict_listing = strict_listing;
        self
    }

    /// Override the snapshot-pin token TTL (seconds; [`ENV_LWS_PIN_TTL`]). Builder-style; a zero
    /// TTL makes every minted pin immediately expired (the deterministic 410-path test hook —
    /// expiry is exclusive, see [`pin::verify`]).
    pub fn with_pin_ttl_secs(mut self, secs: u64) -> Self {
        self.pin_ttl_secs = secs;
        self
    }

    /// Mint the authenticated `lws-gen` token this server's own pagination links carry for
    /// (`container_iri`, `requester`, backend `generation`) — see [`pin`]. `None` when pins are
    /// disabled (no key — the fail-closed RNG posture): the caller then emits UNPINNED links, the
    /// graceful degradation shared with a generation-less backend.
    pub(crate) fn mint_pin(
        &self,
        container_iri: &str,
        requester: Option<&str>,
        generation: u64,
    ) -> Option<String> {
        let key = self.pin_key.as_ref()?;
        let exp = unix_now().saturating_add(self.pin_ttl_secs);
        Some(pin::mint(key, container_iri, requester, generation, exp))
    }

    /// Verify a presented `lws-gen` token for (`container_iri`, `requester`) and return the
    /// backend generation it pins. Fail-closed mapping (see [`pin`]'s module doc): anything not
    /// verifiably minted by this server for exactly this (container, requester) — including the
    /// no-key posture — is the opaque 400 [`PROBLEM_INVALID_GENERATION`]; a genuine token past its
    /// expiry is the 410 [`PROBLEM_SNAPSHOT_GONE`] restart (the walker re-fetches the container's
    /// own URI, an unpinned first page).
    pub(crate) fn verify_pin(
        &self,
        container_iri: &str,
        requester: Option<&str>,
        token: &str,
    ) -> Result<u64, crate::error::ServerError> {
        let Some(key) = self.pin_key.as_ref() else {
            return Err(invalid_generation_problem());
        };
        match pin::verify(key, container_iri, requester, token, unix_now()) {
            Ok(g) => Ok(g),
            Err(pin::PinVerifyError::Unminted) => Err(invalid_generation_problem()),
            Err(pin::PinVerifyError::Expired) => Err(pin_expired_problem()),
        }
    }

    /// Set the step-8-B a2a-rdf affordance (the controller-agent's **Agent Card URL**;
    /// [`ENV_LWS_AGENT_CARD_URL`]). The value is VALIDATED here — the single chokepoint — and
    /// anything that is not an absolute http(s) URL without userinfo collapses to `None`
    /// (fail-closed: a malformed advertisement is never emitted; the description bytes are then
    /// identical to a config never given a URL). Builder-style so every existing `new` caller
    /// keeps the default (no entry).
    pub fn with_agent_card_url(mut self, url: Option<&str>) -> Self {
        self.agent_card_url = url.and_then(validate_agent_card_url);
        self.description_body = Bytes::from(build_storage_description(
            &self.base,
            self.rdf_transform,
            self.agent_card_url.as_deref(),
        ));
        self
    }

    /// Read the LWS configuration from the environment: `None` (surface off — the default) unless
    /// [`ENV_LWS`] is truthy; the transform defaults ON and strictness OFF per the constants' docs;
    /// the page size per [`ENV_LWS_PAGE_SIZE`] (`0` = off, unset/unparseable = the default); the
    /// a2a-rdf agent-card advertisement per [`ENV_LWS_AGENT_CARD_URL`] (unset/invalid = no entry).
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
        let strict_listing = env_truthy(ENV_LWS_STRICT_LISTING);
        let page_size = match std::env::var(ENV_LWS_PAGE_SIZE)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
        {
            Some(n) => std::num::NonZeroUsize::new(n), // 0 ⇒ None ⇒ pagination off
            None => std::num::NonZeroUsize::new(DEFAULT_LWS_PAGE_SIZE),
        };
        let agent_card = std::env::var(ENV_LWS_AGENT_CARD_URL).ok();
        let pin_ttl_secs = std::env::var(ENV_LWS_PIN_TTL)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_LWS_PIN_TTL_SECS);
        Some(
            Self::new(base_url, rdf_transform, strict_put)
                .with_strict_listing(strict_listing)
                .with_page_size(page_size)
                .with_pin_ttl_secs(pin_ttl_secs)
                .with_agent_card_url(agent_card.as_deref()),
        )
    }

    /// The validated agent-card URL this config advertises (step-8 B), when configured.
    pub fn agent_card_url(&self) -> Option<&str> {
        self.agent_card_url.as_deref()
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

/// Unix seconds now, for pin mint/verify. On a pre-epoch clock (unreachable in practice) this
/// FAILS CLOSED via `u64::MAX`: every verify sees `now >= exp` (expired) and every mint saturates
/// to an already-expired token — a broken clock can only ever REFUSE pins, never extend one.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

/// The opaque 400 for anything that is not a token THIS server verifiably minted for exactly this
/// (container, requester) — forged, tampered, replayed cross-container/-principal, malformed, or
/// presented while pins are disabled. One indistinguishable answer for the whole class (a probe
/// learns nothing about WHY).
pub(crate) fn invalid_generation_problem() -> crate::error::ServerError {
    crate::error::ServerError::LwsProblem {
        status: 400,
        type_uri: PROBLEM_INVALID_GENERATION,
        title: "lws-gen must be the opaque generation token from the server's own pagination \
                links",
    }
}

/// The 410 for a genuinely server-minted pin past its TTL: the same `snapshot-gone` restart
/// contract as a backend-retention ageing — the walker re-fetches the container's own URI (an
/// unpinned first page, a fresh snapshot), never a silently different snapshot.
pub(crate) fn pin_expired_problem() -> crate::error::ServerError {
    crate::error::ServerError::LwsProblem {
        status: 410,
        type_uri: PROBLEM_SNAPSHOT_GONE,
        title: "the pagination snapshot is no longer available; restart from the container URI \
                (an unpinned first page)",
    }
}

/// `"1"`/`"true"` (case-insensitive, trimmed) ⇒ true. Mirrors the binary's `env_flag` semantics
/// (kept local so the library crate has no dependency on `main.rs`).
fn env_truthy(key: &str) -> bool {
    std::env::var(key).map(|v| is_truthy(&v)).unwrap_or(false)
}

pub(crate) fn is_truthy(v: &str) -> bool {
    matches!(v.trim(), "1" | "true" | "TRUE" | "True")
}

/// Is the LWS MASTER flag ([`ENV_LWS`]) set? The cheap check the binary uses where it needs the
/// on/off answer before/without building the full [`LwsConfig`] (e.g. the step-8-A
/// [`auth::pop_session_from_env`] gate). Reads the SAME variable [`LwsConfig::from_env`] gates on,
/// so the two can never disagree.
pub fn flag_from_env() -> bool {
    env_truthy(ENV_LWS)
}

/// Validate a step-8-B agent-card URL: an ABSOLUTE `http(s)` URL carrying **no userinfo** (a
/// `user:pw@host` spelling could cosmetically impersonate an origin in an advertisement read by
/// humans/agents — refused outright). Anything else ⇒ `None` — the entry is simply not emitted
/// (fail-closed: never advertise a malformed/unshaped value). The URL is emitted as a JSON string
/// via `serde_json` (escaped), so no injection is possible either way.
fn validate_agent_card_url(v: &str) -> Option<String> {
    let v = v.trim();
    let u = url::Url::parse(v).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    if !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    Some(v.to_string())
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
///
/// `agent_card` (step-8 B, pre-validated by [`LwsConfig::with_agent_card_url`]) appends the
/// OPTIONAL [`A2A_AGENT_INTERACTION_SERVICE`] extension-service entry — `serviceEndpoint` = the
/// controller-agent's Agent Card URL, `conformsTo` = [`A2A_RDF_EXTENSION`]. It joins `service`
/// ONLY (verdict (d): a reference affordance, not a capability — `conformsTo`/`capability` are
/// untouched), and `None` leaves the document byte-identical to pre-step-8.
fn build_storage_description(base: &str, rdf_transform: bool, agent_card: Option<&str>) -> Vec<u8> {
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

    let mut service = vec![json!({
        "type": "StorageDescription",
        "serviceEndpoint": description_url,
    })];
    if let Some(card_url) = agent_card {
        // The step-8-B a2a-rdf affordance: the storage controller's agent, discoverable from the
        // storage (its Agent Card carries the A2A endpoint + extension declaration). Appended
        // AFTER the required StorageDescription entry so the `None` case is byte-invariant.
        service.push(json!({
            "type": A2A_AGENT_INTERACTION_SERVICE,
            "serviceEndpoint": card_url,
            "conformsTo": A2A_RDF_EXTENSION,
        }));
    }

    let doc = json!({
        "@context": JLWS_CONTEXT,
        "id": storage_root,
        "type": "Storage",
        "conformsTo": conforms_to,
        "capability": capability,
        "service": service,
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

    // --- step-8 B: the a2a-rdf AgentInteractionService affordance --------------------------------

    const CARD: &str = "https://agent.example/.well-known/agent-card.json";

    #[test]
    fn description_advertises_agent_interaction_service_when_configured() {
        let cfg =
            LwsConfig::new("https://pod.example", true, false).with_agent_card_url(Some(CARD));
        assert_eq!(cfg.agent_card_url(), Some(CARD));
        let doc: serde_json::Value = serde_json::from_slice(&cfg.description_body()).unwrap();
        let services = doc["service"].as_array().unwrap();
        // The required StorageDescription entry is untouched…
        assert!(services.iter().any(|s| s["type"] == "StorageDescription"
            && s["serviceEndpoint"] == "https://pod.example/.well-known/lws"));
        // …and the extension entry carries EXACTLY the alignment-doc member set (the lws-spec
        // `sd-agent-interaction-service` vector's expectation, server side).
        let agent = services
            .iter()
            .find(|s| s["type"] == A2A_AGENT_INTERACTION_SERVICE)
            .expect("AgentInteractionService entry");
        assert_eq!(agent["serviceEndpoint"], CARD);
        assert_eq!(agent["conformsTo"], A2A_RDF_EXTENSION);
        assert_eq!(agent.as_object().unwrap().len(), 3, "exactly the 3 members");
        // Verdict (d): a REFERENCE affordance — no capability entry, no conformsTo URI is added.
        assert!(!doc["conformsTo"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.as_str().unwrap().contains("a2a-rdf")));
        assert!(!doc["capability"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["type"] == A2A_AGENT_INTERACTION_SERVICE));
    }

    #[test]
    fn description_without_agent_card_is_byte_identical_to_pre_step_8() {
        // The unset path — a config never given a URL and one explicitly given `None` — emits
        // the SAME bytes as the pre-step-8 builder (the additive-only invariant).
        let plain = LwsConfig::new("https://pod.example", true, false);
        let explicit_none =
            LwsConfig::new("https://pod.example", true, false).with_agent_card_url(None);
        assert_eq!(plain.description_body(), explicit_none.description_body());
        let doc: serde_json::Value = serde_json::from_slice(&plain.description_body()).unwrap();
        let services = doc["service"].as_array().unwrap();
        assert_eq!(services.len(), 1, "exactly the StorageDescription entry");
        assert_eq!(services[0]["type"], "StorageDescription");
    }

    #[test]
    fn agent_card_url_is_validated_fail_closed() {
        // Every rejected spelling collapses to "not advertised" — byte-identical to unset.
        let baseline = LwsConfig::new("https://pod.example", true, false);
        for bad in [
            "not-a-url",
            "",
            "   ",
            "ftp://agent.example/card.json",
            "javascript:alert(1)",
            "//agent.example/card.json",          // scheme-relative
            "https://user:pw@agent.example/card", // userinfo — refused (impersonation surface)
            "https://evil@agent.example/card",    // username-only userinfo too
            "/relative/card.json",
        ] {
            let cfg =
                LwsConfig::new("https://pod.example", true, false).with_agent_card_url(Some(bad));
            assert_eq!(cfg.agent_card_url(), None, "must reject: {bad}");
            assert_eq!(
                cfg.description_body(),
                baseline.description_body(),
                "rejected value must leave the bytes unchanged: {bad}"
            );
        }
        // Valid spellings (http for dev/loopback deployments, https for real ones) are kept;
        // surrounding whitespace is trimmed.
        for good in [CARD, "http://localhost:8080/agent-card.json"] {
            let cfg =
                LwsConfig::new("https://pod.example", true, false).with_agent_card_url(Some(good));
            assert_eq!(cfg.agent_card_url(), Some(good));
        }
        let cfg = LwsConfig::new("https://pod.example", true, false)
            .with_agent_card_url(Some(&format!("  {CARD}  ")));
        assert_eq!(cfg.agent_card_url(), Some(CARD));
    }

    /// The WHOLE env matrix for the step-8 flags in ONE test (env vars are process-global and
    /// `cargo test` runs threads in parallel — these variables are mutated ONLY here, mirroring
    /// the `pop::sk` env test's discipline).
    #[test]
    fn step8_env_flags_are_inert_without_the_master_flag() {
        // Master flag OFF: everything is inert regardless of the step-8 knobs.
        std::env::remove_var(ENV_LWS);
        std::env::set_var(super::auth::ENV_LWS_POP_SESSION, "1");
        std::env::set_var(ENV_LWS_AGENT_CARD_URL, CARD);
        assert!(!flag_from_env());
        assert!(LwsConfig::from_env("https://pod.example").is_none());
        assert!(
            !super::auth::pop_session_from_env(),
            "pop_session is inert without SOLID_SERVER_LWS"
        );

        // Master flag ON: the knobs take effect…
        std::env::set_var(ENV_LWS, "1");
        assert!(flag_from_env());
        assert!(super::auth::pop_session_from_env());
        let cfg = LwsConfig::from_env("https://pod.example").expect("surface on");
        assert_eq!(cfg.agent_card_url(), Some(CARD));

        // …and default OFF individually when unset.
        std::env::remove_var(super::auth::ENV_LWS_POP_SESSION);
        std::env::remove_var(ENV_LWS_AGENT_CARD_URL);
        assert!(!super::auth::pop_session_from_env());
        let cfg = LwsConfig::from_env("https://pod.example").expect("surface on");
        assert_eq!(cfg.agent_card_url(), None);

        // An INVALID card URL from the env is fail-closed to "not advertised".
        std::env::set_var(ENV_LWS_AGENT_CARD_URL, "ftp://nope.example/card");
        let cfg = LwsConfig::from_env("https://pod.example").expect("surface on");
        assert_eq!(cfg.agent_card_url(), None);

        std::env::remove_var(ENV_LWS);
        std::env::remove_var(ENV_LWS_AGENT_CARD_URL);
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
