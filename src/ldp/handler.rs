// AUTHORED-BY Claude Opus 4.8
//! The LDP request handlers — GET / HEAD / PUT / POST / DELETE / PATCH over the [`Store`] seam.
//!
//! These are the axum handlers over the [`Store`] seam. They stay thin: target parsing
//! ([`crate::ldp::target`]), content classification + negotiation ([`crate::ldp::content`]),
//! precondition evaluation ([`crate::ldp::conditional`]), range computation ([`crate::ldp::range`]),
//! and the N3-Patch engine ([`crate::ldp::patch`]) are pure modules; the handler is the HTTP glue +
//! the store call.
//!
//! ## The authorization seam (real per-resource WAC)
//!
//! Each handler runs the local in-Rust Web Access Control engine ([`crate::authz`]) BEFORE touching
//! storage: the HTTP method + target maps to a required [`AccessMode`]
//! ([`mode_for_operation`]); the [`WacAuthorizer`] resolves the effective `.acl` (the target's OWN
//! `acl:accessTo` ACL, else the nearest ancestor's `acl:default`, child→root, fail-closed) and returns
//! a [`Decision`]:
//!
//! - **`Allow`** — the operation proceeds; on a permitted GET/HEAD the read response carries the
//!   `WAC-Allow` header (the requester's + the public's effective modes).
//! - **`Unauthenticated`** (the requester is anonymous and auth could plausibly grant) — **401** +
//!   `WWW-Authenticate` challenge, so the client obtains a token.
//! - **`Forbidden`** (authenticated but not authorized) — **403**.
//!
//! Reading or writing a resource's OWN `.acl` requires `acl:Control` (encoded by
//! [`mode_for_operation`]). Public-readable resources are exactly those whose effective ACL grants
//! `foaf:Agent acl:Read` — the conformance seed sets up the WebID-profile + pod-root ACLs (see
//! [`crate::seed`]). Authorization runs BEFORE the existence check, so a permitted read of a missing
//! resource is a 404 while an UNauthorized/anonymous read of the same is a 403/401 (no existence leak).

use std::sync::{Arc, LazyLock};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;

use oxrdf::{NamedNode, Triple};

use crate::acl_cache::AclCache;
use crate::auth::VerifiedToken;
use crate::authz::wac::{Decision, ReadDecision, WacAuthorizer};
use crate::authz::wac_allow::wac_allow_header;
use crate::authz::{mode_for_operation, AccessMode};
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

/// The five vocabulary IRIs above are server CONSTANTS — fixed strings, RFC-3987-valid by
/// construction. Validating them through `NamedNode::new` (oxiri RFC-3987 parse) on every container
/// render is pure waste: the same five strings re-parse identically every time. Validate each ONCE
/// per process via `new_unchecked` behind a `LazyLock` and clone the cached `NamedNode` on the hot
/// path. `new_unchecked` is sound here precisely because the inputs are compile-time constants; a
/// `debug_assert!` re-validates each in debug builds so a typo'd constant fails a test, never ships.
static RDF_TYPE_NODE: LazyLock<NamedNode> = LazyLock::new(|| unchecked_const_iri(RDF_TYPE_IRI));
static LDP_RESOURCE_NODE: LazyLock<NamedNode> =
    LazyLock::new(|| unchecked_const_iri(LDP_RESOURCE_IRI));
static LDP_CONTAINER_NODE: LazyLock<NamedNode> =
    LazyLock::new(|| unchecked_const_iri(LDP_CONTAINER_IRI));
static LDP_BASIC_CONTAINER_NODE: LazyLock<NamedNode> =
    LazyLock::new(|| unchecked_const_iri(LDP_BASIC_CONTAINER_IRI));
static LDP_CONTAINS_NODE: LazyLock<NamedNode> =
    LazyLock::new(|| unchecked_const_iri(LDP_CONTAINS_IRI));

/// Build a `NamedNode` from a COMPILE-TIME-CONSTANT IRI without the per-call RFC-3987 re-parse.
/// Confined to the five `*_IRI` server constants above (validated once, at first use). The
/// `debug_assert!` re-runs the checked parse in debug/test builds so a malformed constant is caught
/// by the test suite rather than silently producing an invalid node.
fn unchecked_const_iri(iri: &str) -> NamedNode {
    debug_assert!(
        NamedNode::new(iri).is_ok(),
        "server-constant IRI must be RFC-3987 valid: {iri}"
    );
    NamedNode::new_unchecked(iri)
}

/// CHEAP (O(len), no allocation) structural guard for a child IRI that is about to be wrapped in a
/// `NamedNode::new_unchecked` and serialised into a Turtle/N-Triples `<...>` term. It is NOT a full
/// RFC-3987 validator (the fast path deliberately skips oxiri's parse) — it rejects ONLY the
/// characters RFC-3987 forbids INSIDE an IRI reference and that would corrupt the serialised term:
/// the C0/C1 control range and DEL, the space, and the ASCII delimiters `< > " { } | ^ \` `\` `.
/// An empty IRI is also rejected. Every IRI the store mints passes this (it is RFC-3987-valid on
/// write); the guard exists so a hypothetically-malformed backend row is OMITTED from the listing
/// rather than silently producing an invalid RDF term (defence-in-depth, matching the prior
/// skip-on-`NamedNode::new`-error behaviour).
fn iri_chars_serialisable(iri: &str) -> bool {
    if iri.is_empty() {
        return false;
    }
    // FAST PATH (the overwhelmingly common case): a child IRI minted by the store is ASCII —
    // `https://host/c/item-0042` etc. Every character RFC-3987 forbids in a serialisable `<...>` term
    // EXCEPT the C1 control range (U+0080..=U+009F) is ASCII, so for an all-ASCII IRI a single byte
    // scan with plain comparisons decides it — WITHOUT decoding UTF-8 to `char` and WITHOUT the
    // per-char Unicode `is_control` property-table lookup the `.chars()` path pays. This is the listing
    // render's largest per-child cost (one call per member); skipping the Unicode table lookup for the
    // common all-ASCII child is the win. The moment any non-ASCII byte (>= 0x80) is seen, fall through
    // to the original `char`-based check (which alone handles the C1 range correctly) — so the result
    // is BYTE-IDENTICAL to the prior implementation for every input, only faster on the ASCII path.
    let bytes = iri.as_bytes();
    let mut all_ascii = true;
    for &b in bytes {
        if b >= 0x80 {
            all_ascii = false;
            break;
        }
        // ASCII forbidden set: C0 controls (< 0x20) + DEL (0x7F) + space + the term delimiters.
        // (`is_control()` for an ASCII char is exactly `b < 0x20 || b == 0x7F`.)
        if b < 0x20
            || b == 0x7F
            || matches!(
                b,
                b' ' | b'<' | b'>' | b'"' | b'{' | b'}' | b'|' | b'^' | b'`' | b'\\'
            )
        {
            return false;
        }
    }
    if all_ascii {
        return true;
    }
    // Non-ASCII present (rare — a `ucschar` like `café`): defer to the exact `char`-based check, which
    // additionally rejects the C1 control range. This is the original implementation, unchanged.
    !iri.chars().any(|c| {
        c.is_control()
            || c == ' '
            || matches!(c, '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\')
    })
}

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
    /// The per-instance ETag-keyed parsed-ACL cache (read-path optimisation #3). Shared across all
    /// requests (it lives in the server-lifetime `Arc<LdpState>`), so a hot resource's UNCHANGED `.acl`
    /// is parsed once and reused — keyed by `(acl-iri, etag)`, never authoritative (see
    /// [`crate::acl_cache`]). Default-on at [`AclCache::new`]`(`[`DEFAULT_ACL_CACHE_CAPACITY`]`)`;
    /// `SOLID_SERVER_ACL_CACHE_CAPACITY=0` ([`AclCache::disabled`]) yields byte-identical pre-cache
    /// behaviour. Configured at router assembly via [`set_acl_cache`](Self::set_acl_cache).
    pub acl_cache: AclCache,
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
            // Default-on: the ACL cache is enabled at the default capacity. `main.rs` overrides this
            // from `SOLID_SERVER_ACL_CACHE_CAPACITY` at router assembly (`=0` ⇒ disabled).
            acl_cache: AclCache::new(crate::acl_cache::DEFAULT_ACL_CACHE_CAPACITY),
        }
    }

    /// Set the `WWW-Authenticate` challenge emitted on a 401 (the verifier-derived one). Called by
    /// [`AppState::new`](crate::app::AppState::new) so the LDP layer's anonymous-401 names the same
    /// issuer(s)/algs as every other challenge.
    pub fn set_www_authenticate(&mut self, challenge: impl Into<String>) {
        self.www_authenticate = challenge.into();
    }

    /// Replace the ACL cache (called by `main.rs` at router assembly to apply the operator-configured
    /// capacity / disable it). The default constructors already enable it at the default capacity.
    pub fn set_acl_cache(&mut self, acl_cache: AclCache) {
        self.acl_cache = acl_cache;
    }

    /// Invalidate the cached parse of an ACL resource after a successful WRITE / DELETE of it (belt-and-
    /// braces — the `(acl-iri, etag)` gate already prevents serving a rotated ACL stale, but freeing the
    /// slot on a mutation is cheap and makes a delete take effect immediately). A no-op for a
    /// non-`.acl` target or a disabled cache.
    fn invalidate_acl_if_acl(&self, target_iri: &str) {
        if crate::authz::is_acl_resource(target_iri) {
            self.acl_cache.invalidate(target_iri);
        }
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

    /// Run Web Access Control for `target` + the `method`-derived required mode against `token`.
    ///
    /// On a permitted operation returns the FULL set of modes the requester holds over the target (so
    /// a GET/HEAD can build `WAC-Allow` without re-walking the ACL hierarchy). On a denial returns the
    /// spec-shaped error: a 401 + `WWW-Authenticate` when the requester is anonymous (so the client
    /// authenticates), a 403 when authenticated-but-unauthorized.
    async fn authorize(
        &self,
        method: &str,
        target: &LdpTarget,
        token: &VerifiedToken,
        origin: Option<&str>,
    ) -> Result<std::collections::BTreeSet<AccessMode>, ServerError> {
        let required = mode_for_operation(method, &target.iri, target.is_container);
        self.authorize_mode(target, required, token, origin).await
    }

    /// Single-pass READ authorization (Optimization #2): authorize a GET/HEAD AND resolve the
    /// `WAC-Allow` audiences (`user` + `public`) from ONE effective-ACL resolution.
    ///
    /// Replaces the read path's prior `authorize(...)` + `wac_allow_value(...)` pair, which built a
    /// fresh [`WacAuthorizer`] and re-resolved the protected resource (and, for an authenticated
    /// requester, re-walked + re-read + re-parsed the SAME `.acl`) a SECOND time. The required mode is
    /// the `method`-derived read mode, overridden to [`AccessMode::Control`] for an `.acl` target
    /// (managing access rules is always Control) — IDENTICAL to [`authorize`](Self::authorize) /
    /// [`authorize_mode`](Self::authorize_mode). On a permitted read returns the
    /// [`EffectivePermissions`] for `WAC-Allow`; on a denial the SAME spec error (401 + challenge when
    /// anonymous, 403 when authenticated-but-unauthorized).
    async fn authorize_read(
        &self,
        method: &str,
        target: &LdpTarget,
        token: &VerifiedToken,
        origin: Option<&str>,
    ) -> Result<crate::authz::EffectivePermissions, ServerError> {
        // The required read mode, with the `.acl`→Control override (an `.acl` is governed by Control
        // regardless of the operation) — matching `authorize`/`authorize_mode` exactly.
        let required = if crate::authz::is_acl_resource(&target.iri) {
            AccessMode::Control
        } else {
            mode_for_operation(method, &target.iri, target.is_container)
        };
        let wac = WacAuthorizer::with_cache(&self.store, &self.base_url, &self.acl_cache);
        match wac
            .authorize_read(&target.iri, required, token.web_id.as_deref(), origin)
            .await?
        {
            ReadDecision::Allow(perms) => Ok(perms),
            ReadDecision::Unauthenticated => Err(self.unauthenticated()),
            ReadDecision::Forbidden => Err(ServerError::Forbidden),
        }
    }

    /// Run Web Access Control for `target` with an EXPLICIT required mode (used by PATCH, whose mode
    /// depends on the patch CONTENT — an insert-only patch needs only `acl:Append`, a patch with any
    /// delete needs `acl:Write`). For an `.acl` target the required mode is overridden to
    /// [`AccessMode::Control`] regardless (managing access rules is always the Control privilege).
    async fn authorize_mode(
        &self,
        target: &LdpTarget,
        required: AccessMode,
        token: &VerifiedToken,
        origin: Option<&str>,
    ) -> Result<std::collections::BTreeSet<AccessMode>, ServerError> {
        // An `.acl` resource is governed by Control regardless of the operation/content.
        let required = if crate::authz::is_acl_resource(&target.iri) {
            AccessMode::Control
        } else {
            required
        };
        let wac = WacAuthorizer::with_cache(&self.store, &self.base_url, &self.acl_cache);
        match wac
            .authorize(&target.iri, required, token.web_id.as_deref(), origin)
            .await?
        {
            Decision::Allow(modes) => Ok(modes),
            Decision::Unauthenticated => Err(self.unauthenticated()),
            Decision::Forbidden => Err(ServerError::Forbidden),
        }
    }

    /// Run WAC for an EXPLICIT (`target_iri`, mode), where `target_iri` may be a synthetic container
    /// IRI (e.g. the parent of the resource being created/deleted, which is itself a valid container
    /// path). Returns the granted modes on Allow, or the spec 401/403 on deny.
    async fn authorize_iri(
        &self,
        target_iri: &str,
        required: AccessMode,
        token: &VerifiedToken,
        origin: Option<&str>,
    ) -> Result<(), ServerError> {
        let wac = WacAuthorizer::with_cache(&self.store, &self.base_url, &self.acl_cache);
        match wac
            .authorize(target_iri, required, token.web_id.as_deref(), origin)
            .await?
        {
            Decision::Allow(_) => Ok(()),
            Decision::Unauthenticated => Err(self.unauthenticated()),
            Decision::Forbidden => Err(ServerError::Forbidden),
        }
    }

    /// WAC container-modification authorization for a CREATE (the missing half of the WAC create rule).
    ///
    /// Creating a resource — and materialising any missing intermediate container via
    /// [`ensure_ancestor_containers`] — MUTATES the `ldp:contains` membership of the nearest EXISTING
    /// ancestor container. Per Web Access Control this requires `acl:Append` (which `acl:Write`
    /// subsumes) ON THAT CONTAINER via its own `acl:accessTo` scope — the "creating a resource requires
    /// write/append access to the containing container" rule (WAC spec §"Modes of access"; CSS's create
    /// authorization; the TS-sibling `authorizeCreation`). This is enforced IN ADDITION to the target's
    /// own effective-ACL Write/Append that the create paths authorize first (which the existence-non-
    /// disclosure V1/V3 closure requires), and makes CREATE **symmetric with DELETE** (whose parent-Write
    /// check gates containment shrink). Without it, an `acl:default`-only Write grant — or a
    /// Control-holder-pre-provisioned target `.acl` — would let an agent with NO mode on the container
    /// create members / intermediate containers in it (a privilege-escalation container-write bypass).
    ///
    /// An `.acl` auxiliary is NOT a contained child (it carries no `ldp:contains` edge — see the create
    /// paths), so authoring one mutates no containment and is exempt (mirroring DELETE, which skips its
    /// parent-Write check for an `.acl`). The check runs against the nearest EXISTING ancestor via
    /// [`nearest_existing_container`](Self::nearest_existing_container); when NONE exists (an
    /// unprovisioned store whose root container is absent) there is no container whose membership is
    /// being mutated, so the check is skipped — exactly as DELETE skips its parent check on a `None`
    /// nearest-parent. The access decision reads only ancestor `.acl` resources (never the target).
    async fn authorize_container_modification(
        &self,
        target_iri: &str,
        token: &VerifiedToken,
        origin: Option<&str>,
    ) -> Result<(), ServerError> {
        // An `.acl` auxiliary is not a contained child — no container-modification right is required.
        if crate::authz::is_acl_resource(target_iri) {
            return Ok(());
        }
        if let Some(container) = self.nearest_existing_container(target_iri).await? {
            self.authorize_iri(&container, AccessMode::Append, token, origin)
                .await?;
        }
        Ok(())
    }

    /// EXISTENCE-NON-DISCLOSURE — the **V4** conditional-channel closure (decisions/0003).
    ///
    /// A conditional precondition (`If-Match` / `If-None-Match`) on a mutating request is evaluated
    /// against the target's CURRENT ETag, which is a CONTENT-derived (for a document) or
    /// MEMBERSHIP-derived (for a container) validator. Its 412-vs-2xx outcome — and any `ETag` the
    /// write response then carries — therefore leak whether the target exists AND a fingerprint of a
    /// representation the requester may NOT be entitled to read. A `Write`-without-`Read` holder doing
    /// `PUT … If-Match: "x"` could thus probe existence (412 if present-and-mismatched, 2xx-then-ETag if
    /// present-and-matched, 412 if absent under `If-Match`) and learn the content/membership ETag of a
    /// body it cannot GET.
    ///
    /// Closure: treat a content/membership-derived validator as REQUIRING the mode that governs READING
    /// the target's representation — `acl:Read` for a normal resource, but `acl:Control` for an `.acl`
    /// target (reading an `.acl`'s representation is itself a Control operation; `Control` does NOT imply
    /// `Read`, so the read-mode for an `.acl` is Control, not Read — else a Control-only holder, who IS
    /// entitled to the `.acl`'s ETag, would be wrongly denied a conditional `.acl` write). When the
    /// request carries ANY conditional precondition AND the (already-authorized) requester's granted
    /// modes do NOT include that read-mode, return the requester's DENIAL code (401 anonymous / 403
    /// authenticated) INSTEAD of evaluating the precondition — so the conditional outcome reveals
    /// nothing. A requester WITHOUT a conditional header is unaffected (no validator is consulted on
    /// their path), and a requester who holds the read-mode keeps full conditional semantics. `granted`
    /// is the mode set the write authorization already returned (no extra ACL resolution).
    fn guard_conditional_requires_read(
        &self,
        target_iri: &str,
        headers: &HeaderMap,
        granted: &std::collections::BTreeSet<AccessMode>,
        token: &VerifiedToken,
    ) -> Result<(), ServerError> {
        let has_conditional =
            headers.contains_key(header::IF_MATCH) || headers.contains_key(header::IF_NONE_MATCH);
        // The mode that governs reading THIS target's representation: Control for an `.acl`, else Read.
        let read_mode = if crate::authz::is_acl_resource(target_iri) {
            AccessMode::Control
        } else {
            AccessMode::Read
        };
        if has_conditional && !granted.contains(&read_mode) {
            return Err(if token.web_id.is_none() {
                self.unauthenticated()
            } else {
                ServerError::Forbidden
            });
        }
        Ok(())
    }

    /// The nearest EXISTING container at or above `target` (its parent, then grandparent, … up to the
    /// storage root), or `None` if none exists (not even the root).
    async fn nearest_existing_container(
        &self,
        target_iri: &str,
    ) -> Result<Option<String>, ServerError> {
        let root = format!("{}/", self.base_url.trim_end_matches('/'));
        // Start from the immediate parent: drop a container's own trailing slash first.
        let mut current = target_iri.to_string();
        if current.ends_with('/') {
            current.pop();
        }
        loop {
            let Some(slash) = current.rfind('/') else {
                break;
            };
            let parent = current[..=slash].to_string();
            if self.store.exists(&parent).await? {
                return Ok(Some(parent));
            }
            if parent == root || parent.len() <= root.len() {
                break;
            }
            current = parent[..parent.len() - 1].to_string();
        }
        Ok(None)
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
///
/// `pub(crate)` so the pre-crypto public-read skip middleware ([`crate::ldp::public_read_skip`]) can
/// serve a PUBLIC read AS anonymous (token = [`VerifiedToken::public`]) over the SAME code path the
/// handler uses — guaranteeing a skipped public read is byte-identical to a genuinely anonymous one
/// (INV-1). The middleware never passes a non-public token here.
pub(crate) async fn serve_read<S: Store>(
    state: &Arc<LdpState<S>>,
    token: &VerifiedToken,
    uri: &axum::http::Uri,
    req_headers: &HeaderMap,
    with_body: bool,
) -> Result<Response, ServerError> {
    let target = parse_target(&state.base_url, uri.path())?;

    // WAC read authorization (real per-resource `.acl` evaluation). A GET/HEAD requires `acl:Read`
    // (Control for an `.acl` target); the public-read class is whatever the effective ACL grants to
    // `foaf:Agent`, so a WebID profile card with a public-read ACL stays anonymously readable while
    // private data answers 401 (anonymous) / 403 (authenticated-but-unauthorized). Authorization runs
    // BEFORE the existence check, so a permitted read of a missing resource is a 404, while an
    // unauthorized read of the same is a 401/403 (no existence leak).
    // SINGLE-PASS read authorization (Optimization #2): resolve the effective ACL ONCE and derive
    // BOTH the access decision (Allow / 401 / 403) AND the `WAC-Allow` audiences (`user` + `public`)
    // from that one resolution. (Previously the decision and the `WAC-Allow` header each resolved the
    // ACL independently.) `perms` is reused below to emit `WAC-Allow` with no further ACL work.
    let origin = request_origin(req_headers);
    let perms = state
        .authorize_read(
            if with_body { "GET" } else { "HEAD" },
            &target,
            token,
            origin,
        )
        .await?;

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
    //
    // V5 (decisions/0003) — the membership-derived container ETag shifts on every child add/remove, so
    // it is a listing oracle. It is exposed ONLY here, on the GET/HEAD read path, which is gated above
    // by `authorize_read` requiring `acl:Read` on the container — so a non-reader NEVER reaches this
    // ETag. The conditional-channel sibling (a non-reader probing the container ETag via `If-Match` on a
    // write) is closed by the V4 `guard_conditional_requires_read` in the mutating handlers. Together
    // these Read-gate the container ETag end to end. (If a future change emits a container's
    // representation ETag outside a Read-gated path, that gate must be re-established there too.)
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
    add_acl_link(&mut out, &target);
    // WAC-Allow (Solid Protocol): advertise the requester's + the public's effective access modes for
    // this target. Both audiences were resolved by `authorize_read` above in the SAME pass as the
    // access decision (no second ACL walk/read/parse) — `perms` is serialised directly.
    let wac_allow = wac_allow_header(&perms);
    set_str(&mut out, HeaderName::from_static("wac-allow"), &wac_allow);

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
    let target = parse_target(&state.base_url, uri.path())?;

    // WAC for PUT — EXISTENCE-NON-DISCLOSURE (decisions/0003): a PUT requires `acl:Write` on the
    // TARGET's effective ACL (inherited via `acl:default` for a not-yet-existing target), authorized
    // **regardless of whether the target exists** so create and overwrite are INDISTINGUISHABLE to an
    // under-authorized requester:
    //  - **Overwrite** (target exists): `acl:Write` on the target — unchanged.
    //  - **Create** (target absent): ALSO `acl:Write` on the target's INHERITED ACL — NOT the weaker
    //    parent-`acl:Append`. This closes the V1 create-vs-forbidden-overwrite existence oracle: a
    //    drop-box writer holding only parent `acl:Append` (no target Write) previously got a 201 on a
    //    free name but a 403 on a taken one — leaking which child names exist. Now both are the SAME
    //    denial. (CTH-safe: every `write-access-*` PUT-fictive row that expects 201 grants the agent
    //    inheritable `acl:Write`; no row expects an Append-only PUT-create=201 — see decisions/0003.)
    //    TRADE-OFF: an `acl:Append`-only agent can no longer PUT-create; it MUST use POST (which mints
    //    a server-opaque, collision-free name — the containment-mutating create primitive). Documented
    //    in the ADR.
    //  - **`.acl` target**: routes to `acl:Control` on the protected resource (managing access rules) —
    //    `mode_for_operation`/`authorize` already override the mode to Control for an `.acl`.
    //
    // Authorize BEFORE any target-dependent `meta()`/existence probe (the V1 timing closure): the
    // under-authorized denial is returned with no observable dependence on whether the target exists,
    // and the access decision itself reads ONLY `.acl` resources (never the target's own bytes/meta).
    let origin = request_origin(&headers);
    let granted = state.authorize("PUT", &target, &token, origin).await?;

    // V4 (decisions/0003): a conditional precondition is a CONTENT/MEMBERSHIP-derived validator — a
    // requester lacking `acl:Read` on the target must NOT get its existence-revealing 412-vs-2xx
    // outcome (nor a returned ETag). Fold to the denial code when a conditional header is present and
    // the requester holds no Read. Done BEFORE the existence probe so it adds no oracle of its own.
    state.guard_conditional_requires_read(&target.iri, &headers, &granted, &token)?;

    // The caller IS authorized. Only NOW probe existence (an authorized writer is entitled to learn
    // create-vs-replace) — reused for the conditional-write ETag and the create/replace branch below.
    let current = state.store.meta(&target.iri).await?;
    let existed = current.is_some();

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
    let current_etag = current.as_ref().map(|m| m.etag.as_str());
    conditional::require(eval_preconditions(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        current_etag,
    ))?;

    let parent = parent_container(&target);

    let meta = if existed {
        // A replace: rewrite the bytes in place; containment is unchanged.
        state.store.write(&target.iri, body, &stored_type).await?
    } else if crate::authz::is_acl_resource(&target.iri) {
        // A CREATE of an AUXILIARY `.acl` resource: it is NOT a contained child. Store it via a plain
        // `write` (no `ldp:contains` edge on the parent, and a later DELETE mutates no parent
        // containment) — the Solid auxiliary-resource model. Auth for `.acl` is Control (above).
        state.store.write(&target.iri, body, &stored_type).await?
    } else {
        // A CREATE via PUT must create intermediate containers (Solid Protocol §writing-resource —
        // "Creating a resource using PUT … must create intermediate containers") AND wire the new
        // resource into its parent's `ldp:contains` membership (so the container GET lists it). An
        // ancestor that already exists as a NON-container is a conflict (a resource cannot have a
        // child) → handled by `ensure_ancestor_containers`.
        //
        // WAC container-modification: this mutates the containment of the nearest existing ancestor, so
        // it requires `acl:Append` (Write subsumes) ON THAT CONTAINER — in addition to the target-ACL
        // Write authorized above. Symmetric with DELETE's parent-Write check; closes the create-authz
        // widening (an `acl:default`-only Write / pre-provisioned target `.acl` must NOT let an agent
        // with no mode on the container mint members or intermediate containers in it).
        state
            .authorize_container_modification(&target.iri, &token, origin)
            .await?;
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
    //
    // EXCEPTION — an AUXILIARY `.acl` resource is NOT a contained child (it was stored via a plain
    // `write`, with NO `ldp:contains` edge added to the parent above). So even on a CREATE its parent
    // membership did NOT change: pass `None` for the emit parent so the hub does NOT derive a spurious
    // container-membership `Add` for a resource the container does not actually contain.
    let activity = if existed {
        ActivityType::Update
    } else {
        ActivityType::Create
    };
    let emit_parent = if existed || crate::authz::is_acl_resource(&target.iri) {
        None
    } else {
        parent.clone()
    };
    state
        .notifications
        .notify(&target.iri, activity, emit_parent.as_deref())
        .await;

    // A PUT to an `.acl` resource changed the access rules: invalidate the cached parse so the NEXT
    // read resolves against the new ACL immediately (belt-and-braces over the etag gate; see
    // `invalidate_acl_if_acl`).
    state.invalidate_acl_if_acl(&target.iri);

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
    let container = parse_target(&state.base_url, uri.path())?;
    // WAC: a POST to a container requires `acl:Append` on the container (a writer also satisfies it).
    // Anonymous ⇒ 401, authenticated-but-unauthorized ⇒ 403. Authorize BEFORE the container-shape /
    // existence checks so an unauthorized caller cannot probe existence (the read-access POST cases
    // accept `[403]` for a real container and `[403, 404]` for a fictive one — authorize-first 403 is
    // within both).
    let origin = request_origin(&headers);
    state.authorize("POST", &container, &token, origin).await?;

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

    // The sanitised Slug STEM (the caller's name hint; `None` if no usable Slug). The mint uses it ONLY
    // as a prefix of an opaque, collision-free name (V2 — see `mint_child_iri`), so the final segment
    // never equals the verbatim Slug. The `.acl`-intent guard below is checked against THIS STEM (the
    // caller's intent) rather than the post-opaque minted IRI.
    let slug = header_str(&headers, HeaderName::from_static("slug"));
    let stem = slug.and_then(sanitise_slug);

    // SECURITY (privilege-escalation guard): a POST authorizes only `acl:Append`/`Write` on the
    // CONTAINER — never `acl:Control`. `sanitise_slug` keeps `.`, so a `Slug: secret.acl` carries the
    // INTENT to mint an ACL auxiliary. Even though V2's opaque-suffix mint would now produce a benign
    // `…/secret.acl-<opaque>` (which the WAC resolver — exact `.acl` suffix only — never reads as an
    // ACL, so the escalation is already structurally defused), we STILL refuse the request: rejecting
    // the INTENT keeps a single, clear contract — "an Append-only POST cannot author an `.acl`" — and
    // is belt-and-braces against any future mint change that might preserve the suffix. A create of a
    // `.acl` is a Control operation; the Control-gated PUT/PATCH of an `.acl` is the only legitimate
    // path. The check is on the SANITISED STEM (the caller's intent, covering the case-variant
    // `secret.ACL` via the case-insensitive `is_acl_auxiliary_suffix`).
    //
    // The denial uses the REQUESTER's denial shape — 401 + `WWW-Authenticate` for an anonymous caller,
    // 403 for an authenticated one — IDENTICAL to every other POST denial. (POST authorization already
    // ran above, so an anonymous caller without public `acl:Append` is already 401'd before here; this
    // matters only for a PUBLIC-append container where an anonymous caller CAN reach this guard, and
    // there the anonymous denial must still carry the auth challenge, not a bare 403 — keeping the
    // denial surface uniform so the `.acl`-intent case is indistinguishable in shape from any other
    // unauthorized POST. The guard is intent-based, not existence-based: `secret.acl` and `benign.acl`
    // are refused regardless of what exists, so it is never an existence oracle.)
    //
    // SCOPE: `.acl` ONLY. `.meta` description-resources are NOT load-bearing in this server (the WAC
    // resolver never consults a `.meta`, and the PUT/PATCH create paths only special-case `.acl`), so
    // a `secret.meta` stem is just a normal resource name — guarding it ONLY at POST while PUT/PATCH
    // would create it freely is an inconsistency with no security benefit, so it is not guarded. If
    // `.meta` (or any other auxiliary) ever becomes load-bearing it MUST be guarded UNIFORMLY across
    // POST/PUT/PATCH/DELETE/read — not POST-only (see `is_acl_auxiliary_suffix`).
    if let Some(s) = &stem {
        // Check the `.acl` suffix on the bare stem (a leaf segment with no scheme/slashes). A trailing
        // `/` is not part of a sanitised stem, so this catches `secret.acl`/`secret.ACL` directly.
        if crate::authz::is_acl_auxiliary_suffix(s) {
            return Err(if token.web_id.is_none() {
                state.unauthenticated()
            } else {
                ServerError::Forbidden
            });
        }
    }

    // Mint the child IRI from the (guarded) stem: an opaque, collision-free name prefixed by the stem,
    // so the `Location` is collision-INDEPENDENT (V2). A container child gets a trailing slash.
    let child_iri = mint_child_iri(
        &state.store,
        &container.iri,
        stem.as_deref(),
        wants_container,
    )
    .await?;

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
    let target = parse_target(&state.base_url, uri.path())?;

    // WAC for DELETE (Solid WAC write-access matrix). Authorize BEFORE the existence check so an
    // unauthorized caller cannot probe existence (a missing target below is reported as a denial, not
    // a 404 — no existence side-channel). The required rights:
    //  - on the TARGET: a CONTAINER needs `acl:Control` (the matrix uniformly forbids DELETE of a
    //    container to a mere Write holder — only the Control holder, typically the owner, may delete
    //    it); a DOCUMENT needs `acl:Write`; an `.acl` target needs `acl:Control` (and the parent-write
    //    check below is skipped — deleting an ACL only restores the inherited ACL, not containment).
    //  - PLUS `acl:Write` on the nearest existing PARENT container (DELETE mutates containment), unless
    //    the target is an `.acl`.
    let is_acl = crate::authz::is_acl_resource(&target.iri);
    // An `.acl` target and a CONTAINER target both require `acl:Control`; a plain document requires
    // `acl:Write`.
    let target_mode = if is_acl || target.is_container {
        AccessMode::Control
    } else {
        AccessMode::Write
    };
    let origin = request_origin(&headers);
    let granted = state
        .authorize_mode(&target, target_mode, &token, origin)
        .await?;
    if !is_acl {
        let parent = state.nearest_existing_container(&target.iri).await?;
        if let Some(p) = parent {
            state
                .authorize_iri(&p, AccessMode::Write, &token, origin)
                .await?;
        }
    }

    // V4 (decisions/0003): a DELETE may carry `If-Match`/`If-None-Match`, whose 412-vs-2xx outcome
    // against the CONTENT/MEMBERSHIP-derived current ETag is an existence+content oracle. A requester
    // authorized to DELETE but NOT to READ the target (a Write-without-Read document holder) must get
    // the denial code rather than that conditional outcome. Folded BEFORE the existence probe.
    state.guard_conditional_requires_read(&target.iri, &headers, &granted, &token)?;

    let current = state.store.meta(&target.iri).await?;
    // A DELETE of a non-existent target is reported through the SAME denial surface as a permission
    // failure (401 anonymous / 403 authenticated), NOT a 404 — so a DELETE cannot be used as an
    // existence side-channel by a requester who could not otherwise learn the resource exists (the
    // WAC matrix asserts `[401]`/`[403]` for `fictive` DELETE rows even where the requester would have
    // had inherited write).
    let current = match current {
        Some(c) => c,
        None => {
            return Err(if token.web_id.is_none() {
                state.unauthenticated()
            } else {
                ServerError::Forbidden
            });
        }
    };

    // Conditional delete: honour If-Match / If-None-Match against the current ETag.
    conditional::require(eval_preconditions(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        Some(current.etag.as_str()),
    ))?;

    // An AUXILIARY `.acl` resource is NOT a contained child (it is created via `store.write`, never via
    // `create_in_container`), so its DELETE must NOT touch parent containment — pass `None` for the
    // parent. (A non-`.acl` resource detaches from its parent's `ldp:contains` as before.)
    let parent = if is_acl {
        None
    } else {
        parent_container(&target)
    };

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
        // A DELETE of an `.acl` removed the access rules (the resource now inherits): invalidate the
        // cached parse so the NEXT read no longer sees the deleted ACL's grants (the `meta` probe will
        // now report it absent and the walk inherits — invalidating frees the slot at once).
        state.invalidate_acl_if_acl(&target.iri);
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
    let target = parse_target(&state.base_url, uri.path())?;

    // Select the PATCH language from the Content-Type (ABSENT ⇒ 400, unsupported ⇒ 415) and parse the
    // document. `text/n3` is the Solid N3 Patch; `application/sparql-update` is the INSERT/DELETE DATA
    // subset. Both reduce to an `N3Patch` the shared engine applies.
    //
    // Parse BEFORE authorizing because the required WAC mode depends on the patch CONTENT: an
    // INSERT-ONLY patch (no `solid:deletes`) needs only `acl:Append`; a patch with ANY delete needs
    // `acl:Write` (a delete removes existing triples). Parsing is SSRF-safe + bounded RDF parsing, and
    // the conformance deny cases accept `[403, 405, 415]`, so parse-then-authorize is correct.
    let patch = match classify_patch_media_type(header_str(&headers, header::CONTENT_TYPE))? {
        PatchKind::N3 => parse_n3_patch(&body, &target.iri)?,
        PatchKind::SparqlUpdate => parse_sparql_update(&body, &target.iri)?,
    };

    let origin = request_origin(&headers);

    // WAC for PATCH — EXISTENCE-NON-DISCLOSURE (decisions/0003): the required mode is derived purely
    // from the patch CONTENT (already parsed) and authorized against the TARGET's effective ACL
    // (inherited via `acl:default` for a not-yet-existing target), **BEFORE any target-dependent
    // read/existence probe**, so create-on-PATCH and forbidden-modify are INDISTINGUISHABLE to an
    // under-authorized requester:
    //  - an INSERT-ONLY patch (no `solid:deletes`) needs `acl:Append`;
    //  - a patch with ANY delete needs `acl:Write` (a delete removes existing triples);
    //  - an `.acl` target needs `acl:Control` (the `authorize_mode` override).
    //
    // This UNIFIES the prior create-vs-modify split (which authorized create-on-PATCH via
    // `authorize_create` = parent-`acl:Append`). That split was the **V3** existence oracle: an agent
    // holding parent-`acl:Append` (e.g. a drop-box) but NOT the target's effective Append got a 2xx on a
    // free name (create path) vs a 401/403 on a taken-but-forbidden name (modify path) — leaking which
    // child names exist. Authorizing the SAME content-derived mode against the SAME (inherited) target
    // ACL for BOTH cases removes the oracle: create and forbidden-modify return byte-identical denials.
    // (CTH-safe: every `write-access-*` PATCH-fictive row that expects 2xx grants the agent inheritable
    // `acl:Append`/`acl:Write` — which the target's effective-ACL resolution picks up via `acl:default`;
    // the `acl:Control`-only fictive rows expect a denial, which Append-on-target rejects. The earlier
    // delete-on-missing closure is now just the general rule. See decisions/0003.)
    //
    // Authorizing BEFORE the target read closes the V3 timing channel too: the under-authorized denial
    // is returned with NO target-dependent read in its path, and the access decision reads ONLY `.acl`
    // resources (never the target's own bytes/meta).
    let has_deletes = !patch.deletes.is_empty();
    let required = if has_deletes {
        AccessMode::Write
    } else {
        AccessMode::Append
    };
    let granted = state
        .authorize_mode(&target, required, &token, origin)
        .await?;

    // V4 (decisions/0003) — the `solid:where` READ-gate. A patch carrying a `solid:where` clause READS
    // the target graph: `apply_patch` runs the BGP solver over the target's CURRENT triples, and its
    // outcome (exactly-one-solution ⇒ 2xx vs zero/many ⇒ 409, and a missing target ⇒ empty graph ⇒
    // always 0 ⇒ 409) is a CONTENT/EXISTENCE oracle — the very channel V4 closes for conditional
    // HEADERS, but reachable through the patch BODY at only `acl:Append`. So a `where`-bearing patch
    // additionally requires the target's READ mode (`acl:Read`, or `acl:Control` for an `.acl` — reading
    // an `.acl`'s representation is a Control op, and `granted` already holds Control for an authorized
    // `.acl` writer). This matches CSS's `N3PatchModesExtractor`, which adds `read` when the patch has
    // `conditions`. Fold to the requester's denial (401 anon / 403 auth) BEFORE the target read, so it
    // adds no oracle of its own. An unconditional (no-`where`) patch is unaffected.
    if !patch.conditions.is_empty() {
        let read_mode = if crate::authz::is_acl_resource(&target.iri) {
            AccessMode::Control
        } else {
            AccessMode::Read
        };
        if !granted.contains(&read_mode) {
            return Err(if token.web_id.is_none() {
                state.unauthenticated()
            } else {
                ServerError::Forbidden
            });
        }
    }

    // V4 (decisions/0003): a conditional precondition is a CONTENT-derived validator — fold to the
    // denial when the requester lacks `acl:Read` and sent a conditional header, BEFORE the target read.
    state.guard_conditional_requires_read(&target.iri, &headers, &granted, &token)?;

    // The caller IS authorized. ONLY NOW load the current representation (an authorized writer is
    // entitled to learn create-vs-modify). Match the read into THREE states:
    //  - `Ok(r)`            → present (modify path);
    //  - `Err(NotFound)`    → absent  (create-on-PATCH / delete-on-missing path);
    //  - `Err(other)`       → a backend/blob inconsistency → surface the 500 (the caller is authorized,
    //                         so a 500 leaks nothing they could not already learn via a normal read).
    //
    // Because authorization already ran above, a non-`NotFound` store error can be propagated
    // immediately here WITHOUT an existence/state oracle: an UNAUTHORIZED caller never reaches this
    // line (they returned the uniform 401/403 above), so a 500 is only ever seen by a caller permitted
    // to read the target. (`ServerError` is not `Clone`; we distinguish present/absent via `current`.)
    let current: Option<crate::store::Resource> = match state.store.read(&target.iri).await {
        Ok(r) => Some(r),
        Err(ServerError::NotFound) => None,
        Err(e) => return Err(e),
    };

    // Apply preconditions against the current ETag.
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
    } else if crate::authz::is_acl_resource(&target.iri) {
        // Create-on-PATCH of an AUXILIARY `.acl` resource: it is NOT a contained child. Storing it via
        // `create_in_container` would add an `ldp:contains` edge to the parent (and a later DELETE would
        // skip parent-write authorization while still mutating containment). An `.acl` is an auxiliary
        // resource (Solid's auxiliary-resource model) — store it via a plain `write` so it carries no
        // containment edge. (Auth for `.acl` ops is Control, already enforced above.)
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
        //
        // WAC container-modification (same as PUT-create): materialising the new member (+ any missing
        // intermediate container) mutates the nearest existing ancestor's containment, so it requires
        // `acl:Append` on THAT container — in addition to the content-derived target-ACL mode above.
        state
            .authorize_container_modification(&target.iri, &token, origin)
            .await?;
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
    //
    // EXCEPTION — an AUXILIARY `.acl` resource is NOT a contained child (create-on-PATCH stored it via
    // a plain `write`, adding NO `ldp:contains` edge to the parent). So its parent membership did NOT
    // change even on a create: pass `None` for the emit parent so the hub does NOT derive a spurious
    // container-membership `Add` for a resource the container does not actually contain.
    let activity = if existed {
        ActivityType::Update
    } else {
        ActivityType::Create
    };
    let emit_parent = if existed || crate::authz::is_acl_resource(&target.iri) {
        None
    } else {
        parent.clone()
    };
    state
        .notifications
        .notify(&target.iri, activity, emit_parent.as_deref())
        .await;

    // A PATCH to an `.acl` resource edited the access rules: invalidate the cached parse so the NEXT
    // read resolves against the patched ACL immediately.
    state.invalidate_acl_if_acl(&target.iri);

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
    let rdf_type = RDF_TYPE_NODE.clone();
    let contains = LDP_CONTAINS_NODE.clone();

    // 1) The container's OWN stored RDF (whatever was written to the container itself). Parse it in
    // its stored format, resolving relative IRIs against the container IRI. If the stored body is
    // non-RDF or unparseable, it contributes nothing (a container body is conventionally RDF/empty) —
    // we never fail the listing over a stored body the server itself stored.
    //
    // The stored set is carried through VERBATIM (no intra-set de-dup) — exactly as before — so a
    // container body that literally repeats a triple keeps both occurrences (the serialised bytes,
    // and hence the representation ETag, stay identical to the prior linear-scan render).
    let stored_triples: Vec<Triple> = match stored_format {
        Some(fmt) => parse_to_triples(fmt, stored_body, container_iri).unwrap_or_default(),
        None => Vec::new(),
    };

    // Build the output Vec DIRECTLY — no whole-graph `HashSet<Triple>` clone-dedup. The previous code
    // seeded a `HashSet` from `stored_triples.iter().cloned()` and clone-inserted every generated
    // triple; both are pure allocation that the structure of the data renders unnecessary:
    //
    //   * the three `rdf:type` triples are mutually distinct, and
    //   * the `ldp:contains` triples are distinct from one another (the index lists each child once —
    //     unique by construction: an RDF graph holds a containment edge at most once, both store impls
    //     enforce a child appears once),
    //
    // so the ONLY suppression the old dedup could ever fire was a GENERATED triple that duplicates a
    // STORED one (exactly the `BasicContainer`-in-stored-body case the byte-identity test pins). We
    // preserve that — and only that — with a membership check against ONLY the stored set, which is
    // empty for the overwhelmingly common empty/typing-free container body, so the hot path does zero
    // membership work. Insertion order + which triples appear are unchanged, so the serialiser emits
    // the same bytes and `representation_etag` is preserved byte-for-byte.
    let children = state.store.list_children(container_iri).await?;
    let stored_len = stored_triples.len();

    // Suppress ONLY a GENERATED triple that duplicates a STORED one. There are exactly `3 + N`
    // generated triples to probe against the stored set, so the membership structure is chosen by the
    // stored-body size to avoid BOTH a per-render `HashSet` allocation on the common path AND an
    // O(stored_len * (3 + N)) cliff on a pathological large-stored-body-plus-many-children container:
    //   * empty stored body (the overwhelmingly common case)  → no membership work at all;
    //   * SMALL stored body (≤ DEDUP_HASHSET_THRESHOLD triples) → a zero-allocation linear `contains`
    //     scan of the stored slice (cheaper than building+hashing a set for a handful of triples);
    //   * LARGE stored body                                    → build a borrowing `HashSet<&Triple>`
    //     of `stored_triples` ONCE (no clones — references into the still-owned Vec) and probe it O(1),
    //     capping the worst case at O(stored_len + (3 + N)) as the old whole-graph HashSet did.
    // All three branches suppress EXACTLY the same triples (a generated triple present in the stored
    // set), so the output bytes + `representation_etag` are identical regardless of which path runs.
    //
    // The generated triples are collected into their own Vec FIRST (so the membership probe can borrow
    // the still-owned `stored_triples`); the final `triples` is then `stored ++ generated`, preserving
    // the prior "stored set verbatim, then generated in order" layout the byte-identity test pins.
    const DEDUP_HASHSET_THRESHOLD: usize = 16;
    let stored_set: Option<std::collections::HashSet<&Triple>> =
        (stored_len > DEDUP_HASHSET_THRESHOLD).then(|| stored_triples.iter().collect());
    let mut generated: Vec<Triple> = Vec::with_capacity(3 + children.len());
    let push_generated = |generated: &mut Vec<Triple>, triple: Triple| {
        let in_stored = match &stored_set {
            // Large stored body: O(1) hashed membership against the borrowed stored set.
            Some(set) => set.contains(&triple),
            // Empty/small stored body: linear scan of the stored slice (zero allocation).
            None => stored_len != 0 && stored_triples.contains(&triple),
        };
        if !in_stored {
            generated.push(triple);
        }
    };

    // 2) The generated LDP typing triples.
    push_generated(
        &mut generated,
        Triple::new(subject.clone(), rdf_type.clone(), LDP_RESOURCE_NODE.clone()),
    );
    push_generated(
        &mut generated,
        Triple::new(
            subject.clone(),
            rdf_type.clone(),
            LDP_CONTAINER_NODE.clone(),
        ),
    );
    push_generated(
        &mut generated,
        Triple::new(subject.clone(), rdf_type, LDP_BASIC_CONTAINER_NODE.clone()),
    );

    // 3) The generated `ldp:contains` membership triples (one per authoritative child). The child IRIs
    // come from the authoritative index and are server-CONSTRUCTED — every stored IRI is
    // `format!("{base}{path}")` for the server's own validated `base_url` and a `path` that already
    // passed `ldp::target::parse_target` (absolute, no `?`/`#`, no `..`/`.`, no `//`). They are
    // therefore structurally well-formed by construction, so this fast path skips the FULL per-IRI
    // `NamedNode::new` oxiri RFC-3987 re-parse (the per-child cost this optimisation removes).
    //
    // Two layers still protect the serialiser, so this is NOT a blind `new_unchecked`:
    //   * debug/test: the FULL checked `NamedNode::new` runs behind a `debug_assert!`, so if the store
    //     ever yielded a non-RFC-3987 child IRI it fails the suite rather than shipping; and
    //   * release: a CHEAP O(len) structural guard (`iri_chars_serialisable`) rejects exactly the
    //     characters RFC-3987 forbids INSIDE an IRI and that would CORRUPT a Turtle `<...>` term
    //     (controls, space/whitespace, the `<>"{}|^\`+backslash delimiters) — a malformed child is
    //     OMITTED from the listing, exactly as the old `NamedNode::new(&child)` skip-on-`Err` did, and
    //     can never produce a corrupt term or break the document.
    //
    // ACCEPTED TRADEOFF (roborev Medium, triaged): the cheap guard does NOT catch an
    // invalid-but-serialisable IRI (e.g. a bad percent-escape) the way the full parse would. That
    // residual is bounded and deliberate: (a) such an IRI is NOT reachable through the LDP write path
    // (the `parse_target` construction above), so it requires a store-layer bug, which the
    // `debug_assert!` catches in test; (b) were one to slip through in release it serialises as a
    // syntactically well-formed but slightly-non-conformant `<...>` term — no corruption, no parse
    // break, no security impact, in ONE membership triple; and (c) restoring the full `NamedNode::new`
    // per child would give back exactly the per-child RFC-3987 parse this optimisation exists to
    // remove (the measured ~2x at N=500). The store-invariant enforcement belongs at the
    // `list_children` boundary, not on this hot render path — tracked as a follow-up, not a blocker.
    for child in children {
        debug_assert!(
            NamedNode::new(&child).is_ok(),
            "store yielded a non-RFC-3987 child IRI: {child}"
        );
        if !iri_chars_serialisable(&child) {
            // Defence-in-depth: a malformed child IRI is omitted from the listing (as the prior
            // `NamedNode::new(&child)` skip-on-Err did), never serialised as a corrupt term.
            continue;
        }
        push_generated(
            &mut generated,
            // SAFETY/validity: `child` passed the structural guard above (and the store's write-time
            // RFC-3987 guarantee), so `new_unchecked` produces a well-formed term without the full
            // oxiri re-parse.
            Triple::new(
                subject.clone(),
                contains.clone(),
                NamedNode::new_unchecked(child),
            ),
        );
    }

    // Assemble `stored ++ generated` — the prior layout (stored set verbatim, then the generated set
    // in order). `stored_set` (which borrowed `stored_triples`) is dropped here, so the owned
    // `stored_triples` can now be moved into the output without a clone.
    drop(stored_set);
    let mut triples: Vec<Triple> = Vec::with_capacity(stored_len + generated.len());
    triples.extend(stored_triples);
    triples.extend(generated);

    let bytes = serialize_triples(format, &triples)?;
    Ok((Bytes::from(bytes), format.media_type().to_string()))
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

/// Mint a child IRI within `container`. A `Slug` (sanitised) is used ONLY as a NON-binding PREFIX of a
/// server-generated, collision-free, **opaque** name — NEVER as the verbatim final segment.
///
/// V2 — EXISTENCE-NON-DISCLOSURE for the `Location` header (decisions/0003). The prior mint returned
/// the verbatim `…/<slug>` when that name was FREE but a mangled `…/<slug>-<opaque>` when it was TAKEN.
/// A POST always returns 201, so the *shape* of the `Location` was the only difference — and it leaked
/// whether `<slug>` already existed in the container to any caller who can POST (an `acl:Append`
/// holder) but cannot READ the container's listing. By ALWAYS appending the opaque suffix (whether or
/// not `<slug>` is free), the `Location` shape is collision-INDEPENDENT — it carries no existence
/// signal — while STILL CONTAINING the Slug substring (the Solid Protocol treats `Slug` as a hint and
/// the conformance `post-uri-assignment-slug` row asserts only `Location contains '<slug>'`, which an
/// opaque-suffixed name satisfies). A name with no usable Slug falls back to the default `resource-…`
/// stem, identical in shape, so the two cases are indistinguishable.
///
/// `generate_unique` does the `exists` probe + retry internally, so the returned IRI is guaranteed
/// free (and, being opaque, never collides with the trailing-slash opposite form either — the old
/// `slash_form_taken` co-existence probe is no longer needed). When `as_container` is set the minted
/// IRI ends in `/` (an LDP container child). `stem` is the ALREADY-SANITISED Slug (the caller
/// sanitises + `.acl`-guards it before this point), used only as the opaque name's prefix.
async fn mint_child_iri<S: Store>(
    store: &S,
    container_iri: &str,
    stem: Option<&str>,
    as_container: bool,
) -> Result<String, ServerError> {
    let base = container_iri.trim_end_matches('/');
    generate_unique(store, base, stem, as_container).await
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

/// The request's `Origin` header (the requesting web app's origin), trimmed; `None` if absent, empty,
/// or not valid UTF-8. Threaded into WAC so an `acl:origin`-restricted authorization grants only from
/// a matching Origin (and a request with no Origin never satisfies such a rule — fail-closed). A bare
/// `Origin: null` is treated as a present-but-non-matching opaque origin (kept verbatim — it will only
/// match a literal `acl:origin <null>`, which is not a real grant).
///
/// `pub(crate)` so the pre-crypto public-read skip middleware reads the request Origin EXACTLY as the
/// handler does (same trim/empty-filter) — the skip's origin input is byte-identical to the read
/// path's, preserving `acl:origin` fail-closed semantics (INV-6).
pub(crate) fn request_origin(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, header::ORIGIN)
        .map(str::trim)
        .filter(|o| !o.is_empty())
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

    #[test]
    fn request_origin_trims_and_filters_empty() {
        let mut present = HeaderMap::new();
        present.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://app.example"),
        );
        assert_eq!(request_origin(&present), Some("https://app.example"));
        // Whitespace is trimmed.
        let mut padded = HeaderMap::new();
        padded.insert(
            header::ORIGIN,
            HeaderValue::from_static("  https://app.example  "),
        );
        assert_eq!(request_origin(&padded), Some("https://app.example"));
        // Absent ⇒ None.
        assert_eq!(request_origin(&HeaderMap::new()), None);
        // Empty/whitespace-only ⇒ None.
        let mut blank = HeaderMap::new();
        blank.insert(header::ORIGIN, HeaderValue::from_static("   "));
        assert_eq!(request_origin(&blank), None);
    }

    // --- Finding 4: a non-NotFound read error must NOT collapse to "missing" (fail-CLOSED) --------

    use crate::store::{
        CompositeStore, DeleteOutcome, InMemoryBlobStore, InMemorySparqClient, Resource,
        ResourceMeta,
    };
    use async_trait::async_trait;
    use axum::body::Bytes as AxBytes;

    /// A [`Store`] whose `read` ALWAYS fails with a non-`NotFound` (`Storage`) error — a simulated
    /// backend/blob inconsistency. Every other method reports the resource as ABSENT, so if the
    /// handler ever (wrongly) treated the failed read as "missing" it would happily take the
    /// create/authorize path. The PATCH handler must instead PROPAGATE the `Storage` error (→ 500),
    /// never authorize.
    struct FaultyReadStore;

    #[async_trait]
    impl Store for FaultyReadStore {
        async fn read(&self, _iri: &str) -> ServerResult<Resource> {
            // NON-`NotFound`: a real storage/blob inconsistency, not an absent resource.
            Err(ServerError::Storage(
                "simulated backend inconsistency".into(),
            ))
        }
        async fn meta(&self, _iri: &str) -> ServerResult<Option<ResourceMeta>> {
            // CONSISTENT with `read`: a real store's `meta` and `read` share ONE authoritative
            // (`get_meta`) source, so they can NOT disagree on presence/error. Since `read` faults with
            // a non-`NotFound` `Storage` error, `meta` faults the SAME way — so the ACL-cache's cheap
            // `meta` probe propagates the inconsistency (fail-closed), NEVER treats it as "absent ACL".
            // (Returning `Ok(None)` here would model an impossible store and let the resolver fail OPEN.)
            Err(ServerError::Storage(
                "simulated backend inconsistency".into(),
            ))
        }
        async fn exists(&self, _iri: &str) -> ServerResult<bool> {
            Ok(false)
        }
        async fn write(
            &self,
            _iri: &str,
            _body: AxBytes,
            _content_type: &str,
        ) -> ServerResult<ResourceMeta> {
            panic!("write must not be reached: the read error must propagate before any write");
        }
        async fn create_in_container(
            &self,
            _container: &str,
            _child: &str,
            _body: AxBytes,
            _content_type: &str,
        ) -> ServerResult<ResourceMeta> {
            panic!("create_in_container must not be reached on a faulted read");
        }
        async fn delete(&self, _iri: &str, _parent: Option<&str>) -> ServerResult<()> {
            Ok(())
        }
        async fn delete_container_if_empty(
            &self,
            _iri: &str,
            _parent: Option<&str>,
        ) -> ServerResult<DeleteOutcome> {
            Ok(DeleteOutcome::NotFound)
        }
        async fn list_children(&self, _container: &str) -> ServerResult<Vec<String>> {
            Ok(Vec::new())
        }
    }

    use crate::error::ServerResult;

    #[tokio::test]
    async fn patch_propagates_non_notfound_read_error_does_not_treat_as_missing() {
        // An INSERT-ONLY PATCH whose EVERY read (target AND `.acl`) fails with a STORAGE error (not
        // NotFound). The handler must NEVER collapse the failed read into "missing" and take the
        // create-on-PATCH path (the pre-fix `read().ok()` fail-OPEN bug): the faulty store PANICS if
        // `write`/`create_in_container` is reached. With the fix, authorization runs first and its own
        // `.acl` read faults (a non-NotFound ACL read propagates — fail-closed), so the storage error
        // surfaces as a 500; either way the create path is never taken. (The narrower
        // unauthorized-caller-must-not-get-500 property is pinned by
        // `patch_unauthorized_caller_with_faulting_target_read_gets_uniform_denial_not_500`, where only
        // the TARGET read faults so authorization can reach a real decision.)
        let state = Arc::new(LdpState::new(FaultyReadStore, "https://pod.example"));
        let token = VerifiedToken {
            web_id: Some("https://pod.example/alice/profile/card#me".into()),
            ..VerifiedToken::default()
        };
        let uri: axum::http::Uri = "/alice/data".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/n3"));
        let patch_body = AxBytes::from(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
             @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
             _:p solid:inserts { <https://pod.example/alice/data#me> foaf:name \"X\" . }.\n",
        );
        let err = patch_handler(State(state), Extension(token), uri, headers, patch_body)
            .await
            .expect_err("a non-NotFound read error must surface, not be treated as missing");
        // It must surface as the storage error (500), NOT a create-path 201 / a 403 / a 404.
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // --- Finding 2 (round-2): a PRE-AUTH storage error must not leak via 500 to an unauthorized caller.

    const OWNER: &str = "https://pod.example/alice/profile/card#me";
    const STRANGER: &str = "https://pod.example/bob/profile/card#me";

    /// A [`Store`] that faults ONLY on the TARGET resource read (a simulated backend/blob
    /// inconsistency on the resource itself) while serving a real, owner-only `.acl` so authorization
    /// can reach a genuine allow/deny decision. This isolates the round-2 property: an UNAUTHORIZED
    /// caller must get the uniform 401/403 (not a 500 distinguishing "faulting backend" from "missing /
    /// normally-stored"), and an AUTHORIZED caller must get the 500 surfaced AFTER authorization.
    ///
    /// `read`:
    ///  - the target IRI → a non-`NotFound` `Storage` error (the inconsistency);
    ///  - the target's `.acl` → an owner-only ACL granting [`OWNER`] Read/Write/Control (so authz runs);
    ///  - anything else (e.g. an ancestor `.acl`) → `NotFound` (no other ACL up the tree).
    struct TargetFaultyAclStore {
        target: String,
    }

    impl TargetFaultyAclStore {
        fn new(target: &str) -> Self {
            Self {
                target: target.to_string(),
            }
        }
        fn acl_body(&self) -> String {
            format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#owner> a acl:Authorization;
         acl:agent <{OWNER}>;
         acl:accessTo <{}>;
         acl:mode acl:Read, acl:Write, acl:Control."#,
                self.target
            )
        }
    }

    #[async_trait]
    impl Store for TargetFaultyAclStore {
        async fn read(&self, iri: &str) -> ServerResult<Resource> {
            if iri == self.target {
                // The inconsistency on the resource itself — a NON-NotFound error.
                return Err(ServerError::Storage(
                    "simulated backend inconsistency".into(),
                ));
            }
            if iri == format!("{}.acl", self.target) {
                // The target's OWN `.acl`: an owner-only authorization, served normally so authz works.
                let body = AxBytes::from(self.acl_body());
                let meta = ResourceMeta {
                    content_type: "text/turtle".into(),
                    blob_key: "k".into(),
                    etag: "\"acl\"".into(),
                };
                return Ok(Resource { body, meta });
            }
            // No other ACL anywhere up the tree.
            Err(ServerError::NotFound)
        }
        async fn meta(&self, iri: &str) -> ServerResult<Option<ResourceMeta>> {
            // CONSISTENT with `read` (a real store's `meta`/`read` share one `get_meta` source):
            //  - the target IRI → the SAME non-`NotFound` `Storage` fault `read` raises (the
            //    inconsistency surfaces through the ACL-cache's cheap `meta` probe too, never as absent);
            //  - the target's `.acl` → `Some` with the SAME etag `read` serves, so the cache MISSES then
            //    `read`s + parses it (authz sees the owner-only ACL);
            //  - anything else → `None` (absent), matching `read`'s `NotFound`.
            if iri == self.target {
                return Err(ServerError::Storage(
                    "simulated backend inconsistency".into(),
                ));
            }
            if iri == format!("{}.acl", self.target) {
                return Ok(Some(ResourceMeta {
                    content_type: "text/turtle".into(),
                    blob_key: "k".into(),
                    etag: "\"acl\"".into(),
                }));
            }
            Ok(None)
        }
        async fn exists(&self, _iri: &str) -> ServerResult<bool> {
            Ok(false)
        }
        async fn write(
            &self,
            _iri: &str,
            _body: AxBytes,
            _content_type: &str,
        ) -> ServerResult<ResourceMeta> {
            panic!("write must not be reached: the faulted target read must surface as 500 first");
        }
        async fn create_in_container(
            &self,
            _container: &str,
            _child: &str,
            _body: AxBytes,
            _content_type: &str,
        ) -> ServerResult<ResourceMeta> {
            panic!("create_in_container must not be reached on a faulted target read");
        }
        async fn delete(&self, _iri: &str, _parent: Option<&str>) -> ServerResult<()> {
            Ok(())
        }
        async fn delete_container_if_empty(
            &self,
            _iri: &str,
            _parent: Option<&str>,
        ) -> ServerResult<DeleteOutcome> {
            Ok(DeleteOutcome::NotFound)
        }
        async fn list_children(&self, _container: &str) -> ServerResult<Vec<String>> {
            Ok(Vec::new())
        }
    }

    /// An INSERT-ONLY `text/n3` PATCH body targeting `subject`.
    fn insert_only_patch(subject: &str) -> AxBytes {
        AxBytes::from(format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
             @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
             _:p solid:inserts {{ <{subject}> foaf:name \"X\" . }}.\n",
        ))
    }

    fn n3_patch_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/n3"));
        headers
    }

    #[tokio::test]
    async fn patch_unauthorized_caller_with_faulting_target_read_gets_uniform_denial_not_500() {
        // (a) An UNAUTHORIZED caller (a stranger, not the ACL's owner) PATCHing a resource whose target
        // read faults must get the uniform authorization denial (403 authenticated), NOT a 500 — the
        // backend inconsistency must never be observable to a caller who is not permitted the operation
        // (an existence/state oracle). The store PANICS if any write is reached.
        let target = "https://pod.example/alice/data";
        let state = Arc::new(LdpState::new(
            TargetFaultyAclStore::new(target),
            "https://pod.example",
        ));
        let token = VerifiedToken {
            web_id: Some(STRANGER.into()),
            ..VerifiedToken::default()
        };
        let uri: axum::http::Uri = "/alice/data".parse().unwrap();
        let err = patch_handler(
            State(state),
            Extension(token),
            uri,
            n3_patch_headers(),
            insert_only_patch(&format!("{target}#me")),
        )
        .await
        .expect_err("an unauthorized caller must be denied, never see the 500");
        // 403 (authenticated-but-unauthorized) — the uniform denial, NOT the 500 the pre-fix leaked.
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn patch_anonymous_caller_with_faulting_target_read_gets_401_not_500() {
        // Same as above but ANONYMOUS: the uniform denial is 401 (so the client authenticates), never a
        // 500. An unauthenticated caller must not learn the backend is inconsistent either.
        let target = "https://pod.example/alice/data";
        let state = Arc::new(LdpState::new(
            TargetFaultyAclStore::new(target),
            "https://pod.example",
        ));
        let token = VerifiedToken::default(); // anonymous (web_id == None)
        let uri: axum::http::Uri = "/alice/data".parse().unwrap();
        let err = patch_handler(
            State(state),
            Extension(token),
            uri,
            n3_patch_headers(),
            insert_only_patch(&format!("{target}#me")),
        )
        .await
        .expect_err("an anonymous caller must be denied, never see the 500");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn patch_authorized_caller_with_faulting_target_read_gets_500_surfaced_post_auth() {
        // (b) An AUTHORIZED caller (the ACL owner) PATCHing the same resource MUST get the 500 — the
        // backend error IS surfaced, but only after authorization succeeds (so it is not an oracle).
        // The store PANICS if a write is reached, proving the error surfaced BEFORE the create path.
        let target = "https://pod.example/alice/data";
        let state = Arc::new(LdpState::new(
            TargetFaultyAclStore::new(target),
            "https://pod.example",
        ));
        let token = VerifiedToken {
            web_id: Some(OWNER.into()),
            ..VerifiedToken::default()
        };
        let uri: axum::http::Uri = "/alice/data".parse().unwrap();
        let err = patch_handler(
            State(state),
            Extension(token),
            uri,
            n3_patch_headers(),
            insert_only_patch(&format!("{target}#me")),
        )
        .await
        .expect_err("an authorized caller must see the backend error surfaced post-auth");
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn patch_authorized_caller_with_notfound_target_takes_normal_create_path() {
        // (c) An AUTHORIZED caller PATCHing a GENUINELY-MISSING target (a real `NotFound`, not a fault)
        // must take the normal create-on-PATCH path → 201 Created, proving the round-2 change did not
        // regress the legitimate create path. Uses the real composite store with a seeded owner ACL.
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        // Seed a root `.acl` granting the owner Read/Write/Control on the root + all descendants.
        let root_acl = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#owner> a acl:Authorization;
         acl:agent <{OWNER}>;
         acl:accessTo <https://pod.example/>;
         acl:default <https://pod.example/>;
         acl:mode acl:Read, acl:Write, acl:Control."#
        );
        store
            .write(
                "https://pod.example/.acl",
                AxBytes::from(root_acl),
                "text/turtle",
            )
            .await
            .expect("seed root acl");
        let state = Arc::new(LdpState::new(store, "https://pod.example"));
        let token = VerifiedToken {
            web_id: Some(OWNER.into()),
            ..VerifiedToken::default()
        };
        let uri: axum::http::Uri = "/alice/note".parse().unwrap();
        let resp = patch_handler(
            State(state),
            Extension(token),
            uri,
            n3_patch_headers(),
            insert_only_patch("https://pod.example/alice/note#me"),
        )
        .await
        .expect("a create-on-PATCH of a genuinely-missing target must succeed");
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // --- Finding 1: an `.acl` (auxiliary) create must NOT emit a parent-containment Add ------------

    /// Seed a root `.acl` granting `OWNER` full control over the root + all descendants, written
    /// through the store as an auxiliary resource. Returns the store ready for handler use.
    async fn store_with_owner_root_acl() -> CompositeStore<InMemorySparqClient, InMemoryBlobStore> {
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        let root_acl = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#owner> a acl:Authorization;
         acl:agent <{OWNER}>;
         acl:accessTo <https://pod.example/>;
         acl:default <https://pod.example/>;
         acl:mode acl:Read, acl:Write, acl:Control."#
        );
        store
            .write(
                "https://pod.example/.acl",
                AxBytes::from(root_acl),
                "text/turtle",
            )
            .await
            .expect("seed root acl");
        store
    }

    fn owner_token() -> VerifiedToken {
        VerifiedToken {
            web_id: Some(OWNER.into()),
            ..VerifiedToken::default()
        }
    }

    #[tokio::test]
    async fn put_create_of_acl_emits_no_parent_containment_add() {
        // A PUT that CREATES an auxiliary `.acl` resource must NOT cause a container-membership `Add`
        // notification on the parent — an `.acl` is NOT a contained child (no `ldp:contains` edge). A
        // subscriber to the parent container must therefore receive NOTHING for the `.acl` create.
        let hub = NotificationHub::new();
        let store = store_with_owner_root_acl().await;
        let state = Arc::new(LdpState::with_hub(
            store,
            "https://pod.example",
            hub.clone(),
        ));

        let parent = "https://pod.example/alice/";
        let mut parent_rx = hub.subscribe(parent).await;

        // PUT the `.acl` for a resource in /alice/ — auth for `.acl` is Control (the owner has it).
        let uri: axum::http::Uri = "/alice/doc.acl".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/turtle"),
        );
        let acl_body = AxBytes::from(format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#o> a acl:Authorization; acl:agent <{OWNER}>; acl:accessTo <https://pod.example/alice/doc>; acl:mode acl:Read, acl:Write, acl:Control."#
        ));
        let resp = put_handler(
            State(state),
            Extension(owner_token()),
            uri,
            headers,
            acl_body,
        )
        .await
        .expect("an owner PUT of an .acl must succeed");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // The parent container subscriber must have received NOTHING — no spurious membership Add.
        assert!(
            parent_rx.try_recv().is_err(),
            "an .acl create must not emit a parent-containment Add notification"
        );
    }

    #[tokio::test]
    async fn put_create_of_normal_resource_does_emit_parent_containment_add() {
        // The control: a PUT that creates a NORMAL (non-`.acl`) resource DOES grow its parent's
        // membership, so the parent subscriber MUST receive a membership `Add`. This guards against the
        // finding-1 fix over-suppressing the legitimate notification.
        let hub = NotificationHub::new();
        let store = store_with_owner_root_acl().await;
        let state = Arc::new(LdpState::with_hub(
            store,
            "https://pod.example",
            hub.clone(),
        ));

        let parent = "https://pod.example/alice/";
        let mut parent_rx = hub.subscribe(parent).await;

        let uri: axum::http::Uri = "/alice/doc".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/turtle"),
        );
        let body = AxBytes::from(
            "<https://pod.example/alice/doc#me> <http://xmlns.com/foaf/0.1/name> \"X\" .",
        );
        let resp = put_handler(State(state), Extension(owner_token()), uri, headers, body)
            .await
            .expect("an owner PUT of a normal resource must succeed");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // The parent container subscriber MUST see a membership Add naming the new child.
        let frame = parent_rx
            .try_recv()
            .expect("a normal resource create must emit a parent-containment Add");
        assert!(frame.contains("\"type\":\"Add\""), "{frame}");
        assert!(
            frame.contains("\"object\":\"https://pod.example/alice/doc\""),
            "{frame}"
        );
    }

    #[tokio::test]
    async fn patch_create_of_acl_emits_no_parent_containment_add() {
        // The PATCH-create path mirrors PUT-create: a create-on-PATCH of an auxiliary `.acl` must NOT
        // emit a parent-containment Add either.
        let hub = NotificationHub::new();
        let store = store_with_owner_root_acl().await;
        let state = Arc::new(LdpState::with_hub(
            store,
            "https://pod.example",
            hub.clone(),
        ));

        let parent = "https://pod.example/alice/";
        let mut parent_rx = hub.subscribe(parent).await;

        // An INSERT-ONLY PATCH that CREATES the `.acl` (target absent → create-on-PATCH). Auth is
        // Control (the owner has it). The inserted triple is a minimal authorization.
        let uri: axum::http::Uri = "/alice/doc2.acl".parse().unwrap();
        let patch_body = AxBytes::from(format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
             @prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
             _:p solid:inserts {{ <#o> a acl:Authorization; acl:agent <{OWNER}>; \
             acl:accessTo <https://pod.example/alice/doc2>; acl:mode acl:Read . }}.\n",
        ));
        let resp = patch_handler(
            State(state),
            Extension(owner_token()),
            uri,
            n3_patch_headers(),
            patch_body,
        )
        .await
        .expect("an owner create-on-PATCH of an .acl must succeed");
        assert_eq!(resp.status(), StatusCode::CREATED);

        assert!(
            parent_rx.try_recv().is_err(),
            "an .acl create-on-PATCH must not emit a parent-containment Add notification"
        );
    }

    // --- HIGH: POST-Slug auxiliary-resource privilege-escalation bypass ----------------------------
    //
    // The exploit (execution-proved by adversarial verification): a POST to a container authorizes
    // only `acl:Append`, but `sanitise_slug` keeps `.`, so `Slug: secret.acl` survives and mints
    // `…/secret.acl`. With NO `.acl`/Control re-check, the create wrote an attacker-controlled
    // `…/secret.acl` that the WAC resolver then reads as the OWN ACL of `…/secret`, overriding
    // inheritance — letting an Append-only agent grant itself Control over a sibling private resource.

    const ALICE: &str = OWNER; // the container owner (private resource is hers)
    const BOB: &str = STRANGER; // the Append-only attacker

    /// Build a store where `/alice/c/` exists, Alice owns it (default Read/Write/Control over the
    /// container + its members), and Bob holds ONLY `acl:Append` on the container itself. The child
    /// `/alice/c/secret` is therefore Alice-private by inheritance (no own ACL).
    async fn store_alice_container_bob_append_only(
    ) -> CompositeStore<InMemorySparqClient, InMemoryBlobStore> {
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        // The container must EXIST for a POST to it to proceed (the handler's existence check).
        store
            .write(
                "https://pod.example/alice/c/",
                AxBytes::from(String::new()),
                "text/turtle",
            )
            .await
            .expect("seed container");
        // The container `.acl`: Alice gets default Read/Write/Control (so `secret` inherits
        // Alice-private); Bob gets ONLY Append on the container itself (he can POST a member, but
        // cannot read/control the container or its members).
        let acl = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#alice> a acl:Authorization;
         acl:agent <{ALICE}>;
         acl:accessTo <https://pod.example/alice/c/>;
         acl:default <https://pod.example/alice/c/>;
         acl:mode acl:Read, acl:Write, acl:Control.
<#bob> a acl:Authorization;
       acl:agent <{BOB}>;
       acl:accessTo <https://pod.example/alice/c/>;
       acl:mode acl:Append."#
        );
        store
            .write(
                "https://pod.example/alice/c/.acl",
                AxBytes::from(acl),
                "text/turtle",
            )
            .await
            .expect("seed container acl");
        store
    }

    fn bob_token() -> VerifiedToken {
        VerifiedToken {
            web_id: Some(BOB.into()),
            ..VerifiedToken::default()
        }
    }

    /// A POST body that, if it landed as `…/secret.acl`, would grant Bob `acl:Control` over
    /// `…/secret` — the escalation payload.
    fn bob_self_control_acl_body() -> AxBytes {
        AxBytes::from(format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#pwn> a acl:Authorization;
       acl:agent <{BOB}>;
       acl:accessTo <https://pod.example/alice/c/secret>;
       acl:mode acl:Read, acl:Write, acl:Control."#
        ))
    }

    fn post_turtle_headers_with_slug(slug: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/turtle"),
        );
        headers.insert(
            HeaderName::from_static("slug"),
            HeaderValue::from_str(slug).unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn post_slug_dot_acl_is_denied_and_grants_attacker_nothing() {
        // THE EXPLOIT, ported as a regression test driving the REAL post_handler + get_handler.
        let store = store_alice_container_bob_append_only().await;
        let state = Arc::new(LdpState::new(store, "https://pod.example"));

        // (1) Bob (Append-only) POSTs `Slug: secret.acl` with a self-Control body → MUST be denied
        //     (403). The auxiliary-mint guard refuses to let an Append-only POST create a `.acl`.
        let uri: axum::http::Uri = "/alice/c/".parse().unwrap();
        let err = post_handler(
            State(state.clone()),
            Extension(bob_token()),
            uri,
            post_turtle_headers_with_slug("secret.acl"),
            bob_self_control_acl_body(),
        )
        .await
        .expect_err("POST Slug: secret.acl by an Append-only caller MUST be denied");
        assert_eq!(
            err.status(),
            StatusCode::FORBIDDEN,
            "the auxiliary-mint escalation must be a 403"
        );

        // (1b) The malicious `.acl` must NOT exist — the create never happened.
        assert!(
            !state
                .store
                .exists("https://pod.example/alice/c/secret.acl")
                .await
                .unwrap(),
            "no attacker-controlled .acl may have been written"
        );

        // (2) Bob then tries to GET the sibling `…/secret` — he gained NOTHING. `secret` is
        //     Alice-private by inheritance and has no (attacker-planted) own ACL, so Bob is denied.
        let get_uri: axum::http::Uri = "/alice/c/secret".parse().unwrap();
        let get_err = get_handler(
            State(state),
            Extension(bob_token()),
            get_uri,
            HeaderMap::new(),
        )
        .await
        .expect_err("Bob must not be able to read Alice's private resource");
        // 403 — Bob is authenticated but unauthorized (he inherits no Read from the Alice-only default).
        assert_eq!(
            get_err.status(),
            StatusCode::FORBIDDEN,
            "Bob must gain no read access to the sibling private resource"
        );
    }

    #[tokio::test]
    async fn post_slug_dot_acl_case_variant_is_also_denied() {
        // Defence-in-depth: a case-variant Slug (`secret.ACL`) must ALSO be rejected at the mint
        // chokepoint — `sanitise_slug` keeps it verbatim, so without a case-insensitive guard it would
        // sail through (and a case-insensitive filesystem/resolver later could make it load-bearing).
        let store = store_alice_container_bob_append_only().await;
        let state = Arc::new(LdpState::new(store, "https://pod.example"));
        let uri: axum::http::Uri = "/alice/c/".parse().unwrap();
        let err = post_handler(
            State(state.clone()),
            Extension(bob_token()),
            uri,
            post_turtle_headers_with_slug("secret.ACL"),
            bob_self_control_acl_body(),
        )
        .await
        .expect_err("a case-variant .acl slug must also be denied");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        assert!(
            !state
                .store
                .exists("https://pod.example/alice/c/secret.ACL")
                .await
                .unwrap(),
            "no case-variant auxiliary resource may have been written"
        );
    }

    #[tokio::test]
    async fn post_slug_dot_meta_is_allowed_meta_is_not_load_bearing() {
        // `.meta` is NOT load-bearing in this server: the WAC resolver never consults a `.meta`, and
        // the create paths only special-case `.acl`. So `secret.meta` is just a normal resource name
        // with no security effect — guarding it ONLY at POST (while a PUT/PATCH could create it freely)
        // was an inconsistency with no benefit. An Append-only POST of `Slug: secret.meta` is therefore
        // ALLOWED, exactly like any other benign append. (If `.meta` ever becomes load-bearing it must
        // be guarded UNIFORMLY across POST/PUT/PATCH/DELETE/read — see `is_acl_auxiliary_suffix`.)
        let store = store_alice_container_bob_append_only().await;
        let state = Arc::new(LdpState::new(store, "https://pod.example"));
        let uri: axum::http::Uri = "/alice/c/".parse().unwrap();
        let resp = post_handler(
            State(state.clone()),
            Extension(bob_token()),
            uri,
            post_turtle_headers_with_slug("secret.meta"),
            AxBytes::from("<https://pod.example/alice/c/secret> <http://p> <http://o> ."),
        )
        .await
        .expect("a .meta slug is a normal resource name and must be allowed");
        assert_eq!(resp.status(), StatusCode::CREATED);
        // V2 (decisions/0003): the minted `Location` is collision-INDEPENDENT — it CONTAINS the Slug
        // stem (`secret.meta`) but is opaque-suffixed (never the verbatim segment), so it carries no
        // existence signal. The created resource exists at exactly that minted Location.
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .expect("Location header")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            loc.starts_with("https://pod.example/alice/c/secret.meta-"),
            "the Location must contain the Slug stem as an opaque-suffixed prefix: {loc}"
        );
        assert!(state.store.exists(&loc).await.unwrap());
        // And it grants Bob NOTHING over the sibling `…/secret` — a `.meta` is not consulted by WAC,
        // so `secret` stays Alice-private by inheritance.
        let get_uri: axum::http::Uri = "/alice/c/secret".parse().unwrap();
        let get_err = get_handler(
            State(state),
            Extension(bob_token()),
            get_uri,
            HeaderMap::new(),
        )
        .await
        .expect_err("Bob must not be able to read Alice's private resource");
        assert_eq!(get_err.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_benign_slug_still_works_no_regression() {
        // The control: an Append-only Bob POSTing a BENIGN slug into the container still succeeds —
        // the fix must not break legitimate container appends.
        let store = store_alice_container_bob_append_only().await;
        let state = Arc::new(LdpState::new(store, "https://pod.example"));
        let uri: axum::http::Uri = "/alice/c/".parse().unwrap();
        let resp = post_handler(
            State(state.clone()),
            Extension(bob_token()),
            uri,
            post_turtle_headers_with_slug("note"),
            AxBytes::from(
                "<https://pod.example/alice/c/note#me> <http://xmlns.com/foaf/0.1/name> \"N\" .",
            ),
        )
        .await
        .expect("a benign Append POST must still succeed");
        assert_eq!(resp.status(), StatusCode::CREATED);
        // V2 (decisions/0003): the child's `Location` CONTAINS the Slug (`note`) as an opaque-suffixed
        // prefix — collision-INDEPENDENT, so it leaks nothing about which names already exist — and the
        // resource exists at exactly that Location. (The CTH `post-uri-assignment-slug` row asserts only
        // `Location contains '<slug>'`, which this satisfies.)
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .expect("Location header")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            loc.starts_with("https://pod.example/alice/c/note-"),
            "the Location must contain the Slug as an opaque-suffixed prefix: {loc}"
        );
        assert!(
            loc.contains("note"),
            "Location must contain the Slug: {loc}"
        );
        assert!(state.store.exists(&loc).await.unwrap());
    }

    #[tokio::test]
    async fn post_slug_dot_acl_denied_even_for_a_controller() {
        // A POST is an Append/Write operation on the CONTAINER, never a Control op — so even a caller
        // who DOES hold Control over the container (Alice) must not be able to mint a `.acl` via the
        // POST-Slug path. The legitimate way to author an `.acl` is a Control-gated PUT/PATCH of the
        // exact `.acl` IRI; the POST chokepoint uniformly refuses to mint an auxiliary child. Consistent
        // behaviour: reject for everyone (no privilege-dependent fork at the mint point — that keeps the
        // chokepoint simple and impossible to confuse). Alice can still PUT `/alice/c/secret.acl`
        // directly, which IS Control-gated and which she passes.
        let store = store_alice_container_bob_append_only().await;
        let state = Arc::new(LdpState::new(store, "https://pod.example"));

        // Alice (controller) POSTs Slug: secret.acl → still 403 at the mint chokepoint.
        let uri: axum::http::Uri = "/alice/c/".parse().unwrap();
        let err = post_handler(
            State(state.clone()),
            Extension(owner_token()),
            uri,
            post_turtle_headers_with_slug("secret.acl"),
            AxBytes::from(format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#a> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <https://pod.example/alice/c/secret>; acl:mode acl:Control."#
            )),
        )
        .await
        .expect_err("POST-Slug minting an .acl is refused for everyone, controllers included");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);

        // But Alice CAN author it the legitimate, Control-gated way: a direct PUT of the .acl IRI.
        let put_uri: axum::http::Uri = "/alice/c/secret.acl".parse().unwrap();
        let mut put_headers = HeaderMap::new();
        put_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/turtle"),
        );
        let resp = put_handler(
            State(state),
            Extension(owner_token()),
            put_uri,
            put_headers,
            AxBytes::from(format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#a> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <https://pod.example/alice/c/secret>; acl:mode acl:Read, acl:Write, acl:Control."#
            )),
        )
        .await
        .expect("a controller may PUT an .acl directly (Control-gated)");
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // --- container listing render (Optimization #1: O(N) de-dup, byte-identical output) -----------

    /// Count occurrences of `needle` in `hay` (a tiny substring counter for the listing-body asserts).
    fn count_occurrences(hay: &str, needle: &str) -> usize {
        if needle.is_empty() {
            return 0;
        }
        let mut n = 0;
        let mut from = 0;
        while let Some(i) = hay[from..].find(needle) {
            n += 1;
            from += i + needle.len();
        }
        n
    }

    #[test]
    fn iri_chars_serialisable_accepts_valid_rejects_corrupting() {
        // The cheap structural guard the listing fast path runs before `new_unchecked`. It must ACCEPT
        // every well-formed IRI (the store mints only these) and REJECT exactly the characters that
        // RFC-3987 forbids in an IRI and that would corrupt a serialised `<...>` term — so a
        // hypothetically-malformed backend row is OMITTED rather than producing an invalid RDF term.
        // Accept: ordinary http(s) IRIs incl. percent-encoding, fragments, and non-ASCII (ucschar).
        for ok in [
            "https://pod.example/c/a",
            "https://pod.example/c/a#me",
            "https://pod.example/c/a%20b",
            "https://pod.example/c/café", // 2-byte ucschar é (U+00E9) — non-control
            "https://pod.example/c/\u{1f600}emoji", // 4-byte non-ASCII — accepted (non-control)
            "urn:uuid:12345678-1234-1234-1234-123456789abc",
        ] {
            assert!(iri_chars_serialisable(ok), "must accept valid IRI: {ok}");
        }
        // Reject: empty, space, controls (incl. newline/tab/DEL), and the term-delimiter set.
        assert!(!iri_chars_serialisable(""), "empty must be rejected");
        for bad in [
            "https://pod.example/c/a b",      // space
            "https://pod.example/c/a\nb",     // newline (control)
            "https://pod.example/c/a\tb",     // tab (control)
            "https://pod.example/c/a\u{7f}b", // DEL (control)
            "https://pod.example/c/<a>",      // angle brackets (would close the term)
            "https://pod.example/c/\"a",      // quote
            "https://pod.example/c/a{b}",     // braces
            "https://pod.example/c/a|b",      // pipe
            "https://pod.example/c/a^b",      // caret
            "https://pod.example/c/a`b",      // backtick
            "https://pod.example/c/a\\b",     // backslash
            "https://pod.example/c/a\u{80}b", // C1 control U+0080 (non-ASCII) — the fallback-path case
            "https://pod.example/c/a\u{9f}b", // C1 control U+009F (non-ASCII) — the fallback-path case
        ] {
            assert!(
                !iri_chars_serialisable(bad),
                "must reject corrupting IRI: {bad:?}"
            );
        }
    }

    /// Equivalence harness: the optimised `iri_chars_serialisable` must agree BYTE-FOR-BYTE with the
    /// reference `.chars()`-based predicate across ASCII, C0/C1 controls, the delimiter set, and
    /// multi-byte ucschar — so the ASCII fast path can never diverge from the proven char path.
    #[test]
    fn iri_chars_serialisable_matches_reference_across_inputs() {
        fn reference(iri: &str) -> bool {
            if iri.is_empty() {
                return false;
            }
            !iri.chars().any(|c| {
                c.is_control()
                    || c == ' '
                    || matches!(c, '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\')
            })
        }
        // Every ASCII byte as a single-char IRI body, plus an empty string and several multi-byte
        // ucschar / C1-control cases — the exact boundary where ASCII-fast-path vs char-path could differ.
        let mut cases: Vec<String> = vec![String::new()];
        for b in 0u8..=0x7f {
            cases.push(format!("a{}z", b as char));
        }
        for s in [
            "café",
            "naïve",
            "\u{1f600}",
            "a\u{80}b",
            "a\u{9f}b",
            "a\u{a0}b",
            "ÿ",
            "ABC",
            "https://h/c/item-0042",
            "",
            "\u{7f}",
            " ",
        ] {
            cases.push(s.to_string());
        }
        for c in cases {
            assert_eq!(
                iri_chars_serialisable(&c),
                reference(&c),
                "diverged from reference for {c:?}"
            );
        }
    }

    #[tokio::test]
    async fn render_container_lists_every_child_once_with_typing() {
        // A multi-child container renders the three ldp typing triples + EXACTLY ONE `ldp:contains`
        // per member, with no duplicates — the contract the O(N) de-dup must preserve.
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        let container = "https://pod.example/c/";
        // Mint the container, then add several distinct children through the authoritative path.
        store
            .write(container, AxBytes::new(), "text/turtle")
            .await
            .expect("mint container");
        let children = [
            "https://pod.example/c/a",
            "https://pod.example/c/b",
            "https://pod.example/c/c",
            "https://pod.example/c/d",
        ];
        for child in children {
            store
                .create_in_container(container, child, AxBytes::new(), "text/turtle")
                .await
                .expect("add child");
        }
        let state = Arc::new(LdpState::new(store, "https://pod.example"));

        let (body, ct) = render_container(
            &state,
            container,
            &AxBytes::new(),
            "text/turtle",
            Some("text/turtle"),
        )
        .await
        .expect("render");
        assert_eq!(ct, "text/turtle");
        let text = String::from_utf8(body.to_vec()).unwrap();

        // The three ldp typing triples are present.
        assert!(text.contains("ldp#Resource"), "body: {text}");
        assert!(text.contains("ldp#Container"), "body: {text}");
        assert!(text.contains("ldp#BasicContainer"), "body: {text}");
        // The containment predicate is rendered (the Turtle serialiser abbreviates the four objects
        // onto ONE `ldp:contains` predicate via `,`-lists, so the predicate string itself appears
        // once — the per-child count below is the real "exactly one containment edge per child" check).
        assert!(text.contains("ldp#contains"), "body: {text}");
        // Each child IRI appears EXACTLY ONCE — no duplicate containment edge, none missing. (Each
        // child IRI is distinct and is not a substring of the container subject or another child.)
        for child in children {
            assert_eq!(
                count_occurrences(&text, child),
                1,
                "child {child} must appear exactly once: {text}"
            );
        }
    }

    #[tokio::test]
    async fn render_container_dedups_generated_against_stored_body_byte_identical() {
        // A stored container body that ALREADY asserts a generated triple (the ldp:BasicContainer
        // typing) must NOT have it repeated by the generated set — the de-dup catches the overlap.
        // This is the one place the HashSet de-dup actually suppresses anything; it must match the
        // old `push_unique` behaviour exactly (the overlapping triple appears ONCE).
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        let container = "https://pod.example/c/";
        let stored_body = AxBytes::from(
            "<https://pod.example/c/> a <http://www.w3.org/ns/ldp#BasicContainer> .".to_string(),
        );
        store
            .write(container, stored_body.clone(), "text/turtle")
            .await
            .expect("mint container with stored body");
        let state = Arc::new(LdpState::new(store, "https://pod.example"));

        let (body, _ct) = render_container(
            &state,
            container,
            &stored_body,
            "text/turtle",
            Some("text/turtle"),
        )
        .await
        .expect("render");
        let text = String::from_utf8(body.to_vec()).unwrap();
        // The BasicContainer typing appears exactly once despite being in BOTH the stored body and the
        // generated set (the overlap is de-duped — matching the prior render).
        assert_eq!(
            count_occurrences(&text, "ldp#BasicContainer"),
            1,
            "the stored+generated BasicContainer triple must appear once: {text}"
        );
    }

    #[tokio::test]
    async fn render_container_dedups_large_stored_body_via_hashset_branch() {
        // A LARGE stored body (> DEDUP_HASHSET_THRESHOLD triples) that ALSO asserts a generated triple
        // (the ldp:BasicContainer typing) must dedup the overlap via the HASHSET branch — the same
        // contract as the small/linear branch (overlap appears once). This guards the threshold-gated
        // path roborev flagged: the large-stored-body case must not double the generated triple, and
        // must not introduce or drop any membership edge.
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        let container = "https://pod.example/c/";
        // 30 distinct stored triples (> the 16 threshold → HashSet branch) — one of which is exactly a
        // GENERATED triple (the BasicContainer typing), the rest unrelated `ex:p_i ex:o_i` assertions.
        let mut body = String::from(
            "<https://pod.example/c/> a <http://www.w3.org/ns/ldp#BasicContainer> .\n",
        );
        for i in 0..29 {
            body.push_str(&format!(
                "<https://pod.example/c/> <https://ex.example/p{i}> <https://ex.example/o{i}> .\n"
            ));
        }
        let stored_body = AxBytes::from(body);
        store
            .write(container, stored_body.clone(), "text/turtle")
            .await
            .expect("mint container with large stored body");
        let children = [
            "https://pod.example/c/x",
            "https://pod.example/c/y",
            "https://pod.example/c/z",
        ];
        for child in children {
            store
                .create_in_container(container, child, AxBytes::new(), "text/turtle")
                .await
                .expect("add child");
        }
        let state = Arc::new(LdpState::new(store, "https://pod.example"));

        let (body_out, _ct) = render_container(
            &state,
            container,
            &stored_body,
            "text/turtle",
            Some("text/turtle"),
        )
        .await
        .expect("render");
        let text = String::from_utf8(body_out.to_vec()).unwrap();
        // The overlapping BasicContainer typing is de-duped to ONE occurrence (HashSet branch).
        assert_eq!(
            count_occurrences(&text, "ldp#BasicContainer"),
            1,
            "large-stored overlap must dedup to once: {text}"
        );
        // Every child still renders exactly once (no membership edge dropped or doubled).
        for child in children {
            assert_eq!(
                count_occurrences(&text, child),
                1,
                "child {child} must appear exactly once on the HashSet branch: {text}"
            );
        }
        // The unrelated stored triples are all carried through verbatim. Match the FULL IRI term
        // (trailing `>`) so e.g. `o1` does not substring-match `o10`..`o19`.
        for i in 0..29 {
            assert_eq!(
                count_occurrences(&text, &format!("https://ex.example/o{i}>")),
                1,
                "stored triple o{i} must be carried through once: {text}"
            );
        }
    }

    // =====================================================================================
    // EXISTENCE-NON-DISCLOSURE (decisions/0003) — the exhaustive byte-identical matrix.
    //
    // THE RULE: 404 is served ONLY to a requester who holds the operation's required mode. Every other
    // requester (anonymous → 401, authenticated-but-unauthorized → 403) gets their DENIAL code for BOTH
    // "forbidden-existing" and "not-found", BYTE-IDENTICALLY (same status + body + Location + ETag +
    // WWW-Authenticate). These tests drive the REAL handlers over the drop-box adversary fixture
    // (`store_alice_container_bob_append_only`: Alice owns `/alice/c/` with inheritable R/W/C; Bob holds
    // ONLY `acl:Append` on the container — the canonical "create-rights-on-parent, no-rights-on-target"
    // shape) and assert the full materialised response is identical across the missing-vs-forbidden axis.
    // =====================================================================================

    /// A fully-materialised HTTP response, reduced to the client-observable fields the rule constrains:
    /// the status, the body bytes, and the security-relevant headers (`Location`, `ETag`,
    /// `WWW-Authenticate`). Two responses are an EXISTENCE ORACLE iff they differ in ANY of these.
    #[derive(Debug, PartialEq, Eq)]
    struct ObservableResponse {
        status: u16,
        body: Vec<u8>,
        location: Option<String>,
        etag: Option<String>,
        www_authenticate: Option<String>,
    }

    /// Materialise a handler result (`Ok(Response)` or `Err(ServerError)`) into the
    /// client-observable response — exactly what the HTTP client sees, via `IntoResponse` (so a denial
    /// `ServerError` is rendered through the SAME path the server uses, carrying its real body +
    /// `WWW-Authenticate`).
    async fn observe(result: Result<Response, ServerError>) -> ObservableResponse {
        let resp = match result {
            Ok(r) => r,
            Err(e) => e.into_response(),
        };
        let status = resp.status().as_u16();
        let header = |resp: &Response, name: HeaderName| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let location = header(&resp, header::LOCATION);
        let etag = header(&resp, header::ETAG);
        let www_authenticate = header(&resp, header::WWW_AUTHENTICATE);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        ObservableResponse {
            status,
            body,
            location,
            etag,
            www_authenticate,
        }
    }

    /// Bob (authenticated, Append-only on `/alice/c/`, NO rights on its members) — the adversary.
    fn bob() -> VerifiedToken {
        VerifiedToken {
            web_id: Some(BOB.into()),
            ..VerifiedToken::default()
        }
    }

    /// An anonymous (no-WebID) requester.
    fn anon() -> VerifiedToken {
        VerifiedToken::default()
    }

    /// The drop-box fixture with an EXISTING Alice-private child `/alice/c/secret` (forbidden to Bob by
    /// inheritance) so we can exercise the "exists-but-forbidden" axis against the "missing" one.
    async fn dropbox_with_secret(
    ) -> Arc<LdpState<CompositeStore<InMemorySparqClient, InMemoryBlobStore>>> {
        let store = store_alice_container_bob_append_only().await;
        // Seed an EXISTING member `/alice/c/secret` (Alice-private by inheritance — no own ACL).
        store
            .write(
                "https://pod.example/alice/c/secret",
                AxBytes::from(
                    "<https://pod.example/alice/c/secret#me> <http://xmlns.com/foaf/0.1/name> \"S\" ."
                        .to_string(),
                ),
                "text/turtle",
            )
            .await
            .expect("seed secret member");
        Arc::new(LdpState::new(store, "https://pod.example"))
    }

    const EXISTING: &str = "/alice/c/secret"; // exists, Alice-private (forbidden to Bob/anon)
    const MISSING: &str = "/alice/c/ghost"; // never created

    fn turtle_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/turtle"),
        );
        h
    }

    fn body_bytes() -> AxBytes {
        AxBytes::from("<https://pod.example/alice/c/x#me> <http://p> <http://o> .".to_string())
    }

    /// Run one verb against one path with one token, returning the observable response. Centralises the
    /// per-verb handler dispatch so the matrix below is a tight loop.
    async fn run_verb(
        state: &Arc<LdpState<CompositeStore<InMemorySparqClient, InMemoryBlobStore>>>,
        verb: &str,
        path: &str,
        token: VerifiedToken,
    ) -> ObservableResponse {
        let uri: axum::http::Uri = path.parse().unwrap();
        let s = State(state.clone());
        let t = Extension(token);
        let result = match verb {
            "GET" => get_handler(s, t, uri, HeaderMap::new()).await,
            "HEAD" => head_handler(s, t, uri, HeaderMap::new()).await,
            "PUT" => put_handler(s, t, uri, turtle_headers(), body_bytes()).await,
            "POST" => post_handler(s, t, uri, turtle_headers(), body_bytes()).await,
            "PATCH" => {
                patch_handler(
                    s,
                    t,
                    uri,
                    n3_patch_headers(),
                    insert_only_patch("https://pod.example/alice/c/x#me"),
                )
                .await
            }
            "DELETE" => delete_handler(s, t, uri, HeaderMap::new()).await,
            other => panic!("unknown verb {other}"),
        };
        observe(result).await
    }

    /// THE MATRIX: for every verb × {anonymous, Bob-unauthorized}, the response to the EXISTING-but-
    /// forbidden target MUST be BYTE-IDENTICAL to the response to the MISSING target — no verb is an
    /// existence oracle, and the denial code is the requester's (401 anon / 403 Bob), never a 404.
    #[tokio::test]
    async fn matrix_missing_equals_forbidden_byte_identical_for_every_verb() {
        for verb in ["GET", "HEAD", "PUT", "POST", "PATCH", "DELETE"] {
            for (label, token_fn) in [
                ("anonymous", anon as fn() -> VerifiedToken),
                ("bob-unauthorized", bob as fn() -> VerifiedToken),
            ] {
                // A FRESH fixture per (verb, requester) so a mutating verb on one axis cannot perturb
                // the other (e.g. a stray write changing membership/ETag).
                let state_existing = dropbox_with_secret().await;
                let state_missing = dropbox_with_secret().await;
                let on_existing = run_verb(&state_existing, verb, EXISTING, token_fn()).await;
                let on_missing = run_verb(&state_missing, verb, MISSING, token_fn()).await;

                assert_eq!(
                    on_existing, on_missing,
                    "{verb} as {label}: the exists-but-forbidden response must be BYTE-IDENTICAL to the \
                     not-found response (else it is an existence oracle).\n exists:  {on_existing:?}\n \
                     missing: {on_missing:?}"
                );
                // And the denial code is the requester's — NEVER a 404 (only an authorized holder of the
                // required mode learns 404). Anonymous → 401, Bob (authenticated) → 403.
                let expected = if label == "anonymous" { 401 } else { 403 };
                assert_eq!(
                    on_existing.status, expected,
                    "{verb} as {label}: must be the denial code {expected}, never 404/2xx"
                );
                assert_ne!(
                    on_existing.status, 404,
                    "{verb} as {label}: an under-authorized requester must NEVER see 404"
                );
                // A POST/PUT/PATCH denial must not have leaked a Location (no created child revealed).
                assert!(
                    on_existing.location.is_none(),
                    "{verb} as {label}: a denial must carry no Location"
                );
            }
        }
    }

    /// POSITIVE control: an AUTHORIZED reader (Alice, who has inheritable Read on `/alice/c/`) gets a
    /// TRUE 404 on a genuinely-missing resource — the rule keeps the authorized-reader-404 (the CTH
    /// `read-access-*` fictive rows + `post-target-not-found` GET depend on this). Bob/anon get the
    /// denial for the SAME missing path (already covered by the matrix) — so 404 ⇒ "you were allowed to
    /// know, and it isn't there."
    #[tokio::test]
    async fn authorized_reader_gets_true_404_on_genuinely_missing() {
        let state = dropbox_with_secret().await;
        let alice = VerifiedToken {
            web_id: Some(ALICE.into()),
            ..VerifiedToken::default()
        };
        let got = run_verb(&state, "GET", MISSING, alice.clone()).await;
        assert_eq!(
            got.status, 404,
            "an authorized reader (Alice) must get a TRUE 404 on a missing resource: {got:?}"
        );
        // HEAD likewise.
        let head = run_verb(&state, "HEAD", MISSING, alice).await;
        assert_eq!(head.status, 404, "HEAD must also be a true 404 for Alice");
    }

    // --- V1: PUT-create now requires target Write (the drop-box trade-off) -------------------------

    #[tokio::test]
    async fn v1_append_only_put_create_is_denied_not_201() {
        // Bob holds parent `acl:Append` (he can POST) but NOT target `acl:Write`. A PUT-create of a free
        // name MUST now be denied (403) — it previously fell through to a parent-Append 201, which (paired
        // with the 403 on a taken name) leaked existence. The denial is byte-identical to the missing case
        // (covered by the matrix); here we pin the specific status + that NOTHING was created.
        let state = dropbox_with_secret().await;
        let got = run_verb(&state, "PUT", MISSING, bob()).await;
        assert_eq!(
            got.status, 403,
            "an Append-only PUT-create must be a 403, not a 201: {got:?}"
        );
        use crate::store::Store;
        assert!(
            !state
                .store
                .exists("https://pod.example/alice/c/ghost")
                .await
                .unwrap(),
            "a denied PUT-create must not have written anything"
        );
    }

    #[tokio::test]
    async fn v1_owner_put_create_still_succeeds_201() {
        // The control: the OWNER (Alice, inheritable Write) can still PUT-create a fresh resource → 201.
        // The V1 tightening (require target Write) must not regress the legitimate create.
        let state = dropbox_with_secret().await;
        let alice = VerifiedToken {
            web_id: Some(ALICE.into()),
            ..VerifiedToken::default()
        };
        let got = run_verb(&state, "PUT", MISSING, alice).await;
        assert_eq!(
            got.status, 201,
            "the owner's PUT-create must still succeed: {got:?}"
        );
    }

    // --- V3: insert-only PATCH-create is symmetric with forbidden-modify ---------------------------

    #[tokio::test]
    async fn v3_append_holder_patch_create_succeeds_but_oracle_is_closed() {
        // An INSERT-ONLY PATCH-create needs `acl:Append` on the TARGET (inherited). Bob has Append only
        // on the CONTAINER, not on the members (the `/alice/c/.acl` grants Bob Append via `acl:accessTo`
        // on the container, NOT `acl:default`), so the member `ghost` does NOT inherit Bob's Append → an
        // insert-only PATCH-create is DENIED (403). Crucially this is the SAME 403 Bob gets modifying the
        // EXISTING forbidden `secret` — no create-vs-modify oracle. (Both are covered byte-identically by
        // the matrix; this pins the V3-specific reasoning.)
        let state_missing = dropbox_with_secret().await;
        let state_existing = dropbox_with_secret().await;
        let create = run_verb(&state_missing, "PATCH", MISSING, bob()).await;
        let modify = run_verb(&state_existing, "PATCH", EXISTING, bob()).await;
        assert_eq!(
            create.status, 403,
            "Bob's PATCH-create is denied: {create:?}"
        );
        assert_eq!(
            create, modify,
            "V3: PATCH-create and PATCH-forbidden-modify must be byte-identical (no existence oracle)"
        );
    }

    // --- V2: the POST Location is collision-INDEPENDENT (no taken-vs-free signal) ------------------

    #[tokio::test]
    async fn v2_post_location_shape_is_collision_independent() {
        // An AUTHORIZED appender POSTing `Slug: foo` gets a `…/foo-<opaque>` Location whether or not
        // `foo` already exists — so the Location reveals nothing about which names are taken. Drive it as
        // Bob (who HOLDS container Append, so the POST is authorized) twice with the same Slug: the two
        // Locations differ (distinct opaque names) and NEITHER is the verbatim `…/foo`.
        let state = dropbox_with_secret().await;
        let uri: axum::http::Uri = "/alice/c/".parse().unwrap();
        let post = |slug: &'static str| {
            let st = State(state.clone());
            let mut headers = turtle_headers();
            headers.insert(
                HeaderName::from_static("slug"),
                HeaderValue::from_static(slug),
            );
            let u = uri.clone();
            async move {
                observe(post_handler(st, Extension(bob()), u, headers, body_bytes()).await).await
            }
        };
        let first = post("foo").await;
        let second = post("foo").await;
        assert_eq!(first.status, 201);
        assert_eq!(second.status, 201);
        let loc1 = first.location.expect("Location");
        let loc2 = second.location.expect("Location");
        // Collision-independent: same Slug, DIFFERENT opaque Locations; neither is the verbatim name.
        assert_ne!(
            loc1, loc2,
            "two POSTs of the same Slug must mint distinct opaque names"
        );
        assert_ne!(
            loc1, "https://pod.example/alice/c/foo",
            "Location must not be the verbatim Slug"
        );
        assert!(
            loc1.starts_with("https://pod.example/alice/c/foo-"),
            "Location must contain the Slug: {loc1}"
        );
        assert!(
            loc2.starts_with("https://pod.example/alice/c/foo-"),
            "Location must contain the Slug: {loc2}"
        );
    }

    #[tokio::test]
    async fn post_slug_dot_acl_anonymous_on_public_append_gets_401_not_bare_403() {
        // roborev denial-shape consistency: on a PUBLIC-`acl:Append` container an ANONYMOUS caller CAN
        // pass POST authorization and reach the `.acl`-intent guard. Its denial must carry the
        // requester's shape — 401 + `WWW-Authenticate` for anonymous — NOT a bare 403, so the
        // `.acl`-intent case is indistinguishable in shape from any other unauthorized anonymous POST.
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        store
            .write(
                "https://pod.example/alice/c/",
                AxBytes::from(String::new()),
                "text/turtle",
            )
            .await
            .expect("seed container");
        // The container grants the PUBLIC (`foaf:Agent`) Append — so anonymous may POST.
        let acl = r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.
<#pub> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo <https://pod.example/alice/c/>; acl:mode acl:Append."#;
        store
            .write(
                "https://pod.example/alice/c/.acl",
                AxBytes::from(acl.to_string()),
                "text/turtle",
            )
            .await
            .expect("seed public-append acl");
        let state = Arc::new(LdpState::new(store, "https://pod.example"));
        let uri: axum::http::Uri = "/alice/c/".parse().unwrap();
        // Anonymous POST with `Slug: secret.acl` (a benign body — the body is irrelevant; the INTENT is
        // what is refused).
        let got = observe(
            post_handler(
                State(state.clone()),
                Extension(anon()),
                uri,
                post_turtle_headers_with_slug("secret.acl"),
                body_bytes(),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 401,
            "an anonymous `.acl`-intent POST on a public-append container must be 401 (not a bare 403)"
        );
        assert!(
            got.www_authenticate.is_some(),
            "the anonymous denial must carry a WWW-Authenticate challenge"
        );
        // A benign anonymous Slug on the SAME container still succeeds (public Append is real) — the
        // guard rejects only the `.acl` intent, uniformly by shape.
        let benign = observe(
            post_handler(
                State(state),
                Extension(anon()),
                "/alice/c/".parse().unwrap(),
                post_turtle_headers_with_slug("benign"),
                body_bytes(),
            )
            .await,
        )
        .await;
        assert_eq!(
            benign.status, 201,
            "a benign anonymous Slug on a public-append container must still succeed: {benign:?}"
        );
    }

    // --- V4: a conditional precondition requires Read (the Write-without-Read shape) ---------------

    /// A store where Bob holds `acl:Write` (and Append) on `/alice/c/wonly` but NOT `acl:Read` — the
    /// "Write-without-Read" shape. Alice owns the container. An EXISTING `wonly` is present.
    ///
    /// Bob is ALSO granted `acl:Write` on the CONTAINER itself (via the container's own `acl:accessTo`),
    /// so that a DELETE of `wonly` PASSES its parent-containment write authorization (`acl:Write` on the
    /// nearest parent) and actually REACHES the V4 conditional-read guard — without this, the DELETE
    /// would be denied at the parent-write check and the V4 DELETE test would pass for the wrong reason
    /// (the roborev finding). The container grant deliberately omits `acl:Read`, and `wonly`'s OWN `.acl`
    /// (below) overrides inheritance, so Bob's effective modes on `wonly` stay exactly {Write, Append} —
    /// no Read — preserving the Write-without-Read shape the V4 guard is meant to catch.
    async fn store_bob_write_without_read(
    ) -> Arc<LdpState<CompositeStore<InMemorySparqClient, InMemoryBlobStore>>> {
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        store
            .write(
                "https://pod.example/alice/c/",
                AxBytes::from(String::new()),
                "text/turtle",
            )
            .await
            .expect("seed container");
        store
            .write(
                "https://pod.example/alice/c/wonly",
                AxBytes::from(
                    "<https://pod.example/alice/c/wonly#me> <http://p> <http://o> .".to_string(),
                ),
                "text/turtle",
            )
            .await
            .expect("seed wonly");
        // Alice: full control over the container + members (default). Bob: `acl:Write` on the CONTAINER
        // itself (so a DELETE's parent-write check passes and the V4 guard is reached) — but NO `acl:Read`
        // on the container, and `wonly`'s OWN `.acl` overrides inheritance so Bob never gains Read on
        // `wonly`.
        let container_acl = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#alice> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <https://pod.example/alice/c/>; acl:default <https://pod.example/alice/c/>; acl:mode acl:Read, acl:Write, acl:Control.
<#bob> a acl:Authorization; acl:agent <{BOB}>; acl:accessTo <https://pod.example/alice/c/>; acl:mode acl:Write, acl:Append."#
        );
        store
            .write(
                "https://pod.example/alice/c/.acl",
                AxBytes::from(container_acl),
                "text/turtle",
            )
            .await
            .expect("seed container acl");
        let wonly_acl = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#alice> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <https://pod.example/alice/c/wonly>; acl:mode acl:Read, acl:Write, acl:Control.
<#bob> a acl:Authorization; acl:agent <{BOB}>; acl:accessTo <https://pod.example/alice/c/wonly>; acl:mode acl:Write, acl:Append."#
        );
        store
            .write(
                "https://pod.example/alice/c/wonly.acl",
                AxBytes::from(wonly_acl),
                "text/turtle",
            )
            .await
            .expect("seed wonly acl");
        Arc::new(LdpState::new(store, "https://pod.example"))
    }

    #[tokio::test]
    async fn v4_write_without_read_conditional_put_is_denied_not_412_or_2xx() {
        // Bob has Write but NOT Read on `wonly`. A conditional `PUT … If-Match: "x"` would otherwise
        // yield a 412-vs-2xx outcome (an existence/content probe) + an ETag of a body Bob cannot GET.
        // V4 folds it to Bob's denial code (403) BEFORE any precondition evaluation.
        let state = store_bob_write_without_read().await;
        let uri: axum::http::Uri = "/alice/c/wonly".parse().unwrap();
        let mut headers = turtle_headers();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"deadbeef\""));
        let got = observe(
            put_handler(
                State(state.clone()),
                Extension(bob()),
                uri,
                headers,
                body_bytes(),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 403,
            "a Write-without-Read conditional PUT must be the denial code, not 412/2xx: {got:?}"
        );
        assert!(got.etag.is_none(), "a V4 denial must not leak an ETag");
    }

    #[tokio::test]
    async fn v4_write_without_read_unconditional_put_still_succeeds() {
        // The control: WITHOUT a conditional header, Bob's Write IS sufficient — an unconditional PUT to
        // `wonly` succeeds (204). V4 only gates the CONDITIONAL channel; it must not block a plain write.
        let state = store_bob_write_without_read().await;
        let uri: axum::http::Uri = "/alice/c/wonly".parse().unwrap();
        let got = observe(
            put_handler(
                State(state),
                Extension(bob()),
                uri,
                turtle_headers(),
                body_bytes(),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 204,
            "an unconditional PUT by a Write holder must still succeed: {got:?}"
        );
    }

    #[tokio::test]
    async fn v4_write_without_read_conditional_delete_is_denied() {
        // The same closure on DELETE: a `DELETE … If-Match` by a Write-without-Read holder folds to the
        // denial, not the 412-vs-204 existence/content outcome.
        //
        // The fixture grants Bob `acl:Write` on the CONTAINER (so the DELETE's parent-containment write
        // authorization PASSES and control reaches the V4 guard) but NO `acl:Read` on `wonly` — so the
        // 403 here is genuinely from V4, NOT from the parent-write check. The unconditional-DELETE
        // control below PROVES that: the SAME Bob CAN delete `wonly` without a conditional header, so the
        // only thing that turns the conditional DELETE into a 403 is the V4 guard.
        let state = store_bob_write_without_read().await;
        let uri: axum::http::Uri = "/alice/c/wonly".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"deadbeef\""));
        let got = observe(delete_handler(State(state), Extension(bob()), uri, headers).await).await;
        assert_eq!(
            got.status, 403,
            "a Write-without-Read conditional DELETE must be the denial code: {got:?}"
        );
    }

    #[tokio::test]
    async fn v4_write_without_read_unconditional_delete_succeeds_proving_v4_is_the_cause() {
        // CONTROL for the test above (the roborev finding): with the SAME fixture and NO conditional
        // header, Bob's Write (on `wonly`) + container Write (parent-containment) IS sufficient to delete
        // `wonly` → 204. This proves the conditional-DELETE 403 above comes from the V4 guard, not the
        // parent-write authorization — the test is not vacuous.
        let state = store_bob_write_without_read().await;
        let uri: axum::http::Uri = "/alice/c/wonly".parse().unwrap();
        let got =
            observe(delete_handler(State(state), Extension(bob()), uri, HeaderMap::new()).await)
                .await;
        assert_eq!(
            got.status, 204,
            "an UNCONDITIONAL DELETE by the same Write holder must succeed — proving the conditional \
             403 is from V4, not the parent-write check: {got:?}"
        );
    }

    #[tokio::test]
    async fn v4_control_only_holder_conditional_acl_write_is_not_wrongly_denied() {
        // EDGE: the V4 read-mode for an `.acl` target is CONTROL, not Read (reading an `.acl`'s
        // representation is a Control op; `Control` does NOT imply `Read`). A holder of Control-but-NOT-
        // Read on a resource IS entitled to its `.acl`'s ETag, so a CONDITIONAL `.acl` write by such a
        // holder must NOT be folded to a denial by V4. This pins the regression: if the guard used `Read`
        // (instead of the `.acl` read-mode `Control`) it would wrongly 403 this legitimate write.
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        // Alice gets ONLY Control on `/alice/c/manager` (no Read, no Write) — a pure access-manager.
        let acl = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#alice> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <https://pod.example/alice/c/manager>; acl:mode acl:Control."#
        );
        store
            .write(
                "https://pod.example/alice/c/manager.acl",
                AxBytes::from(acl),
                "text/turtle",
            )
            .await
            .expect("seed manager .acl");
        let state = Arc::new(LdpState::new(store, "https://pod.example"));
        let alice = VerifiedToken {
            web_id: Some(ALICE.into()),
            ..VerifiedToken::default()
        };
        // A CONDITIONAL PUT REPLACING the existing `.acl` (it exists, so `If-Match: *` is satisfied and
        // the precondition is genuinely evaluated — exercising the V4 gate before it).
        let uri: axum::http::Uri = "/alice/c/manager.acl".parse().unwrap();
        let mut headers = turtle_headers();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("*"));
        let acl_body = AxBytes::from(format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#alice> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <https://pod.example/alice/c/manager>; acl:mode acl:Control, acl:Read."#
        ));
        let got =
            observe(put_handler(State(state), Extension(alice), uri, headers, acl_body).await)
                .await;
        assert_eq!(
            got.status, 204,
            "a Control-only holder's CONDITIONAL .acl write must reach the write path (204), not a V4 \
             denial — the `.acl` read-mode is Control, not Read: {got:?}"
        );
    }

    // --- V5: the membership-derived container ETag is Read-gated -----------------------------------

    #[tokio::test]
    async fn v5_container_etag_only_reaches_a_reader() {
        // The container's membership-derived ETag is exposed ONLY on the Read-gated GET/HEAD path. An
        // Append-only Bob cannot GET `/alice/c/` (no Read) → 401/403, so he NEVER observes the ETag that
        // shifts on child add/remove. Alice (Read) does observe it. (The conditional-channel sibling — a
        // non-reader probing the ETag via a conditional write — is closed by V4 above.)
        let state = dropbox_with_secret().await;
        // Bob (Append-only, no Read on the container) → denied, no ETag observable.
        let bob_get = run_verb(&state, "GET", "/alice/c/", bob()).await;
        assert_eq!(
            bob_get.status, 403,
            "Bob cannot read the container: {bob_get:?}"
        );
        assert!(
            bob_get.etag.is_none(),
            "a non-reader must observe NO container ETag (it is the membership oracle): {bob_get:?}"
        );
        // Alice (Read) DOES get the container listing + its membership ETag.
        let alice = VerifiedToken {
            web_id: Some(ALICE.into()),
            ..VerifiedToken::default()
        };
        let alice_get = run_verb(&state, "GET", "/alice/c/", alice).await;
        assert_eq!(alice_get.status, 200);
        assert!(
            alice_get.etag.is_some(),
            "the authorized reader DOES receive the container ETag"
        );
    }

    // =====================================================================================
    // CREATE-AUTHZ CONTAINER-MODIFICATION (PR #3 review finding [HIGH]) — creating a member (or an
    // intermediate container) requires `acl:Append`/`Write` on the CONTAINING container, in ADDITION
    // to the target's own effective-ACL mode. An `acl:default`-only Write grant (or a pre-provisioned
    // target `.acl`) must NOT let an agent with NO mode on the container mint members in it. Symmetric
    // with DELETE's parent-Write check.
    // =====================================================================================

    /// A third agent (distinct from ALICE/BOB) for the create-authz positive control.
    const CAROL: &str = "https://pod.example/carol/profile/card#me";

    /// `/alice/c/` exists with a container `.acl` where:
    ///  - ALICE: `acl:accessTo` + `acl:default` Read/Write/Control (full owner).
    ///  - BOB: `acl:default acl:Write` ONLY — inheritable Write on the container's MEMBERS, but NO
    ///    `acl:accessTo` on the container itself (so Bob holds NO mode on `/alice/c/` as a target). This
    ///    is the attacker shape the finding names: Bob can WRITE any member's representation (target-ACL
    ///    Write via default) yet must NOT be able to CREATE one (no container-modification right).
    ///  - CAROL: `acl:default acl:Write` (member Write, so target auth passes) PLUS `acl:accessTo
    ///    acl:Append` on the container (the container-modification right) — the "WITH container
    ///    write/append" agent who IS allowed to create.
    async fn store_default_write_no_container_access(
    ) -> Arc<LdpState<CompositeStore<InMemorySparqClient, InMemoryBlobStore>>> {
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        store
            .write(
                "https://pod.example/alice/c/",
                AxBytes::from(String::new()),
                "text/turtle",
            )
            .await
            .expect("seed container");
        let acl = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#alice> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <https://pod.example/alice/c/>; acl:default <https://pod.example/alice/c/>; acl:mode acl:Read, acl:Write, acl:Control.
<#bob> a acl:Authorization; acl:agent <{BOB}>; acl:default <https://pod.example/alice/c/>; acl:mode acl:Write.
<#carol> a acl:Authorization; acl:agent <{CAROL}>; acl:accessTo <https://pod.example/alice/c/>; acl:default <https://pod.example/alice/c/>; acl:mode acl:Write, acl:Append."#
        );
        store
            .write(
                "https://pod.example/alice/c/.acl",
                AxBytes::from(acl),
                "text/turtle",
            )
            .await
            .expect("seed container acl");
        Arc::new(LdpState::new(store, "https://pod.example"))
    }

    fn carol() -> VerifiedToken {
        VerifiedToken {
            web_id: Some(CAROL.into()),
            ..VerifiedToken::default()
        }
    }

    #[tokio::test]
    async fn create_authz_default_write_only_agent_denied_put_create() {
        // Bob holds member Write via `acl:default` (so his target-ACL Write authorizes the write itself)
        // but NO mode on the container → a PUT-create must be DENIED (403), and nothing written. Pre-fix
        // the create authorized purely against the (inherited) target ACL and returned 201.
        let state = store_default_write_no_container_access().await;
        let got = observe(
            put_handler(
                State(state.clone()),
                Extension(bob()),
                "/alice/c/newdoc".parse().unwrap(),
                turtle_headers(),
                body_bytes(),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 403,
            "an acl:default-only Write agent with NO container mode must be denied PUT-create: {got:?}"
        );
        assert!(
            !state
                .store
                .exists("https://pod.example/alice/c/newdoc")
                .await
                .unwrap(),
            "a denied PUT-create must have written nothing"
        );
    }

    #[tokio::test]
    async fn create_authz_default_write_only_agent_denied_patch_create() {
        // The same closure on the create-on-PATCH path: an INSERT-only patch (needs Append on the
        // target, which Bob's member Write satisfies) still must be denied at the container-modification
        // check because Bob holds no Append on the container → 403, nothing written.
        let state = store_default_write_no_container_access().await;
        let got = observe(
            patch_handler(
                State(state.clone()),
                Extension(bob()),
                "/alice/c/newdoc".parse().unwrap(),
                n3_patch_headers(),
                insert_only_patch("https://pod.example/alice/c/newdoc#me"),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 403,
            "an acl:default-only Write agent must be denied create-on-PATCH: {got:?}"
        );
        assert!(
            !state
                .store
                .exists("https://pod.example/alice/c/newdoc")
                .await
                .unwrap(),
            "a denied PATCH-create must have written nothing"
        );
    }

    #[tokio::test]
    async fn create_authz_default_write_only_agent_denied_post() {
        // POST already routes the container-modification right through its container-Append
        // authorization: Bob holds no `acl:accessTo` mode on `/alice/c/`, so a POST is denied (403). This
        // pins that CREATE (PUT/PATCH) is now symmetric with POST — all three require the container right.
        let state = store_default_write_no_container_access().await;
        let got = observe(
            post_handler(
                State(state.clone()),
                Extension(bob()),
                "/alice/c/".parse().unwrap(),
                turtle_headers(),
                body_bytes(),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 403,
            "an acl:default-only Write agent must be denied POST (no container Append): {got:?}"
        );
    }

    #[tokio::test]
    async fn create_authz_default_write_only_agent_denied_deep_ancestor_mint() {
        // The `ensure_ancestor_containers` escalation: Bob PUT-creates `/alice/c/deep/x` (an inherited
        // target ACL grants member Write). The container-modification check authorizes Append on the
        // NEAREST EXISTING ancestor (`/alice/c/`) — which Bob lacks — so the mint of the intermediate
        // container `/alice/c/deep/` is refused (403), and no intermediate container is materialised.
        let state = store_default_write_no_container_access().await;
        let got = observe(
            put_handler(
                State(state.clone()),
                Extension(bob()),
                "/alice/c/deep/x".parse().unwrap(),
                turtle_headers(),
                body_bytes(),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 403,
            "a deep-ancestor mint by an agent with no container right must be denied: {got:?}"
        );
        assert!(
            !state
                .store
                .exists("https://pod.example/alice/c/deep/")
                .await
                .unwrap(),
            "a denied deep mint must NOT have materialised the intermediate container"
        );
        assert!(
            !state
                .store
                .exists("https://pod.example/alice/c/deep/x")
                .await
                .unwrap(),
            "a denied deep mint must NOT have written the target"
        );
    }

    #[tokio::test]
    async fn create_authz_agent_with_container_append_is_allowed() {
        // The positive control: CAROL holds member Write (target auth) AND `acl:accessTo acl:Append` on
        // the container (the container-modification right) → her PUT-create succeeds (201). This proves
        // the fix denies ONLY the missing-container-right shape, not every non-owner create.
        let state = store_default_write_no_container_access().await;
        let got = observe(
            put_handler(
                State(state.clone()),
                Extension(carol()),
                "/alice/c/newdoc".parse().unwrap(),
                turtle_headers(),
                body_bytes(),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 201,
            "an agent WITH container Append (+ member Write) must be allowed to create: {got:?}"
        );
        assert!(
            state
                .store
                .exists("https://pod.example/alice/c/newdoc")
                .await
                .unwrap(),
            "the allowed create must have written the resource"
        );
    }

    // =====================================================================================
    // N3-PATCH `solid:where` READ-GATE (PR #3 review finding [MEDIUM]) — a patch carrying a where clause
    // READS the target graph (the BGP solver), so its 2xx-vs-409 outcome is a content/existence oracle.
    // An Append-without-Read agent must NOT be able to use a where clause to probe triple presence.
    // =====================================================================================

    /// A where-bearing INSERT-only patch (conditions non-empty, NO deletes ⇒ required mode is Append):
    /// it binds `?n` from an existing `<subject> foaf:name ?n` triple in the target and inserts a nick.
    /// Its outcome depends on whether that triple is PRESENT (one solution ⇒ apply) or ABSENT (zero
    /// solutions ⇒ 409) — the exact existence/content oracle the read-gate closes.
    fn where_insert_patch(subject: &str) -> AxBytes {
        AxBytes::from(format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
             @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
             _:p solid:where   {{ <{subject}> foaf:name ?n . }} ;\n\
                 solid:inserts {{ <{subject}> foaf:nick ?n . }} .\n",
        ))
    }

    /// `/alice/log` exists holding `body`; its own `.acl` grants ALICE full control and BOB ONLY
    /// `acl:Append` (accessTo) — the Append-without-Read shape. (An own `.acl` fixes Bob's effective
    /// modes on `/alice/log` to exactly `{Append}` regardless of inheritance.)
    async fn store_bob_append_only_log(
        body: &str,
    ) -> Arc<LdpState<CompositeStore<InMemorySparqClient, InMemoryBlobStore>>> {
        let store = CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new());
        store
            .write(
                "https://pod.example/alice/log",
                AxBytes::from(body.to_string()),
                "text/turtle",
            )
            .await
            .expect("seed log");
        let acl = format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#alice> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <https://pod.example/alice/log>; acl:mode acl:Read, acl:Write, acl:Control.
<#bob> a acl:Authorization; acl:agent <{BOB}>; acl:accessTo <https://pod.example/alice/log>; acl:mode acl:Append."#
        );
        store
            .write(
                "https://pod.example/alice/log.acl",
                AxBytes::from(acl),
                "text/turtle",
            )
            .await
            .expect("seed log acl");
        Arc::new(LdpState::new(store, "https://pod.example"))
    }

    #[tokio::test]
    async fn where_patch_by_append_only_agent_is_denied_not_a_content_probe() {
        // Bob holds `acl:Append` on `/alice/log` but NOT `acl:Read`. A where-bearing patch would run the
        // BGP solver over the log's triples and leak (via 2xx-vs-409) whether the probed triple exists.
        // The read-gate folds it to Bob's denial (403) BEFORE any target read.
        let state = store_bob_append_only_log(
            "<https://pod.example/alice/log#me> <http://xmlns.com/foaf/0.1/name> \"L\" .",
        )
        .await;
        let got = observe(
            patch_handler(
                State(state),
                Extension(bob()),
                "/alice/log".parse().unwrap(),
                n3_patch_headers(),
                where_insert_patch("https://pod.example/alice/log#me"),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 403,
            "an Append-without-Read where-patch must be the denial code, not a 2xx/409 probe: {got:?}"
        );
    }

    #[tokio::test]
    async fn where_patch_is_not_an_existence_oracle_present_vs_absent_byte_identical() {
        // The oracle is CLOSED: the same where-patch by the same Append-only Bob is BYTE-IDENTICAL
        // whether the probed triple is PRESENT (would-be 2xx) or ABSENT (would-be 409) — both fold to
        // the SAME 403 before the solver ever runs, so Bob learns nothing about the triple's presence.
        let subject = "https://pod.example/alice/log#me";
        let present = store_bob_append_only_log(
            "<https://pod.example/alice/log#me> <http://xmlns.com/foaf/0.1/name> \"L\" .",
        )
        .await;
        let absent = store_bob_append_only_log(
            "<https://pod.example/alice/log#me> <http://xmlns.com/foaf/0.1/note> \"other\" .",
        )
        .await;
        let on_present = observe(
            patch_handler(
                State(present),
                Extension(bob()),
                "/alice/log".parse().unwrap(),
                n3_patch_headers(),
                where_insert_patch(subject),
            )
            .await,
        )
        .await;
        let on_absent = observe(
            patch_handler(
                State(absent),
                Extension(bob()),
                "/alice/log".parse().unwrap(),
                n3_patch_headers(),
                where_insert_patch(subject),
            )
            .await,
        )
        .await;
        assert_eq!(on_present.status, 403);
        assert_eq!(
            on_present, on_absent,
            "the where-patch response must not depend on whether the probed triple exists (no oracle)"
        );
    }

    #[tokio::test]
    async fn plain_append_patch_by_the_same_agent_still_succeeds_proving_gate_is_the_cause() {
        // CONTROL (non-vacuous): the SAME Append-only Bob, with a WHERE-LESS insert patch, DOES succeed
        // (204 modify of the existing resource) — proving the 403 above is specifically the where-clause
        // read-gate, not a general denial of Bob's Append.
        let state = store_bob_append_only_log(
            "<https://pod.example/alice/log#me> <http://xmlns.com/foaf/0.1/name> \"L\" .",
        )
        .await;
        let got = observe(
            patch_handler(
                State(state),
                Extension(bob()),
                "/alice/log".parse().unwrap(),
                n3_patch_headers(),
                insert_only_patch("https://pod.example/alice/log#me"),
            )
            .await,
        )
        .await;
        assert_eq!(
            got.status, 204,
            "a WHERE-LESS append patch by the same Append holder must still succeed: {got:?}"
        );
    }
}
