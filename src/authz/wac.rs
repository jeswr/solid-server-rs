// AUTHORED-BY Claude Opus 4.8
//! The Web Access Control authorizer (Solid WAC).
//!
//! Resolves the effective `.acl` for a target by walking the container hierarchy (`acl:default`
//! inheritance), reads each candidate ACL **through the [`Store`]** (ACLs are RDF resources), parses
//! it with `oxttl`/`oxjsonld`, and computes the modes granted to the requester. Denies with `401`
//! when the requester is anonymous (so the client authenticates), `403` when authenticated but
//! unauthorized — exactly the prod-solid-server `src/authz/wac.ts` semantics.
//!
//! ## ACL resolution (WAC)
//!  1. The target's OWN ACL (`<target>.acl` for a document, `<container>/.acl` for a container) — if
//!     present, only its `acl:accessTo <target>` rules apply.
//!  2. Otherwise the NEAREST ancestor container that HAS an ACL — its `acl:default` rules apply
//!     (inheritance). The search proceeds child→root and STOPS at the first ACL found (a closer ACL
//!     fully overrides a more distant one — WAC does not union across levels).
//!  3. If no ACL exists anywhere up to and including the storage root, access is DENIED (fail-closed).
//!
//! Reading/writing an `.acl` resource itself requires `acl:Control`; [`super::mode::mode_for_operation`]
//! encodes that, and the protected resource the ACL belongs to is what this resolver gates.
//!
//! ## Fail-closed on store error
//! A `NotFound` reading an ACL is the COMMON case (most resources inherit) → "no own ACL, keep
//! walking". Any OTHER store error (a transient backend failure) PROPAGATES — it must never be
//! silently treated as "no ACL" (that would fail OPEN by skipping a real ACL).

use std::collections::BTreeSet;

use crate::acl_cache::AclCache;
use crate::error::ServerError;
use crate::ldp::content::{classify, parse_to_triples, RdfFormat};
use crate::store::Store;

use super::acl::{modes_for, satisfies, AclScope, Requester};
use super::mode::{is_acl_resource, AccessMode, ACL_SUFFIX};
use super::wac_allow::EffectivePermissions;

/// The outcome of an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permitted: the FULL set of modes the requester holds over the target (threaded into the
    /// `WAC-Allow` advertisement so a permitted read need not re-walk the hierarchy).
    Allow(BTreeSet<AccessMode>),
    /// Denied because the requester is ANONYMOUS → 401 + `WWW-Authenticate` (the client should obtain
    /// a token).
    Unauthenticated,
    /// Denied because the requester IS authenticated but lacks the required mode → 403.
    Forbidden,
}

/// The outcome of a single-pass READ authorization ([`WacAuthorizer::authorize_read`]). Mirrors
/// [`Decision`], but the `Allow` variant carries the full [`EffectivePermissions`] (the requester's
/// AND the public's modes) resolved in the SAME pass — so the read path builds `WAC-Allow` with no
/// further ACL work. The denial variants map to the SAME 401 (+ challenge) / 403 as [`Decision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadDecision {
    /// Permitted: the effective `user` + `public` modes for the target, from one resolution.
    Allow(EffectivePermissions),
    /// Denied, requester anonymous → 401 + `WWW-Authenticate`.
    Unauthenticated,
    /// Denied, requester authenticated but unauthorized → 403.
    Forbidden,
}

/// The EFFECTIVE ACL governing a resource, resolved ONCE (the walk + read + parse) so it can be
/// evaluated against MULTIPLE requesters (e.g. a read's `user` + `public` audiences) without
/// re-resolving. `None` (no governing ACL anywhere) is the fail-closed case: no grants for anyone.
struct ResolvedAcl {
    /// The parsed ACL triples + the base resource the rules match against + the matching scope —
    /// `None` when no ACL governs the resource (fail-closed → empty modes for every requester).
    parsed: Option<(Vec<oxrdf::Triple>, String, AclScope)>,
}

impl ResolvedAcl {
    fn found(triples: Vec<oxrdf::Triple>, base: String, scope: AclScope) -> Self {
        Self {
            parsed: Some((triples, base, scope)),
        }
    }

    fn none() -> Self {
        Self { parsed: None }
    }

    /// The modes the resolved ACL grants `requester` — pure rule-matching over the already-parsed
    /// triples (no I/O). An unresolved ACL (`None`) grants nothing (fail-closed). Identical in result
    /// to the prior inline `modes_for(&triples, base, requester, scope)` call.
    fn modes_for(&self, requester: &Requester<'_>) -> BTreeSet<AccessMode> {
        match &self.parsed {
            Some((triples, base, scope)) => modes_for(triples, base, requester, *scope),
            None => BTreeSet::new(),
        }
    }
}

/// The Web Access Control authorizer over a [`Store`] and the server base URL.
///
/// Optionally fronted by a per-instance [`AclCache`] (read-path optimisation #3): when present, the
/// effective-ACL resolution reuses the PARSED triples of an UNCHANGED ACL across requests (keyed by
/// `(acl-iri, etag)`), skipping the byte-fetch + `oxttl` re-parse — without ever changing the decision
/// (the cache is never authoritative; see [`crate::acl_cache`]). When absent (`None`) the resolver
/// reads + parses every ACL every time — the pre-cache behaviour, also exactly what the `=0` disabled
/// cache yields.
pub struct WacAuthorizer<'a, S: Store> {
    store: &'a S,
    base_url: String,
    /// The shared, per-instance parsed-ACL cache (`None` ⇒ no caching, every ACL read+parsed afresh).
    acl_cache: Option<&'a AclCache>,
}

impl<'a, S: Store> WacAuthorizer<'a, S> {
    /// Build an authorizer with NO ACL cache — every effective-ACL resolution reads + parses each
    /// candidate ACL afresh (the pre-cache path; used by unit tests and any caller without a cache).
    pub fn new(store: &'a S, base_url: impl Into<String>) -> Self {
        Self {
            store,
            base_url: base_url.into(),
            acl_cache: None,
        }
    }

    /// Build an authorizer fronted by the per-instance [`AclCache`]. The cache reuses the PARSED
    /// triples of an unchanged ACL across requests (keyed by `(acl-iri, etag)`), never changing a
    /// decision (see [`crate::acl_cache`]).
    pub fn with_cache(store: &'a S, base_url: impl Into<String>, acl_cache: &'a AclCache) -> Self {
        Self {
            store,
            base_url: base_url.into(),
            acl_cache: Some(acl_cache),
        }
    }

    /// Authorize an operation: the `target` IRI, the `required` mode (from
    /// [`super::mode::mode_for_operation`]), the requester's `web_id` (`None` ⇒ anonymous), and the
    /// request's `origin` (the HTTP `Origin` header; `None` when the request carried none).
    ///
    /// The `origin` is threaded into rule-matching so an `acl:origin`-restricted authorization grants
    /// ONLY when the request's Origin matches one of the rule's `acl:origin` values (an app-scoping
    /// restriction); a rule with no `acl:origin` is unaffected by it.
    ///
    /// Resolves the effective ACL of the PROTECTED resource (for an `.acl` target that is the resource
    /// the ACL governs — Control of THAT resource gates reading/writing its `.acl`), computes the
    /// requester's modes, and returns a [`Decision`].
    pub async fn authorize(
        &self,
        target: &str,
        required: AccessMode,
        web_id: Option<&str>,
        origin: Option<&str>,
    ) -> Result<Decision, ServerError> {
        let protected = self.protected_resource(target);
        let requester = Requester { web_id, origin };
        let granted = self.effective_modes(&protected, &requester).await?;

        if satisfies(&granted, required) {
            return Ok(Decision::Allow(granted));
        }
        Ok(if web_id.is_none() {
            Decision::Unauthenticated
        } else {
            Decision::Forbidden
        })
    }

    /// Single-pass READ authorization (Optimization #2): resolve the target's effective ACL ONCE and
    /// derive BOTH the access decision AND the `WAC-Allow` audiences from that single resolution.
    ///
    /// The GET/HEAD read path previously called [`authorize`](Self::authorize) (resolve the protected
    /// resource → walk + read + parse the `.acl` → compute the requester's modes) and THEN
    /// [`effective_permissions`](Self::effective_permissions) (a SECOND `WacAuthorizer`, a second
    /// `protected_resource`, and — for an authenticated requester — a SECOND full ACL walk/read/parse
    /// to compute the public set). This resolves the effective ACL EXACTLY ONCE
    /// ([`resolve_effective_acl`](Self::resolve_effective_acl) — the only walk/read/parse) and derives
    /// BOTH audiences from that shared, already-parsed resolution via pure rule-matching:
    ///
    /// - the requester's modes (`user`) are the gate input AND the `WAC-Allow` `user` audience;
    /// - the access decision is `satisfies(user, required)` → `Allow` / `Unauthenticated` (anonymous) /
    ///   `Forbidden` (authenticated) — byte-identical to [`authorize`](Self::authorize);
    /// - the `public` audience is `user.clone()` for an anonymous requester (it IS the public — no
    ///   extra work), else a second `modes_for` over the SAME parsed triples against
    ///   `Requester { web_id: None, origin }` (the origin-scoped public set — identical RESULT to
    ///   [`effective_permissions`](Self::effective_permissions), preserving `acl:origin` semantics,
    ///   but WITHOUT a second ACL walk/read/parse). So an AUTHENTICATED read reads + parses the `.acl`
    ///   once, not twice.
    ///
    /// The returned [`ReadDecision::Allow`] carries the full [`EffectivePermissions`] (user + public),
    /// so the read handler needs no further ACL work to build `WAC-Allow`. The denial variants are the
    /// same as [`Decision`] so the handler maps them to the SAME 401 (+ challenge) / 403 as before.
    ///
    /// SECURITY: the decision (`satisfies(user, required)`, the 401-vs-403 split on `web_id`) and the
    /// `public`/`user` sets are computed by the SAME helpers (`modes_for`, `satisfies`) the split path
    /// used, against the SAME `protected_resource` and the SAME parsed ACL triples, so the gate and the
    /// advertisement are unchanged — including fail-closed on a missing/broken ACL
    /// ([`ResolvedAcl::none`] / an empty-triples `Some` both yield empty modes, which `satisfies`
    /// rejects for any required mode) and the origin-scoped public set.
    pub async fn authorize_read(
        &self,
        target: &str,
        required: AccessMode,
        web_id: Option<&str>,
        origin: Option<&str>,
    ) -> Result<ReadDecision, ServerError> {
        let protected = self.protected_resource(target);
        // Resolve the effective ACL ONCE (the only walk/read/parse — the expensive part). Both the
        // `user` and `public` audiences are then evaluated against this SHARED, already-parsed
        // resolution (pure rule-matching, no further I/O) — so an AUTHENTICATED read no longer
        // re-walks/re-reads/re-parses the same `.acl` for its public set (the roborev finding).
        let resolved = self.resolve_effective_acl(&protected).await?;

        // 1) The requester's modes — the gate input AND the `WAC-Allow` `user` audience.
        let user = resolved.modes_for(&Requester { web_id, origin });

        // 2) The access decision — identical to `authorize`: a permitted read requires the resolved
        //    set to `satisfy` the required mode; a denial is 401 (anonymous) / 403 (authenticated).
        if !satisfies(&user, required) {
            return Ok(if web_id.is_none() {
                ReadDecision::Unauthenticated
            } else {
                ReadDecision::Forbidden
            });
        }

        // 3) The `public` audience, from the SAME resolution: `user.clone()` for an anonymous
        //    requester (it IS the public — no extra evaluation); else a second rule-match (NOT a
        //    second walk/read/parse) against the origin-scoped public requester — identical RESULT to
        //    `effective_permissions`, preserving `acl:origin` semantics, at the cost of only the pure
        //    `modes_for` over the already-parsed triples.
        let public = if web_id.is_none() {
            user.clone()
        } else {
            resolved.modes_for(&Requester {
                web_id: None,
                origin,
            })
        };
        Ok(ReadDecision::Allow(EffectivePermissions { user, public }))
    }

    /// The effective access modes a `WAC-Allow` header should advertise on a permitted read of
    /// `target`: `user` (what the requester may do) and `public` (what an unauthenticated agent may
    /// do), both from the SAME effective ACL.
    ///
    /// `user_modes`, when supplied, is the requester's already-resolved mode set (e.g. the value a
    /// prior [`authorize`](Self::authorize) returned for the SAME target+web_id) — passing it skips
    /// recomputing `user`. For an anonymous requester `public == user` and no extra work is done.
    pub async fn effective_permissions(
        &self,
        target: &str,
        web_id: Option<&str>,
        origin: Option<&str>,
        user_modes: Option<BTreeSet<AccessMode>>,
    ) -> Result<EffectivePermissions, ServerError> {
        let protected = self.protected_resource(target);

        let user = match user_modes {
            Some(m) => m,
            None => {
                self.effective_modes(&protected, &Requester { web_id, origin })
                    .await?
            }
        };
        // The public set: for an anonymous requester it EQUALS user (an anonymous requester IS the
        // public); for an authenticated requester it is resolved independently against the public —
        // an ANONYMOUS IDENTITY (no WebID) but carrying THIS request's `origin`. Threading the Origin
        // matters: an ORIGIN-SCOPED public grant (`acl:agentClass foaf:Agent` + `acl:origin <o>`)
        // grants the public ONLY from a matching Origin. Resolving the public set with
        // `Requester::anonymous()` (origin `None`) would always FAIL such an `acl:origin`-restricted
        // public rule and so UNDER-REPORT `public=` even when the current request's Origin satisfies
        // it. Using `Requester { web_id: None, origin }` reports exactly the public modes available
        // from the request's own Origin (and still omits them when the Origin does not match / is
        // absent — fail-closed in `matches_origin`).
        let public = if web_id.is_none() {
            user.clone()
        } else {
            self.effective_modes(
                &protected,
                &Requester {
                    web_id: None,
                    origin,
                },
            )
            .await?
        };
        Ok(EffectivePermissions { user, public })
    }

    /// The modes granted to `requester` over `resource` by the effective ACL (its OWN ACL via
    /// `acl:accessTo`, else the nearest ancestor's `acl:default`). Empty set when no ACL governs it
    /// (fail-closed).
    ///
    /// Implemented as resolve-once ([`resolve_effective_acl`](Self::resolve_effective_acl)) + evaluate
    /// the requester ([`ResolvedAcl::modes_for`]) — so a caller that needs SEVERAL audiences over the
    /// same resource (e.g. the read path's `user` + `public`) can resolve once and evaluate many.
    async fn effective_modes(
        &self,
        resource: &str,
        requester: &Requester<'_>,
    ) -> Result<BTreeSet<AccessMode>, ServerError> {
        Ok(self
            .resolve_effective_acl(resource)
            .await?
            .modes_for(requester))
    }

    /// Resolve the EFFECTIVE ACL governing `resource` ONCE — the expensive part (the child→root walk,
    /// the per-`.acl` `store.read`, and the `oxttl`/`oxjsonld` parse). Returns the parsed triples + the
    /// base resource the rules match against + the [`AclScope`] (`AccessTo` for the resource's own ACL,
    /// `Default` for an inherited ancestor ACL), or [`ResolvedAcl::none`] when no ACL governs it
    /// anywhere (fail-closed — no grants for ANY requester).
    ///
    /// The returned [`ResolvedAcl`] is then evaluated PER requester via [`ResolvedAcl::modes_for`]
    /// (pure rule-matching over the already-parsed triples — no further I/O), so resolving once and
    /// evaluating both the authenticated requester AND the public requester costs ONE walk/read/parse,
    /// not two. This is the substance of Optimization #2 for the authenticated read path.
    async fn resolve_effective_acl(&self, resource: &str) -> Result<ResolvedAcl, ServerError> {
        // 1. The resource's OWN ACL (accessTo scope).
        if let Some(triples) = self.read_acl(&self.acl_for(resource)).await? {
            return Ok(ResolvedAcl::found(
                triples,
                resource.to_string(),
                AclScope::AccessTo,
            ));
        }

        // 2. Walk ancestors child→root; the first one with an ACL governs via `acl:default`.
        for ancestor in self.ancestors_nearest_first(resource) {
            if let Some(triples) = self.read_acl(&self.acl_for(&ancestor)).await? {
                return Ok(ResolvedAcl::found(triples, ancestor, AclScope::Default));
            }
        }

        // 3. No ACL anywhere → no grants (fail-closed) for any requester.
        Ok(ResolvedAcl::none())
    }

    /// Read and parse an ACL resource through the [`Store`] into triples. `Ok(None)` if the ACL does
    /// NOT exist (the common case). Any other store error propagates (a transient failure must not be
    /// silently treated as "no ACL" → fail-open). A malformed ACL body yields an empty triple set via
    /// the parser error being mapped to "no usable rules" — but here we propagate a parse error as a
    /// storage error is avoided: an unparseable ACL is treated as PRESENT-but-granting-nothing
    /// (fail-closed), NOT as absent (which would wrongly inherit the parent's grants).
    ///
    /// ## ETag-keyed parsed-ACL cache (read-path optimisation #3)
    /// When an [`AclCache`] is attached, this:
    ///  1. cheaply probes the ACL's CURRENT etag via [`Store::meta`] (an index lookup — NO blob
    ///     byte-fetch, NO parse). An ABSENT ACL (`None`) is the `Ok(None)` "no own ACL, keep walking"
    ///     case (unchanged), and the cache holds nothing for it (it can never fabricate a removed ACL);
    ///  2. on a cache HIT for `(acl, etag)` returns the cached parse — the byte-fetch + `oxttl` parse
    ///     are SKIPPED (the win);
    ///  3. on a MISS reads the bytes + parses, then REFRESHES the entry under the etag of the bytes it
    ///     ACTUALLY read (so the cached parse always corresponds to the cached etag — no TOCTOU stale).
    ///
    /// SECURITY: the cache only avoids the re-PARSE of an UNCHANGED ACL — the etag-equality gate
    /// guarantees a cached parse is reused ONLY when the bytes are unchanged, so a rotated/removed ACL
    /// can never be served stale and the resulting triples (hence the decision + `WAC-Allow`) are
    /// byte-identical to the cold path. When NO cache is attached, the original single `store.read` +
    /// parse path runs (no extra `meta` round-trip) — byte-identical to the pre-cache code AND to the
    /// `=0` disabled-cache configuration.
    async fn read_acl(&self, acl: &str) -> Result<Option<Vec<oxrdf::Triple>>, ServerError> {
        // No cache attached: the original path — ONE `store.read` (get_meta + blob.get) + parse. No
        // extra `meta` probe, so cost is identical to the pre-cache code.
        let Some(cache) = self.acl_cache else {
            return self.read_and_parse_acl(acl).await;
        };

        // Cache attached: probe the ACL's current etag CHEAPLY (index get_meta — no bytes, no parse).
        let meta = match self.store.meta(acl).await? {
            Some(m) => m,
            // Absent ACL → `Ok(None)` (the common "no own ACL here, keep walking" case). The cache
            // cannot resurrect a removed ACL: there is no `get` for an absent IRI.
            None => return Ok(None),
        };
        let now = Self::now_secs();
        // HIT on `(acl, current-etag)`: reuse the cached parse — skip the byte-fetch + `oxttl` parse.
        if let Some(triples) = cache.get(acl, &meta.etag, now) {
            return Ok(Some(triples));
        }
        // MISS (no entry / rotated etag / TTL-stale): read the bytes + parse, then refresh the cache
        // under the etag of the BYTES ACTUALLY READ (the authoritative etag for this parse). A
        // concurrent rotation between the `meta` probe and this `read` just means we parse + cache the
        // newer bytes — never a stale parse.
        let resource = match self.store.read(acl).await {
            Ok(r) => r,
            // The ACL vanished between the `meta` probe and the read (a concurrent DELETE) → treat as
            // absent: `Ok(None)`, exactly as a cold walk that found it gone would.
            Err(ServerError::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        let triples = Self::parse_acl_body(&resource, acl);
        cache.insert(acl, &resource.meta.etag, triples.clone(), now);
        Ok(Some(triples))
    }

    /// The uncached read+parse of an ACL: ONE `store.read` (get_meta + blob.get) + the `oxttl` parse —
    /// the exact pre-cache path, used when no cache is attached.
    async fn read_and_parse_acl(
        &self,
        acl: &str,
    ) -> Result<Option<Vec<oxrdf::Triple>>, ServerError> {
        let resource = match self.store.read(acl).await {
            Ok(r) => r,
            Err(ServerError::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(Some(Self::parse_acl_body(&resource, acl)))
    }

    /// Parse an ACL resource's bytes into triples, mapping a PARSE error to an EMPTY triple set
    /// (PRESENT-but-granting-nothing, fail-closed) — NOT to absent. A broken own-ACL must DENY, never
    /// fall through to a parent's `acl:default`. The single home for the ACL parse + its fail-closed
    /// error mapping, shared by the cached and uncached paths so they are byte-identical.
    fn parse_acl_body(resource: &crate::store::Resource, acl: &str) -> Vec<oxrdf::Triple> {
        let format = classify(Some(&resource.meta.content_type)).unwrap_or(RdfFormat::Turtle);
        // A PRESENT but malformed ACL grants nothing (fail-closed) — it is NOT absent. A parse error
        // maps to an EMPTY triple set (NOT propagated, NOT treated as absent): the caller returns it as
        // `Some(Vec::new())`, which stops the inheritance walk so a broken own-ACL DENIES rather than
        // falling through to a parent's `acl:default`.
        parse_to_triples(format, &resource.body, acl).unwrap_or_default()
    }

    /// Current epoch seconds for the ACL-cache freshness gate (the validation TTL). A clock error
    /// (pre-1970, impossible in practice) yields 0 — the cache then treats every entry as old (a miss),
    /// which is the SAFE direction (re-read + re-parse, never a stale hit).
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// The protected resource an `.acl` target governs: for an `.acl` IRI, strip the trailing `.acl`
    /// (Control of the governed resource gates its ACL); otherwise the target itself.
    fn protected_resource(&self, target: &str) -> String {
        if is_acl_resource(target) {
            target[..target.len() - ACL_SUFFIX.len()].to_string()
        } else {
            target.to_string()
        }
    }

    /// The ACL identifier for a resource: `<document>.acl` and `<container>/.acl`. For a container
    /// `https://pod/c/` the ACL is `https://pod/c/.acl`.
    fn acl_for(&self, resource: &str) -> String {
        format!("{resource}{ACL_SUFFIX}")
    }

    /// The ancestor containers of `resource`, NEAREST first, up to and including the storage root.
    /// For a document `https://pod/a/b/doc`: `[https://pod/a/b/, https://pod/a/, https://pod/]`. For a
    /// container `https://pod/a/b/`: `[https://pod/a/, https://pod/]` (its own ACL is checked
    /// separately, so its PARENT is the first ancestor). The root has no ancestors.
    fn ancestors_nearest_first(&self, resource: &str) -> Vec<String> {
        let root = format!("{}/", self.base_url.trim_end_matches('/'));
        let mut ancestors: Vec<String> = Vec::new();
        if resource == root {
            return ancestors;
        }
        // The immediate parent of `resource`. For a container, drop its own trailing slash first.
        let mut current = resource.to_string();
        if current.ends_with('/') {
            current.pop();
        }
        while current.len() > root.len() {
            let Some(slash) = current.rfind('/') else {
                break;
            };
            let parent = current[..=slash].to_string();
            ancestors.push(parent.clone());
            // Step to the parent without its trailing slash for the next iteration.
            current = parent[..parent.len() - 1].to_string();
        }
        // Ensure the root is included (the loop stops once `current` reaches the root length).
        if ancestors.last().map(String::as_str) != Some(root.as_str()) {
            ancestors.push(root);
        }
        ancestors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient};
    use axum::body::Bytes;

    const BASE: &str = "https://pod.example";
    const ALICE: &str = "https://pod.example/alice/profile/card#me";
    const BOB: &str = "https://pod.example/bob/profile/card#me";

    type TestStore = CompositeStore<InMemorySparqClient, InMemoryBlobStore>;

    fn store() -> TestStore {
        CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new())
    }

    async fn put_acl(store: &TestStore, acl_iri: &str, body: &str) {
        store
            .write(acl_iri, Bytes::from(body.to_string()), "text/turtle")
            .await
            .expect("write acl");
    }

    fn owner_default_acl(target: &str, owner: &str) -> String {
        format!(
            r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
            <#owner> a acl:Authorization;
                     acl:agent <{owner}>;
                     acl:accessTo <{target}>;
                     acl:default <{target}>;
                     acl:mode acl:Read, acl:Write, acl:Control."#
        )
    }

    // --- own-vs-inherited resolution ----------------------------------------------------------

    #[tokio::test]
    async fn own_acl_wins_over_inherited() {
        let s = store();
        let container = "https://pod.example/alice/";
        let resource = "https://pod.example/alice/data";
        // The container grants Bob default Read (inheritable).
        put_acl(
            &s,
            "https://pod.example/alice/.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#d> a acl:Authorization; acl:agent <{BOB}>; acl:default <{container}>; acl:mode acl:Read."#
            ),
        )
        .await;
        // The resource has its OWN acl granting Bob nothing (only Alice).
        put_acl(
            &s,
            "https://pod.example/alice/data.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        // Bob is DENIED on the resource (own acl wins; the inherited default does NOT apply).
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
        // Alice IS allowed by the own acl.
        assert!(matches!(
            wac.authorize(resource, AccessMode::Read, Some(ALICE), None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
    }

    #[tokio::test]
    async fn inherits_default_from_nearest_ancestor() {
        let s = store();
        let resource = "https://pod.example/alice/test/data";
        // The pod root grants Alice default control; /alice/test/ has NO own acl.
        put_acl(
            &s,
            "https://pod.example/alice/.acl",
            &owner_default_acl("https://pod.example/alice/", ALICE),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        // Alice inherits read/write/control via the pod-root default.
        let d = wac
            .authorize(resource, AccessMode::Write, Some(ALICE), None)
            .await
            .unwrap();
        assert!(matches!(d, Decision::Allow(_)));
        // Bob inherits nothing → 403.
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
    }

    #[tokio::test]
    async fn nearest_acl_fully_overrides_more_distant() {
        let s = store();
        let resource = "https://pod.example/alice/test/data";
        // Root grants Bob default read.
        put_acl(
            &s,
            "https://pod.example/alice/.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#d> a acl:Authorization; acl:agent <{BOB}>; acl:default <https://pod.example/alice/>; acl:mode acl:Read."#
            ),
        )
        .await;
        // The nearer container /alice/test/ has its OWN acl granting only Alice (default). This fully
        // overrides root — Bob gets nothing.
        put_acl(
            &s,
            "https://pod.example/alice/test/.acl",
            &owner_default_acl("https://pod.example/alice/test/", ALICE),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
        assert!(matches!(
            wac.authorize(resource, AccessMode::Read, Some(ALICE), None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
    }

    // --- public vs authenticated vs specific-agent + 401-vs-403 -------------------------------

    #[tokio::test]
    async fn public_read_allows_anonymous() {
        let s = store();
        let resource = "https://pod.example/alice/test/pub";
        put_acl(
            &s,
            "https://pod.example/alice/test/pub.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                @prefix foaf: <http://xmlns.com/foaf/0.1/>.
                <#p> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        assert!(matches!(
            wac.authorize(resource, AccessMode::Read, None, None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
    }

    #[tokio::test]
    async fn anonymous_denied_is_401_authenticated_denied_is_403() {
        let s = store();
        let resource = "https://pod.example/alice/test/secret";
        // Only Alice may read.
        put_acl(
            &s,
            "https://pod.example/alice/test/secret.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        // Anonymous → 401 (Unauthenticated).
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, None, None)
                .await
                .unwrap(),
            Decision::Unauthenticated
        );
        // Bob (authenticated, not granted) → 403 (Forbidden).
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
    }

    // --- Control governs .acl -----------------------------------------------------------------

    #[tokio::test]
    async fn control_governs_reading_the_acl_document() {
        let s = store();
        let resource = "https://pod.example/alice/test/data";
        let acl = "https://pod.example/alice/test/data.acl";
        // Bob has Read but NOT Control on the resource; Alice has Control.
        put_acl(
            &s,
            acl,
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#bob> a acl:Authorization; acl:agent <{BOB}>; acl:accessTo <{resource}>; acl:mode acl:Read.
                <#alice> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read, acl:Write, acl:Control."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        // Reading the .acl requires Control: Bob (Read only) is FORBIDDEN; Alice (Control) is ALLOWED.
        assert_eq!(
            wac.authorize(acl, AccessMode::Control, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
        assert!(matches!(
            wac.authorize(acl, AccessMode::Control, Some(ALICE), None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
    }

    #[tokio::test]
    async fn write_holder_is_denied_control() {
        // The foundation of the container-DELETE rule (DELETE of a container needs Control, not mere
        // Write): a requester granted Read+Write but NOT Control must be DENIED a Control decision —
        // Control is never implied by Write.
        let s = store();
        let resource = "https://pod.example/alice/test/c/";
        put_acl(
            &s,
            "https://pod.example/alice/test/c/.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#bob> a acl:Authorization; acl:agent <{BOB}>; acl:accessTo <{resource}>; acl:mode acl:Read, acl:Write.
                <#alice> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read, acl:Write, acl:Control."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        // Bob has Write but not Control → a Control decision is FORBIDDEN.
        assert_eq!(
            wac.authorize(resource, AccessMode::Control, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
        // Bob's Write decision is still allowed (Write does not imply, but is granted).
        assert!(matches!(
            wac.authorize(resource, AccessMode::Write, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
        // Alice (Control) is allowed Control.
        assert!(matches!(
            wac.authorize(resource, AccessMode::Control, Some(ALICE), None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
    }

    // --- fail-closed on missing / malformed ----------------------------------------------------

    #[tokio::test]
    async fn no_acl_anywhere_denies_fail_closed() {
        let s = store();
        let resource = "https://pod.example/alice/test/data";
        let wac = WacAuthorizer::new(&s, BASE);
        // No ACL exists at all → denied. Anonymous → 401, authenticated → 403.
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, None, None)
                .await
                .unwrap(),
            Decision::Unauthenticated
        );
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
    }

    #[tokio::test]
    async fn malformed_own_acl_denies_does_not_inherit() {
        let s = store();
        let resource = "https://pod.example/alice/test/data";
        // The pod root would grant Alice control by inheritance...
        put_acl(
            &s,
            "https://pod.example/alice/.acl",
            &owner_default_acl("https://pod.example/alice/", ALICE),
        )
        .await;
        // ...but the resource has a MALFORMED own acl. A present-but-broken own acl must DENY, NOT fall
        // through to the parent's default (fail-closed).
        put_acl(
            &s,
            "https://pod.example/alice/test/data.acl",
            "this is not valid turtle @@@ <<< broken",
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(ALICE), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
    }

    // --- the no-bypass test -------------------------------------------------------------------

    #[tokio::test]
    async fn no_bypass_wrong_webid_or_anonymous_cannot_read_or_write() {
        let s = store();
        let resource = "https://pod.example/alice/test/private";
        // Only Alice may read+write.
        put_acl(
            &s,
            "https://pod.example/alice/test/private.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read, acl:Write, acl:Control."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        // Wrong WebID (Bob) cannot read or write.
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
        assert_eq!(
            wac.authorize(resource, AccessMode::Write, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
        // Anonymous cannot read or write.
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, None, None)
                .await
                .unwrap(),
            Decision::Unauthenticated
        );
        assert_eq!(
            wac.authorize(resource, AccessMode::Write, None, None)
                .await
                .unwrap(),
            Decision::Unauthenticated
        );
        // A near-miss WebID (same prefix, different agent) is NOT Alice — no string-prefix bypass.
        let near = "https://pod.example/alice/profile/card#evil";
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(near), None)
                .await
                .unwrap(),
            Decision::Forbidden
        );
    }

    // --- WAC-Allow accuracy --------------------------------------------------------------------

    #[tokio::test]
    async fn wac_allow_reflects_owner_full_and_public_subset() {
        let s = store();
        let resource = "https://pod.example/alice/test/doc";
        // Alice (owner) full control; public read only — the public-access-direct shape.
        put_acl(
            &s,
            "https://pod.example/alice/test/doc.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                @prefix foaf: <http://xmlns.com/foaf/0.1/>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read, acl:Write, acl:Control.
                <#p> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        // Alice's WAC-Allow: user = read/write/control, public = read.
        let perms = wac
            .effective_permissions(resource, Some(ALICE), None, None)
            .await
            .unwrap();
        assert_eq!(
            perms.user,
            [AccessMode::Read, AccessMode::Write, AccessMode::Control]
                .into_iter()
                .collect()
        );
        assert_eq!(perms.public, [AccessMode::Read].into_iter().collect());

        // An anonymous reader's WAC-Allow: user == public == read.
        let pub_perms = wac
            .effective_permissions(resource, None, None, None)
            .await
            .unwrap();
        assert_eq!(pub_perms.user, [AccessMode::Read].into_iter().collect());
        assert_eq!(pub_perms.public, [AccessMode::Read].into_iter().collect());
    }

    #[tokio::test]
    async fn wac_allow_user_only_no_public() {
        let s = store();
        let container = "https://pod.example/alice/test/c/";
        let resource = "https://pod.example/alice/test/c/doc";
        // Bob granted inheritable read via the container default; no public access.
        put_acl(
            &s,
            "https://pod.example/alice/test/c/.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#d> a acl:Authorization; acl:agent <{BOB}>; acl:default <{container}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);
        let perms = wac
            .effective_permissions(resource, Some(BOB), None, None)
            .await
            .unwrap();
        assert_eq!(perms.user, [AccessMode::Read].into_iter().collect());
        assert!(
            perms.public.is_empty(),
            "public must be empty: {:?}",
            perms.public
        );
    }

    #[tokio::test]
    async fn wac_allow_public_reflects_origin_scoped_grant_for_authenticated_request() {
        // Finding 3: WAC-Allow `public=` for an AUTHENTICATED request must carry the CURRENT request's
        // Origin when resolving the public set, so an ORIGIN-SCOPED public grant
        // (`acl:agentClass foaf:Agent` + `acl:origin <o>`) is reported when the request Origin matches
        // — and omitted when it does not / when no Origin is sent (fail-closed). Resolving the public
        // set with `Requester::anonymous()` (origin None) would always omit it (the under-report bug).
        const APP: &str = "https://app.example";
        const OTHER: &str = "https://evil.example";
        let s = store();
        let resource = "https://pod.example/alice/test/scoped";
        // Alice (owner) full control; the PUBLIC gets Read but ONLY from https://app.example.
        put_acl(
            &s,
            "https://pod.example/alice/test/scoped.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                @prefix foaf: <http://xmlns.com/foaf/0.1/>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read, acl:Write, acl:Control.
                <#p> a acl:Authorization; acl:agentClass foaf:Agent; acl:origin <{APP}>; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let wac = WacAuthorizer::new(&s, BASE);

        // Authenticated (Alice) request FROM the trusted origin: public= must report the origin-scoped
        // public Read.
        let matched = wac
            .effective_permissions(resource, Some(ALICE), Some(APP), None)
            .await
            .unwrap();
        assert_eq!(
            matched.public,
            [AccessMode::Read].into_iter().collect(),
            "an origin-scoped public grant must be reported in public= when the request Origin matches"
        );
        // Alice herself still has her full set regardless of origin (her grant has no acl:origin).
        assert_eq!(
            matched.user,
            [AccessMode::Read, AccessMode::Write, AccessMode::Control]
                .into_iter()
                .collect()
        );

        // Authenticated request from a DIFFERENT origin: the origin-scoped public grant must be OMITTED.
        let other_origin = wac
            .effective_permissions(resource, Some(ALICE), Some(OTHER), None)
            .await
            .unwrap();
        assert!(
            other_origin.public.is_empty(),
            "an origin-scoped public grant must be omitted from public= for a non-matching Origin: {:?}",
            other_origin.public
        );

        // Authenticated request with NO Origin: an origin-restricted public rule never matches
        // (fail-closed) ⇒ public= empty.
        let no_origin = wac
            .effective_permissions(resource, Some(ALICE), None, None)
            .await
            .unwrap();
        assert!(
            no_origin.public.is_empty(),
            "an origin-scoped public grant must be omitted from public= when no Origin is sent: {:?}",
            no_origin.public
        );
    }

    // --- ancestor walk shape -------------------------------------------------------------------

    #[test]
    fn ancestors_for_a_document() {
        let s = store();
        let wac = WacAuthorizer::new(&s, BASE);
        assert_eq!(
            wac.ancestors_nearest_first("https://pod.example/a/b/doc"),
            vec![
                "https://pod.example/a/b/".to_string(),
                "https://pod.example/a/".to_string(),
                "https://pod.example/".to_string(),
            ]
        );
    }

    #[test]
    fn ancestors_for_a_container_start_at_parent() {
        let s = store();
        let wac = WacAuthorizer::new(&s, BASE);
        assert_eq!(
            wac.ancestors_nearest_first("https://pod.example/a/b/"),
            vec![
                "https://pod.example/a/".to_string(),
                "https://pod.example/".to_string(),
            ]
        );
    }

    #[test]
    fn root_has_no_ancestors() {
        let s = store();
        let wac = WacAuthorizer::new(&s, BASE);
        assert!(wac
            .ancestors_nearest_first("https://pod.example/")
            .is_empty());
    }

    #[test]
    fn protected_resource_strips_dot_acl() {
        let s = store();
        let wac = WacAuthorizer::new(&s, BASE);
        assert_eq!(
            wac.protected_resource("https://pod.example/a/b.acl"),
            "https://pod.example/a/b"
        );
        assert_eq!(
            wac.protected_resource("https://pod.example/a/.acl"),
            "https://pod.example/a/"
        );
        assert_eq!(
            wac.protected_resource("https://pod.example/a/b"),
            "https://pod.example/a/b"
        );
    }

    // --- Opt #2: authorize_read is byte-equivalent to authorize + effective_permissions -----------

    /// Cross-check `authorize_read` against the OLD two-call path (`authorize` then
    /// `effective_permissions(Some(granted))`) for the SAME (target, required, web_id, origin): the
    /// access decision AND the resulting `EffectivePermissions` must be IDENTICAL. This is the
    /// security-critical invariant of the single-pass refactor — the gate and the `WAC-Allow`
    /// advertisement do not change.
    async fn assert_read_matches_old_path(
        wac: &WacAuthorizer<'_, TestStore>,
        target: &str,
        required: AccessMode,
        web_id: Option<&str>,
        origin: Option<&str>,
    ) {
        // OLD path: authorize → (on Allow) effective_permissions reusing the granted user set.
        let old_decision = wac
            .authorize(target, required, web_id, origin)
            .await
            .unwrap();
        let old = match old_decision {
            Decision::Allow(granted) => {
                let perms = wac
                    .effective_permissions(target, web_id, origin, Some(granted))
                    .await
                    .unwrap();
                ReadDecision::Allow(perms)
            }
            Decision::Unauthenticated => ReadDecision::Unauthenticated,
            Decision::Forbidden => ReadDecision::Forbidden,
        };
        // NEW single-pass path.
        let new = wac
            .authorize_read(target, required, web_id, origin)
            .await
            .unwrap();
        assert_eq!(
            new, old,
            "authorize_read must match the old authorize+effective_permissions path \
             for target={target} web_id={web_id:?} origin={origin:?}"
        );
    }

    #[tokio::test]
    async fn authorize_read_equivalence_across_cases() {
        const APP: &str = "https://app.example";
        const OTHER: &str = "https://evil.example";
        let s = store();
        // Owner full control; public Read; AND an origin-scoped public Append from APP only.
        let resource = "https://pod.example/alice/test/doc";
        put_acl(
            &s,
            "https://pod.example/alice/test/doc.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                @prefix foaf: <http://xmlns.com/foaf/0.1/>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read, acl:Write, acl:Control.
                <#p> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo <{resource}>; acl:mode acl:Read.
                <#s> a acl:Authorization; acl:agentClass foaf:Agent; acl:origin <{APP}>; acl:accessTo <{resource}>; acl:mode acl:Append."#
            ),
        )
        .await;
        // A fully-private sibling (only Alice; no public) for the 401/403 paths.
        let secret = "https://pod.example/alice/test/secret";
        put_acl(
            &s,
            "https://pod.example/alice/test/secret.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{secret}>; acl:mode acl:Read, acl:Write, acl:Control."#
            ),
        )
        .await;
        // A resource with NO ACL anywhere (fail-closed).
        let orphan = "https://pod.example/bob/orphan";

        let wac = WacAuthorizer::new(&s, BASE);
        // Public-read resource: anonymous allow (public==user); authed allow with public resolved
        // separately; authed allow from a matching/ non-matching/ no origin (origin-scoped public).
        assert_read_matches_old_path(&wac, resource, AccessMode::Read, None, None).await;
        assert_read_matches_old_path(&wac, resource, AccessMode::Read, Some(ALICE), None).await;
        assert_read_matches_old_path(&wac, resource, AccessMode::Read, Some(ALICE), Some(APP))
            .await;
        assert_read_matches_old_path(&wac, resource, AccessMode::Read, Some(ALICE), Some(OTHER))
            .await;
        assert_read_matches_old_path(&wac, resource, AccessMode::Read, Some(BOB), Some(APP)).await;
        // Private secret: anonymous → Unauthenticated; wrong authed agent → Forbidden.
        assert_read_matches_old_path(&wac, secret, AccessMode::Read, None, None).await;
        assert_read_matches_old_path(&wac, secret, AccessMode::Read, Some(BOB), None).await;
        // No-ACL orphan: fail-closed (anon 401, authed 403).
        assert_read_matches_old_path(&wac, orphan, AccessMode::Read, None, None).await;
        assert_read_matches_old_path(&wac, orphan, AccessMode::Read, Some(BOB), None).await;
        // Reading the `.acl` itself requires Control (the read path passes Control for an `.acl`):
        // Alice (Control) allowed, Bob (none) forbidden, anon unauthenticated — all must match.
        let acl = "https://pod.example/alice/test/doc.acl";
        assert_read_matches_old_path(&wac, acl, AccessMode::Control, Some(ALICE), None).await;
        assert_read_matches_old_path(&wac, acl, AccessMode::Control, Some(BOB), None).await;
        assert_read_matches_old_path(&wac, acl, AccessMode::Control, None, None).await;
    }

    // --- Opt #3: the ETag-keyed parsed-ACL cache is decision-equivalent to the cold resolve ---------

    use crate::acl_cache::AclCache;

    /// A cached `authorize` must return the IDENTICAL [`Decision`] a NON-cached `authorize` does — on
    /// the COLD pass (cache miss → populates) AND on the WARM pass (cache hit → reuses the parse). This
    /// is the security-critical invariant: the cache only avoids the re-parse; it never changes the
    /// decision. Asserts the warm pass equals the cold/uncached decision for the SAME inputs.
    async fn assert_cached_authorize_matches_uncached(
        store: &TestStore,
        cache: &AclCache,
        target: &str,
        required: AccessMode,
        web_id: Option<&str>,
        origin: Option<&str>,
    ) {
        let uncached = WacAuthorizer::new(store, BASE)
            .authorize(target, required, web_id, origin)
            .await
            .unwrap();
        let cached = WacAuthorizer::with_cache(store, BASE, cache);
        // COLD pass (cache miss → populate) must match the uncached decision.
        let cold = cached
            .authorize(target, required, web_id, origin)
            .await
            .unwrap();
        assert_eq!(
            cold, uncached,
            "cold cached authorize must equal uncached for target={target} web_id={web_id:?} origin={origin:?}"
        );
        // WARM pass (cache hit → reuse the parse) must ALSO match — a hit cannot change the decision.
        let warm = cached
            .authorize(target, required, web_id, origin)
            .await
            .unwrap();
        assert_eq!(
            warm, uncached,
            "warm (cache-hit) authorize must equal uncached for target={target} web_id={web_id:?} origin={origin:?}"
        );
    }

    /// Same equivalence for `authorize_read` (the GET/HEAD WAC-Allow path): the cached COLD + WARM
    /// [`ReadDecision`] (incl. the full `EffectivePermissions` on Allow) must equal the uncached one.
    async fn assert_cached_read_matches_uncached(
        store: &TestStore,
        cache: &AclCache,
        target: &str,
        required: AccessMode,
        web_id: Option<&str>,
        origin: Option<&str>,
    ) {
        let uncached = WacAuthorizer::new(store, BASE)
            .authorize_read(target, required, web_id, origin)
            .await
            .unwrap();
        let cached = WacAuthorizer::with_cache(store, BASE, cache);
        let cold = cached
            .authorize_read(target, required, web_id, origin)
            .await
            .unwrap();
        assert_eq!(
            cold, uncached,
            "cold cached authorize_read must equal uncached for {target}"
        );
        let warm = cached
            .authorize_read(target, required, web_id, origin)
            .await
            .unwrap();
        assert_eq!(warm, uncached, "warm cached authorize_read must equal uncached (hit cannot change WAC-Allow) for {target}");
    }

    /// The cache is decision-equivalent across EVERY ACL shape — public-read / private / no-ACL /
    /// `.acl`-Control / origin match/non-match/absent / broken-ACL-fail-closed / inherited-default —
    /// on BOTH a cold (populating) and a warm (hit) pass. Proves a hit returns the identical decision +
    /// WAC-Allow as a cold resolve.
    #[tokio::test]
    async fn cached_resolve_is_decision_equivalent_across_shapes() {
        const APP: &str = "https://app.example";
        const OTHER: &str = "https://evil.example";
        let s = store();
        // public-read + owner-control + an origin-scoped public Append.
        let public_doc = "https://pod.example/alice/test/doc";
        put_acl(
            &s,
            "https://pod.example/alice/test/doc.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                @prefix foaf: <http://xmlns.com/foaf/0.1/>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{public_doc}>; acl:mode acl:Read, acl:Write, acl:Control.
                <#p> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo <{public_doc}>; acl:mode acl:Read.
                <#s> a acl:Authorization; acl:agentClass foaf:Agent; acl:origin <{APP}>; acl:accessTo <{public_doc}>; acl:mode acl:Append."#
            ),
        )
        .await;
        // private (only Alice).
        let secret = "https://pod.example/alice/test/secret";
        put_acl(
            &s,
            "https://pod.example/alice/test/secret.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{secret}>; acl:mode acl:Read, acl:Write, acl:Control."#
            ),
        )
        .await;
        // inherited-default: /alice/.acl grants Alice control; /alice/inh/data has no own ACL.
        put_acl(
            &s,
            "https://pod.example/alice/.acl",
            &owner_default_acl("https://pod.example/alice/", ALICE),
        )
        .await;
        let inherited = "https://pod.example/alice/inh/data";
        // broken own-ACL (fail-closed): present-but-malformed.
        let broken = "https://pod.example/alice/broken";
        put_acl(
            &s,
            "https://pod.example/alice/broken.acl",
            "@@@ not valid turtle <<< broken",
        )
        .await;
        // no-ACL orphan anywhere.
        let orphan = "https://pod.example/zzz/orphan";

        let cache = AclCache::new(64);
        // Run each (target, mode, web_id, origin) tuple through BOTH authorize + authorize_read,
        // cold-then-warm, and assert decision-equivalence with the uncached resolve.
        let cases: &[(&str, AccessMode, Option<&str>, Option<&str>)] = &[
            (public_doc, AccessMode::Read, None, None),
            (public_doc, AccessMode::Read, Some(ALICE), None),
            (public_doc, AccessMode::Read, Some(ALICE), Some(APP)),
            (public_doc, AccessMode::Read, Some(ALICE), Some(OTHER)),
            (public_doc, AccessMode::Read, Some(BOB), Some(APP)),
            (secret, AccessMode::Read, None, None),
            (secret, AccessMode::Read, Some(BOB), None),
            (secret, AccessMode::Read, Some(ALICE), None),
            (inherited, AccessMode::Write, Some(ALICE), None),
            (inherited, AccessMode::Read, Some(BOB), None),
            (broken, AccessMode::Read, Some(ALICE), None),
            (broken, AccessMode::Read, None, None),
            (orphan, AccessMode::Read, None, None),
            (orphan, AccessMode::Read, Some(BOB), None),
            // The `.acl` document itself (Control-gated).
            (
                "https://pod.example/alice/test/doc.acl",
                AccessMode::Control,
                Some(ALICE),
                None,
            ),
            (
                "https://pod.example/alice/test/doc.acl",
                AccessMode::Control,
                Some(BOB),
                None,
            ),
            (
                "https://pod.example/alice/test/doc.acl",
                AccessMode::Control,
                None,
                None,
            ),
        ];
        for (target, mode, web_id, origin) in cases {
            assert_cached_authorize_matches_uncached(&s, &cache, target, *mode, *web_id, *origin)
                .await;
            assert_cached_read_matches_uncached(&s, &cache, target, *mode, *web_id, *origin).await;
        }
    }

    /// A WRITE to the ACL that CHANGES its rules must be seen by the NEXT cached read — no stale grant.
    /// Two mechanisms guarantee this: (1) the rewritten ACL has DIFFERENT bytes ⇒ a DIFFERENT etag ⇒
    /// the `(acl, etag)` gate misses and re-parses; (2) the handler also explicitly invalidates on an
    /// `.acl` write. This test exercises (1) directly at the resolver: it populates the cache with a
    /// permissive ACL, then rewrites the SAME `.acl` to a restrictive one and asserts the cached
    /// resolve now DENIES (the new rules), proving the cache cannot serve a stale ALLOW after a change.
    #[tokio::test]
    async fn acl_write_is_seen_by_next_cached_read_no_stale_grant() {
        let s = store();
        let resource = "https://pod.example/alice/rot/data";
        let acl = "https://pod.example/alice/rot/data.acl";
        // Initially: BOB may read.
        put_acl(
            &s,
            acl,
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#b> a acl:Authorization; acl:agent <{BOB}>; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let cache = AclCache::new(64);
        let wac = WacAuthorizer::with_cache(&s, BASE, &cache);
        // Populate the cache: Bob is allowed (cold), and a second read confirms the warm hit allows.
        assert!(matches!(
            wac.authorize(resource, AccessMode::Read, Some(BOB), None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
        assert!(
            matches!(
                wac.authorize(resource, AccessMode::Read, Some(BOB), None)
                    .await
                    .unwrap(),
                Decision::Allow(_)
            ),
            "second read must still allow (this is the cache hit being populated/served)"
        );
        // ROTATE the ACL: now ONLY Alice may read — Bob is removed. Different bytes ⇒ different etag.
        put_acl(
            &s,
            acl,
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#a> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        // The NEXT cached read MUST see the new rules: Bob is now FORBIDDEN (no stale Allow), Alice now
        // allowed. The etag changed, so the cache misses + re-parses the new ACL.
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, Some(BOB), None).await.unwrap(),
            Decision::Forbidden,
            "a rotated ACL must DENY the now-removed agent — the cache must not serve a stale grant"
        );
        assert!(matches!(
            wac.authorize(resource, AccessMode::Read, Some(ALICE), None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
    }

    /// The `=0` disabled cache yields BYTE-IDENTICAL decisions to no cache at all (the off-switch). A
    /// disabled cache never stores, so every read re-resolves — its decisions must equal the
    /// uncached path exactly, across the same shapes.
    #[tokio::test]
    async fn disabled_cache_is_byte_identical_to_no_cache() {
        let s = store();
        let resource = "https://pod.example/alice/d/doc";
        put_acl(
            &s,
            "https://pod.example/alice/d/doc.acl",
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                @prefix foaf: <http://xmlns.com/foaf/0.1/>.
                <#o> a acl:Authorization; acl:agent <{ALICE}>; acl:accessTo <{resource}>; acl:mode acl:Read, acl:Write, acl:Control.
                <#p> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let disabled = AclCache::disabled();
        for (web_id, origin) in [(None, None), (Some(ALICE), None), (Some(BOB), None)] {
            let uncached = WacAuthorizer::new(&s, BASE)
                .authorize_read(resource, AccessMode::Read, web_id, origin)
                .await
                .unwrap();
            let off = WacAuthorizer::with_cache(&s, BASE, &disabled)
                .authorize_read(resource, AccessMode::Read, web_id, origin)
                .await
                .unwrap();
            assert_eq!(
                off, uncached,
                "disabled cache must equal no-cache for web_id={web_id:?}"
            );
        }
        // A disabled cache never stored anything.
        assert_eq!(disabled.len(), 0);
    }

    /// A removed ACL is NEVER resurrected by the cache: populate the cache with an ALLOW via an own
    /// ACL, then DELETE that `.acl` so the resource has no governing ACL anywhere → the cached resolve
    /// must now DENY (fail-closed), proving the cache cannot fabricate a deleted grant. The `meta`
    /// probe returns `None` for the deleted ACL, so the resolver never even consults the cache for it.
    #[tokio::test]
    async fn deleted_acl_is_not_resurrected_by_cache() {
        let s = store();
        let resource = "https://pod.example/alice/del/data";
        let acl = "https://pod.example/alice/del/data.acl";
        put_acl(
            &s,
            acl,
            &format!(
                r#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                <#p> a acl:Authorization; acl:agentClass <http://xmlns.com/foaf/0.1/Agent>; acl:accessTo <{resource}>; acl:mode acl:Read."#
            ),
        )
        .await;
        let cache = AclCache::new(64);
        let wac = WacAuthorizer::with_cache(&s, BASE, &cache);
        // Cold + warm: anonymous read is ALLOWED (public) and the cache is populated.
        assert!(matches!(
            wac.authorize(resource, AccessMode::Read, None, None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
        assert!(matches!(
            wac.authorize(resource, AccessMode::Read, None, None)
                .await
                .unwrap(),
            Decision::Allow(_)
        ));
        // DELETE the own ACL — no ACL governs the resource anywhere now (no ancestor ACL either).
        s.delete(acl, None).await.expect("delete acl");
        // The cached resolve must now DENY (fail-closed: no ACL → 401 for anonymous). The deleted ACL
        // is gone from the index, so the `meta` probe reports it absent and the walk inherits nothing.
        assert_eq!(
            wac.authorize(resource, AccessMode::Read, None, None).await.unwrap(),
            Decision::Unauthenticated,
            "a deleted ACL must NOT be served from cache — removing it must fail-close the resource"
        );
    }
}
