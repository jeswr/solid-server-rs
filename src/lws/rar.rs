// AUTHORED-BY Claude Fable 5
//! **RFC 9396 `authorization_details` — NARROWING-ONLY enforcement (M3)** for the LWS auth chain
//! (`jeswr/lws-spec` `index.html` §rar).
//!
//! The spec's rule is one sentence and it is the security property this module exists to hold:
//! *"A storage server MUST NOT treat an `authorization_details` claim as widening access beyond
//! its own policy: the claim can only narrow."* Concretely, the effective access is the
//! INTERSECTION
//!
//! ```text
//! effective = WAC decision  ∩  audience containment  ∩  authorization_details scope
//! ```
//!
//! and this module implements ONLY the last term — as a pure predicate consulted by
//! [`LwsBearerAuth::verify_bearer`](super::auth::LwsBearerAuth::verify_bearer) to **deny** a
//! request the other two terms would have admitted. It has no authority to admit anything:
//! the WAC engine still runs downstream, unchanged, on every request that passes here, and the
//! audience-containment check has already run before it. A widening attempt (an entry whose
//! `locations`/`actions` exceed the WAC grant or the token audience) therefore cannot relax
//! anything — intersection is monotone — which is the structural "never widens" argument the
//! tests then pin behaviourally.
//!
//! ## Where enforcement happens (one chokepoint, not N)
//! The check runs INSIDE `verify_bearer`, per request, against the server-reconstructed target
//! and the HTTP method — the same single, non-bypassable place the audience containment runs.
//! Every LWS-authenticated request routes through it (the auth middleware wraps all LDP routes +
//! the subscription route); nothing downstream needs to remember to re-check. Because the spec
//! scopes `locations` as URI PREFIXES on the same containment algebra as `aud`
//! ([`super::auth::audience_contains`] — complete `/`-segment boundaries), a container that
//! passes the chokepoint has every member inside the same location, so the fail-closed listing
//! filter (D12) can never disclose a member outside the narrowed scope: containment is
//! transitive over path-aligned membership.
//!
//! ## Method → action mapping (deliberately conservative)
//! The profile's action set (`§access-requests-grants`): `read`, `modify`, `delete` (ODRL core)
//! plus `create` and `append` (`odrl:includedIn odrl:modify` — one-directional: `modify` grants
//! the narrower two, never the reverse). At this chokepoint the request's concrete action is
//! derived from the HTTP method:
//!
//! | method    | required action                          |
//! |-----------|------------------------------------------|
//! | GET/HEAD  | `read`                                   |
//! | PUT       | `modify` (create-or-replace; `create` alone is NOT sufficient — under-grant) |
//! | POST      | `create` (or `modify` via `includedIn`)  |
//! | PATCH     | `modify` (content unseen here; an insert-only patch under an `append`-only grant is under-granted) |
//! | DELETE    | `delete` (NOT implied by `modify` — the inclusion covers create/append only) |
//! | OPTIONS   | exempt (no resource content; the CORS layer answers most OPTIONS before auth anyway) |
//! | anything else | denied (fail closed)                 |
//!
//! Every imprecision resolves toward DENIAL (an under-grant), never a widen — documented in
//! `decisions/0006`. Refining PUT-create/PATCH-append to their narrower actions needs
//! request-state the authn chokepoint deliberately does not consult.
//!
//! ## Fail-closed parsing
//! A present claim that this server cannot FULLY interpret as a narrowing rejects the TOKEN
//! (401): unknown entry `type`s (RFC 9396 — an RS must not accept authorization details it does
//! not understand; with the mandatory single audience the claim can only be meant for this
//! storage), malformed `locations`/`actions`, non-object entries, a non-array claim. Two
//! deliberate softer points, both still deny-only: an entry carrying members beyond
//! `type`/`locations`/`actions` (e.g. the spec's OPTIONAL `datatypes`/`purposes`, which are
//! FURTHER constraints this server cannot evaluate) is kept but GRANTS NOTHING — honouring an
//! entry while ignoring one of its constraints would be the widen; and an unknown action STRING
//! inside a well-formed entry grants nothing (the profile's own fail-closed rule: "an unknown
//! action grants nothing") without invalidating the entry's known actions.

use serde_json::Value;

use super::auth::audience_contains;

/// The `authorization_details` entry `type` this profile defines (spec §rar).
pub const ACCESS_REQUEST_TYPE: &str = "https://w3id.org/jeswr/lws#AccessRequest";

/// The ODRL 2.2 core action IRIs (long forms accepted beside the short names the spec's
/// test-vector suite uses).
const ODRL_NS: &str = "http://www.w3.org/ns/odrl/2/";

/// A concrete action this chokepoint can require (the profile action set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Modify,
    Delete,
    Create,
    Append,
}

impl Action {
    /// Parse one wire action string: the short names (`"read"`, …, per the spec's vector suite)
    /// or the full ODRL / jlws IRIs. `None` = unknown (grants nothing — fail closed).
    fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Action::Read),
            "modify" => Some(Action::Modify),
            "delete" => Some(Action::Delete),
            "create" => Some(Action::Create),
            "append" => Some(Action::Append),
            _ => {
                if let Some(rest) = s.strip_prefix(ODRL_NS) {
                    match rest {
                        "read" => Some(Action::Read),
                        "modify" => Some(Action::Modify),
                        "delete" => Some(Action::Delete),
                        _ => None,
                    }
                } else if let Some(rest) = s.strip_prefix(super::JLWS_NS) {
                    match rest {
                        "create" => Some(Action::Create),
                        "append" => Some(Action::Append),
                        _ => None,
                    }
                } else {
                    None
                }
            }
        }
    }
}

/// The concrete action an HTTP method requires at this chokepoint (`None` = no mapping ⇒ the
/// caller denies, EXCEPT `OPTIONS`, which the caller exempts). See the module table.
pub fn action_for_method(method: &str) -> Option<Action> {
    match method.to_ascii_uppercase().as_str() {
        "GET" | "HEAD" => Some(Action::Read),
        "PUT" | "PATCH" => Some(Action::Modify),
        "POST" => Some(Action::Create),
        "DELETE" => Some(Action::Delete),
        _ => None,
    }
}

/// One parsed, validated `AccessRequest` entry.
#[derive(Debug, Clone)]
struct Entry {
    /// Absolute http(s) URI prefixes (validated at parse); the target must be CONTAINED in one
    /// (same segment-boundary algebra as the audience — [`audience_contains`]).
    locations: Vec<String>,
    /// The recognised actions. Unknown wire strings were dropped (grant nothing).
    actions: Vec<Action>,
    /// The entry carried members this server cannot evaluate (`datatypes`, `purposes`, or any
    /// unknown member): it is kept for shape-validation but GRANTS NOTHING — enforcing an entry
    /// while ignoring one of its constraints would widen past the AS's decision.
    unenforceable: bool,
}

/// A parsed `authorization_details` narrowing: the deny-only scope predicate.
#[derive(Debug, Clone)]
pub struct Narrowing {
    entries: Vec<Entry>,
}

/// A parse rejection — the caller maps it to a fail-closed 401 (`invalid_token`): the token
/// carries an authorization decision this server cannot faithfully enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedAuthorizationDetails(pub &'static str);

/// Parse the VERIFIED claims' `authorization_details` member.
///
/// - Absent ⇒ `Ok(None)`: no narrowing — the WAC baseline alone decides (the spec's `rar-absent`
///   vector).
/// - Present and fully intelligible ⇒ `Ok(Some(_))`.
/// - Present but not a non-empty array of well-formed `AccessRequest` entries ⇒ `Err` (the
///   fail-closed 401; see the module doc's parsing rules).
pub fn parse_authorization_details(
    claims: &Value,
) -> Result<Option<Narrowing>, MalformedAuthorizationDetails> {
    let Some(raw) = claims.get("authorization_details") else {
        return Ok(None);
    };
    let Some(list) = raw.as_array() else {
        return Err(MalformedAuthorizationDetails(
            "authorization_details must be a JSON array",
        ));
    };
    if list.is_empty() {
        return Err(MalformedAuthorizationDetails(
            "authorization_details must not be empty",
        ));
    }
    let mut entries = Vec::with_capacity(list.len());
    for item in list {
        let Some(obj) = item.as_object() else {
            return Err(MalformedAuthorizationDetails(
                "authorization_details entries must be objects",
            ));
        };
        match obj.get("type").and_then(Value::as_str) {
            Some(t) if t == ACCESS_REQUEST_TYPE => {}
            // An entry type this server does not understand cannot be enforced — and with the
            // mandatory single storage audience it can only have been meant for this storage.
            // Reject the token (RFC 9396's RS posture), never silently ignore.
            _ => {
                return Err(MalformedAuthorizationDetails(
                    "unrecognised authorization_details entry type",
                ))
            }
        }
        let locations = match obj.get("locations").and_then(Value::as_array) {
            Some(locs) if !locs.is_empty() => {
                let mut out = Vec::with_capacity(locs.len());
                for l in locs {
                    match l.as_str() {
                        Some(s) if is_absolute_http_url(s) => out.push(s.to_string()),
                        _ => {
                            return Err(MalformedAuthorizationDetails(
                                "locations must be absolute http(s) URIs",
                            ))
                        }
                    }
                }
                out
            }
            _ => {
                return Err(MalformedAuthorizationDetails(
                    "an AccessRequest entry must carry non-empty locations",
                ))
            }
        };
        let actions = match obj.get("actions").and_then(Value::as_array) {
            Some(acts) if !acts.is_empty() => {
                let mut out = Vec::new();
                for a in acts {
                    let Some(s) = a.as_str() else {
                        return Err(MalformedAuthorizationDetails("actions must be strings"));
                    };
                    // Unknown action STRINGS grant nothing but do not reject the token (the
                    // profile's own fail-closed rule for unknown actions).
                    if let Some(action) = Action::parse(s) {
                        out.push(action);
                    }
                }
                out
            }
            _ => {
                return Err(MalformedAuthorizationDetails(
                    "an AccessRequest entry must carry non-empty actions",
                ))
            }
        };
        // Members beyond {type, locations, actions} are constraints this server cannot evaluate
        // (the spec's OPTIONAL datatypes/purposes, or extensions): the entry grants NOTHING.
        let unenforceable = obj
            .keys()
            .any(|k| !matches!(k.as_str(), "type" | "locations" | "actions"));
        entries.push(Entry {
            locations,
            actions,
            unenforceable,
        });
    }
    Ok(Some(Narrowing { entries }))
}

impl Narrowing {
    /// Does this narrowing permit `action` on `target` (the server-reconstructed absolute request
    /// URL)? PURELY a deny-gate: `true` only defers to the WAC decision downstream; `false`
    /// denies a request WAC/aud might have allowed. An entry grants `action` when it names it
    /// directly, or names `modify` and `action` is one of the `odrl:includedIn` narrower two
    /// (`create`/`append`) — never the reverse, and never `delete` via `modify`.
    pub fn allows(&self, action: Action, target: &str) -> bool {
        self.entries.iter().any(|e| {
            !e.unenforceable
                && e.actions.iter().any(|a| {
                    *a == action
                        || (*a == Action::Modify
                            && matches!(action, Action::Create | Action::Append))
                })
                && e.locations.iter().any(|l| audience_contains(l, target))
        })
    }
}

/// Absolute http(s) URL shape check (mirrors the auth module's helper; kept local so this module
/// stays dependency-light and independently testable).
fn is_absolute_http_url(s: &str) -> bool {
    match url::Url::parse(s) {
        Ok(u) => matches!(u.scheme(), "http" | "https"),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOTES: &str = "https://storage.example/alice/notes/";
    const A: &str = "https://storage.example/alice/notes/a.txt";

    fn claims_with(details: Value) -> Value {
        json!({ "sub": "https://storage.example/alice#me", "authorization_details": details })
    }

    fn narrowing(details: Value) -> Narrowing {
        parse_authorization_details(&claims_with(details))
            .expect("well-formed")
            .expect("present")
    }

    fn entry(locations: Value, actions: Value) -> Value {
        json!({ "type": ACCESS_REQUEST_TYPE, "locations": locations, "actions": actions })
    }

    // --- absence + malformed fail-closed --------------------------------------------------------

    #[test]
    fn absent_claim_is_no_narrowing() {
        let claims = json!({ "sub": "x" });
        assert!(parse_authorization_details(&claims).unwrap().is_none());
    }

    #[test]
    fn malformed_claims_fail_closed() {
        // Every shape violation REJECTS (⇒ the caller's 401) — never "ignored ⇒ WAC baseline",
        // which would silently WIDEN past whatever the AS meant to encode.
        for bad in [
            json!(42),                                              // not an array
            json!("read"),                                          // not an array
            json!({}),                                              // not an array
            json!([]),                                              // empty
            json!([42]),                                            // entry not an object
            json!([{ "locations": [NOTES], "actions": ["read"] }]), // no type
            json!([{ "type": "https://other.example/Thing", "locations": [NOTES], "actions": ["read"] }]), // foreign type
            json!([entry(json!([]), json!(["read"]))]), // empty locations
            json!([entry(json!(["/alice/"]), json!(["read"]))]), // relative location
            json!([entry(json!(["ftp://x/"]), json!(["read"]))]), // non-http scheme
            json!([entry(json!([42]), json!(["read"]))]), // non-string location
            json!([entry(json!([NOTES]), json!([]))]),  // empty actions
            json!([entry(json!([NOTES]), json!([42]))]), // non-string action
            json!([{ "type": ACCESS_REQUEST_TYPE, "actions": ["read"] }]), // no locations
            json!([{ "type": ACCESS_REQUEST_TYPE, "locations": [NOTES] }]), // no actions
            // ONE malformed entry poisons the whole claim (partial enforcement = partial widen).
            json!([entry(json!([NOTES]), json!(["read"])), json!(42)]),
        ] {
            assert!(
                parse_authorization_details(&claims_with(bad.clone())).is_err(),
                "must reject: {bad}"
            );
        }
    }

    // --- the narrowing matrix -------------------------------------------------------------------

    #[test]
    fn narrows_locations_on_segment_boundaries() {
        let n = narrowing(json!([entry(json!([NOTES]), json!(["read"]))]));
        assert!(n.allows(Action::Read, A));
        assert!(n.allows(Action::Read, NOTES));
        // Outside the location: denied (the spec's rar-narrows-locations vector).
        assert!(!n.allows(Action::Read, "https://storage.example/alice/other.txt"));
        // Sibling raw-prefix can never satisfy (the audience algebra: complete segments).
        let n = narrowing(json!([entry(
            json!(["https://storage.example/alice"]),
            json!(["read"])
        )]));
        assert!(n.allows(Action::Read, "https://storage.example/alice/x"));
        assert!(!n.allows(Action::Read, "https://storage.example/alicemalicious"));
    }

    #[test]
    fn a_single_resource_location_grants_exactly_that_resource() {
        let n = narrowing(json!([entry(json!([A]), json!(["read"]))]));
        assert!(n.allows(Action::Read, A));
        assert!(!n.allows(Action::Read, NOTES));
        assert!(!n.allows(
            Action::Read,
            "https://storage.example/alice/notes/other.txt"
        ));
    }

    #[test]
    fn narrows_actions_and_modify_implies_only_create_and_append() {
        let n = narrowing(json!([entry(json!([NOTES]), json!(["modify"]))]));
        // modify ⊇ create + append (odrl:includedIn, one-directional)…
        assert!(n.allows(Action::Modify, A));
        assert!(n.allows(Action::Create, A));
        assert!(n.allows(Action::Append, A));
        // …but NOT read, and NOT delete (delete is a distinct core action).
        assert!(!n.allows(Action::Read, A));
        assert!(!n.allows(Action::Delete, A));
        // The reverse inclusions never hold: create/append-only grants are not modify.
        let n = narrowing(json!([entry(json!([NOTES]), json!(["create", "append"]))]));
        assert!(!n.allows(Action::Modify, A));
        assert!(n.allows(Action::Create, A));
        assert!(n.allows(Action::Append, A));
        // delete-only grants delete and nothing else.
        let n = narrowing(json!([entry(json!([NOTES]), json!(["delete"]))]));
        assert!(n.allows(Action::Delete, A));
        assert!(!n.allows(Action::Read, A));
        assert!(!n.allows(Action::Modify, A));
    }

    #[test]
    fn long_form_action_iris_are_accepted() {
        let n = narrowing(json!([entry(
            json!([NOTES]),
            json!([
                "http://www.w3.org/ns/odrl/2/read",
                "https://w3id.org/jeswr/lws#append"
            ])
        )]));
        assert!(n.allows(Action::Read, A));
        assert!(n.allows(Action::Append, A));
        assert!(!n.allows(Action::Modify, A));
    }

    #[test]
    fn unknown_action_strings_grant_nothing_but_do_not_poison() {
        let n = narrowing(json!([entry(
            json!([NOTES]),
            json!(["read", "odrl:frobnicate", "levitate"])
        )]));
        assert!(n.allows(Action::Read, A));
        assert!(!n.allows(Action::Modify, A));
        // ONLY unknown actions ⇒ a valid entry granting nothing.
        let n = narrowing(json!([entry(json!([NOTES]), json!(["levitate"]))]));
        assert!(!n.allows(Action::Read, A));
    }

    #[test]
    fn entries_with_unenforceable_constraints_grant_nothing() {
        // datatypes/purposes (spec-OPTIONAL further constraints) — this server cannot evaluate
        // them, so honouring the entry's actions while ignoring them would WIDEN. Fail closed:
        // the entry grants nothing.
        for extra in ["datatypes", "purposes", "x-custom"] {
            let mut e = entry(json!([NOTES]), json!(["read"]));
            e[extra] = json!(["something"]);
            let n = narrowing(json!([e]));
            assert!(
                !n.allows(Action::Read, A),
                "{extra}-constrained entry must grant nothing"
            );
        }
    }

    #[test]
    fn multiple_entries_union() {
        let n = narrowing(json!([
            entry(json!([NOTES]), json!(["read"])),
            entry(
                json!(["https://storage.example/alice/inbox/"]),
                json!(["create"])
            ),
        ]));
        assert!(n.allows(Action::Read, A));
        assert!(n.allows(Action::Create, "https://storage.example/alice/inbox/"));
        // Neither entry leaks into the other's scope.
        assert!(!n.allows(Action::Create, A));
        assert!(!n.allows(Action::Read, "https://storage.example/alice/inbox/"));
    }

    #[test]
    fn method_action_mapping_is_conservative() {
        assert_eq!(action_for_method("GET"), Some(Action::Read));
        assert_eq!(action_for_method("head"), Some(Action::Read));
        assert_eq!(action_for_method("PUT"), Some(Action::Modify));
        assert_eq!(action_for_method("PATCH"), Some(Action::Modify));
        assert_eq!(action_for_method("POST"), Some(Action::Create));
        assert_eq!(action_for_method("DELETE"), Some(Action::Delete));
        // Unknown methods have NO mapping — the caller denies (fail closed).
        assert_eq!(action_for_method("QUERY"), None);
        assert_eq!(action_for_method("TRACE"), None);
        assert_eq!(action_for_method("PROPFIND"), None);
    }

    #[test]
    fn wider_locations_than_needed_still_only_defer_to_wac() {
        // A location WIDER than the audience is not a grant of anything outside the other
        // intersection terms: `allows` is only ever consulted to DENY. This pins the pure-predicate
        // shape — the origin root location admits the target here, and the caller still runs
        // aud-containment + WAC on it.
        let n = narrowing(json!([entry(
            json!(["https://storage.example/"]),
            json!(["read"])
        )]));
        assert!(n.allows(Action::Read, A));
    }
}
