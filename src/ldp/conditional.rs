// AUTHORED-BY Claude Opus 4.8
//! HTTP conditional-request preconditions (`If-Match` / `If-None-Match`) over the strong ETag.
//!
//! This is pure value logic (no I/O): given a request's precondition headers and the resource's
//! current ETag (or its absence, when the resource does not exist), it decides whether a mutating
//! request may proceed (RFC 9110 §13.1–§13.2). The handler holds the I/O; this module holds the
//! exact comparison rules so they are exhaustively unit-testable.
//!
//! The server emits only **strong** ETags (`"…"`), so weak comparison (`W/…`) does not arise on the
//! produce side; on the *consume* side an inbound `W/`-prefixed validator is compared by its opaque
//! tag, which for our strong tags is exactly the strong comparison. The wildcard `*` is handled per
//! spec: `If-None-Match: *` ⇒ "only if it does NOT exist" (the create guard); `If-Match: *` ⇒ "only
//! if it DOES exist".

use crate::error::ServerError;

/// The outcome of evaluating preconditions: proceed, or fail with the spec-mandated status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precondition {
    /// Preconditions are satisfied — the request may proceed.
    Proceed,
    /// A precondition was not met — the request must be rejected with 412 Precondition Failed.
    ///
    /// (For a GET, an unmet `If-None-Match` is instead a 304; this server applies preconditions only
    /// to mutating verbs (PUT/PATCH/DELETE), where the failure status is always 412 — see RFC 9110
    /// §13.1.2: "for methods other than GET/HEAD … 412".)
    Failed,
}

/// Evaluate the `If-Match` / `If-None-Match` preconditions for a mutating request.
///
/// `if_match` / `if_none_match` are the raw header values (already validated as UTF-8 by the HTTP
/// layer). `current` is `Some(etag)` if the target exists with that strong ETag, or `None` if the
/// target does not currently exist.
///
/// Precedence follows RFC 9110 §13.2.2: when both are present, `If-Match` is evaluated **first**.
/// (`If-None-Match` then still applies — but a request that supplies both a matching `If-Match` and
/// an `If-None-Match` for the same existing tag is contradictory and fails on the `If-None-Match`.)
pub fn evaluate(
    if_match: Option<&str>,
    if_none_match: Option<&str>,
    current: Option<&str>,
) -> Precondition {
    // --- If-Match: proceed only if the current representation matches one of the listed tags.
    if let Some(im) = if_match {
        let ok = match current {
            // `If-Match: *` ⇒ the resource must exist.
            _ if is_wildcard(im) => current.is_some(),
            Some(cur) => tag_list(im).any(|t| strong_eq(t, cur)),
            // No current representation can match a concrete tag list.
            None => false,
        };
        if !ok {
            return Precondition::Failed;
        }
    }

    // --- If-None-Match: proceed only if NONE of the listed tags match (the create / no-overwrite
    // guard). `If-None-Match: *` ⇒ the resource must NOT exist.
    if let Some(inm) = if_none_match {
        let matched = match current {
            _ if is_wildcard(inm) => current.is_some(),
            Some(cur) => tag_list(inm).any(|t| strong_eq(t, cur)),
            None => false,
        };
        if matched {
            return Precondition::Failed;
        }
    }

    Precondition::Proceed
}

/// Map a [`Precondition`] outcome to a `Result` the handler can `?`-propagate.
pub fn require(p: Precondition) -> Result<(), ServerError> {
    match p {
        Precondition::Proceed => Ok(()),
        Precondition::Failed => Err(ServerError::PreconditionFailed),
    }
}

/// Whether a header value is the wildcard `*` (after trimming).
fn is_wildcard(header: &str) -> bool {
    header.trim() == "*"
}

/// Iterate the entity-tags in a comma-separated `If-(None-)Match` header value, trimming whitespace
/// and a leading weak-validator marker (`W/`). An empty/blank entry is skipped.
fn tag_list(header: &str) -> impl Iterator<Item = &str> {
    header
        .split(',')
        .map(|t| t.trim())
        .map(|t| t.strip_prefix("W/").unwrap_or(t))
        .filter(|t| !t.is_empty())
}

/// Strong comparison of two opaque entity-tags (RFC 9110 §8.8.3.2): byte-equal, both strong. The
/// stored tag is always strong; a `W/` prefix on either side was already stripped by [`tag_list`],
/// so this is a plain equality of the quoted opaque values.
fn strong_eq(a: &str, b: &str) -> bool {
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &str = "\"abc-123\"";
    const OTHER: &str = "\"xyz-999\"";

    #[test]
    fn no_preconditions_always_proceeds() {
        assert_eq!(evaluate(None, None, Some(TAG)), Precondition::Proceed);
        assert_eq!(evaluate(None, None, None), Precondition::Proceed);
    }

    #[test]
    fn if_none_match_star_creates_only_when_absent() {
        // Create guard: proceed when the resource does NOT exist.
        assert_eq!(evaluate(None, Some("*"), None), Precondition::Proceed);
        // Fail when it already exists (no-overwrite create).
        assert_eq!(evaluate(None, Some("*"), Some(TAG)), Precondition::Failed);
    }

    #[test]
    fn if_match_star_requires_existence() {
        assert_eq!(evaluate(Some("*"), None, Some(TAG)), Precondition::Proceed);
        assert_eq!(evaluate(Some("*"), None, None), Precondition::Failed);
    }

    #[test]
    fn if_match_matches_current_tag() {
        assert_eq!(evaluate(Some(TAG), None, Some(TAG)), Precondition::Proceed);
        assert_eq!(evaluate(Some(OTHER), None, Some(TAG)), Precondition::Failed);
        // If-Match against a missing resource never matches.
        assert_eq!(evaluate(Some(TAG), None, None), Precondition::Failed);
    }

    #[test]
    fn if_none_match_concrete_tag_blocks_on_match() {
        // The tag matches ⇒ "none match" fails.
        assert_eq!(evaluate(None, Some(TAG), Some(TAG)), Precondition::Failed);
        // A different tag ⇒ proceeds.
        assert_eq!(
            evaluate(None, Some(OTHER), Some(TAG)),
            Precondition::Proceed
        );
    }

    #[test]
    fn if_match_list_and_weak_prefix() {
        let list = format!("{OTHER}, W/{TAG}");
        // The current tag appears (weak-prefixed) in the list ⇒ If-Match proceeds.
        assert_eq!(
            evaluate(Some(&list), None, Some(TAG)),
            Precondition::Proceed
        );
    }

    #[test]
    fn require_maps_to_status() {
        assert!(require(Precondition::Proceed).is_ok());
        let err = require(Precondition::Failed).unwrap_err();
        assert_eq!(err.status().as_u16(), 412);
    }
}
