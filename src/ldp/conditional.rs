// AUTHORED-BY Claude Opus 4.8
//! HTTP conditional-request preconditions (`If-Match` / `If-None-Match`) over the strong ETag.
//!
//! This is pure value logic (no I/O): given a request's precondition headers and the resource's
//! current ETag (or its absence, when the resource does not exist), it decides whether a mutating
//! request may proceed (RFC 9110 §13.1–§13.2). The handler holds the I/O; this module holds the
//! exact comparison rules so they are exhaustively unit-testable.
//!
//! The server emits only **strong** ETags (`"…"`). Validator strength is honoured per RFC 9110:
//! `If-Match` uses **strong comparison** (§13.1.1 — "the server MUST NOT … weak"), so an inbound
//! weak validator (`W/"…"`) can NEVER satisfy `If-Match` and the request fails; `If-None-Match` uses
//! **weak comparison** (§13.1.2), so a `W/`-prefixed validator matches by its opaque tag. The
//! wildcard `*` is handled per spec: `If-None-Match: *` ⇒ "only if it does NOT exist" (the create
//! guard); `If-Match: *` ⇒ "only if it DOES exist".

use std::time::{SystemTime, UNIX_EPOCH};

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
    // --- If-Match: proceed only if the current representation matches one of the listed tags, by
    // STRONG comparison (RFC 9110 §13.1.1) — a weak (`W/`) validator never satisfies If-Match.
    if let Some(im) = if_match {
        let ok = match current {
            // `If-Match: *` ⇒ the resource must exist.
            _ if is_wildcard(im) => current.is_some(),
            Some(cur) => tag_list(im).any(|t| t.matches_strong(cur)),
            // No current representation can match a concrete tag list.
            None => false,
        };
        if !ok {
            return Precondition::Failed;
        }
    }

    // --- If-None-Match: proceed only if NONE of the listed tags match (the create / no-overwrite
    // guard), by WEAK comparison (RFC 9110 §13.1.2). `If-None-Match: *` ⇒ the resource must NOT
    // exist.
    if let Some(inm) = if_none_match {
        let matched = match current {
            _ if is_wildcard(inm) => current.is_some(),
            Some(cur) => tag_list(inm).any(|t| t.matches_weak(cur)),
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

/// The outcome of evaluating the READ preconditions of a GET/HEAD (RFC 9110 §13): serve the normal
/// response, or short-circuit **304 Not Modified**.
///
/// A read precondition NEVER fails with 412 — for GET/HEAD an unmet `If-None-Match` / a satisfied
/// `If-Modified-Since` is a 304 (RFC 9110 §13.1.2 / §13.1.3), not a rejection. That is the whole
/// point of the read fast-path: a 304 carries the validators and no body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadPrecondition {
    /// No read precondition short-circuited — serve the normal 200 (or 206 / 406 / 416) response.
    Proceed,
    /// A read precondition matched — return **304 Not Modified** (the validators, no body).
    NotModified,
}

/// Evaluate the READ preconditions (`If-None-Match`, then `If-Modified-Since`) of a GET/HEAD against
/// the resource's CURRENT validators (RFC 9110 §13).
///
/// The caller has already (a) authorized the read and (b) confirmed the resource EXISTS (a missing
/// target is a 404 *before* this point, so no 304 can leak the existence of a resource the caller
/// could not otherwise read). `current_etag` is therefore the ETag a 200 would carry for this exact
/// representation state — the 304 uses the IDENTICAL tag.
///
/// Precedence (RFC 9110 §13.1.3): **`If-None-Match` takes precedence over `If-Modified-Since`.** When
/// `If-None-Match` is present, `If-Modified-Since` is IGNORED entirely (evaluated only as a fallback
/// when `If-None-Match` is absent).
///
/// - **`If-None-Match`** uses WEAK comparison for GET/HEAD (§13.1.2): a `W/`-prefixed inbound tag
///   matches by its opaque value, and `*` matches the (existing) resource. A match ⇒ 304.
/// - **`If-Modified-Since`** (only when `If-None-Match` is absent): if the resource's `last_modified`
///   is `≤` the header date, the representation has NOT changed ⇒ 304. When the store surfaces no
///   modification time (`last_modified` is `None`) or the date is unparseable, the condition CANNOT be
///   proven "not modified", so we fail OPEN to a fresh 200 — never a spurious 304.
pub fn evaluate_read(
    if_none_match: Option<&str>,
    if_modified_since: Option<&str>,
    current_etag: &str,
    last_modified: Option<SystemTime>,
) -> ReadPrecondition {
    // --- If-None-Match takes precedence (§13.1.3): if present it decides, and If-Modified-Since is
    // ignored. Weak comparison (§13.1.2); `*` matches the existing resource.
    if let Some(inm) = if_none_match {
        let matched = if is_wildcard(inm) {
            // The resource exists (the read reached it post-auth), so `*` matches.
            true
        } else {
            tag_list(inm).any(|t| t.matches_weak(current_etag))
        };
        return if matched {
            ReadPrecondition::NotModified
        } else {
            ReadPrecondition::Proceed
        };
    }

    // --- If-Modified-Since (ONLY when If-None-Match is absent). 304 iff the resource's Last-Modified
    // is ≤ the client's date (the representation has not changed since). Missing/unparseable ⇒ Proceed.
    if let (Some(ims), Some(lm)) = (if_modified_since, last_modified) {
        if let (Some(ims_secs), Some(lm_secs)) = (parse_http_date(ims), system_time_to_unix(lm)) {
            if lm_secs <= ims_secs {
                return ReadPrecondition::NotModified;
            }
        }
    }

    ReadPrecondition::Proceed
}

/// Whether a header value is the wildcard `*` (after trimming).
fn is_wildcard(header: &str) -> bool {
    header.trim() == "*"
}

/// A [`SystemTime`] as whole seconds since the Unix epoch, or `None` for a pre-epoch time (which no
/// stored resource realistically has — treated as "cannot compare" ⇒ the caller fails open).
fn system_time_to_unix(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

/// Parse an HTTP **IMF-fixdate** (RFC 9110 §5.6.7 — the format a sender MUST produce), e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`, to whole seconds since the Unix epoch. Returns `None` for any
/// value that is not a well-formed IMF-fixdate (the obsolete RFC 850 / asctime forms are not parsed —
/// a conforming client always sends IMF-fixdate; accepting the legacy forms is a possible follow-up).
///
/// No third-party date crate is pulled in for this: the grammar is fixed-width and the epoch
/// conversion is the standard days-from-civil algorithm, so a small self-contained parser is exact
/// and keeps the dependency surface unchanged.
fn parse_http_date(value: &str) -> Option<i64> {
    // `Sun, 06 Nov 1994 08:49:37 GMT`
    let v = value.trim();
    let rest = v.split_once(", ")?.1; // drop the day-name + ", "
    let mut parts = rest.split(' ');
    let day: u32 = parts.next()?.parse().ok()?;
    let month = month_from_abbrev(parts.next()?)?;
    let year: i64 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let gmt = parts.next()?;
    if gmt != "GMT" || parts.next().is_some() {
        return None;
    }
    let mut hms = time.split(':');
    let hh: i64 = hms.next()?.parse().ok()?;
    let mm: i64 = hms.next()?.parse().ok()?;
    let ss: i64 = hms.next()?.parse().ok()?;
    if hms.next().is_some() || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}

/// Map a three-letter English month abbreviation to its 1-based number.
fn month_from_abbrev(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days from the Unix epoch (1970-01-01) to `y-m-d` (proleptic Gregorian), by Howard Hinnant's
/// `days_from_civil` algorithm. Exact for all civil dates; negative for dates before the epoch.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// An inbound entity-tag with its validator strength preserved (RFC 9110 §8.8.3).
struct InboundTag<'a> {
    /// The opaque quoted tag value (e.g. `"abc"`), with any `W/` prefix removed.
    opaque: &'a str,
    /// Whether the inbound validator was weak (`W/`-prefixed).
    weak: bool,
}

impl InboundTag<'_> {
    /// STRONG comparison (for `If-Match`): both validators must be strong and the opaque tags equal.
    /// The server's stored tag is always strong, so a weak inbound tag never matches strongly.
    fn matches_strong(&self, current_strong: &str) -> bool {
        !self.weak && self.opaque == current_strong
    }

    /// WEAK comparison (for `If-None-Match`): the opaque tags are equal regardless of strength.
    fn matches_weak(&self, current_strong: &str) -> bool {
        self.opaque == current_strong
    }
}

/// Iterate the entity-tags in a comma-separated `If-(None-)Match` header value, preserving each
/// tag's validator STRENGTH (so `If-Match` can correctly reject a weak validator). Whitespace is
/// trimmed and an empty/blank entry is skipped.
fn tag_list(header: &str) -> impl Iterator<Item = InboundTag<'_>> {
    header
        .split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| match t.strip_prefix("W/") {
            Some(rest) => InboundTag {
                opaque: rest.trim(),
                weak: true,
            },
            None => InboundTag {
                opaque: t,
                weak: false,
            },
        })
        .filter(|t| !t.opaque.is_empty())
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
    fn if_match_list_matches_a_strong_member() {
        // A strong member of the list matches ⇒ If-Match proceeds (strong comparison).
        let list = format!("{OTHER}, {TAG}");
        assert_eq!(
            evaluate(Some(&list), None, Some(TAG)),
            Precondition::Proceed
        );
    }

    #[test]
    fn if_match_rejects_a_weak_validator() {
        // RFC 9110 §13.1.1: a weak (`W/`) validator must NOT satisfy If-Match — even with the same
        // opaque tag, so this must FAIL (the bug roborev flagged).
        let weak = format!("W/{TAG}");
        assert_eq!(evaluate(Some(&weak), None, Some(TAG)), Precondition::Failed);
        // …and a list whose only matching tag is weak still fails.
        let list = format!("{OTHER}, W/{TAG}");
        assert_eq!(evaluate(Some(&list), None, Some(TAG)), Precondition::Failed);
    }

    #[test]
    fn if_none_match_accepts_a_weak_validator() {
        // RFC 9110 §13.1.2: If-None-Match uses WEAK comparison — a `W/`-prefixed tag with the same
        // opaque value DOES match (so "none match" fails ⇒ 412 on a mutation).
        let weak = format!("W/{TAG}");
        assert_eq!(evaluate(None, Some(&weak), Some(TAG)), Precondition::Failed);
    }

    #[test]
    fn require_maps_to_status() {
        assert!(require(Precondition::Proceed).is_ok());
        let err = require(Precondition::Failed).unwrap_err();
        assert_eq!(err.status().as_u16(), 412);
    }

    // --- READ preconditions (GET/HEAD → 304) -------------------------------------------------------

    use std::time::Duration;

    /// A `SystemTime` `secs` seconds after the Unix epoch.
    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn read_no_preconditions_proceeds() {
        assert_eq!(
            evaluate_read(None, None, TAG, None),
            ReadPrecondition::Proceed
        );
        assert_eq!(
            evaluate_read(None, None, TAG, Some(at(1_000))),
            ReadPrecondition::Proceed
        );
    }

    #[test]
    fn read_if_none_match_matching_is_304() {
        // A matching tag ⇒ the client's cache is fresh ⇒ 304.
        assert_eq!(
            evaluate_read(Some(TAG), None, TAG, None),
            ReadPrecondition::NotModified
        );
    }

    #[test]
    fn read_if_none_match_non_matching_is_200() {
        assert_eq!(
            evaluate_read(Some(OTHER), None, TAG, None),
            ReadPrecondition::Proceed
        );
    }

    #[test]
    fn read_if_none_match_star_on_existing_is_304() {
        // `If-None-Match: *` on a resource that exists (the read reached it) ⇒ 304.
        assert_eq!(
            evaluate_read(Some("*"), None, TAG, None),
            ReadPrecondition::NotModified
        );
    }

    #[test]
    fn read_if_none_match_weak_validator_matches() {
        // GET/HEAD use WEAK comparison (§13.1.2): a `W/`-prefixed inbound tag matches the strong
        // current tag by opaque value ⇒ 304.
        let weak = format!("W/{TAG}");
        assert_eq!(
            evaluate_read(Some(&weak), None, TAG, None),
            ReadPrecondition::NotModified
        );
    }

    #[test]
    fn read_if_none_match_list_matches_any_member() {
        let list = format!("{OTHER}, {TAG}");
        assert_eq!(
            evaluate_read(Some(&list), None, TAG, None),
            ReadPrecondition::NotModified
        );
    }

    #[test]
    fn read_if_modified_since_not_modified_is_304() {
        // Resource last modified at t=1000; client asks "modified since t=2000?" → no ⇒ 304.
        let ims = "Thu, 01 Jan 1970 00:33:20 GMT"; // 2000s after epoch
        assert_eq!(
            evaluate_read(None, Some(ims), TAG, Some(at(1_000))),
            ReadPrecondition::NotModified
        );
    }

    #[test]
    fn read_if_modified_since_modified_is_200() {
        // Resource last modified at t=3000; client asks "modified since t=2000?" → yes ⇒ 200.
        let ims = "Thu, 01 Jan 1970 00:33:20 GMT"; // 2000s
        assert_eq!(
            evaluate_read(None, Some(ims), TAG, Some(at(3_000))),
            ReadPrecondition::Proceed
        );
    }

    #[test]
    fn read_if_modified_since_equal_boundary_is_304() {
        // Last-Modified EXACTLY equal to the date ⇒ "not modified since" is inclusive ⇒ 304.
        let ims = "Thu, 01 Jan 1970 00:33:20 GMT"; // 2000s
        assert_eq!(
            evaluate_read(None, Some(ims), TAG, Some(at(2_000))),
            ReadPrecondition::NotModified
        );
    }

    #[test]
    fn read_if_none_match_present_suppresses_if_modified_since() {
        // Precedence (§13.1.3): a NON-matching If-None-Match ⇒ Proceed, EVEN with an
        // If-Modified-Since that would otherwise 304. If-None-Match decides; If-Modified-Since ignored.
        let ims = "Thu, 01 Jan 1970 00:33:20 GMT"; // 2000s — would be "not modified" for lm=1000
        assert_eq!(
            evaluate_read(Some(OTHER), Some(ims), TAG, Some(at(1_000))),
            ReadPrecondition::Proceed
        );
        // …and a MATCHING If-None-Match still 304s regardless of the (contradictory) IMS.
        assert_eq!(
            evaluate_read(Some(TAG), Some(ims), TAG, Some(at(3_000))),
            ReadPrecondition::NotModified
        );
    }

    #[test]
    fn read_if_modified_since_without_last_modified_proceeds() {
        // No stored modification time ⇒ cannot prove "not modified" ⇒ fail OPEN to a fresh 200.
        let ims = "Thu, 01 Jan 1970 00:33:20 GMT";
        assert_eq!(
            evaluate_read(None, Some(ims), TAG, None),
            ReadPrecondition::Proceed
        );
    }

    #[test]
    fn read_if_modified_since_unparseable_proceeds() {
        assert_eq!(
            evaluate_read(None, Some("not-a-date"), TAG, Some(at(1_000))),
            ReadPrecondition::Proceed
        );
    }

    #[test]
    fn parse_http_date_known_values() {
        // The canonical RFC 9110 example: 784111777 seconds since the epoch.
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        // The epoch itself.
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        // A round-2000s value used by the tests above.
        assert_eq!(
            parse_http_date("Thu, 01 Jan 1970 00:33:20 GMT"),
            Some(2_000)
        );
    }

    #[test]
    fn parse_http_date_rejects_malformed() {
        assert_eq!(parse_http_date(""), None);
        assert_eq!(parse_http_date("garbage"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 UTC"), None); // not GMT
        assert_eq!(parse_http_date("Sun, 32 Nov 1994 08:49:37 GMT"), None); // bad day
        assert_eq!(parse_http_date("Sun, 06 Foo 1994 08:49:37 GMT"), None); // bad month
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 25:49:37 GMT"), None); // bad hour
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT extra"), None);
        // trailing junk
    }
}
