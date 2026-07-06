// AUTHORED-BY Claude Fable 5
//! **Server-minted, authenticated `lws-gen` pagination-pin tokens** — the defence-in-depth half of
//! the pinned-listing metadata-disclosure closure (see [`super::container`]'s module doc; the
//! primary closure is the current-existence guard in
//! `LdpState::authorize_listing_member`).
//!
//! ## Why the pin must be authenticated
//! The backend's snapshot generation is a SMALL MONOTONIC integer. Accepting any client-supplied
//! `lws-gen=<u64>` and forwarding it as a backend pin lets ANY requester rewind a container
//! listing to an arbitrary recent store state they never observed — they don't need a leaked
//! token, they can simply guess (or have been handed a generation for a DIFFERENT container /
//! principal). The snapshot pin is a capability the server chose to expose to ONE requester for
//! ONE container walk; it must therefore be unforgeable, bound, and short-lived.
//!
//! ## The token
//! `lws-gen=<generation>.<expiry-unix-secs>.<hex(HMAC-SHA256(key, msg))>` where
//!
//! ```text
//! msg = "jlws-gen-pin/v1" \n container-IRI \n requester-tag \n generation \n expiry
//! requester-tag = "webid:" + WebID   (authenticated)  |  "anon"  (anonymous)
//! ```
//!
//! - **Server-minted only:** the MAC key ([`PinKey`]) is 32 bytes of per-process OS entropy
//!   generated at [`super::LwsConfig`] construction and never serialised — only tokens this
//!   process minted verify. (Deployment note: with multiple replicas behind one backend, a pin
//!   minted by one replica fails verification on another with the 400 problem and the walker
//!   restarts unpinned — the same graceful degradation as a backend-retention ageing. A shared,
//!   operator-provisioned key is a documented follow-up seam, not built here.)
//! - **Bound to the container** — a token minted for `/c/` never pins a listing of `/d/`.
//! - **Bound to the requester** (WebID, or the anonymous class) — a pin handed to Alice in HER
//!   pagination links cannot be replayed by Bob to walk a snapshot the server never chose to
//!   expose to him. (Anonymous requesters share one class: there is no stronger identity to bind;
//!   server-mintedness + container binding + expiry still hold.)
//! - **Short-lived** — `expiry` bounds the token's life independently of the backend's own
//!   generation-retention window (which still applies underneath: a verified pin whose generation
//!   aged out at the backend remains the 410 `snapshot-gone` restart).
//!
//! ## Fail-closed verification order
//! MAC first, then expiry: a FORGED token is always the opaque 400 `invalid-generation` problem —
//! it is never told it "expired" (410), which would confirm the guess named a once-valid token.
//! Malformed shape, non-canonical fields, wrong binding, wrong key ⇒ [`PinVerifyError::Unminted`]
//! (→ 400); a genuinely server-minted token past its expiry ⇒ [`PinVerifyError::Expired`] (→ 410,
//! the walker's restart-unpinned path). Nothing here panics on any input (the no-panic guarantee):
//! parsing is strict byte-checked decimal/hex, comparison is constant-time (`subtle`), and the
//! HMAC is the vetted `aws-lc-rs` primitive (house rule — never hand-roll crypto).

use std::fmt;

use aws_lc_rs::hmac;
use subtle::ConstantTimeEq;

/// The domain-separation prefix of the MAC message (versioned so a future format change can
/// never collide with v1 tokens).
const MSG_PREFIX: &str = "jlws-gen-pin/v1";

/// The hex-encoded HMAC-SHA256 length (32 bytes → 64 lowercase hex chars).
const MAC_HEX_LEN: usize = 64;

/// The per-process pagination-pin MAC key: 32 bytes of OS entropy, generated once per
/// [`super::LwsConfig`] construction. Deliberately NOT `Debug`-printable (redacted) and never
/// serialised — see the module doc.
#[derive(Clone)]
pub struct PinKey([u8; 32]);

impl PinKey {
    /// Generate a fresh key from the OS CSPRNG. `None` on RNG failure — the caller FAILS CLOSED
    /// by disabling pins entirely (no pinned links minted, every presented pin refused), never by
    /// minting under weak entropy. (Mirrors `CompositeStore::mint_blob_key`'s posture; `getrandom`
    /// does not fail on any platform we target.)
    pub fn generate() -> Option<Self> {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).ok()?;
        Some(Self(k))
    }
}

impl fmt::Debug for PinKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material (LwsConfig derives Debug and can end up in logs).
        f.write_str("PinKey(..)")
    }
}

/// Why a presented pin token was refused. The caller maps these to the two problem responses —
/// see the module doc's fail-closed order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinVerifyError {
    /// Not a token this server minted for this (container, requester): malformed shape,
    /// non-canonical fields, MAC mismatch (wrong key / tampered / wrong binding). → the opaque
    /// 400 `invalid-generation` problem.
    Unminted,
    /// A genuinely server-minted token past its expiry. → the 410 `snapshot-gone` restart problem.
    Expired,
}

/// The canonical MAC input. `container_iri` comes from the server's own target parse and
/// `requester` from the verified token — neither can contain the `\n` separator (HTTP request
/// targets cannot carry raw control bytes; a verified WebID is a parsed URL), and `generation` /
/// `expiry` are fixed-position trailing integers, so the message is injection-free.
fn mac_hex(key: &PinKey, container_iri: &str, requester: Option<&str>, g: u64, exp: u64) -> String {
    let requester_tag: String = match requester {
        // Distinct prefixes so an (impossible-by-verifier, but cheap to exclude) empty WebID can
        // never alias the anonymous class.
        Some(w) => format!("webid:{w}"),
        None => "anon".to_string(),
    };
    let msg = format!("{MSG_PREFIX}\n{container_iri}\n{requester_tag}\n{g}\n{exp}");
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, &key.0),
        msg.as_bytes(),
    );
    let mut out = String::with_capacity(MAC_HEX_LEN);
    for b in tag.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Mint the pin token this server's own pagination links carry for (`container_iri`, `requester`,
/// `generation`), valid until `exp_unix` (exclusive — see [`verify`]).
pub(crate) fn mint(
    key: &PinKey,
    container_iri: &str,
    requester: Option<&str>,
    generation: u64,
    exp_unix: u64,
) -> String {
    format!(
        "{generation}.{exp_unix}.{}",
        mac_hex(key, container_iri, requester, generation, exp_unix)
    )
}

/// Strict canonical decimal: non-empty, ASCII digits only (no sign, no whitespace — `u64::parse`
/// alone would accept a leading `+`), fits in a u64.
fn parse_canonical_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// Verify a presented `lws-gen` token for (`container_iri`, `requester`) at `now_unix`; returns
/// the backend generation it pins on success.
///
/// Fail-closed order (module doc): shape → canonical fields → **MAC (constant-time)** → expiry.
/// Expiry is EXCLUSIVE (`now >= exp` ⇒ expired), so a zero TTL means "immediately expired" —
/// there is no configuration in which a token never expires.
pub(crate) fn verify(
    key: &PinKey,
    container_iri: &str,
    requester: Option<&str>,
    token: &str,
    now_unix: u64,
) -> Result<u64, PinVerifyError> {
    // Exactly three `.`-separated fields. (`splitn(3, ..)` folds extra dots into the MAC field,
    // where the strict hex check below refuses them — no fourth-field ambiguity.)
    let mut it = token.splitn(3, '.');
    let (Some(g_s), Some(exp_s), Some(mac_s)) = (it.next(), it.next(), it.next()) else {
        return Err(PinVerifyError::Unminted);
    };
    let (Some(g), Some(exp)) = (parse_canonical_u64(g_s), parse_canonical_u64(exp_s)) else {
        return Err(PinVerifyError::Unminted);
    };
    // Canonical lowercase hex of exactly the HMAC-SHA256 width. (Length/shape are not secret —
    // only the MAC VALUE comparison below needs constant time.)
    if mac_s.len() != MAC_HEX_LEN
        || !mac_s
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PinVerifyError::Unminted);
    }
    // MAC before expiry: a forged token must never learn it named a once-valid (expired) pin.
    let expected = mac_hex(key, container_iri, requester, g, exp);
    if !bool::from(expected.as_bytes().ct_eq(mac_s.as_bytes())) {
        return Err(PinVerifyError::Unminted);
    }
    if now_unix >= exp {
        return Err(PinVerifyError::Expired);
    }
    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTAINER: &str = "https://pod.example/alice/notes/";
    const ALICE: Option<&str> = Some("https://pod.example/alice/profile/card#me");
    const BOB: Option<&str> = Some("https://pod.example/bob/profile/card#me");

    fn key() -> PinKey {
        PinKey::generate().expect("OS RNG available in tests")
    }

    #[test]
    fn mint_verify_roundtrip_returns_the_generation() {
        let k = key();
        let t = mint(&k, CONTAINER, ALICE, 42, 1_000);
        assert_eq!(verify(&k, CONTAINER, ALICE, &t, 999), Ok(42));
        // The anonymous class round-trips too.
        let t = mint(&k, CONTAINER, None, 7, 1_000);
        assert_eq!(verify(&k, CONTAINER, None, &t, 999), Ok(7));
    }

    #[test]
    fn every_binding_dimension_is_enforced() {
        let k = key();
        let t = mint(&k, CONTAINER, ALICE, 42, 1_000);
        // Wrong container: a pin never crosses containers.
        assert_eq!(
            verify(&k, "https://pod.example/alice/other/", ALICE, &t, 999),
            Err(PinVerifyError::Unminted)
        );
        // Wrong requester: Bob cannot replay Alice's pin; nor can the anonymous class.
        assert_eq!(
            verify(&k, CONTAINER, BOB, &t, 999),
            Err(PinVerifyError::Unminted)
        );
        assert_eq!(
            verify(&k, CONTAINER, None, &t, 999),
            Err(PinVerifyError::Unminted)
        );
        // And an anonymous pin does not verify for an authenticated principal.
        let anon = mint(&k, CONTAINER, None, 42, 1_000);
        assert_eq!(
            verify(&k, CONTAINER, ALICE, &anon, 999),
            Err(PinVerifyError::Unminted)
        );
        // Wrong key (another process / a restart): unminted, never accepted.
        let other = key();
        assert_eq!(
            verify(&other, CONTAINER, ALICE, &t, 999),
            Err(PinVerifyError::Unminted)
        );
    }

    #[test]
    fn tampering_any_field_unmints_the_token() {
        let k = key();
        let t = mint(&k, CONTAINER, ALICE, 42, 1_000);
        let parts: Vec<&str> = t.splitn(3, '.').collect();
        let (g, exp, mac) = (parts[0], parts[1], parts[2]);
        // A different generation under the same MAC (the guessable-int attack, post-fix shape).
        let forged = format!("41.{exp}.{mac}");
        assert_eq!(
            verify(&k, CONTAINER, ALICE, &forged, 999),
            Err(PinVerifyError::Unminted)
        );
        // A pushed-out expiry.
        let forged = format!("{g}.9999999999.{mac}");
        assert_eq!(
            verify(&k, CONTAINER, ALICE, &forged, 999),
            Err(PinVerifyError::Unminted)
        );
        // A flipped MAC character.
        let flipped: String = {
            let mut m: Vec<u8> = mac.bytes().collect();
            m[0] = if m[0] == b'0' { b'1' } else { b'0' };
            String::from_utf8(m).unwrap()
        };
        let forged = format!("{g}.{exp}.{flipped}");
        assert_eq!(
            verify(&k, CONTAINER, ALICE, &forged, 999),
            Err(PinVerifyError::Unminted)
        );
    }

    #[test]
    fn malformed_shapes_are_unminted_never_a_panic() {
        let k = key();
        let real_mac = "a".repeat(MAC_HEX_LEN);
        for bad in [
            "",
            "7",                                  // the bare-u64 legacy/guess shape
            "18446744073709551615",               // bare u64::MAX
            "7.1000",                             // missing MAC
            "7.1000.",                            // empty MAC
            "7..",                                // empty fields
            &format!(".1000.{real_mac}"),         // empty generation
            &format!("+7.1000.{real_mac}"),       // non-canonical sign
            &format!("7.+1000.{real_mac}"),       // non-canonical sign (expiry)
            &format!("07a.1000.{real_mac}"),      // non-decimal generation
            &format!("99999999999999999999.1000.{real_mac}"), // u64 overflow
            &format!("7.1000.{}", "a".repeat(63)),            // short MAC
            &format!("7.1000.{}", "a".repeat(65)),            // long MAC
            &format!("7.1000.{}", "A".repeat(MAC_HEX_LEN)),   // uppercase (non-canonical) hex
            &format!("7.1000.{}", "z".repeat(MAC_HEX_LEN)),   // non-hex
            &format!("7.1000.1.{}", "a".repeat(62)),          // 4th field folded into a bad MAC
        ] {
            assert_eq!(
                verify(&k, CONTAINER, ALICE, bad, 0),
                Err(PinVerifyError::Unminted),
                "must be Unminted: {bad:?}"
            );
        }
    }

    #[test]
    fn expiry_is_exclusive_and_only_reported_for_genuine_tokens() {
        let k = key();
        let t = mint(&k, CONTAINER, ALICE, 42, 1_000);
        // Strictly before expiry: valid; AT expiry (and after): expired — a zero TTL therefore
        // means immediately-expired, never never-expiring.
        assert_eq!(verify(&k, CONTAINER, ALICE, &t, 999), Ok(42));
        assert_eq!(
            verify(&k, CONTAINER, ALICE, &t, 1_000),
            Err(PinVerifyError::Expired)
        );
        assert_eq!(
            verify(&k, CONTAINER, ALICE, &t, u64::MAX),
            Err(PinVerifyError::Expired)
        );
        // MAC-before-expiry: an EXPIRED-looking FORGED token is Unminted, not Expired (a guess
        // must never learn it named a once-valid pin).
        let forged = format!("42.1.{}", "a".repeat(MAC_HEX_LEN));
        assert_eq!(
            verify(&k, CONTAINER, ALICE, &forged, u64::MAX),
            Err(PinVerifyError::Unminted)
        );
    }

    #[test]
    fn keys_are_unique_per_generate_and_debug_redacted() {
        let a = key();
        let b = key();
        let t = mint(&a, CONTAINER, ALICE, 1, 10);
        assert_eq!(
            verify(&b, CONTAINER, ALICE, &t, 5),
            Err(PinVerifyError::Unminted),
            "two generated keys must not verify each other's tokens"
        );
        assert_eq!(format!("{a:?}"), "PinKey(..)", "key material never Debug-prints");
    }
}
