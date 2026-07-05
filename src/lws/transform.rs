// AUTHORED-BY Claude Fable 5
//! The **RDF content-transformation opt-in** (`rdf-transform.html` — the `rdf-1` profile).
//!
//! With the `ContentNegotiation` capability on, a stored RDF representation (`text/turtle` /
//! `application/ld+json` — the advertised SOURCES) can be read as any advertised TARGET:
//! `text/turtle`, `application/ld+json`, or `application/n-triples`. The contract implemented
//! here, per the spec:
//!
//! - **§round-trip (`rdf-1`)**: the derived representation encodes an RDF graph isomorphic to the
//!   authoritative one — the transform is parse (via the EXISTING [`crate::ldp::content`] path,
//!   which resolves relative IRIs against the resource URI and is SSRF-safe: oxjsonld performs no
//!   remote `@context` fetches by construction) → serialise, with no inference and nothing
//!   added/removed. N-Triples output uses `oxttl`'s serializer (never hand-concatenated RDF).
//! - **§authoritative-bytes**: the stored byte stream is authoritative — a read in the stored
//!   media type returns it verbatim (this store declares no `normalizes`); derived representations
//!   carry per-representation entity-tags (`"<state>+ttl"` / `"+jsonld"` / `"+nt"` via
//!   [`crate::ldp::conditional::variant_etag`]) that rotate whenever the resource state changes,
//!   and `Vary: Accept` rides on the read path (already emitted by `serve_read`). `If-Match` with
//!   EITHER representation's current tag is accepted — the existing state-part comparison in
//!   [`crate::ldp::conditional`] already implements exactly that rule, unchanged.
//! - **§round-trip, unparseable source**: if the stored bytes fail to parse under the stored type,
//!   a request for a DERIVED representation is a 406 with problem details
//!   ([`super::PROBLEM_UNPARSEABLE_SOURCE`]) — the stored bytes remain readable in the stored
//!   type (the byte store never breaks because a transform does). Unreachable through this
//!   server's own write path (RDF writes are parse-validated), but implemented for spec fidelity.
//! - **§authoritative-bytes, writes in a derived type**: [`write_type_guard`] — a PUT whose
//!   `Content-Type` is an advertised TARGET that is NOT itself an advertised SOURCE
//!   (`application/n-triples` in this capability matrix) over an existing RDF-readable resource is
//!   a **415** with problem details, because accepting it would flip the stored type to one the
//!   server cannot transform FROM, stranding the resource and silently breaking the advertised
//!   negotiation targets.
//!
//! ## Equivalence with the flag-off surface (load-bearing)
//! For any `Accept` header whose resolution does not select `application/n-triples`, the
//! negotiation here returns EXACTLY what [`content::negotiate_accept`] returns (same q rules, same
//! wildcard coverage — `text/*` ⇒ Turtle only, `application/*` ⇒ JSON-LD only, never N-Triples —
//! same stored-format tie-break), so turning the opt-in ON does not change any response the Solid
//! surface already produced; it only makes previously-406 N-Triples requests succeed. Pinned by
//! the property test below and the HTTP-level tests.

use bytes::Bytes;
use oxrdf::Triple;

use crate::error::ServerError;
use crate::ldp::conditional::variant_etag;
use crate::ldp::content::{self, parse_to_triples, serialize_triples, RdfFormat};

use super::{PROBLEM_NOT_A_SOURCE, PROBLEM_UNPARSEABLE_SOURCE};

/// A representation format negotiable under the transform opt-in: the two existing RDF formats
/// plus the target-only N-Triples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LwsFormat {
    Turtle,
    JsonLd,
    NTriples,
}

impl LwsFormat {
    /// The canonical media type string.
    pub fn media_type(self) -> &'static str {
        match self {
            LwsFormat::Turtle => "text/turtle",
            LwsFormat::JsonLd => "application/ld+json",
            LwsFormat::NTriples => "application/n-triples",
        }
    }

    /// The `+<variant>` ETag suffix token (kept short and `+`-free so the state-part split in
    /// [`crate::ldp::conditional`] stays unambiguous — same rule as the handler's
    /// `variant_suffix`).
    fn variant_suffix(self) -> &'static str {
        match self {
            LwsFormat::Turtle => "ttl",
            LwsFormat::JsonLd => "jsonld",
            LwsFormat::NTriples => "nt",
        }
    }

    fn from_rdf(f: RdfFormat) -> Self {
        match f {
            RdfFormat::Turtle => LwsFormat::Turtle,
            RdfFormat::JsonLd => LwsFormat::JsonLd,
        }
    }
}

/// Negotiate the response format for an RDF-readable resource under the transform opt-in.
///
/// Mirrors [`content::negotiate_accept`] EXACTLY for the Turtle/JSON-LD domain (same q defaults,
/// clamping, wildcard coverage, and stored-format tie-break), adding `application/n-triples` as an
/// EXPLICIT-ONLY concrete type: no wildcard (`text/*`, `application/*`, `*/*`) ever selects it, and
/// it wins only with a STRICTLY higher weight than both existing types — so every `Accept` the
/// existing surface satisfied resolves identically, and N-Triples is chosen exactly when the
/// client named it and preferred it.
pub fn negotiate(accept: Option<&str>, stored: RdfFormat) -> Option<LwsFormat> {
    let raw = match accept {
        None => return Some(LwsFormat::from_rdf(stored)),
        Some(s) if s.trim().is_empty() => return Some(LwsFormat::from_rdf(stored)),
        Some(s) => s,
    };

    // N-Triples weight: EXPLICIT parts only (wildcards keep their existing meaning).
    let mut q_nt = 0.0f32;
    for part in raw.split(',') {
        let (media, q, _) = super::parse_accept_part(part);
        if media == "application/n-triples" {
            q_nt = q_nt.max(q);
        }
    }

    // The existing two-way resolution (unchanged semantics — delegated, not re-implemented).
    let existing = content::negotiate_accept(accept, stored);

    if q_nt > 0.0 {
        // N-Triples wins only with a STRICTLY higher weight than every existing producible type —
        // computed with the same effective-q rules the existing negotiator applies.
        let (q_turtle, q_jsonld) = effective_existing_q(raw);
        if q_nt > q_turtle && q_nt > q_jsonld {
            return Some(LwsFormat::NTriples);
        }
    }
    existing.map(LwsFormat::from_rdf)
}

/// The effective weights [`content::negotiate_accept`] assigns to Turtle and JSON-LD for `raw`:
/// an explicit q wins, else the most specific applicable wildcard (`text/*` covers Turtle only;
/// `application/*` covers JSON-LD only), else `*/*`. Kept in lock-step with that function (the
/// equivalence property test cross-checks the resulting DECISIONS on an N-Triples-free corpus).
fn effective_existing_q(raw: &str) -> (f32, f32) {
    let mut q_turtle: Option<f32> = None;
    let mut q_jsonld: Option<f32> = None;
    let mut q_text_star: Option<f32> = None;
    let mut q_app_star: Option<f32> = None;
    let mut q_any: Option<f32> = None;
    fn bump(slot: &mut Option<f32>, q: f32) {
        *slot = Some(slot.unwrap_or(0.0).max(q));
    }
    for part in raw.split(',') {
        let (media, q, _) = super::parse_accept_part(part);
        match media.as_str() {
            "text/turtle" => bump(&mut q_turtle, q),
            "application/ld+json" => bump(&mut q_jsonld, q),
            "text/*" => bump(&mut q_text_star, q),
            "application/*" => bump(&mut q_app_star, q),
            "*/*" => bump(&mut q_any, q),
            _ => {}
        }
    }
    (
        q_turtle.or(q_text_star).or(q_any).unwrap_or(0.0),
        q_jsonld.or(q_app_star).or(q_any).unwrap_or(0.0),
    )
}

/// The validator (ETag) a read of this resource under `accept` carries, with the transform on —
/// the per-representation entity-tag rule of §authoritative-bytes (RFC 9110 §8.8.3), computed
/// WITHOUT serialising a body (the read-304 fast path, exactly like the flag-off
/// `negotiated_validator`):
///
/// - non-RDF stored content ⇒ the stored tag (byte-native, one representation);
/// - the stored format itself ⇒ the stored tag (the authoritative representation);
/// - a derived format ⇒ `"<state>+<variant>"` — distinct per representation, rotating with the
///   state, and write-precondition-compatible via the state-part comparison.
pub fn negotiated_validator(
    stored_etag: &str,
    stored_content_type: &str,
    accept: Option<&str>,
) -> Result<String, ServerError> {
    let Ok(stored_format) = content::classify(Some(stored_content_type)) else {
        // Non-RDF stored content: byte-native, no transform — the stored tag whatever the Accept.
        return Ok(stored_etag.to_string());
    };
    let chosen = negotiate(accept, stored_format).ok_or(ServerError::NotAcceptable)?;
    Ok(if chosen == LwsFormat::from_rdf(stored_format) {
        stored_etag.to_string()
    } else {
        variant_etag(stored_etag, chosen.variant_suffix())
    })
}

/// Content-negotiate the response body with the transform on. Non-RDF stored bytes pass through
/// verbatim (byte-native); the stored format is returned byte-exact (authoritative bytes, no
/// `normalizes`); a derived format is parse → serialise per the `rdf-1` contract. The format
/// decision is the same [`negotiate`] call [`negotiated_validator`] makes, so the validator and
/// the body it labels can never disagree.
pub fn negotiate_body(
    stored_body: &Bytes,
    stored_content_type: &str,
    accept: Option<&str>,
    base_iri: &str,
) -> Result<(Bytes, String), ServerError> {
    let stored_format = match content::classify(Some(stored_content_type)) {
        Ok(f) => f,
        // Non-RDF stored content: byte-native passthrough (identical to the flag-off branch).
        Err(_) => return Ok((stored_body.clone(), stored_content_type.to_string())),
    };
    let chosen = negotiate(accept, stored_format).ok_or(ServerError::NotAcceptable)?;
    if chosen == LwsFormat::from_rdf(stored_format) {
        // The authoritative representation: the stored bytes, verbatim (§authoritative-bytes).
        return Ok((stored_body.clone(), stored_content_type.to_string()));
    }
    // A DERIVED representation: parse the authoritative bytes, reserialise. A stored body that
    // fails to parse under its stored type degrades per-resource to a 406 problem
    // (§round-trip) — the stored type remains readable.
    let triples = parse_to_triples(stored_format, stored_body, base_iri).map_err(|_| {
        ServerError::LwsProblem {
            status: 406,
            type_uri: PROBLEM_UNPARSEABLE_SOURCE,
            title: "the stored representation does not parse under its stored media type; \
                    the resource remains readable in its stored type",
        }
    })?;
    let bytes = match chosen {
        LwsFormat::NTriples => serialize_ntriples(&triples)?,
        LwsFormat::Turtle => serialize_triples(RdfFormat::Turtle, &triples)?,
        LwsFormat::JsonLd => serialize_triples(RdfFormat::JsonLd, &triples)?,
    };
    Ok((Bytes::from(bytes), chosen.media_type().to_string()))
}

/// Serialise a triple set as N-Triples via `oxttl` (the house rule: never hand-concatenate RDF).
fn serialize_ntriples(triples: &[Triple]) -> Result<Vec<u8>, ServerError> {
    let mut ser = oxttl::NTriplesSerializer::new().for_writer(Vec::new());
    for t in triples {
        ser.serialize_triple(t)
            .map_err(|e| ServerError::Storage(format!("n-triples serialise: {e}")))?;
    }
    Ok(ser.finish())
}

/// The §authoritative-bytes WRITE guard: reject (415 + problem details) a PUT whose
/// `Content-Type` is an advertised TARGET that is not itself an advertised SOURCE
/// (`application/n-triples` in this capability matrix) over an EXISTING resource whose stored
/// type IS an advertised source. Accepting it would make N-Triples the new stored type — one the
/// server cannot transform from — stranding the resource and silently breaking the negotiation
/// targets advertised for it.
///
/// Scope (deliberately narrow, so the composed Solid surface changes minimally when the opt-in is
/// on): a CREATE with N-Triples content, and any write over a NON-RDF-readable resource, are
/// untouched — those are plain byte-native resources with no transform expectations.
pub fn write_type_guard(
    current_stored_type: Option<&str>,
    written_content_type: &str,
) -> Result<(), ServerError> {
    let Some(current) = current_stored_type else {
        return Ok(()); // A create: no stored representation to strand.
    };
    if content::classify(Some(current)).is_err() {
        return Ok(()); // The existing resource is not RDF-readable: byte-native, no contract.
    }
    let essence = written_content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if essence == "application/n-triples" {
        return Err(ServerError::LwsProblem {
            status: 415,
            type_uri: PROBLEM_NOT_A_SOURCE,
            title: "application/n-triples is an advertised transformation target but not a \
                    source; writing it over an RDF-readable resource would strand the resource — \
                    write text/turtle or application/ld+json",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IRI: &str = "https://pod.example/alice/data";
    const TURTLE: &str =
        "<https://pod.example/alice/data#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .";

    /// The load-bearing equivalence property: for an N-Triples-free Accept corpus, [`negotiate`]
    /// resolves EXACTLY as the existing [`content::negotiate_accept`] — turning the opt-in on
    /// changes no response the Solid surface already produced.
    #[test]
    fn negotiation_matches_existing_surface_when_ntriples_absent() {
        let corpus: &[Option<&str>] = &[
            None,
            Some(""),
            Some("*/*"),
            Some("text/turtle"),
            Some("application/ld+json"),
            Some("text/*"),
            Some("application/*"),
            Some("text/html"),
            Some("application/xml"),
            Some("text/turtle;q=0.5, application/ld+json;q=0.9"),
            Some("text/turtle;q=0, application/ld+json"),
            Some("text/*;q=0.3, application/ld+json;q=0.9"),
            Some("application/json, text/turtle;q=0.5"),
            Some("text/turtle;q=abc"),
            Some("application/ld+json;profile=\"https://w3id.org/jeswr/lws/v1\""),
        ];
        for stored in [RdfFormat::Turtle, RdfFormat::JsonLd] {
            for accept in corpus {
                let existing = content::negotiate_accept(*accept, stored);
                let lws = negotiate(*accept, stored);
                assert_eq!(
                    lws,
                    existing.map(LwsFormat::from_rdf),
                    "divergence for accept={accept:?} stored={stored:?}"
                );
            }
        }
    }

    #[test]
    fn explicit_ntriples_is_negotiable() {
        // Alone: previously 406, now N-Triples.
        assert_eq!(
            negotiate(Some("application/n-triples"), RdfFormat::Turtle),
            Some(LwsFormat::NTriples)
        );
        // Strictly preferred by weight: wins.
        assert_eq!(
            negotiate(
                Some("text/turtle;q=0.4, application/n-triples;q=0.9"),
                RdfFormat::Turtle
            ),
            Some(LwsFormat::NTriples)
        );
        // A TIE goes to the pre-existing pair (surface preservation).
        assert_eq!(
            negotiate(
                Some("text/turtle;q=0.5, application/n-triples;q=0.5"),
                RdfFormat::JsonLd
            ),
            Some(LwsFormat::Turtle)
        );
        // Wildcards never select N-Triples.
        assert_eq!(
            negotiate(Some("*/*"), RdfFormat::Turtle),
            Some(LwsFormat::Turtle)
        );
        assert_eq!(
            negotiate(Some("application/*"), RdfFormat::Turtle),
            Some(LwsFormat::JsonLd)
        );
        // q=0 refuses it.
        assert_eq!(
            negotiate(Some("application/n-triples;q=0"), RdfFormat::Turtle),
            None
        );
    }

    #[test]
    fn ntriples_body_is_derived_and_isomorphic() {
        let body = Bytes::from_static(TURTLE.as_bytes());
        let (nt, ct) =
            negotiate_body(&body, "text/turtle", Some("application/n-triples"), IRI).unwrap();
        assert_eq!(ct, "application/n-triples");
        // Round-trip: the derived N-Triples parses back to the same single triple (rdf-1 —
        // isomorphism; no blank nodes here so equality is exact).
        let mut parsed = Vec::new();
        for t in oxttl::NTriplesParser::new().for_slice(&nt) {
            parsed.push(t.unwrap());
        }
        let original = parse_to_triples(RdfFormat::Turtle, &body, IRI).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn stored_type_read_is_byte_exact() {
        // §authoritative-bytes: a read in the stored media type returns the stored bytes VERBATIM
        // (no normalizes declared) — even though a reserialisation would reformat them.
        let body = Bytes::from_static(TURTLE.as_bytes());
        let (out, ct) = negotiate_body(&body, "text/turtle", Some("text/turtle"), IRI).unwrap();
        assert_eq!(out, body);
        assert_eq!(ct, "text/turtle");
    }

    #[test]
    fn validators_are_per_representation_and_share_the_state_part() {
        let stored = "\"42-abc\"";
        let ttl = negotiated_validator(stored, "text/turtle", Some("text/turtle")).unwrap();
        let nt =
            negotiated_validator(stored, "text/turtle", Some("application/n-triples")).unwrap();
        let ld = negotiated_validator(stored, "text/turtle", Some("application/ld+json")).unwrap();
        // Stored format ⇒ the stored tag; derived ⇒ distinct variant tags.
        assert_eq!(ttl, stored);
        assert_ne!(nt, ttl);
        assert_ne!(ld, ttl);
        assert_ne!(nt, ld);
        assert!(nt.contains("+nt"));
        // The write path accepts EITHER representation's tag: the state-part comparison already
        // treats `"42-abc+nt"` as matching the stored state `"42-abc"` (rdf-transform
        // §authoritative-bytes; conditional's GET → If-Match round-trip rule).
        use crate::ldp::conditional::{evaluate, Precondition};
        assert_eq!(
            evaluate(Some(&nt), None, Some(stored)),
            Precondition::Proceed
        );
        assert_eq!(
            evaluate(Some(&ld), None, Some(stored)),
            Precondition::Proceed
        );
        // A STALE derived tag still fails (412) — the state part governs.
        assert_eq!(
            evaluate(Some("\"41-old+nt\""), None, Some(stored)),
            Precondition::Failed
        );
    }

    #[test]
    fn unparseable_source_degrades_to_406_problem() {
        // A derived-representation request over unparseable stored bytes is the LWS 406 problem;
        // the stored type itself stays readable (byte-exact passthrough).
        let body = Bytes::from_static(b"@prefix broken");
        let err =
            negotiate_body(&body, "text/turtle", Some("application/n-triples"), IRI).unwrap_err();
        match err {
            ServerError::LwsProblem {
                status, type_uri, ..
            } => {
                assert_eq!(status, 406);
                assert_eq!(type_uri, PROBLEM_UNPARSEABLE_SOURCE);
            }
            other => panic!("expected LwsProblem, got {other:?}"),
        }
        let (out, _) = negotiate_body(&body, "text/turtle", Some("text/turtle"), IRI).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn write_type_guard_blocks_only_nt_over_rdf() {
        // NT over an RDF-readable resource ⇒ 415 problem (would strand the resource).
        let err = write_type_guard(Some("text/turtle"), "application/n-triples").unwrap_err();
        match err {
            ServerError::LwsProblem {
                status, type_uri, ..
            } => {
                assert_eq!(status, 415);
                assert_eq!(type_uri, PROBLEM_NOT_A_SOURCE);
            }
            other => panic!("expected LwsProblem, got {other:?}"),
        }
        // Everything else passes: a create, NT over a non-RDF resource, and source-type writes.
        assert!(write_type_guard(None, "application/n-triples").is_ok());
        assert!(write_type_guard(Some("text/plain"), "application/n-triples").is_ok());
        assert!(write_type_guard(Some("text/turtle"), "application/ld+json").is_ok());
        assert!(write_type_guard(Some("application/ld+json"), "text/turtle").is_ok());
        assert!(write_type_guard(Some("text/turtle"), "text/plain").is_ok());
        // Parameters on the written type are ignored (essence match).
        assert!(
            write_type_guard(Some("text/turtle"), "application/n-triples; charset=utf-8").is_err()
        );
    }
}
