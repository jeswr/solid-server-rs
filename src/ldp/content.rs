// AUTHORED-BY Claude Opus 4.8
//! RDF content-type handling for the LDP path.
//!
//! M1 supports the two RDF formats the production server allows: **Turtle** and **JSON-LD** (the
//! house rule — `oxttl` for Turtle, `oxjsonld` for JSON-LD, per the spike §4). This module classifies
//! a media type and validates that a body parses as RDF in that format, returning the parsed quad
//! count (proof the body is well-formed RDF) without retaining the graph — the slice stores bytes
//! verbatim and lets SPARQ be authoritative for the triples.
//!
//! M2: full content negotiation (an `Accept`-driven serialisation choice), N-Triples/N-Quads/N3,
//! and the JSON-LD `noRemoteContextLoader` SSRF posture (oxjsonld is local-only by construction, so
//! that posture ports favourably).

use oxjsonld::JsonLdParser;
use oxttl::TurtleParser;

use crate::error::ServerError;

/// A supported RDF media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdfFormat {
    Turtle,
    JsonLd,
}

impl RdfFormat {
    /// The canonical media type string.
    pub fn media_type(self) -> &'static str {
        match self {
            RdfFormat::Turtle => "text/turtle",
            RdfFormat::JsonLd => "application/ld+json",
        }
    }
}

/// Classify a `Content-Type` header value into a supported [`RdfFormat`].
///
/// The media-type is matched case-insensitively and any parameters (e.g. `; charset=utf-8`) are
/// ignored. An unsupported or absent type is an [`ServerError::UnsupportedMediaType`] — the LDP
/// surface accepts only RDF on this slice's single-resource PUT path.
pub fn classify(content_type: Option<&str>) -> Result<RdfFormat, ServerError> {
    let raw = content_type.ok_or_else(|| ServerError::UnsupportedMediaType("missing".into()))?;
    let essence = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match essence.as_str() {
        "text/turtle" => Ok(RdfFormat::Turtle),
        "application/ld+json" => Ok(RdfFormat::JsonLd),
        other => Err(ServerError::UnsupportedMediaType(other.to_string())),
    }
}

/// Validate that `body` parses as RDF in `format`, returning the number of triples/quads parsed.
///
/// `base_iri` is the resource's own IRI: per the LDP/RDF convention a server resolves relative IRIs
/// in a submitted document against the request URI, so a document that uses relative IRIs is valid.
/// This proves the body is well-formed RDF before the slice stores it. The parsed graph is NOT
/// retained — SPARQ is the authoritative triple store; the blob store keeps the bytes verbatim.
pub fn validate_rdf(format: RdfFormat, body: &[u8], base_iri: &str) -> Result<usize, ServerError> {
    match format {
        RdfFormat::Turtle => {
            let parser = TurtleParser::new()
                .with_base_iri(base_iri)
                .map_err(|e| ServerError::BadRequest(format!("invalid base IRI: {e}")))?;
            let mut count = 0usize;
            for triple in parser.for_slice(body) {
                triple.map_err(|e| ServerError::BadRequest(format!("invalid Turtle: {e}")))?;
                count += 1;
            }
            Ok(count)
        }
        RdfFormat::JsonLd => {
            // oxjsonld is local-only by construction (no remote context loader) — the SSRF-safe
            // posture the production server enforces explicitly is the default here.
            let parser = JsonLdParser::new()
                .with_base_iri(base_iri)
                .map_err(|e| ServerError::BadRequest(format!("invalid base IRI: {e}")))?;
            let mut count = 0usize;
            for quad in parser.for_slice(body) {
                quad.map_err(|e| ServerError::BadRequest(format!("invalid JSON-LD: {e}")))?;
                count += 1;
            }
            Ok(count)
        }
    }
}
