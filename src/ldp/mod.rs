// AUTHORED-BY Claude Opus 4.8
//! The LDP / Solid Protocol request path (M1 + the M2 verb-completion slice).
//!
//! - [`target`] — request-URL / LDP-target parsing (pure value logic).
//! - [`content`] — Turtle / JSON-LD classification, RDF validation, re-serialisation, and `Accept`
//!   content negotiation.
//! - [`conditional`] — `If-Match` / `If-None-Match` precondition evaluation over the strong ETag.
//! - [`range`] — single `Range: bytes=…` request handling (206 / 416).
//! - [`patch`] — the Solid N3-Patch engine (`text/n3`): insert/delete plus the `solid:where`
//!   variable solver (basic-graph-pattern matching with the spec's exactly-one-solution rule).
//! - [`handler`] — the GET / HEAD / PUT / POST / DELETE / PATCH axum handlers over the
//!   [`crate::store::Store`] seam.
//!
//! M2-next (clearly seamed, not implemented): full WAC authorization (needs the SPARQ access-control
//! design), multipart Range, and `application/sparql-update` PATCH.

pub mod conditional;
pub mod content;
pub mod handler;
pub mod patch;
pub mod range;
pub mod target;
