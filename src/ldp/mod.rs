// AUTHORED-BY Claude Opus 4.8
//! The LDP / Solid Protocol request path (M1 slice).
//!
//! - [`target`] — request-URL / LDP-target parsing (pure value logic).
//! - [`content`] — Turtle / JSON-LD content-type classification + RDF validation.
//! - [`handler`] — the GET / HEAD / PUT axum handlers over the [`crate::store::Store`] seam.
//!
//! M2 extends this with the rest of the verb set (POST/DELETE/PATCH), Range + conditional requests,
//! full content negotiation, and containment/container semantics.

pub mod content;
pub mod handler;
pub mod target;
