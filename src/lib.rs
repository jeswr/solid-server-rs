// AUTHORED-BY Claude Opus 4.8
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
//! # solid-server-rs (EXPERIMENTAL)
//!
//! An **experimental, parallel-track** Rust reimplementation of a Solid/LDP server. It does **NOT**
//! replace and must **NEVER** touch the production TypeScript
//! [`prod-solid-server`](https://github.com/jeswr/prod-solid-server) (the live, supported server).
//!
//! ## Architecture (the maintainer's directive + the Rust-migration spike)
//! - **SPARQ is authoritative** for RDF data, metadata, containment, AND access-control evaluation —
//!   queried over its HTTP API (the [`store::SparqClient`] seam).
//! - **`object_store`/S3 is backup-only** for resource bytes (the [`store::BlobStore`] seam).
//! - **DPoP/Solid-OIDC verification is delegated** to the standalone
//!   [`solid-oidc-verifier`](https://github.com/jeswr/solid-oidc-verifier) crate (a git dependency).
//!   Auth is **not** reimplemented here. See [`auth`].
//!
//! ## Vertical slice (this crate)
//! A coherent, compiling slice with clean trait seams + tests:
//! - an axum server skeleton ([`app`]) that boots,
//! - DPoP-bound auth middleware ([`auth`]) over the verifier,
//! - the LDP verb surface ([`ldp`]) through a [`store::Store`] trait: GET/HEAD (with `Accept`
//!   content negotiation + `Range`), PUT/POST/DELETE/PATCH (conditional `If-Match`/`If-None-Match`),
//!   POST `Slug`-honouring child creation, the empty-container DELETE refusal, and the Solid N3-Patch
//!   engine (`text/n3`, insert/delete plus the `solid:where` variable solver),
//! - LDP target/URL parsing + Turtle/JSON-LD content handling ([`ldp::target`], [`ldp::content`]).
//!
//! Everything network-facing (the live SPARQ HTTP client, live JWKS) and the parts of the Solid
//! surface that need designs not yet written (full WAC authorization, notifications, the reconciler,
//! multipart Range, SPARQL-Update PATCH) are clearly
//! marked `M2-next:` seams, not implemented. The default impls used here are in-memory test doubles.

pub mod app;
pub mod auth;
pub mod error;
pub mod ldp;
pub mod store;
pub mod tls;

pub use app::{build_router, AppState};
pub use error::{ServerError, ServerResult};
