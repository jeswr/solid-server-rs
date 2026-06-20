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
//! ## M1 vertical slice (this crate)
//! A coherent, compiling slice with clean trait seams + tests:
//! - an axum server skeleton ([`app`]) that boots,
//! - DPoP-bound auth middleware ([`auth`]) over the verifier,
//! - GET/HEAD/PUT on a single resource ([`ldp`]) through a [`store::Store`] trait,
//! - LDP target/URL parsing + Turtle/JSON-LD content-type handling ([`ldp::target`], [`ldp::content`]).
//!
//! Everything network-facing (the live SPARQ HTTP client, live JWKS) and the rest of the Solid
//! surface (full WAC, the full LDP verb set, notifications, reconciliation) is a clearly-marked
//! `M2:` seam, not implemented. The default impls used in M1 are in-memory test doubles.

pub mod app;
pub mod auth;
pub mod error;
pub mod ldp;
pub mod store;

pub use app::{build_router, AppState};
pub use error::{ServerError, ServerResult};
