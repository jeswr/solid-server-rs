// AUTHORED-BY Claude Opus 4.8
//! The SPARQ client seam — the **authoritative** source for RDF data, metadata, and containment.
//!
//! Per the maintainer's directive, SPARQ (queried over its HTTP API) is the system of record for the
//! resource graph and its metadata (existence, content type, the `s3Key` byte-pointer). Read paths
//! consult SPARQ, **not** an S3 LIST/HEAD (the same "QLever/SPARQ is the source of truth" invariant
//! as the production server). This module defines the [`SparqClient`] trait + an in-memory test impl.
//!
//! M2: the live HTTP client (a SPARQL Query/Update client over SPARQ's endpoint, with the bearer
//! gating SPARQ requires for UPDATE) plugs in behind this trait. It needs a running SPARQ instance,
//! so it is exercised by an integration test, not the M1 unit tests.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

/// The authoritative metadata SPARQ holds for a resource (the index record, not the bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMeta {
    /// The RDF content type the resource was stored as (e.g. `text/turtle`).
    pub content_type: String,
    /// The opaque blob-store key the bytes live under (the `pss:s3Key` pointer).
    pub blob_key: String,
    /// An opaque entity tag for conditional requests. M2: derived from the SPARQ index state.
    pub etag: String,
}

/// A SPARQ-client error (opaque — never leaks backend detail to a client).
#[derive(Debug, thiserror::Error)]
pub enum SparqError {
    #[error("resource not indexed")]
    NotFound,
    #[error("sparq backend error: {0}")]
    Backend(String),
}

/// The authoritative RDF index over SPARQ.
///
/// In M1 only the metadata-record operations needed by GET/HEAD/PUT are defined. M2 extends this
/// with containment membership, the `usage()` quota view, and the WAC/ACP ACL-document graphs that
/// the (future) access-evaluation step reads.
#[async_trait]
pub trait SparqClient: Send + Sync {
    /// Fetch the authoritative metadata for a resource IRI, or [`SparqError::NotFound`].
    async fn get_meta(&self, iri: &str) -> Result<ResourceMeta, SparqError>;

    /// Upsert the authoritative metadata record for a resource IRI.
    async fn put_meta(&self, iri: &str, meta: ResourceMeta) -> Result<(), SparqError>;

    /// Whether the resource is indexed (the authoritative existence check — never an S3 HEAD).
    async fn exists(&self, iri: &str) -> Result<bool, SparqError>;
}

/// An in-memory [`SparqClient`] for tests and the M1 boot-without-SPARQ path.
#[derive(Default)]
pub struct InMemorySparqClient {
    inner: Mutex<HashMap<String, ResourceMeta>>,
}

impl InMemorySparqClient {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SparqClient for InMemorySparqClient {
    async fn get_meta(&self, iri: &str) -> Result<ResourceMeta, SparqError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        guard.get(iri).cloned().ok_or(SparqError::NotFound)
    }

    async fn put_meta(&self, iri: &str, meta: ResourceMeta) -> Result<(), SparqError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        guard.insert(iri.to_string(), meta);
        Ok(())
    }

    async fn exists(&self, iri: &str) -> Result<bool, SparqError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SparqError::Backend("poisoned".into()))?;
        Ok(guard.contains_key(iri))
    }
}
