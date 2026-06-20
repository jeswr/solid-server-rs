// AUTHORED-BY Claude Opus 4.8
//! The composite [`Store`] — the LDP handler's single view of storage.
//!
//! A [`Store`] reads/writes RDF + metadata via [`SparqClient`] (authoritative) and bytes via
//! [`BlobStore`] (backup), mirroring the production server's S3+index composite. The default impl,
//! [`CompositeStore`], wires the two seams together; both seams have in-memory test doubles so the
//! whole stack is testable without a running SPARQ or S3.

pub mod blob;
pub mod sparq;

use async_trait::async_trait;
use bytes::Bytes;

pub use blob::{BlobError, BlobStore, InMemoryBlobStore};
pub use sparq::{InMemorySparqClient, ResourceMeta, SparqClient, SparqError};

use crate::error::{ServerError, ServerResult};

/// A resource as the LDP handler sees it: bytes + the authoritative metadata.
#[derive(Debug, Clone)]
pub struct Resource {
    pub body: Bytes,
    pub meta: ResourceMeta,
}

/// The composite storage seam used by the LDP handlers.
///
/// M1 covers the single-resource GET/HEAD/PUT path. M2 extends it with containers/containment,
/// DELETE, conditional writes (the ETag CAS), and the reconciler that GCs orphaned bytes/index rows.
#[async_trait]
pub trait Store: Send + Sync {
    /// Read a resource by IRI: its authoritative metadata (SPARQ) + its bytes (blob store).
    async fn read(&self, iri: &str) -> ServerResult<Resource>;

    /// Whether a resource exists (the authoritative SPARQ existence check — never an S3 HEAD).
    async fn exists(&self, iri: &str) -> ServerResult<bool>;

    /// Create-or-replace a resource: write the bytes, then the authoritative metadata.
    async fn write(&self, iri: &str, body: Bytes, content_type: &str)
        -> ServerResult<ResourceMeta>;
}

/// The default [`Store`]: SPARQ (authoritative metadata) + a blob store (backup bytes).
pub struct CompositeStore<S: SparqClient, B: BlobStore> {
    sparq: S,
    blob: B,
}

impl<S: SparqClient, B: BlobStore> CompositeStore<S, B> {
    pub fn new(sparq: S, blob: B) -> Self {
        Self { sparq, blob }
    }

    /// Derive the opaque blob-store key for an IRI.
    ///
    /// M2: this is the production server's `KeyMapper` — a stable, collision-free,
    /// directory-traversal-safe mapping. The M1 placeholder is a simple percent-flattening that is
    /// deterministic and reversible enough for the slice's tests.
    fn blob_key_for(iri: &str) -> String {
        // Replace the few path-structural characters; the IRI is already opaque to the blob store.
        iri.replace([':', '/', '?', '#', '%'], "_")
    }

    /// A trivial, deterministic ETag for the slice. M2: derive it from the SPARQ index state so it
    /// participates in the conditional-request CAS (If-None-Match/If-Match).
    fn etag_for(body: &Bytes) -> String {
        format!("\"{}-{}\"", body.len(), fnv1a(body))
    }
}

#[async_trait]
impl<S: SparqClient, B: BlobStore> Store for CompositeStore<S, B> {
    async fn read(&self, iri: &str) -> ServerResult<Resource> {
        // Authoritative existence + metadata FIRST (SPARQ), then fetch the bytes it points at.
        let meta = match self.sparq.get_meta(iri).await {
            Ok(m) => m,
            Err(SparqError::NotFound) => return Err(ServerError::NotFound),
            Err(SparqError::Backend(e)) => return Err(ServerError::Storage(e)),
        };
        let body = self.blob.get(&meta.blob_key).await.map_err(|e| match e {
            // The index says it exists but bytes are missing: a reconciler-class inconsistency.
            // M2: the reconciler resolves this; for the slice we surface it as a storage error.
            BlobError::NotFound => ServerError::Storage("byte/index inconsistency".into()),
            BlobError::Backend(msg) => ServerError::Storage(msg),
        })?;
        Ok(Resource { body, meta })
    }

    async fn exists(&self, iri: &str) -> ServerResult<bool> {
        self.sparq
            .exists(iri)
            .await
            .map_err(|e| ServerError::Storage(format!("{e}")))
    }

    async fn write(
        &self,
        iri: &str,
        body: Bytes,
        content_type: &str,
    ) -> ServerResult<ResourceMeta> {
        // Crash-consistency: bytes FIRST, then the authoritative index (spike §6). On an index-write
        // failure the production server issues a compensating delete; M2 ports that + the reconciler.
        let blob_key = Self::blob_key_for(iri);
        let etag = Self::etag_for(&body);
        self.blob
            .put(&blob_key, body)
            .await
            .map_err(|e| ServerError::Storage(format!("{e}")))?;
        let meta = ResourceMeta {
            content_type: content_type.to_string(),
            blob_key,
            etag,
        };
        self.sparq
            .put_meta(iri, meta.clone())
            .await
            .map_err(|e| ServerError::Storage(format!("{e}")))?;
        Ok(meta)
    }
}

/// A tiny FNV-1a hash used only for the placeholder ETag (NOT a cryptographic digest).
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
