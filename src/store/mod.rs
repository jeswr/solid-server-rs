// AUTHORED-BY Claude Opus 4.8
//! The composite [`Store`] — the LDP handler's single view of storage.
//!
//! A [`Store`] reads/writes RDF + metadata via [`SparqClient`] (authoritative) and bytes via
//! [`BlobStore`] (backup), mirroring prod-solid-server's S3+index composite. The default impl,
//! [`CompositeStore`], wires the two seams together; both seams have in-memory test doubles so the
//! whole stack is testable without a running SPARQ or S3.

pub mod blob;
pub mod http;
pub mod sparq;
pub mod sparql;

use async_trait::async_trait;
use bytes::Bytes;

pub use blob::{BlobError, BlobStore, InMemoryBlobStore};
pub use http::{HttpSparqClient, SparqHttpError};
pub use sparq::{DeleteOutcome, InMemorySparqClient, ResourceMeta, SparqClient, SparqError};
pub use sparql::{BodyObject, BuildError};

use crate::error::{ServerError, ServerResult};

/// A resource as the LDP handler sees it: bytes + the authoritative metadata.
#[derive(Debug, Clone)]
pub struct Resource {
    pub body: Bytes,
    pub meta: ResourceMeta,
}

/// The composite storage seam used by the LDP handlers.
///
/// M1 covered the single-resource GET/HEAD/PUT path. M2 adds DELETE, containment (POST mints a child
/// + records membership; an empty-container check governs DELETE), and the metadata needed for the
/// conditional-write ETag CAS (the [`ResourceMeta::etag`] the handler compares).
///
/// Next: the reconciler that GCs orphaned bytes/index rows after a crash between the byte and index
/// writes. Container delete is supported for EMPTY containers — the handler refuses a non-empty one
/// with 409 (the conservative spec choice); an opt-in recursive/cascade delete is intentionally not
/// offered yet.
#[async_trait]
pub trait Store: Send + Sync {
    /// Read a resource by IRI: its authoritative metadata (SPARQ) + its bytes (blob store).
    async fn read(&self, iri: &str) -> ServerResult<Resource>;

    /// Fetch just the authoritative metadata for a resource IRI (no bytes), or `None` if absent.
    ///
    /// Used by the conditional-request path to learn the current ETag without paying for the body.
    async fn meta(&self, iri: &str) -> ServerResult<Option<ResourceMeta>>;

    /// Whether a resource exists (the authoritative SPARQ existence check — never an S3 HEAD).
    async fn exists(&self, iri: &str) -> ServerResult<bool>;

    /// Create-or-replace a resource: write the bytes, then the authoritative metadata.
    async fn write(&self, iri: &str, body: Bytes, content_type: &str)
        -> ServerResult<ResourceMeta>;

    /// Create a resource AND record it as a child of `container` (the POST containment path). The
    /// `child` IRI is the server-minted target. Returns the new resource's metadata.
    async fn create_in_container(
        &self,
        container: &str,
        child: &str,
        body: Bytes,
        content_type: &str,
    ) -> ServerResult<ResourceMeta>;

    /// Delete a resource: remove its index record + its bytes, and detach it from `parent`'s
    /// containment (if `parent` is given). The caller is responsible for the existence (404) and
    /// empty-container (409) decisions; this performs the removal.
    ///
    /// This is the NON-container delete path. A CONTAINER delete must instead go through
    /// [`delete_container_if_empty`](Store::delete_container_if_empty), which folds the empty-check
    /// into the delete atomically.
    async fn delete(&self, iri: &str, parent: Option<&str>) -> ServerResult<()>;

    /// ATOMICALLY delete a container ONLY if it is empty (the container-DELETE path).
    ///
    /// The membership check (`ldp:contains` empty?) and the delete are performed as ONE store
    /// operation with NO interleaving between them, so a child POSTed concurrently can never slip in
    /// between an empty-check and the delete and be orphaned under a deleted container (the TOCTOU the
    /// separate `list_children` + `delete` had). It detaches the container from `parent`'s
    /// containment (if given) only AFTER a successful [`DeleteOutcome::Deleted`], and removes the
    /// container's own bytes. Returns:
    /// - [`DeleteOutcome::Deleted`] — it existed, was empty, and is gone;
    /// - [`DeleteOutcome::NotEmpty`] — it existed with members; NOTHING was deleted (⇒ 409);
    /// - [`DeleteOutcome::NotFound`] — it did not exist (⇒ 404).
    async fn delete_container_if_empty(
        &self,
        iri: &str,
        parent: Option<&str>,
    ) -> ServerResult<DeleteOutcome>;

    /// List the direct children (their IRIs) of a container — the authoritative `ldp:contains`
    /// membership. Used for the empty-container DELETE refusal.
    async fn list_children(&self, container: &str) -> ServerResult<Vec<String>>;
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
    /// M2: this is prod-solid-server's `KeyMapper` — a stable, collision-free,
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

    async fn meta(&self, iri: &str) -> ServerResult<Option<ResourceMeta>> {
        match self.sparq.get_meta(iri).await {
            Ok(m) => Ok(Some(m)),
            Err(SparqError::NotFound) => Ok(None),
            Err(SparqError::Backend(e)) => Err(ServerError::Storage(e)),
        }
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
        // failure prod-solid-server issues a compensating delete; M2 ports that + the reconciler.
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

    async fn create_in_container(
        &self,
        container: &str,
        child: &str,
        body: Bytes,
        content_type: &str,
    ) -> ServerResult<ResourceMeta> {
        // Write the bytes FIRST (content-addressed by key; idempotent), then commit the child's
        // metadata AND its containment edge in ONE atomic index operation (`create_child`). Because
        // the metadata + the edge commit together, there is no window in which the edge exists
        // without backing metadata — so the POST path needs NO removal-based compensation and a
        // concurrent same-IRI creator can never observe or tear down a half-built containment. A
        // missing container ⇒ 404; the bytes written above are then orphaned and GC'd by the
        // reconciler (M2-next) — the same crash-consistency model `write` documents.
        let blob_key = Self::blob_key_for(child);
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
        match self
            .sparq
            .create_child(container, child, meta.clone())
            .await
        {
            Ok(()) => Ok(meta),
            Err(SparqError::NotFound) => Err(ServerError::NotFound),
            Err(SparqError::Backend(e)) => Err(ServerError::Storage(e)),
        }
    }

    async fn delete(&self, iri: &str, parent: Option<&str>) -> ServerResult<()> {
        // Look up the byte-pointer from the authoritative index so we delete the right blob.
        let blob_key = match self.sparq.get_meta(iri).await {
            Ok(m) => Some(m.blob_key),
            Err(SparqError::NotFound) => None,
            Err(SparqError::Backend(e)) => return Err(ServerError::Storage(e)),
        };
        // Detach from the parent's containment first, then drop the index record, then the bytes.
        // Index-before-bytes keeps the invariant "if it's indexed, its bytes exist" — a crash after
        // the index delete leaves orphaned bytes (the reconciler GCs them — M2-next), never an index
        // row pointing at missing bytes.
        if let Some(p) = parent {
            self.sparq
                .remove_child(p, iri)
                .await
                .map_err(|e| ServerError::Storage(format!("{e}")))?;
        }
        self.sparq
            .delete_meta(iri)
            .await
            .map_err(|e| ServerError::Storage(format!("{e}")))?;
        if let Some(key) = blob_key {
            self.blob
                .delete(&key)
                .await
                .map_err(|e| ServerError::Storage(format!("{e}")))?;
        }
        Ok(())
    }

    async fn delete_container_if_empty(
        &self,
        iri: &str,
        parent: Option<&str>,
    ) -> ServerResult<DeleteOutcome> {
        // Look up the byte-pointer FIRST so a successful delete can drop the right blob. This read is
        // outside the atomic empty-check+delete window deliberately: it only governs WHICH blob to GC
        // on success, never the delete decision, so it cannot reintroduce the TOCTOU (the authoritative
        // empty-check+delete is the single `delete_meta_if_empty` op below). A missing record here just
        // means there is no blob to GC; the atomic op will report NotFound.
        let blob_key = match self.sparq.get_meta(iri).await {
            Ok(m) => Some(m.blob_key),
            Err(SparqError::NotFound) => None,
            Err(SparqError::Backend(e)) => return Err(ServerError::Storage(e)),
        };
        // The ATOMIC empty-check + delete (no interleaving — see `delete_meta_if_empty`).
        let outcome = self
            .sparq
            .delete_meta_if_empty(iri)
            .await
            .map_err(|e| ServerError::Storage(format!("{e}")))?;
        if outcome != DeleteOutcome::Deleted {
            // NotEmpty / NotFound: nothing was deleted, so leave the parent edge + bytes untouched.
            return Ok(outcome);
        }
        // Deleted: detach from the parent's containment (a different graph, idempotent) and GC bytes.
        // Index-(record-)before-bytes keeps "if it's indexed, its bytes exist": a crash here leaves
        // orphaned bytes for the reconciler, never an index row pointing at missing bytes.
        if let Some(p) = parent {
            self.sparq
                .remove_child(p, iri)
                .await
                .map_err(|e| ServerError::Storage(format!("{e}")))?;
        }
        if let Some(key) = blob_key {
            self.blob
                .delete(&key)
                .await
                .map_err(|e| ServerError::Storage(format!("{e}")))?;
        }
        Ok(DeleteOutcome::Deleted)
    }

    async fn list_children(&self, container: &str) -> ServerResult<Vec<String>> {
        self.sparq
            .list_children(container)
            .await
            .map_err(|e| ServerError::Storage(format!("{e}")))
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
