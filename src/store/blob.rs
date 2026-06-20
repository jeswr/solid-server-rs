// AUTHORED-BY Claude Opus 4.8
//! The blob (byte) store seam.
//!
//! Per the architecture, `object_store`/S3 is **backup-only** for resource bytes: SPARQ is the
//! authoritative index, and the blob store holds a durable copy of the bytes keyed by an opaque
//! `s3Key`. This module defines the [`BlobStore`] trait and an in-memory test impl. The real
//! `object_store`-backed impl (S3 / Local) is an M2 adapter behind the same trait.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;

/// A blob-store error (kept opaque so it never leaks backend detail to a client).
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("blob not found")]
    NotFound,
    #[error("blob backend error: {0}")]
    Backend(String),
}

/// The byte store: a key/value store of resource bodies, keyed by an opaque storage key.
///
/// M2: an `object_store`-backed impl (`object_store::aws::AmazonS3` / `LocalFileSystem`) plugs in
/// here, using `PutMode::Create`/`Update` for the S3 If-None-Match/If-Match CAS (spike §6).
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Read the bytes for a storage key.
    async fn get(&self, key: &str) -> Result<Bytes, BlobError>;

    /// Write (create-or-replace) the bytes for a storage key.
    async fn put(&self, key: &str, body: Bytes) -> Result<(), BlobError>;

    /// Whether a key exists.
    async fn exists(&self, key: &str) -> Result<bool, BlobError>;
}

/// An in-memory [`BlobStore`] for tests and the M1 boot-without-S3 path.
#[derive(Default)]
pub struct InMemoryBlobStore {
    inner: Mutex<HashMap<String, Bytes>>,
}

impl InMemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BlobStore for InMemoryBlobStore {
    async fn get(&self, key: &str) -> Result<Bytes, BlobError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        guard.get(key).cloned().ok_or(BlobError::NotFound)
    }

    async fn put(&self, key: &str, body: Bytes) -> Result<(), BlobError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        guard.insert(key.to_string(), body);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, BlobError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        Ok(guard.contains_key(key))
    }
}
