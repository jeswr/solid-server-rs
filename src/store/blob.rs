// AUTHORED-BY Claude Opus 4.8
//! The blob (byte) store seam.
//!
//! Per the architecture, `object_store`/S3 is **backup-only** for resource bytes: SPARQ is the
//! authoritative index, and the blob store holds a durable copy of the bytes keyed by an opaque
//! `s3Key`. This module defines the [`BlobStore`] trait and an in-memory test impl. The real
//! `object_store`-backed impl (S3 / Local) is an M2 adapter behind the same trait.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

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

/// One stored blob, as surfaced by [`BlobStore::list`] for the reconciler's orphan sweep.
///
/// The `last_modified` timestamp is LOAD-BEARING for the reconciler's grace period: an orphan is only
/// GC'd when it is OLDER than the grace window, so a blob whose bytes were just written but whose index
/// row has not yet committed (the write-in-progress race) is protected. Backends that do not expose a
/// timestamp (none here yet) must report `None` and are then NEVER GC'd by the reconciler (fail-closed
/// — we can't prove an undated blob is old enough to be safe to delete).
#[derive(Debug, Clone)]
pub struct BlobEntry {
    /// The opaque storage key the bytes live under.
    pub key: String,
    /// When the bytes were last written, if the backend records it. `None` ⇒ unknown ⇒ never GC'd.
    pub last_modified: Option<SystemTime>,
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

    /// Remove the bytes for a storage key. Idempotent: deleting an absent key is `Ok(())` (the
    /// authoritative existence decision lives in the index, not here).
    async fn delete(&self, key: &str) -> Result<(), BlobError>;

    /// List every stored blob key with its last-modified time (if the backend records one).
    ///
    /// This is the read side the reconciler's orphaned-bytes sweep needs: SPARQ is authoritative for
    /// *which* bytes are referenced, but only the blob store can enumerate which bytes *physically
    /// exist*, so the reconciler diffs the two. This is the ONLY read path permitted to enumerate the
    /// blob store directly — the LDP request path must never LIST/HEAD the blob store (the
    /// "SPARQ is the source of truth" invariant); the reconciler is the documented exception because GC
    /// is *about* the bytes the index does not know about.
    ///
    /// M2-next (the `object_store` adapter): implement via `object_store::ObjectStore::list` — its
    /// `ObjectMeta` carries `location` (→ `key`) + `last_modified` (a `chrono::DateTime<Utc>` → map to
    /// [`SystemTime`]), so the real S3/Local backend reports a real timestamp and the grace window
    /// works against true object age. Until that adapter lands the in-memory double below is the only
    /// impl.
    async fn list(&self) -> Result<Vec<BlobEntry>, BlobError>;

    /// Re-read ONE key's current state (its present `last_modified`), or `None` if the key no longer
    /// exists. The single-key counterpart to [`list`](BlobStore::list).
    ///
    /// The reconciler uses this to RE-STAT a candidate orphan immediately before deleting it: the
    /// [`list`](BlobStore::list) snapshot taken at sweep start can be stale by the time the delete loop
    /// reaches a key, and with today's deterministic per-IRI blob keys an overwrite reuses the same key,
    /// so a recreate landing between the snapshot and the delete would otherwise let the GC clobber
    /// newly-written LIVE bytes. Re-stat lets the reconciler notice "this key's bytes are now NEWER than
    /// my snapshot saw" (⇒ rewritten ⇒ skip) — see [`super::reconcile::reconcile_orphans`].
    ///
    /// The default implementation derives the answer from [`list`](BlobStore::list) so existing/future
    /// impls keep working unchanged; a backend with a cheap single-key HEAD (object_store, the in-memory
    /// double) SHOULD override this with the O(1) path rather than re-enumerating the whole store.
    ///
    /// M2 (the `object_store` adapter): override via `object_store::ObjectStore::head(&location)` — its
    /// `ObjectMeta.last_modified` maps to [`SystemTime`]; a `NotFound` from the backend maps to `Ok(None)`
    /// (the key is gone), any other error propagates.
    async fn stat(&self, key: &str) -> Result<Option<BlobEntry>, BlobError> {
        Ok(self.list().await?.into_iter().find(|e| e.key == key))
    }
}

/// A stored blob in the in-memory double: the bytes + the insert/overwrite time (for the grace check).
struct StoredBlob {
    body: Bytes,
    last_modified: SystemTime,
}

/// An in-memory [`BlobStore`] for tests and the M1 boot-without-S3 path.
///
/// Each [`put`](InMemoryBlobStore::put) stamps the wall-clock insert time, mirroring an object store's
/// `last_modified`, so the reconciler's grace window can be exercised without a real backend. Tests
/// that need a *specific* age use [`put_with_time`](InMemoryBlobStore::put_with_time) to back-date a
/// blob deterministically (no `sleep`).
#[derive(Default)]
pub struct InMemoryBlobStore {
    inner: Mutex<HashMap<String, StoredBlob>>,
}

impl InMemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert bytes with an EXPLICIT last-modified time. Test-only helper so the grace-window tests can
    /// back-date a blob deterministically (e.g. "2 hours ago") instead of sleeping. Not part of the
    /// [`BlobStore`] trait — production code uses [`put`](InMemoryBlobStore::put), which stamps `now`.
    pub fn put_with_time(&self, key: &str, body: Bytes, last_modified: SystemTime) {
        let mut guard = self.inner.lock().expect("blob store mutex poisoned");
        guard.insert(
            key.to_string(),
            StoredBlob {
                body,
                last_modified,
            },
        );
    }
}

#[async_trait]
impl BlobStore for InMemoryBlobStore {
    async fn get(&self, key: &str) -> Result<Bytes, BlobError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        guard
            .get(key)
            .map(|b| b.body.clone())
            .ok_or(BlobError::NotFound)
    }

    async fn put(&self, key: &str, body: Bytes) -> Result<(), BlobError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        guard.insert(
            key.to_string(),
            StoredBlob {
                body,
                last_modified: SystemTime::now(),
            },
        );
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, BlobError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        Ok(guard.contains_key(key))
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        guard.remove(key);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<BlobEntry>, BlobError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        Ok(guard
            .iter()
            .map(|(key, blob)| BlobEntry {
                key: key.clone(),
                last_modified: Some(blob.last_modified),
            })
            .collect())
    }

    /// O(1) single-key re-stat (a HashMap lookup) instead of the trait default's whole-store
    /// enumeration — the shape the real object_store HEAD will take.
    async fn stat(&self, key: &str) -> Result<Option<BlobEntry>, BlobError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| BlobError::Backend("poisoned".into()))?;
        Ok(guard.get(key).map(|blob| BlobEntry {
            key: key.to_string(),
            last_modified: Some(blob.last_modified),
        }))
    }
}
