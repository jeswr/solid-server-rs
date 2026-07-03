// AUTHORED-BY Claude Fable 5
//! Deterministic backend round-trip counters at the [`SparqClient`] / [`BlobStore`] seams —
//! read-1 of the read-path perf plan (`docs/design/backend-read-path.md` §7).
//!
//! ## What this measures (and why it is deterministic)
//! [`CountingSparqClient`] / [`CountingBlobStore`] are transparent decorators that count, per trait
//! method, **the number of backend protocol requests the LIVE client issues for that method** —
//! verified against [`super::http::HttpSparqClient`], where every read method is exactly ONE SPARQL
//! Protocol query (the protocol permits exactly one query string per request, so there is no
//! request-level batching to blur the count). The counts are integers derived from the code path
//! taken, not from timing — so a test can PIN them exactly (the repo's perf-gate discipline:
//! deterministic metrics hard, wall-clock advisory).
//!
//! ## The await-depth (sequential-RTT) witness
//! Both decorators share one [`BackendCounters`] and wrap every backend call in an in-flight
//! guard. [`CounterSnapshot::max_in_flight`] is the high-water mark of concurrently-outstanding
//! backend calls: when it reads **1** for an operation, every backend call strictly awaited the
//! previous one — so the operation's **sequential RTT depth equals its total backend-call count**
//! (`sparql_queries + sparql_updates + blob ops`). That is the §1.1 "sequential RTT depth" column,
//! measured rather than asserted.
//!
//! ## Query-count mapping (per [`SparqClient`] method, mirroring `HttpSparqClient`)
//! - `get_meta` / `exists` / `list_children` / `referenced_blob_keys`: **1 query**.
//! - `put_meta` / `delete_meta` / `remove_child`: **1 update**.
//! - `create_child`: **1 update + 1 query** (the guarded insert, then the create-marker ASK).
//! - `delete_meta_if_empty`: **1 update**, then **1 query** (marker ASK) when the outcome is
//!   `Deleted`, else **2 queries** (marker ASK + exists ASK).
//!
//! Error paths are counted best-effort (the live client may abort mid-sequence); the pinned tests
//! only assert success paths, where the mapping is exact.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use super::blob::{BlobEntry, BlobError, BlobStore};
use super::sparq::{DeleteOutcome, ResourceMeta, SparqClient, SparqError};

/// Shared, lock-free counters for the backend seams. Cheap to clone via `Arc`; a test holds the
/// `Arc` and diffs [`snapshot`](BackendCounters::snapshot)s around one operation.
#[derive(Debug, Default)]
pub struct BackendCounters {
    /// SPARQL Protocol **query** requests (SELECT / ASK / CONSTRUCT) the live client would issue.
    sparql_queries: AtomicU64,
    /// SPARQL Protocol **update** requests.
    sparql_updates: AtomicU64,
    /// Blob-store byte fetches (`get`).
    blob_gets: AtomicU64,
    /// Blob-store byte writes (`put`).
    blob_puts: AtomicU64,
    /// Every other blob-store call (`exists` / `delete` / `list` / `stat` / CAS-delete).
    blob_others: AtomicU64,
    /// Currently-outstanding backend calls (both seams).
    in_flight: AtomicU64,
    /// High-water mark of `in_flight` — **1 ⇒ strictly sequential**, so an op's sequential RTT
    /// depth equals its total backend-call count.
    max_in_flight: AtomicU64,
}

/// A point-in-time copy of the counters. Subtract two with [`CounterSnapshot::since`] to get the
/// per-operation deltas a test pins. `max_in_flight` is NOT differenced (it is a high-water mark);
/// `since` carries the LATER snapshot's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub sparql_queries: u64,
    pub sparql_updates: u64,
    pub blob_gets: u64,
    pub blob_puts: u64,
    pub blob_others: u64,
    pub max_in_flight: u64,
}

impl CounterSnapshot {
    /// The per-operation delta `self - earlier` (counter fields), keeping `self`'s high-water mark.
    pub fn since(&self, earlier: &CounterSnapshot) -> CounterSnapshot {
        CounterSnapshot {
            sparql_queries: self.sparql_queries - earlier.sparql_queries,
            sparql_updates: self.sparql_updates - earlier.sparql_updates,
            blob_gets: self.blob_gets - earlier.blob_gets,
            blob_puts: self.blob_puts - earlier.blob_puts,
            blob_others: self.blob_others - earlier.blob_others,
            max_in_flight: self.max_in_flight,
        }
    }

    /// Total backend calls in this (delta) snapshot — with `max_in_flight == 1` this IS the
    /// operation's sequential RTT depth (every call awaited the previous one).
    pub fn total_backend_ops(&self) -> u64 {
        self.sparql_queries
            + self.sparql_updates
            + self.blob_gets
            + self.blob_puts
            + self.blob_others
    }
}

impl BackendCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            sparql_queries: self.sparql_queries.load(Ordering::Relaxed),
            sparql_updates: self.sparql_updates.load(Ordering::Relaxed),
            blob_gets: self.blob_gets.load(Ordering::Relaxed),
            blob_puts: self.blob_puts.load(Ordering::Relaxed),
            blob_others: self.blob_others.load(Ordering::Relaxed),
            max_in_flight: self.max_in_flight.load(Ordering::Relaxed),
        }
    }

    /// RAII in-flight guard: increments the gauge (updating the high-water mark) for the duration
    /// of one backend call. Two overlapping guards ⇒ `max_in_flight ≥ 2` (the sequentiality
    /// witness flips only when calls genuinely overlap).
    fn op_guard(self: &Arc<Self>) -> OpGuard {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        OpGuard {
            counters: Arc::clone(self),
        }
    }

    fn count_queries(&self, n: u64) {
        self.sparql_queries.fetch_add(n, Ordering::Relaxed);
    }
    fn count_update(&self) {
        self.sparql_updates.fetch_add(1, Ordering::Relaxed);
    }
}

struct OpGuard {
    counters: Arc<BackendCounters>,
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        self.counters.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A [`SparqClient`] decorator counting the SPARQL Protocol requests each method costs on the live
/// client (see the module docs for the mapping). Fully transparent: every call forwards to `inner`.
pub struct CountingSparqClient<S: SparqClient> {
    inner: S,
    counters: Arc<BackendCounters>,
}

impl<S: SparqClient> CountingSparqClient<S> {
    pub fn new(inner: S, counters: Arc<BackendCounters>) -> Self {
        Self { inner, counters }
    }
}

#[async_trait]
impl<S: SparqClient> SparqClient for CountingSparqClient<S> {
    async fn get_meta(&self, iri: &str) -> Result<ResourceMeta, SparqError> {
        let _g = self.counters.op_guard();
        self.counters.count_queries(1);
        self.inner.get_meta(iri).await
    }

    async fn put_meta(&self, iri: &str, meta: ResourceMeta) -> Result<(), SparqError> {
        let _g = self.counters.op_guard();
        self.counters.count_update();
        self.inner.put_meta(iri, meta).await
    }

    async fn exists(&self, iri: &str) -> Result<bool, SparqError> {
        let _g = self.counters.op_guard();
        self.counters.count_queries(1);
        self.inner.exists(iri).await
    }

    async fn delete_meta(&self, iri: &str) -> Result<(), SparqError> {
        let _g = self.counters.op_guard();
        self.counters.count_update();
        self.inner.delete_meta(iri).await
    }

    async fn delete_meta_if_empty(
        &self,
        iri: &str,
        parent: Option<&str>,
    ) -> Result<DeleteOutcome, SparqError> {
        let _g = self.counters.op_guard();
        // The live client: 1 guarded update, then the marker ASK; a non-Deleted outcome needs the
        // second (exists) ASK to split NotEmpty from NotFound.
        self.counters.count_update();
        let outcome = self.inner.delete_meta_if_empty(iri, parent).await?;
        self.counters
            .count_queries(if outcome == DeleteOutcome::Deleted {
                1
            } else {
                2
            });
        Ok(outcome)
    }

    async fn create_child(
        &self,
        container: &str,
        child: &str,
        meta: ResourceMeta,
    ) -> Result<(), SparqError> {
        let _g = self.counters.op_guard();
        // The live client: 1 guarded update + 1 create-marker ASK (issued for BOTH the created and
        // the container-missing outcome — the ASK is how NotFound is learned).
        self.counters.count_update();
        self.counters.count_queries(1);
        self.inner.create_child(container, child, meta).await
    }

    async fn remove_child(&self, container: &str, child: &str) -> Result<(), SparqError> {
        let _g = self.counters.op_guard();
        self.counters.count_update();
        self.inner.remove_child(container, child).await
    }

    async fn list_children(&self, container: &str) -> Result<Vec<String>, SparqError> {
        let _g = self.counters.op_guard();
        self.counters.count_queries(1);
        self.inner.list_children(container).await
    }

    async fn referenced_blob_keys(&self) -> Result<HashSet<String>, SparqError> {
        let _g = self.counters.op_guard();
        self.counters.count_queries(1);
        self.inner.referenced_blob_keys().await
    }
}

/// A [`BlobStore`] decorator counting byte fetches/writes (and every other backend call) against
/// the shared [`BackendCounters`].
pub struct CountingBlobStore<B: BlobStore> {
    inner: B,
    counters: Arc<BackendCounters>,
}

impl<B: BlobStore> CountingBlobStore<B> {
    pub fn new(inner: B, counters: Arc<BackendCounters>) -> Self {
        Self { inner, counters }
    }
}

#[async_trait]
impl<B: BlobStore> BlobStore for CountingBlobStore<B> {
    async fn get(&self, key: &str) -> Result<Bytes, BlobError> {
        let _g = self.counters.op_guard();
        self.counters.blob_gets.fetch_add(1, Ordering::Relaxed);
        self.inner.get(key).await
    }

    async fn put(&self, key: &str, body: Bytes) -> Result<(), BlobError> {
        let _g = self.counters.op_guard();
        self.counters.blob_puts.fetch_add(1, Ordering::Relaxed);
        self.inner.put(key, body).await
    }

    async fn exists(&self, key: &str) -> Result<bool, BlobError> {
        let _g = self.counters.op_guard();
        self.counters.blob_others.fetch_add(1, Ordering::Relaxed);
        self.inner.exists(key).await
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        let _g = self.counters.op_guard();
        self.counters.blob_others.fetch_add(1, Ordering::Relaxed);
        self.inner.delete(key).await
    }

    async fn list(&self) -> Result<Vec<BlobEntry>, BlobError> {
        let _g = self.counters.op_guard();
        self.counters.blob_others.fetch_add(1, Ordering::Relaxed);
        self.inner.list().await
    }

    async fn stat(&self, key: &str) -> Result<Option<BlobEntry>, BlobError> {
        let _g = self.counters.op_guard();
        self.counters.blob_others.fetch_add(1, Ordering::Relaxed);
        self.inner.stat(key).await
    }

    async fn delete_if_unchanged(
        &self,
        key: &str,
        expected_generation: u64,
    ) -> Result<bool, BlobError> {
        let _g = self.counters.op_guard();
        self.counters.blob_others.fetch_add(1, Ordering::Relaxed);
        self.inner
            .delete_if_unchanged(key, expected_generation)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InMemoryBlobStore, InMemorySparqClient};

    #[tokio::test]
    async fn counters_pin_the_per_method_mapping() {
        let counters = BackendCounters::new();
        let sparq = CountingSparqClient::new(InMemorySparqClient::new(), Arc::clone(&counters));
        let blob = CountingBlobStore::new(InMemoryBlobStore::new(), Arc::clone(&counters));

        let meta = ResourceMeta {
            content_type: "text/turtle".into(),
            blob_key: "k1".into(),
            etag: "\"e1\"".into(),
        };
        sparq.put_meta("https://p/c/", meta.clone()).await.unwrap();
        let s0 = counters.snapshot();
        assert_eq!((s0.sparql_updates, s0.sparql_queries), (1, 0));

        sparq.get_meta("https://p/c/").await.unwrap();
        sparq.exists("https://p/c/").await.unwrap();
        sparq.list_children("https://p/c/").await.unwrap();
        let d = counters.snapshot().since(&s0);
        assert_eq!(d.sparql_queries, 3, "3 read methods = 3 queries");
        assert_eq!(d.sparql_updates, 0);

        blob.put("k1", Bytes::from_static(b"x")).await.unwrap();
        blob.get("k1").await.unwrap();
        let d2 = counters.snapshot().since(&s0);
        assert_eq!((d2.blob_puts, d2.blob_gets), (1, 1));

        // create_child = 1 update + 1 (marker-ASK-modelled) query.
        let before = counters.snapshot();
        sparq
            .create_child("https://p/c/", "https://p/c/doc", meta.clone())
            .await
            .unwrap();
        let d3 = counters.snapshot().since(&before);
        assert_eq!((d3.sparql_updates, d3.sparql_queries), (1, 1));

        // delete_meta_if_empty on a NON-empty container: 1 update + 2 queries (marker + exists ASK).
        let before = counters.snapshot();
        let outcome = sparq
            .delete_meta_if_empty("https://p/c/", None)
            .await
            .unwrap();
        assert_eq!(outcome, DeleteOutcome::NotEmpty);
        let d4 = counters.snapshot().since(&before);
        assert_eq!((d4.sparql_updates, d4.sparql_queries), (1, 2));

        // Sequential calls throughout ⇒ the await-depth witness stays 1.
        assert_eq!(counters.snapshot().max_in_flight, 1);
    }

    #[tokio::test]
    async fn max_in_flight_detects_overlap() {
        let counters = BackendCounters::new();
        let sparq = Arc::new(CountingSparqClient::new(
            InMemorySparqClient::new(),
            Arc::clone(&counters),
        ));
        // Two concurrent backend calls ⇒ the high-water mark exceeds 1 (the witness is live, not
        // vacuously 1). `join!` polls both futures in one task; each holds its guard across an
        // `.await` on the in-memory client, so the overlap is observable deterministically… the
        // in-memory client has no await points inside the lock, so drive overlap explicitly:
        // hold one guard while issuing a call.
        let g = counters.op_guard();
        sparq.exists("https://p/x").await.unwrap();
        drop(g);
        assert!(counters.snapshot().max_in_flight >= 2);
    }
}
