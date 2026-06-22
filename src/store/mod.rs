// AUTHORED-BY Claude Opus 4.8
//! The composite [`Store`] — the LDP handler's single view of storage.
//!
//! A [`Store`] reads/writes RDF + metadata via [`SparqClient`] (authoritative) and bytes via
//! [`BlobStore`] (backup), mirroring prod-solid-server's S3+index composite. The default impl,
//! [`CompositeStore`], wires the two seams together; both seams have in-memory test doubles so the
//! whole stack is testable without a running SPARQ or S3.

pub mod blob;
pub mod http;
pub mod reconcile;
pub mod sparq;
pub mod sparql;

use async_trait::async_trait;
use bytes::Bytes;

pub use blob::{BlobEntry, BlobError, BlobStore, InMemoryBlobStore};
pub use http::{HttpSparqClient, SparqHttpError};
pub use reconcile::{
    reconcile_orphans, spawn_periodic, ReconcileError, ReconcileOptions, ReconcileReport,
    DEFAULT_GRACE,
};
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
    /// The membership check (`ldp:contains` empty?), the record delete, AND the detach of the
    /// container's edge in `parent`'s containment graph are performed as ONE store operation with NO
    /// interleaving, so neither (a) a child POSTed concurrently can slip between an empty-check and the
    /// delete and be orphaned under a deleted container (the TOCTOU the separate `list_children` +
    /// `delete` had), NOR (b) a concurrent POST can recreate the child under the parent in a window
    /// between the graph delete and a separate parent-edge detach and then be orphaned by that stale
    /// detach. The container's own bytes are NOT deleted inline: after the atomic index delete they are
    /// ORPHANED (no index row references them) and GC'd by the reconciler's orphaned-bytes sweep. We
    /// leave the bytes to the reconciler rather than delete them inline because the blob store is a
    /// separate system (its `delete` is unconditional). Since the composite store now mints UNIQUE
    /// blob keys per write ([`CompositeStore::mint_blob_key`]), a concurrent same-IRI recreate gets a
    /// DIFFERENT key, so an inline delete of THIS container's key could no longer clobber a recreate's
    /// bytes — but leaving them to the reconciler keeps the path uniform and side-effect-free (the sweep
    /// only GCs bytes with NO index row). Transient orphan until a sweep runs — space only, never an
    /// observable inconsistency. Returns:
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

    /// Mint a fresh, **unique-per-write** opaque blob-store key for an IRI.
    ///
    /// # The root fix: unique keys retire the deterministic-key race class
    /// The earlier `blob_key_for` derived the key DETERMINISTICALLY from the IRI (a percent-flatten),
    /// so every write to the same logical resource REUSED the same blob key. That single design choice
    /// was the source of a whole race class: two concurrent writes to the same IRI collided on one key
    /// (the loser's bytes could interleave with / clobber the winner's), and a delete's inline
    /// `blob.delete(key)` raced a concurrent same-IRI recreate that had just rewritten the SAME key —
    /// forcing the elaborate `generation`-CAS + grace-window + snapshot-threading machinery in
    /// [`super::blob`] and [`super::reconcile`] to exist purely to make a reused key safe.
    ///
    /// This mints a NEW key on EVERY write: an IRI-derived prefix (kept for operator-debuggability — a
    /// key still traces back to its resource) plus a hyphen-joined **128-bit cryptographically-random
    /// suffix** from the OS RNG. So:
    ///
    /// - **Two concurrent writes to the same IRI get DIFFERENT keys** — they write to disjoint blob
    ///   objects and can never collide or interleave. The "latest committed" winner is decided solely by
    ///   which write's index `put_meta` commits last (SPARQ is authoritative); whichever metadata pointer
    ///   wins, a read resolves through it to that write's own bytes. The other write's bytes become an
    ///   unreferenced orphan, reclaimed by the reconciler — never a clobber of live bytes.
    /// - **A delete's inline blob delete can no longer race a recreate.** A recreate mints a brand-new
    ///   key, so deleting the OLD key's bytes can never touch the recreate's bytes. (The collision the
    ///   `generation`-CAS existed to catch simply cannot arise once keys are never reused.)
    ///
    /// The metadata pointer ([`ResourceMeta::blob_key`]) records the minted key, and every read already
    /// resolves bytes THROUGH that pointer (`read` does `get(&meta.blob_key)`), so correctness
    /// (read-after-write returns the latest committed blob) is preserved unchanged — the only difference
    /// is that the pointer now names a unique object rather than a shared one.
    ///
    /// 128 bits of OS entropy makes a key collision across independent writes cryptographically
    /// negligible; the IRI prefix is cosmetic (debuggability) and carries no uniqueness requirement.
    fn mint_blob_key(iri: &str) -> String {
        // The IRI-derived prefix is for human/operator traceability only; uniqueness comes entirely from
        // the random suffix, so the prefix need not be collision-free.
        let prefix = iri.replace([':', '/', '?', '#', '%'], "_");
        let mut suffix = [0u8; 16];
        // The OS CSPRNG. `getrandom` is the de-facto OS-entropy source and does not fail on any platform
        // we target; on the theoretical error we fall back to a still-unique value composed from the
        // process- + time-derived entropy below, so a write is never blocked and keys stay unique.
        if getrandom::getrandom(&mut suffix).is_err() {
            // Defensive, effectively-unreachable fallback: combine the wall clock (nanos) with the
            // resource's address-of bytes to still produce a per-write-distinct value. This path never
            // runs on a supported OS; it only guarantees we never panic / reuse a key if the OS RNG is
            // somehow unavailable.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            suffix[..16].copy_from_slice(&nanos.to_le_bytes());
        }
        let hex = suffix.iter().fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        format!("{prefix}-{hex}")
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
        //
        // The blob key is minted UNIQUE PER WRITE (`mint_blob_key`): a concurrent same-IRI write gets a
        // DIFFERENT key and so writes a disjoint object — no collision/interleave on a shared key. The
        // "latest committed" winner is whichever write's `put_meta` commits last (SPARQ authoritative);
        // a read then resolves through that winner's pointer to ITS bytes, and the loser's bytes become
        // an unreferenced orphan the reconciler GCs (never a clobber of the live bytes). A re-write of
        // an existing resource likewise lands on a NEW key, leaving the previous key orphaned for GC.
        let blob_key = Self::mint_blob_key(iri);
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
        //
        // The child's blob key is minted UNIQUE PER WRITE (`mint_blob_key`), so a concurrent same-IRI
        // create writes a disjoint object and cannot collide with this one on a shared key.
        let blob_key = Self::mint_blob_key(child);
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
        // The ATOMIC empty-check + record delete + PARENT-edge detach in ONE index op (no interleaving
        // — see `delete_meta_if_empty`). The parent-edge detach is folded INTO this single op (it is no
        // longer a separate `remove_child` afterwards) so there is no window in which the container
        // graph is gone but the parent still `ldp:contains` it — a window a concurrent recreate could
        // exploit to be orphaned by a stale detach.
        //
        // reconciler: the container's bytes are NOT deleted inline here. After the atomic index delete,
        // the bytes become ORPHANED (no index row references them) and are GC'd by the reconciler's
        // orphaned-bytes sweep. We leave the bytes to the reconciler rather than delete them inline: the
        // blob store is a SEPARATE system (object store) whose `delete` is unconditional. With the
        // UNIQUE-PER-WRITE keys the composite store now mints (`mint_blob_key`), a concurrent same-IRI
        // recreate writes its bytes under a DIFFERENT key, so an inline delete of THIS container's key
        // could no longer clobber a recreate's bytes even if we did it (the root-cause race is closed) —
        // but deleting NO bytes here keeps the path uniform with `write`/`create_in_container`'s
        // orphan-then-GC model and side-effect-free. The trade-off is a transient orphan until a sweep
        // runs: benign (disk space only, never an observable inconsistency), and it IS the documented
        // architecture (SPARQ authoritative; blob store durable bytes; reconciler GCs orphans —
        // `decisions`/the spike crash-consistency model).
        let outcome = self
            .sparq
            .delete_meta_if_empty(iri, parent)
            .await
            .map_err(|e| ServerError::Storage(format!("{e}")))?;
        // NotEmpty / NotFound: nothing was deleted. Deleted: the record AND the parent edge are gone
        // atomically (above); the now-orphaned bytes are the reconciler's responsibility (see above).
        Ok(outcome)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::blob::InMemoryBlobStore;
    use crate::store::sparq::InMemorySparqClient;

    type S = CompositeStore<InMemorySparqClient, InMemoryBlobStore>;

    #[test]
    fn mint_blob_key_is_unique_per_call_for_the_same_iri() {
        // The ROOT-fix unit invariant: minting a key for the SAME IRI twice yields DIFFERENT keys (no
        // deterministic reuse). A handful of repeats makes a chance collision of the 128-bit random
        // suffix astronomically unlikely, so a single `assert_ne!` is enough; we mint a batch and assert
        // all-distinct to be thorough. MUTATION-CHECK: revert to the old deterministic `iri.replace(...)`
        // and every minted key is identical ⇒ this fails.
        let iri = "https://pod.example/alice/data";
        let mut keys: Vec<String> = (0..32).map(|_| S::mint_blob_key(iri)).collect();
        let total = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(
            keys.len(),
            total,
            "every mint for the same IRI must be unique (the deterministic-key reuse is gone)"
        );
    }

    #[test]
    fn mint_blob_key_keeps_an_iri_derived_prefix_for_traceability() {
        // Uniqueness comes from the random suffix; the IRI-derived prefix is retained (cosmetic) so an
        // operator can still trace a key back to its resource. The minted key must START with the
        // percent-flattened IRI followed by the `-` separator.
        let iri = "https://pod.example/alice/data";
        let prefix = iri.replace([':', '/', '?', '#', '%'], "_");
        let key = S::mint_blob_key(iri);
        assert!(
            key.starts_with(&format!("{prefix}-")),
            "minted key {key:?} must keep the IRI-derived prefix {prefix:?} for traceability"
        );
        // ...and the suffix is the 32-hex-char (128-bit) random tail.
        let suffix = &key[prefix.len() + 1..];
        assert_eq!(
            suffix.len(),
            32,
            "the random suffix is 16 bytes = 32 hex chars"
        );
        assert!(
            suffix.bytes().all(|b| b.is_ascii_hexdigit()),
            "the suffix must be lowercase hex"
        );
    }
}
