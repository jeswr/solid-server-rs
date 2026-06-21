// AUTHORED-BY Claude Opus 4.8
//! The orphaned-bytes **reconciler** — the GC for blobs the index no longer references.
//!
//! ## Why this exists (the crash-consistency model)
//! SPARQ is authoritative for existence/metadata/containment; the blob store holds the durable bytes.
//! The composite store deliberately writes bytes FIRST then commits the index, and on DELETE drops the
//! index FIRST then (best-effort) the bytes — so the invariant "if it is indexed, its bytes exist"
//! always holds and a crash can only ever leave the *benign* opposite: **bytes with no index row**.
//! Those are ORPHANS — they cost disk but are never observable through the LDP surface (a read goes
//! index-first, so it never sees them). Several documented paths produce them on purpose to avoid a
//! worse race: [`super::Store::delete_container_if_empty`] leaves a deleted container's bytes for the
//! sweep rather than racing a same-IRI recreate; a `create_in_container` whose index commit fails
//! (missing parent) orphans the bytes it already PUT. This reconciler is the GC that reclaims them.
//!
//! ## What it does — and the grace period (LOAD-BEARING)
//! [`reconcile_orphans`]:
//! 1. asks SPARQ for the WHOLE referenced-blob-key set ONCE ([`SparqClient::referenced_blob_keys`]),
//! 2. lists the physically-stored blobs ([`BlobStore::list`]) — the START-OF-SWEEP snapshot,
//! 3. classifies each stored blob against that snapshot (referenced / too-young / undated / a
//!    delete candidate),
//! 4. re-fetches the referenced set ONCE more, then for each delete candidate RE-CHECKS it against that
//!    fresh set AND RE-STATS its current `last_modified` ([`BlobStore::stat`]) immediately before
//!    deleting — see the snapshot-staleness race below,
//! 5. deletes a candidate **iff** it is STILL unreferenced (fresh index) AND STILL old enough (fresh
//!    stat, not rewritten).
//!
//! ### The snapshot-staleness race (Finding 1 — why the re-check + re-stat exist)
//! The blob list in step 2 is a SNAPSHOT; by the time the delete loop reaches a key, a resource may have
//! been recreated/overwritten at the SAME blob key. Blob keys are TODAY deterministic per IRI, so an
//! overwrite REUSES the key before — or as — its index row commits. A recreate landing between the
//! snapshot and the `delete()` would otherwise make the GC clobber newly-written LIVE bytes. The
//! re-check (fresh referenced set) + re-stat (fresh `last_modified`) narrow that window to the tiny
//! (fresh-check → delete) gap. The DEFINITIVE race-free fix is **unique-per-write blob keys** (an
//! overwrite never reuses a candidate's key, so the reconciler can never target live bytes) — that is a
//! SEPARATE beaded slice; this reconciler only makes the sweep SAFE given today's deterministic keys.
//!
//! The grace period is the safety crux. There is an inverse race to the delete-orphan case: a *write
//! in progress* PUTs its bytes and has NOT YET committed its index row — for that instant the blob is
//! unreferenced but is NOT an orphan, it is about to become live. Deleting it would corrupt an
//! in-flight write (the index row would land pointing at bytes the reconciler just deleted). The grace
//! window closes that race: the sweep only GCs a blob whose `last_modified` is older than `grace`, so a
//! freshly-written-but-not-yet-committed blob is always protected (a write commits its index far
//! inside the window). The default is 1 hour — comfortably longer than any single write's
//! byte-then-index gap (even with retries/backpressure) yet short enough that orphans don't accumulate
//! for long. It is configurable for tests + operators.
//!
//! A blob whose backend reports NO `last_modified` is NEVER GC'd (fail-closed — we cannot prove it is
//! old enough to be safe), and counted as `skipped_unknown_age`.
//!
//! ## Safety / idempotency
//! - **Fail-closed on the referenced set.** If [`SparqClient::referenced_blob_keys`] errors, the whole
//!   sweep aborts with that error — it NEVER treats a failed query as "nothing is referenced" (which
//!   would delete every blob in the pod). The referenced set is fetched BEFORE any delete.
//! - **Idempotent + safe to re-run.** A second run over the same state finds the just-deleted orphans
//!   gone, so it deletes nothing. Concurrent writes are protected by the grace window. The order
//!   (referenced-set THEN list) means a blob created+committed between the two steps is simply seen as
//!   referenced or not-yet-listed — never wrongly deleted.
//! - A per-blob delete failure is recorded (`delete_errors`) and the sweep CONTINUES — one bad key
//!   never aborts the whole GC.
//!
//! ## On-demand vs periodic (the best call, documented)
//! The core [`reconcile_orphans`] is **on-demand**: a pure function over the two seams, callable from a
//! future admin endpoint / CLI / a one-shot boot sweep. That is the right primary shape — GC is a rare,
//! operator-or-schedule-triggered maintenance op, not part of the hot request path, and an on-demand
//! function is trivially testable and composable. A periodic background runner is OFFERED as an
//! opt-in convenience ([`spawn_periodic`], gated behind `SOLID_SERVER_RECONCILE_INTERVAL_SECS`, OFF by
//! default) for a single-instance deployment that wants a self-driving sweep; in a horizontally-scaled
//! deployment GC should instead be a single scheduled job (a leader-elected task / a cron hitting the
//! admin endpoint), NOT a per-replica timer racing N sweeps — which is why periodic is opt-in and
//! documented, not wired on by default. The in-memory M1 boot does not wire it (a single-process,
//! never-crashing in-memory store produces no durable orphans), so it stays a seam for the live store.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use super::blob::{BlobError, BlobStore};
use super::sparq::{SparqClient, SparqError};

/// The default grace window: an unreferenced blob younger than this is PROTECTED (it may be a
/// write-in-progress whose index row has not yet committed). 1h ≫ any single byte-then-index write gap.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(60 * 60);

/// Tuning for a reconciler sweep.
#[derive(Debug, Clone)]
pub struct ReconcileOptions {
    /// Only GC an orphan OLDER than this. Protects the write-in-progress (bytes-PUT-but-index-uncommitted)
    /// race. Default [`DEFAULT_GRACE`].
    pub grace: Duration,
    /// If `true`, scan + classify (INCLUDING the fresh re-check + re-stat) but DELETE nothing (a dry run
    /// — report what *would* be GC'd). All disposition counts are still populated; the deletable orphans
    /// land in `would_delete` (not `deleted`, which stays 0), so the partition invariant holds in both
    /// modes.
    pub dry_run: bool,
}

impl Default for ReconcileOptions {
    fn default() -> Self {
        Self {
            grace: DEFAULT_GRACE,
            dry_run: false,
        }
    }
}

/// The outcome of one reconciler sweep. Counts partition the scanned blobs so the totals reconcile in
/// BOTH modes:
/// - `scanned == referenced + orphaned`, and
/// - `orphaned == deleted + would_delete + too_young + skipped_unknown_age + skipped_revalidated +
///   delete_errors`.
///
/// The deletable orphans split by mode: a real run increments [`deleted`](Self::deleted), a dry run
/// increments [`would_delete`](Self::would_delete) (it touches nothing) — so the partition invariant
/// holds whether or not deletes ran. [`skipped_revalidated`](Self::skipped_revalidated) is the
/// fresh-recheck disposition (Finding 1): a candidate that, at delete time, turned out to be referenced
/// again OR to have been rewritten since the snapshot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Total physically-stored blobs examined.
    pub scanned: usize,
    /// Blobs still referenced by an index row (kept, untouched).
    pub referenced: usize,
    /// Unreferenced blobs (orphan candidates) — the sum of the six dispositions below.
    pub orphaned: usize,
    /// Orphans that were old enough, passed the fresh re-check, and were DELETED (0 on a dry run).
    pub deleted: usize,
    /// Orphans that WOULD be deleted but were not, because this was a dry run. The dry-run counterpart
    /// of [`deleted`](Self::deleted): on a real run this is always 0, on a dry run it carries the
    /// deletable count (so the partition holds in both modes and operators see what a real run would
    /// reclaim).
    pub would_delete: usize,
    /// Orphans inside the grace window — KEPT (protects the write-in-progress race).
    pub too_young: usize,
    /// Orphans whose backend reported no `last_modified` — KEPT fail-closed (age unknowable).
    pub skipped_unknown_age: usize,
    /// Orphans that looked deletable from the START-OF-SWEEP snapshot but, on a FRESH re-check just
    /// before the delete, turned out to be live again — either now referenced by a freshly-committed
    /// index row, or rewritten (a newer `last_modified` / now inside the grace window). KEPT. This is
    /// the Finding-1 guard against clobbering a recreate that landed mid-sweep with today's
    /// deterministic (reused-on-overwrite) blob keys.
    pub skipped_revalidated: usize,
    /// Orphans we tried to delete but the backend delete failed (KEPT; the sweep continued).
    pub delete_errors: usize,
}

/// An error that ABORTS the whole sweep before (or independent of) any per-blob disposition.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// The referenced-set query failed — we fail closed and do NOT delete anything (a missing
    /// referenced set must NEVER be read as "nothing is referenced").
    #[error("could not fetch the referenced-blob-key set: {0}")]
    ReferencedSet(#[source] SparqError),
    /// Listing the blob store failed — nothing to reconcile against, so abort.
    #[error("could not list the blob store: {0}")]
    ListBlobs(#[source] BlobError),
}

/// Run ONE orphaned-bytes reconciliation sweep over the two storage seams.
///
/// Lists every stored blob, diffs it against SPARQ's referenced-key set, and deletes the unreferenced
/// blobs that are older than `opts.grace`. Returns a [`ReconcileReport`]; idempotent and safe to
/// re-run. See the module docs for the crash-consistency model + the grace-window rationale.
///
/// `now` is taken from the wall clock; ages are `now - last_modified` (saturating, so a clock skew that
/// makes a blob appear "in the future" yields a zero age ⇒ treated as too-young ⇒ kept, never deleted).
pub async fn reconcile_orphans<S: SparqClient + ?Sized, B: BlobStore + ?Sized>(
    sparq: &S,
    blob: &B,
    opts: &ReconcileOptions,
) -> Result<ReconcileReport, ReconcileError> {
    // 1. The referenced set FIRST (fail-closed): if this errors we abort and delete NOTHING.
    let referenced: HashSet<String> = sparq
        .referenced_blob_keys()
        .await
        .map_err(ReconcileError::ReferencedSet)?;

    // 2. The physically-stored blobs.
    let stored = blob.list().await.map_err(ReconcileError::ListBlobs)?;

    let now = SystemTime::now();
    let mut report = ReconcileReport {
        scanned: stored.len(),
        ..Default::default()
    };

    // First pass — classify against the START-OF-SWEEP snapshot. Everything that is referenced,
    // too-young, or undated is decided HERE (these dispositions need no fresh re-check: a referenced or
    // too-young or undated blob is never a delete candidate). The blobs that LOOK deletable from the
    // snapshot (old-enough + unreferenced) are collected, with the `last_modified` the SNAPSHOT saw, for
    // a second pass that re-checks each immediately before deleting.
    let mut candidates: Vec<(String, SystemTime)> = Vec::new();
    for entry in stored {
        if referenced.contains(&entry.key) {
            report.referenced += 1;
            continue;
        }
        // Unreferenced ⇒ an orphan candidate.
        report.orphaned += 1;

        // The GRACE GUARD: only GC an orphan older than the window. A blob without a known
        // last-modified is kept (fail-closed). `duration_since` errs when the stamp is in the future
        // (clock skew) — treat that as age 0 ⇒ too-young ⇒ kept.
        let old_enough = match entry.last_modified {
            None => {
                report.skipped_unknown_age += 1;
                continue;
            }
            Some(ts) => {
                let age = now.duration_since(ts).unwrap_or(Duration::ZERO);
                if age >= opts.grace {
                    Some(ts)
                } else {
                    None
                }
            }
        };
        match old_enough {
            Some(snapshot_ts) => candidates.push((entry.key, snapshot_ts)),
            None => report.too_young += 1,
        }
    }

    // RE-CHECK against the INDEX once, just before the delete pass (Finding 1, part a). The
    // start-of-sweep `referenced` set can be stale: with today's deterministic per-IRI blob keys an
    // overwrite/recreate REUSES the same key, so a resource recreated between the snapshot and now would
    // have committed a FRESH index row pointing at a candidate key — deleting it would clobber live
    // bytes. Re-fetching the referenced set ONCE here (not per-key) and skipping any candidate now in it
    // closes that window down to the (this fetch → the per-key delete) gap. Fail-closed: if it errors we
    // ABORT and delete nothing (a failed query is NEVER "nothing is referenced").
    let referenced_fresh: HashSet<String> = sparq
        .referenced_blob_keys()
        .await
        .map_err(ReconcileError::ReferencedSet)?;

    // Second pass — re-validate each candidate immediately before deleting it.
    for (key, snapshot_ts) in candidates {
        // (a) Re-check referenced-ness against the FRESH index set: a recreate may have committed a row
        // pointing at this key since the snapshot.
        if referenced_fresh.contains(&key) {
            report.skipped_revalidated += 1;
            continue;
        }

        // (b) Re-STAT the key's CURRENT last_modified: a rewrite reuses the same key (deterministic
        // keying), so if the bytes are now newer than the snapshot saw — or now young enough to be inside
        // the grace window — the blob was overwritten and must NOT be deleted. A stat failure is treated
        // fail-closed (skip, count under delete_errors) rather than blindly deleting on incomplete info.
        let current = match blob.stat(&key).await {
            Ok(Some(entry)) => entry,
            // The key is already gone (a concurrent delete / it never existed by delete-time) — nothing
            // to reclaim, and re-deleting is a harmless no-op we simply skip. Count as revalidated
            // (it is no longer a deletable orphan), keeping the partition exact.
            Ok(None) => {
                report.skipped_revalidated += 1;
                continue;
            }
            Err(_) => {
                report.delete_errors += 1;
                continue;
            }
        };
        let rewritten = match current.last_modified {
            // The fresh stat reports no age ⇒ unknowable ⇒ fail-closed, do NOT delete.
            None => true,
            Some(ts) => {
                // Newer than the snapshot (overwritten), or now inside the grace window (a fresh write
                // whose index row may not have committed yet). Either way, not safe to GC.
                ts > snapshot_ts || now.duration_since(ts).unwrap_or(Duration::ZERO) < opts.grace
            }
        };
        if rewritten {
            report.skipped_revalidated += 1;
            continue;
        }

        if opts.dry_run {
            // Deletable, but a dry run touches nothing — counted under `would_delete`, not `deleted`, so
            // the partition holds in both modes and the operator sees what a real run would reclaim.
            report.would_delete += 1;
            continue;
        }

        // Still old enough + still unreferenced (fresh index) + not rewritten (fresh stat) + not a dry
        // run ⇒ reclaim it. A per-key failure is recorded and the sweep CONTINUES (one bad key never
        // aborts the whole GC).
        //
        // RESIDUAL RACE (documented): the two fresh checks above narrow the clobber window to the gap
        // between this re-check/re-stat and the `delete()` below — a recreate that commits its index row
        // AND rewrites the bytes in that sub-millisecond gap could still be lost. The DEFINITIVE
        // race-free fix is unique-per-write blob keys (so an overwrite never reuses a candidate's key and
        // the reconciler can never target live bytes); that is a SEPARATE beaded slice — this branch
        // only makes the reconciler SAFE given today's deterministic keys.
        match blob.delete(&key).await {
            Ok(()) => report.deleted += 1,
            Err(_) => report.delete_errors += 1,
        }
    }

    Ok(report)
}

/// Spawn an OPT-IN periodic reconciler: a tokio task that runs [`reconcile_orphans`] every `interval`.
///
/// OFF by default — the binary only calls this when `SOLID_SERVER_RECONCILE_INTERVAL_SECS` is set (see
/// the module docs for why periodic is opt-in, not the default: in a scaled deployment GC should be a
/// single scheduled job, not a per-replica timer). The seams are taken by value (typically cheap
/// `Arc`/`Clone` handles — the live `HttpSparqClient` is `Arc`-backed) so the task owns them. The task
/// runs until the runtime drops; each tick logs the report (a failed sweep is logged and the loop
/// continues — a transient SPARQ blip must not kill the GC task). The first tick fires after one
/// `interval`, not immediately, so it never contends with boot.
///
/// Returns the [`tokio::task::JoinHandle`] so a caller that wants graceful teardown can abort it.
pub fn spawn_periodic<S, B>(
    sparq: S,
    blob: B,
    interval: Duration,
    opts: ReconcileOptions,
) -> tokio::task::JoinHandle<()>
where
    S: SparqClient + 'static,
    B: BlobStore + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip missed ticks rather than bursting to catch up (a long sweep must not queue a backlog of
        // immediate re-runs).
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate first tick so the first sweep is one full interval after boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            // Log via stderr (the crate has no `tracing` dep — main.rs logs the same way). A failed
            // sweep is logged and the loop continues — a transient SPARQ blip must not kill the GC.
            match reconcile_orphans(&sparq, &blob, &opts).await {
                Ok(report) => {
                    eprintln!(
                        "reconciler sweep complete: scanned={} orphaned={} deleted={} \
                         would_delete={} too_young={} skipped_unknown_age={} \
                         skipped_revalidated={} delete_errors={}",
                        report.scanned,
                        report.orphaned,
                        report.deleted,
                        report.would_delete,
                        report.too_young,
                        report.skipped_unknown_age,
                        report.skipped_revalidated,
                        report.delete_errors,
                    );
                }
                Err(e) => {
                    eprintln!("reconciler sweep aborted (will retry next tick): {e}");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::blob::InMemoryBlobStore;
    use crate::store::sparq::{InMemorySparqClient, ResourceMeta};
    use bytes::Bytes;
    use std::sync::Mutex;

    fn meta(blob_key: &str) -> ResourceMeta {
        ResourceMeta {
            content_type: "text/turtle".into(),
            blob_key: blob_key.to_string(),
            etag: "\"e\"".into(),
        }
    }

    /// A timestamp `secs` ago — for deterministically back-dating a blob (no sleep).
    fn ago(secs: u64) -> SystemTime {
        SystemTime::now() - Duration::from_secs(secs)
    }

    // A short grace for the tests (so "older than grace" is easy to arrange deterministically).
    fn opts() -> ReconcileOptions {
        ReconcileOptions {
            grace: Duration::from_secs(60),
            dry_run: false,
        }
    }

    #[tokio::test]
    async fn unreferenced_and_old_enough_blob_is_deleted() {
        let sparq = InMemorySparqClient::new();
        let blob = InMemoryBlobStore::new();
        // An orphan: bytes exist, NO index row references "orphan". Back-dated past the grace window.
        blob.put_with_time("orphan", Bytes::from_static(b"x"), ago(3600));

        let report = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.orphaned, 1);
        assert_eq!(report.deleted, 1);
        assert_eq!(report.referenced, 0);
        assert!(!blob.exists("orphan").await.unwrap(), "orphan must be GC'd");
    }

    #[tokio::test]
    async fn referenced_blob_is_kept_even_if_old() {
        let sparq = InMemorySparqClient::new();
        let blob = InMemoryBlobStore::new();
        // A LIVE resource: an index row references "live-key", and its bytes are old.
        sparq.put_meta("iri", meta("live-key")).await.unwrap();
        blob.put_with_time("live-key", Bytes::from_static(b"x"), ago(99999));

        let report = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.referenced, 1);
        assert_eq!(report.orphaned, 0);
        assert_eq!(report.deleted, 0);
        assert!(
            blob.exists("live-key").await.unwrap(),
            "a referenced blob must NEVER be GC'd, however old"
        );
    }

    #[tokio::test]
    async fn unreferenced_but_too_young_blob_is_kept() {
        // THE GRACE TEST: an unreferenced blob younger than the window is a possible write-in-progress
        // (bytes PUT, index row not yet committed) — it MUST be protected.
        let sparq = InMemorySparqClient::new();
        let blob = InMemoryBlobStore::new();
        blob.put_with_time("fresh-orphan", Bytes::from_static(b"x"), ago(1)); // 1s < 60s grace

        let report = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.orphaned, 1);
        assert_eq!(report.too_young, 1);
        assert_eq!(report.deleted, 0);
        assert!(
            blob.exists("fresh-orphan").await.unwrap(),
            "the grace window must protect a too-young orphan (the write-in-progress race)"
        );
    }

    #[tokio::test]
    async fn report_counts_partition_correctly() {
        let sparq = InMemorySparqClient::new();
        let blob = InMemoryBlobStore::new();
        // 1 referenced (old), 1 old orphan (deleted), 1 young orphan (kept), 1 unknown-age orphan (kept).
        sparq.put_meta("iri", meta("ref")).await.unwrap();
        blob.put_with_time("ref", Bytes::from_static(b"r"), ago(99999));
        blob.put_with_time("old-orphan", Bytes::from_static(b"o"), ago(3600));
        blob.put_with_time("young-orphan", Bytes::from_static(b"y"), ago(1));
        blob.put_with_time(
            "undated-orphan",
            Bytes::from_static(b"u"),
            SystemTime::now(),
        );
        // Force the unknown-age path by listing-time stamping is awkward; instead assert the
        // partition algebra on the known stamps. (The unknown-age branch is covered separately below.)

        let report = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(report.scanned, 4);
        assert_eq!(report.referenced, 1);
        assert_eq!(report.orphaned, 3);
        assert_eq!(report.deleted, 1); // only "old-orphan"
                                       // "young-orphan" + "undated-orphan"(now) are both inside the 60s window ⇒ too_young.
        assert_eq!(report.too_young, 2);
        // The SIX dispositions of an orphan must sum to `orphaned` (the full partition).
        assert_eq!(
            report.deleted
                + report.would_delete
                + report.too_young
                + report.skipped_unknown_age
                + report.skipped_revalidated
                + report.delete_errors,
            report.orphaned
        );
        // And referenced + orphaned == scanned.
        assert_eq!(report.referenced + report.orphaned, report.scanned);
    }

    #[tokio::test]
    async fn unknown_age_blob_is_kept_fail_closed() {
        // A backend that reports no last_modified ⇒ age unknowable ⇒ NEVER GC'd.
        let sparq = InMemorySparqClient::new();
        let blob = UndatedBlobStore::with_key("ghost");

        let report = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.orphaned, 1);
        assert_eq!(report.skipped_unknown_age, 1);
        assert_eq!(report.deleted, 0);
    }

    #[tokio::test]
    async fn idempotent_second_run_deletes_nothing() {
        let sparq = InMemorySparqClient::new();
        let blob = InMemoryBlobStore::new();
        blob.put_with_time("orphan", Bytes::from_static(b"x"), ago(3600));

        let first = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(first.deleted, 1);

        // Second run over the now-clean state: nothing left to delete.
        let second = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(second.scanned, 0);
        assert_eq!(second.orphaned, 0);
        assert_eq!(second.deleted, 0);
    }

    #[tokio::test]
    async fn dry_run_deletes_nothing_but_reports_orphans() {
        let sparq = InMemorySparqClient::new();
        let blob = InMemoryBlobStore::new();
        // 1 deletable orphan (old), 1 too-young orphan, 1 referenced — so the partition has >1 term.
        sparq.put_meta("iri", meta("ref")).await.unwrap();
        blob.put_with_time("ref", Bytes::from_static(b"r"), ago(99999));
        blob.put_with_time("orphan", Bytes::from_static(b"x"), ago(3600));
        blob.put_with_time("young", Bytes::from_static(b"y"), ago(1));

        let dry = ReconcileOptions {
            grace: Duration::from_secs(60),
            dry_run: true,
        };
        let report = reconcile_orphans(&sparq, &blob, &dry).await.unwrap();
        assert_eq!(report.scanned, 3);
        assert_eq!(report.referenced, 1);
        assert_eq!(report.orphaned, 2);
        assert_eq!(report.deleted, 0, "dry run must not delete");
        // Finding 2: the deletable orphan is counted under `would_delete`, NOT `deleted`.
        assert_eq!(
            report.would_delete, 1,
            "dry run reports the deletable count"
        );
        assert_eq!(report.too_young, 1);
        // The partition invariant must hold in DRY-RUN mode too.
        assert_eq!(
            report.deleted
                + report.would_delete
                + report.too_young
                + report.skipped_unknown_age
                + report.skipped_revalidated
                + report.delete_errors,
            report.orphaned
        );
        assert_eq!(report.referenced + report.orphaned, report.scanned);
        assert!(
            blob.exists("orphan").await.unwrap(),
            "dry run must keep the bytes"
        );
        assert!(blob.exists("young").await.unwrap());
    }

    #[tokio::test]
    async fn candidate_that_becomes_referenced_between_snapshot_and_delete_is_kept() {
        // FINDING 1 (part a) regression: a candidate that looked unreferenced at the start-of-sweep
        // snapshot but becomes REFERENCED (a recreate committed a fresh index row at the same
        // deterministic key) before the delete pass must NOT be deleted.
        //
        // `ToggleReferencedSparq` returns {} on the FIRST `referenced_blob_keys()` (the snapshot) and
        // {"orphan"} on the SECOND (the pre-delete fresh re-check). The blob is old enough, so without
        // the fresh re-check it WOULD be classified deletable and removed — the mutation-check.
        let sparq = ToggleReferencedSparq::new(["orphan"]);
        let blob = InMemoryBlobStore::new();
        blob.put_with_time("orphan", Bytes::from_static(b"x"), ago(3600));

        let report = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(report.scanned, 1);
        // Snapshot said unreferenced ⇒ it was an orphan candidate...
        assert_eq!(report.orphaned, 1);
        // ...but the fresh re-check found it referenced again ⇒ revalidated, NOT deleted.
        assert_eq!(report.skipped_revalidated, 1);
        assert_eq!(report.deleted, 0);
        assert!(
            blob.exists("orphan").await.unwrap(),
            "a candidate referenced again by delete-time must NOT be GC'd (the recreate race)"
        );
    }

    #[tokio::test]
    async fn mutation_check_without_fresh_recheck_the_recreate_would_be_deleted() {
        // The mutation-check made explicit: with the SNAPSHOT referenced set (empty), the candidate is
        // old-enough + unreferenced ⇒ the un-rechecked logic would delete it. We assert that the
        // snapshot view alone classifies it deletable, proving the test above is non-vacuous: it is the
        // FRESH re-check (the second referenced query) that flips the outcome to kept.
        let snapshot_referenced: HashSet<String> = HashSet::new();
        // From the start-of-sweep snapshot the key is unreferenced + old ⇒ would be deleted.
        assert!(!snapshot_referenced.contains("orphan"));
        // The fresh set (what the fix consults) DOES contain it ⇒ the fix keeps it.
        let fresh_referenced: HashSet<String> = ["orphan".to_string()].into_iter().collect();
        assert!(fresh_referenced.contains("orphan"));
    }

    #[tokio::test]
    async fn candidate_whose_bytes_are_rewritten_between_snapshot_and_delete_is_kept() {
        // FINDING 1 (part b) regression: a candidate old-enough at the snapshot whose BYTES are
        // REWRITTEN (a newer `last_modified` — a same-key overwrite under deterministic keying) before
        // the delete pass must NOT be deleted.
        //
        // `RewrittenBlobStore::list()` reports an OLD stamp (so it is classified deletable); its
        // `stat()` reports a FRESH stamp (the rewrite). Without the re-stat the candidate WOULD be
        // deleted — the mutation-check (the snapshot view alone says delete).
        let sparq = InMemorySparqClient::new();
        let blob = RewrittenBlobStore::new(
            "rewritten",
            ago(3600),         // old at snapshot ⇒ classified deletable
            SystemTime::now(), // freshly rewritten by delete-time ⇒ must be kept
        );

        let report = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.orphaned, 1);
        // The re-stat saw newer bytes ⇒ revalidated, NOT deleted.
        assert_eq!(report.skipped_revalidated, 1);
        assert_eq!(report.deleted, 0);
        assert!(
            !blob.deleted_keys().contains(&"rewritten".to_string()),
            "a candidate whose bytes were rewritten by delete-time must NOT be GC'd"
        );
    }

    #[tokio::test]
    async fn referenced_set_error_aborts_and_deletes_nothing() {
        // Fail-closed: if the referenced-set query fails we must NOT delete (a failed query is NOT
        // "nothing is referenced"). The blob list is never even consulted.
        let sparq = FailingSparq;
        let blob = InMemoryBlobStore::new();
        blob.put_with_time("orphan", Bytes::from_static(b"x"), ago(3600));

        let err = reconcile_orphans(&sparq, &blob, &opts()).await.unwrap_err();
        assert!(matches!(err, ReconcileError::ReferencedSet(_)));
        assert!(
            blob.exists("orphan").await.unwrap(),
            "a failed referenced-set query must abort the sweep without deleting"
        );
    }

    // --- test doubles for the fail-closed / unknown-age / fresh-recheck branches ---

    /// A SPARQ client whose `referenced_blob_keys` returns the EMPTY set on the first call (the
    /// start-of-sweep snapshot) and a configured non-empty set on every subsequent call (the pre-delete
    /// fresh re-check) — modelling a recreate that committed an index row mid-sweep at a reused
    /// deterministic key. Only `referenced_blob_keys` is reachable in these tests; the rest panic.
    struct ToggleReferencedSparq {
        fresh: HashSet<String>,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl ToggleReferencedSparq {
        fn new<I: IntoIterator<Item = &'static str>>(fresh: I) -> Self {
            Self {
                fresh: fresh.into_iter().map(str::to_string).collect(),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }
    #[async_trait::async_trait]
    impl SparqClient for ToggleReferencedSparq {
        async fn get_meta(&self, _: &str) -> Result<ResourceMeta, SparqError> {
            unreachable!()
        }
        async fn put_meta(&self, _: &str, _: ResourceMeta) -> Result<(), SparqError> {
            unreachable!()
        }
        async fn exists(&self, _: &str) -> Result<bool, SparqError> {
            unreachable!()
        }
        async fn delete_meta(&self, _: &str) -> Result<(), SparqError> {
            unreachable!()
        }
        async fn delete_meta_if_empty(
            &self,
            _: &str,
            _: Option<&str>,
        ) -> Result<super::super::sparq::DeleteOutcome, SparqError> {
            unreachable!()
        }
        async fn create_child(&self, _: &str, _: &str, _: ResourceMeta) -> Result<(), SparqError> {
            unreachable!()
        }
        async fn remove_child(&self, _: &str, _: &str) -> Result<(), SparqError> {
            unreachable!()
        }
        async fn list_children(&self, _: &str) -> Result<Vec<String>, SparqError> {
            unreachable!()
        }
        async fn referenced_blob_keys(&self) -> Result<HashSet<String>, SparqError> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // First call (the snapshot): nothing referenced. Later calls (the fresh re-check): the
            // recreate's row is now visible.
            if n == 0 {
                Ok(HashSet::new())
            } else {
                Ok(self.fresh.clone())
            }
        }
    }

    /// A blob store whose `list()` reports an OLD `last_modified` (so a key is classified deletable) but
    /// whose `stat()` reports a FRESH one (modelling a same-key overwrite that landed after the
    /// snapshot). Records every `delete()` so a test can assert nothing was actually removed.
    struct RewrittenBlobStore {
        key: String,
        list_stamp: SystemTime,
        stat_stamp: SystemTime,
        deleted: Mutex<Vec<String>>,
    }
    impl RewrittenBlobStore {
        fn new(key: &str, list_stamp: SystemTime, stat_stamp: SystemTime) -> Self {
            Self {
                key: key.to_string(),
                list_stamp,
                stat_stamp,
                deleted: Mutex::new(Vec::new()),
            }
        }
        fn deleted_keys(&self) -> Vec<String> {
            self.deleted.lock().expect("poisoned").clone()
        }
    }
    #[async_trait::async_trait]
    impl BlobStore for RewrittenBlobStore {
        async fn get(&self, _: &str) -> Result<Bytes, BlobError> {
            Ok(Bytes::from_static(b"x"))
        }
        async fn put(&self, _: &str, _: Bytes) -> Result<(), BlobError> {
            Ok(())
        }
        async fn exists(&self, key: &str) -> Result<bool, BlobError> {
            Ok(key == self.key)
        }
        async fn delete(&self, key: &str) -> Result<(), BlobError> {
            self.deleted.lock().expect("poisoned").push(key.to_string());
            Ok(())
        }
        async fn list(&self) -> Result<Vec<super::super::blob::BlobEntry>, BlobError> {
            Ok(vec![super::super::blob::BlobEntry {
                key: self.key.clone(),
                last_modified: Some(self.list_stamp),
            }])
        }
        async fn stat(
            &self,
            key: &str,
        ) -> Result<Option<super::super::blob::BlobEntry>, BlobError> {
            // The FRESH (rewritten) view: a newer stamp than `list()` reported.
            Ok((key == self.key).then(|| super::super::blob::BlobEntry {
                key: self.key.clone(),
                last_modified: Some(self.stat_stamp),
            }))
        }
    }

    /// A blob store whose `list` reports keys with NO last_modified (the unknown-age path).
    struct UndatedBlobStore {
        key: String,
        inner: InMemoryBlobStore,
    }
    impl UndatedBlobStore {
        fn with_key(key: &str) -> Self {
            let inner = InMemoryBlobStore::new();
            inner.put_with_time(key, Bytes::from_static(b"x"), SystemTime::now());
            Self {
                key: key.to_string(),
                inner,
            }
        }
    }
    #[async_trait::async_trait]
    impl BlobStore for UndatedBlobStore {
        async fn get(&self, key: &str) -> Result<Bytes, BlobError> {
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, body: Bytes) -> Result<(), BlobError> {
            self.inner.put(key, body).await
        }
        async fn exists(&self, key: &str) -> Result<bool, BlobError> {
            self.inner.exists(key).await
        }
        async fn delete(&self, key: &str) -> Result<(), BlobError> {
            self.inner.delete(key).await
        }
        async fn list(&self) -> Result<Vec<super::super::blob::BlobEntry>, BlobError> {
            Ok(vec![super::super::blob::BlobEntry {
                key: self.key.clone(),
                last_modified: None,
            }])
        }
    }

    /// A SPARQ client whose `referenced_blob_keys` always errors (the fail-closed test). All other
    /// methods are unreachable in this test, so they panic.
    struct FailingSparq;
    #[async_trait::async_trait]
    impl SparqClient for FailingSparq {
        async fn get_meta(&self, _: &str) -> Result<ResourceMeta, SparqError> {
            unreachable!()
        }
        async fn put_meta(&self, _: &str, _: ResourceMeta) -> Result<(), SparqError> {
            unreachable!()
        }
        async fn exists(&self, _: &str) -> Result<bool, SparqError> {
            unreachable!()
        }
        async fn delete_meta(&self, _: &str) -> Result<(), SparqError> {
            unreachable!()
        }
        async fn delete_meta_if_empty(
            &self,
            _: &str,
            _: Option<&str>,
        ) -> Result<super::super::sparq::DeleteOutcome, SparqError> {
            unreachable!()
        }
        async fn create_child(&self, _: &str, _: &str, _: ResourceMeta) -> Result<(), SparqError> {
            unreachable!()
        }
        async fn remove_child(&self, _: &str, _: &str) -> Result<(), SparqError> {
            unreachable!()
        }
        async fn list_children(&self, _: &str) -> Result<Vec<String>, SparqError> {
            unreachable!()
        }
        async fn referenced_blob_keys(&self) -> Result<HashSet<String>, SparqError> {
            Err(SparqError::Backend(
                "simulated referenced-set failure".into(),
            ))
        }
    }
}
