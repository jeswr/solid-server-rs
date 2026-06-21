// AUTHORED-BY Claude Opus 4.8
//! Store-trait tests against the in-memory composite (SPARQ-authoritative metadata + blob bytes),
//! plus the RDF content-type classification + validation.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Bytes;
use solid_server_rs::error::ServerError;
use solid_server_rs::ldp::content::{classify, validate_rdf, RdfFormat};
use solid_server_rs::store::{
    BlobError, BlobStore, CompositeStore, DeleteOutcome, InMemoryBlobStore, InMemorySparqClient,
    ResourceMeta, SparqClient, SparqError, Store,
};

const IRI: &str = "https://pod.example/alice/data";
const TURTLE: &str =
    "<https://pod.example/alice/data#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .";

fn store() -> impl Store {
    CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new())
}

#[tokio::test]
async fn read_of_a_missing_resource_is_not_found() {
    let s = store();
    let err = s.read(IRI).await.unwrap_err();
    assert!(matches!(err, ServerError::NotFound));
}

#[tokio::test]
async fn exists_is_false_before_a_write() {
    let s = store();
    assert!(!s.exists(IRI).await.unwrap());
}

#[tokio::test]
async fn write_then_read_round_trips_bytes_and_content_type() {
    let s = store();
    let body = Bytes::from_static(TURTLE.as_bytes());
    let meta = s.write(IRI, body.clone(), "text/turtle").await.unwrap();
    assert_eq!(meta.content_type, "text/turtle");
    assert!(!meta.etag.is_empty());

    assert!(s.exists(IRI).await.unwrap());
    let resource = s.read(IRI).await.unwrap();
    assert_eq!(resource.body, body);
    assert_eq!(resource.meta.content_type, "text/turtle");
    assert_eq!(resource.meta.etag, meta.etag);
}

#[tokio::test]
async fn rewrite_replaces_the_bytes() {
    let s = store();
    s.write(IRI, Bytes::from_static(b"<a> <b> <c> ."), "text/turtle")
        .await
        .unwrap();
    let new_body = Bytes::from_static(b"<a> <b> <d> .");
    s.write(IRI, new_body.clone(), "text/turtle").await.unwrap();
    let resource = s.read(IRI).await.unwrap();
    assert_eq!(resource.body, new_body);
}

#[tokio::test]
async fn different_bytes_yield_a_different_etag() {
    let s = store();
    let m1 = s
        .write(IRI, Bytes::from_static(b"<a> <b> <c> ."), "text/turtle")
        .await
        .unwrap();
    let m2 = s
        .write(
            IRI,
            Bytes::from_static(b"<a> <b> <different> ."),
            "text/turtle",
        )
        .await
        .unwrap();
    assert_ne!(
        m1.etag, m2.etag,
        "different content must yield a different ETag"
    );
}

// --- M2: delete + containment ---

#[tokio::test]
async fn delete_removes_metadata_and_bytes() {
    let s = store();
    s.write(IRI, Bytes::from_static(TURTLE.as_bytes()), "text/turtle")
        .await
        .unwrap();
    assert!(s.exists(IRI).await.unwrap());

    s.delete(IRI, None).await.unwrap();
    assert!(!s.exists(IRI).await.unwrap());
    assert!(matches!(
        s.read(IRI).await.unwrap_err(),
        ServerError::NotFound
    ));
}

#[tokio::test]
async fn delete_is_idempotent_on_absent() {
    let s = store();
    // Deleting a never-written resource is not an error at the store layer.
    s.delete(IRI, None).await.unwrap();
}

#[tokio::test]
async fn create_in_container_records_membership() {
    let s = store();
    let container = "https://pod.example/alice/";
    let child = "https://pod.example/alice/note1";
    // The container must exist before a child can be attached (atomic parent-exists invariant).
    s.write(
        container,
        Bytes::from_static(b"<#c> <#p> \"C\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    s.create_in_container(
        container,
        child,
        Bytes::from_static(b"<#it> <#p> \"x\" ."),
        "text/turtle",
    )
    .await
    .unwrap();

    let children = s.list_children(container).await.unwrap();
    assert_eq!(children, vec![child.to_string()]);
    assert!(s.exists(child).await.unwrap());
}

#[tokio::test]
async fn create_in_a_missing_container_is_not_found() {
    let s = store();
    // The container was never created — create_in_container must refuse + write nothing.
    let err = s
        .create_in_container(
            "https://pod.example/missing/",
            "https://pod.example/missing/child",
            Bytes::from_static(b"<#it> <#p> \"x\" ."),
            "text/turtle",
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ServerError::NotFound));
    // Nothing was written under the missing container.
    assert!(!s.exists("https://pod.example/missing/child").await.unwrap());
}

#[tokio::test]
async fn create_in_container_twice_keeps_a_single_membership() {
    // Re-creating the same child IRI in a container must not duplicate the membership edge
    // (add_child is idempotent).
    let s = store();
    let container = "https://pod.example/alice/";
    let child = "https://pod.example/alice/note1";
    s.write(
        container,
        Bytes::from_static(b"<#c> <#p> \"C\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    for _ in 0..2 {
        s.create_in_container(
            container,
            child,
            Bytes::from_static(b"<#it> <#p> \"x\" ."),
            "text/turtle",
        )
        .await
        .unwrap();
    }
    assert_eq!(
        s.list_children(container).await.unwrap(),
        vec![child.to_string()]
    );
}

#[tokio::test]
async fn create_child_commits_metadata_and_membership_atomically() {
    // Directly exercise the atomic create on the SparqClient: both the child metadata and the edge
    // appear together, and a missing container is refused with nothing written.
    let sparq = InMemorySparqClient::new();
    let container = "https://pod.example/alice/";
    let child = "https://pod.example/alice/note1";
    let meta = ResourceMeta {
        content_type: "text/turtle".into(),
        blob_key: "k".into(),
        etag: "\"e\"".into(),
    };

    // Missing container ⇒ NotFound, no metadata + no edge written.
    let err = sparq
        .create_child(container, child, meta.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, SparqError::NotFound));
    assert!(!sparq.exists(child).await.unwrap());
    assert!(sparq.list_children(container).await.unwrap().is_empty());

    // With the container indexed, create_child commits the child meta AND the edge together.
    sparq.put_meta(container, meta.clone()).await.unwrap();
    sparq.create_child(container, child, meta).await.unwrap();
    assert!(sparq.exists(child).await.unwrap());
    assert_eq!(
        sparq.list_children(container).await.unwrap(),
        vec![child.to_string()]
    );
}

#[tokio::test]
async fn delete_detaches_from_parent_container() {
    let s = store();
    let container = "https://pod.example/alice/";
    let child = "https://pod.example/alice/note1";
    s.write(
        container,
        Bytes::from_static(b"<#c> <#p> \"C\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    s.create_in_container(
        container,
        child,
        Bytes::from_static(b"<#it> <#p> \"x\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    assert_eq!(s.list_children(container).await.unwrap().len(), 1);

    s.delete(child, Some(container)).await.unwrap();
    assert!(s.list_children(container).await.unwrap().is_empty());
    assert!(!s.exists(child).await.unwrap());
}

#[tokio::test]
async fn deleting_a_container_clears_its_own_containment_set() {
    // Deleting a container removes its OWN record AND its `ldp:contains` set (parity with the live
    // `DROP SILENT GRAPH`): a container re-created at the same IRI must not inherit a stale member.
    let s = store();
    let parent = "https://pod.example/alice/";
    let container = "https://pod.example/alice/sub/";
    let child = "https://pod.example/alice/sub/note1";
    s.write(
        parent,
        Bytes::from_static(b"<#c> <#p> \"P\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    // Create the sub-container as a child of the parent, then a child inside it.
    s.create_in_container(
        parent,
        container,
        Bytes::from_static(b"<#c> <#p> \"S\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    s.create_in_container(
        container,
        child,
        Bytes::from_static(b"<#it> <#p> \"x\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    // Empty the sub-container (the handler's empty-container precondition), then delete the container.
    s.delete(child, Some(container)).await.unwrap();
    assert!(s.list_children(container).await.unwrap().is_empty());
    s.delete(container, Some(parent)).await.unwrap();

    // The container is gone, detached from its parent, and its own containment set is cleared.
    assert!(!s.exists(container).await.unwrap());
    assert!(s.list_children(parent).await.unwrap().is_empty());
    assert!(
        s.list_children(container).await.unwrap().is_empty(),
        "a deleted container must leave no stale containment set"
    );
}

// --- M2: ATOMIC empty-container delete (the TOCTOU fix) ---

#[tokio::test]
async fn delete_container_if_empty_refuses_a_populated_container() {
    // The atomic op must report NotEmpty for a populated container AND delete NOTHING — the container
    // and its child both survive (no orphaning). This is the safety invariant: a non-empty container
    // is never deleted, so a concurrently-added child can't be orphaned under a deleted parent.
    let s = store();
    let container = "https://pod.example/alice/";
    let child = "https://pod.example/alice/note1";
    s.write(
        container,
        Bytes::from_static(b"<#c> <#p> \"C\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    s.create_in_container(
        container,
        child,
        Bytes::from_static(b"<#it> <#p> \"x\" ."),
        "text/turtle",
    )
    .await
    .unwrap();

    let outcome = s.delete_container_if_empty(container, None).await.unwrap();
    assert_eq!(outcome, DeleteOutcome::NotEmpty);
    // NOTHING was deleted: the container + its child + the membership edge all survive.
    assert!(
        s.exists(container).await.unwrap(),
        "a NotEmpty result must leave the container present"
    );
    assert!(
        s.exists(child).await.unwrap(),
        "a NotEmpty result must leave the child present (not orphaned)"
    );
    assert_eq!(
        s.list_children(container).await.unwrap(),
        vec![child.to_string()],
        "a NotEmpty result must leave the membership edge intact"
    );
}

#[tokio::test]
async fn delete_container_if_empty_deletes_an_empty_container() {
    // The atomic op returns Deleted for an empty container, and it is gone afterwards.
    let s = store();
    let container = "https://pod.example/alice/empty/";
    s.write(
        container,
        Bytes::from_static(b"<#c> <#p> \"C\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    assert!(s.exists(container).await.unwrap());

    let outcome = s.delete_container_if_empty(container, None).await.unwrap();
    assert_eq!(outcome, DeleteOutcome::Deleted);
    assert!(!s.exists(container).await.unwrap());
    assert!(matches!(
        s.read(container).await.unwrap_err(),
        ServerError::NotFound
    ));
}

#[tokio::test]
async fn delete_container_if_empty_reports_not_found_for_an_absent_container() {
    // An absent container ⇒ NotFound (the handler maps this to 404), nothing touched.
    let s = store();
    let outcome = s
        .delete_container_if_empty("https://pod.example/alice/nope/", None)
        .await
        .unwrap();
    assert_eq!(outcome, DeleteOutcome::NotFound);
}

#[tokio::test]
async fn delete_container_if_empty_detaches_from_parent_and_routes_recreate_clean() {
    // The atomic empty-delete detaches the (deleted) container from its parent's containment, and a
    // container re-created at the same IRI inherits no stale membership — the delete-then-recreate
    // no-stale-membership case routed through the NEW atomic op.
    let s = store();
    let parent = "https://pod.example/alice/";
    let container = "https://pod.example/alice/sub/";
    let child = "https://pod.example/alice/sub/note1";
    s.write(
        parent,
        Bytes::from_static(b"<#c> <#p> \"P\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    s.create_in_container(
        parent,
        container,
        Bytes::from_static(b"<#c> <#p> \"S\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    s.create_in_container(
        container,
        child,
        Bytes::from_static(b"<#it> <#p> \"x\" ."),
        "text/turtle",
    )
    .await
    .unwrap();

    // While the sub-container has a member, the atomic delete refuses it (409 ⇒ NotEmpty).
    assert_eq!(
        s.delete_container_if_empty(container, Some(parent))
            .await
            .unwrap(),
        DeleteOutcome::NotEmpty
    );

    // Empty it, then the atomic delete succeeds + detaches from the parent.
    s.delete(child, Some(container)).await.unwrap();
    assert_eq!(
        s.delete_container_if_empty(container, Some(parent))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(!s.exists(container).await.unwrap());
    assert!(
        s.list_children(parent).await.unwrap().is_empty(),
        "the deleted container must be detached from its parent"
    );

    // Re-create a container at the SAME IRI — it must inherit NO stale member from the deleted one.
    s.create_in_container(
        parent,
        container,
        Bytes::from_static(b"<#c> <#p> \"S2\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    assert!(
        s.list_children(container).await.unwrap().is_empty(),
        "a re-created container must not inherit a stale containment set"
    );
}

#[tokio::test]
async fn delete_meta_if_empty_on_the_sparq_client_is_atomic() {
    // Directly exercise the atomic op on the SparqClient: NotEmpty leaves both the container record and
    // the membership edge intact; Deleted removes the record + clears the containment set.
    let sparq = InMemorySparqClient::new();
    let container = "https://pod.example/alice/";
    let child = "https://pod.example/alice/note1";
    let meta = ResourceMeta {
        content_type: "text/turtle".into(),
        blob_key: "k".into(),
        etag: "\"e\"".into(),
    };

    // Absent ⇒ NotFound.
    assert_eq!(
        sparq.delete_meta_if_empty(container, None).await.unwrap(),
        DeleteOutcome::NotFound
    );

    // Populated ⇒ NotEmpty, nothing removed.
    sparq.put_meta(container, meta.clone()).await.unwrap();
    sparq
        .create_child(container, child, meta.clone())
        .await
        .unwrap();
    assert_eq!(
        sparq.delete_meta_if_empty(container, None).await.unwrap(),
        DeleteOutcome::NotEmpty
    );
    assert!(sparq.exists(container).await.unwrap());
    assert_eq!(
        sparq.list_children(container).await.unwrap(),
        vec![child.to_string()]
    );

    // Empty it, then Deleted ⇒ record gone + containment set cleared.
    sparq.remove_child(container, child).await.unwrap();
    sparq.delete_meta(child).await.unwrap();
    assert_eq!(
        sparq.delete_meta_if_empty(container, None).await.unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(!sparq.exists(container).await.unwrap());
    assert!(sparq.list_children(container).await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_meta_if_empty_folds_the_parent_detach_into_the_one_op() {
    // FINDING 2 (in-memory parity): the parent-edge detach must happen IN the same atomic op as the
    // record delete — a single `delete_meta_if_empty(container, Some(parent))` both removes the
    // container record AND detaches `<parent> ldp:contains <container>`, with no separate `remove_child`
    // step. After a Deleted outcome the parent's containment must no longer list the container.
    let sparq = InMemorySparqClient::new();
    let parent = "https://pod.example/alice/";
    let container = "https://pod.example/alice/sub/";
    let meta = ResourceMeta {
        content_type: "text/turtle".into(),
        blob_key: "k".into(),
        etag: "\"e\"".into(),
    };
    sparq.put_meta(parent, meta.clone()).await.unwrap();
    // Index the empty sub-container AND its edge in the parent (create_child commits both).
    sparq
        .create_child(parent, container, meta.clone())
        .await
        .unwrap();
    assert_eq!(
        sparq.list_children(parent).await.unwrap(),
        vec![container.to_string()],
        "the parent lists the sub-container before the delete"
    );

    // ONE op deletes the (empty) sub-container AND detaches it from the parent — no follow-up call.
    assert_eq!(
        sparq
            .delete_meta_if_empty(container, Some(parent))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(!sparq.exists(container).await.unwrap());
    assert!(
        sparq.list_children(parent).await.unwrap().is_empty(),
        "the parent edge is detached in the SAME atomic op (no separate remove_child)"
    );
}

/// A [`BlobStore`] wrapper whose `delete` is unconditional (exactly like `InMemoryBlobStore`'s and
/// the real `object_store` delete the HIGH finding is about), but which COUNTS its `delete` calls so
/// the test can prove the store no longer issues an inline blob delete. The inner store is shared
/// (`Arc`) so the test can stage the in-window recreate and inspect the surviving bytes directly.
struct CountingBlob {
    inner: Arc<InMemoryBlobStore>,
    deletes_seen: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl BlobStore for CountingBlob {
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
        // Unconditional, idempotent — same contract as the real object_store delete. The point is only
        // to count: an inline delete here is exactly the clobber the finding describes.
        self.deletes_seen
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.delete(key).await
    }

    async fn list(&self) -> Result<Vec<solid_server_rs::store::BlobEntry>, BlobError> {
        self.inner.list().await
    }

    async fn delete_if_unchanged(
        &self,
        key: &str,
        expected_generation: u64,
    ) -> Result<bool, BlobError> {
        // Delegate to the inner atomic CAS. This is the reconciler's delete path, not the inline
        // post-index-delete `delete` this test counts — so it deliberately does NOT bump `deletes_seen`.
        self.inner
            .delete_if_unchanged(key, expected_generation)
            .await
    }
}

#[tokio::test]
async fn delete_container_if_empty_does_not_clobber_a_concurrent_same_iri_recreate() {
    // HIGH-finding regression: after the atomic index delete, the (former) post-delete blob GC must
    // NOT remove a concurrent same-IRI recreate's bytes. With deterministic key reuse, a POST
    // recreating the SAME resource IRI between the index delete and an inline blob delete writes NEW
    // bytes to the SAME key + a fresh index row; an inline unconditional `blob.delete` would clobber
    // those NEW bytes, leaving the fresh index row pointing at MISSING bytes (the FALSE "an index row
    // never points at missing bytes" invariant). The fix removes the inline delete (bytes are
    // reconciler-GC'd), so the recreate's bytes always survive.
    //
    // We model the race window EXPLICITLY: stage the concurrent recreate's NEW bytes at the (reused)
    // deterministic key BEFORE the atomic index delete returns — i.e. they are already present when
    // any inline blob delete would fire. The test is NON-VACUOUS — it FAILS against the old code:
    //   - OLD code: `delete_container_if_empty` issues an inline `blob.delete(key)` AFTER the index
    //     delete → the staged recreate bytes are removed → `deletes_seen == 1` AND the key holds NO
    //     bytes → BOTH asserts FAIL.
    //   - FIX: no inline delete → `deletes_seen == 0` AND the staged recreate bytes survive → PASS.
    let recreate_bytes = Bytes::from_static(b"<#recreated> <#p> \"v2\" .");
    let deletes_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let inner = Arc::new(InMemoryBlobStore::new());
    let blob = CountingBlob {
        inner: inner.clone(),
        deletes_seen: deletes_seen.clone(),
    };
    let s = CompositeStore::new(InMemorySparqClient::new(), blob);

    let container = "https://pod.example/alice/sub/";
    // Create the (empty) container — bytes land at the deterministic key for this IRI.
    s.write(
        container,
        Bytes::from_static(b"<#c> <#p> \"v1\" ."),
        "text/turtle",
    )
    .await
    .unwrap();
    // The deterministic key reuse is the precondition of the race: the recreate and the original share
    // a key (mirrors `CompositeStore::blob_key_for`'s percent-flatten).
    let key = container.replace([':', '/', '?', '#', '%'], "_");

    // Stage the concurrent same-IRI recreate: it has landed its NEW bytes at the SAME deterministic
    // key (and, conceptually, a fresh index row). These bytes MUST survive the container delete.
    inner.put(&key, recreate_bytes.clone()).await.unwrap();

    // Atomically delete the (now-empty, as far as the index is concerned) container's index row.
    let outcome = s.delete_container_if_empty(container, None).await.unwrap();
    assert_eq!(outcome, DeleteOutcome::Deleted);

    // The FIX must not have invoked an inline blob delete at all (orphaned bytes are the reconciler's
    // job, not an inline delete that can race a recreate). Under the OLD code this would be 1.
    assert_eq!(
        deletes_seen.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the fixed delete_container_if_empty must NOT delete bytes inline (reconciler GCs orphans); \
         the old inline-unconditional-delete code would call blob.delete here and clobber a recreate"
    );

    // The concurrent recreate's bytes at the deterministic key are intact — i.e. the fresh index row a
    // recreate writes is never left pointing at MISSING bytes. Under the OLD inline-delete code the
    // staged bytes were removed during the delete, so `get` would be `NotFound`.
    let surviving = inner
        .get(&key)
        .await
        .expect("a concurrent same-IRI recreate's bytes must survive the container delete");
    assert_eq!(
        surviving, recreate_bytes,
        "the recreated resource's bytes must be intact (never clobbered by an inline GC)"
    );
}

#[tokio::test]
async fn meta_returns_etag_without_bytes() {
    let s = store();
    let written = s
        .write(IRI, Bytes::from_static(TURTLE.as_bytes()), "text/turtle")
        .await
        .unwrap();
    let meta = s
        .meta(IRI)
        .await
        .unwrap()
        .expect("meta present after write");
    assert_eq!(meta.etag, written.etag);
    // Absent resource ⇒ None.
    assert!(s.meta("https://pod.example/nope").await.unwrap().is_none());
}

// --- content-type classification + RDF validation ---

#[test]
fn classifies_turtle_and_jsonld_ignoring_params() {
    assert_eq!(classify(Some("text/turtle")).unwrap(), RdfFormat::Turtle);
    assert_eq!(
        classify(Some("text/turtle; charset=utf-8")).unwrap(),
        RdfFormat::Turtle
    );
    assert_eq!(
        classify(Some("application/ld+json")).unwrap(),
        RdfFormat::JsonLd
    );
    // Case-insensitive.
    assert_eq!(classify(Some("TEXT/Turtle")).unwrap(), RdfFormat::Turtle);
}

#[test]
fn rejects_an_unsupported_or_absent_content_type() {
    assert!(matches!(
        classify(Some("application/json")).unwrap_err(),
        ServerError::UnsupportedMediaType(_)
    ));
    assert!(matches!(
        classify(None).unwrap_err(),
        ServerError::UnsupportedMediaType(_)
    ));
}

#[test]
fn validates_well_formed_turtle() {
    let n = validate_rdf(RdfFormat::Turtle, TURTLE.as_bytes(), IRI).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn relative_iris_resolve_against_the_resource_base() {
    // A document using relative IRIs is valid — they resolve against the resource's own IRI.
    let body = b"<#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .";
    let n = validate_rdf(RdfFormat::Turtle, body, IRI).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn rejects_malformed_turtle() {
    let bad = b"<a> <b> ."; // missing object
    let err = validate_rdf(RdfFormat::Turtle, bad, IRI).unwrap_err();
    assert!(matches!(err, ServerError::BadRequest(_)));
}

#[test]
fn validates_well_formed_jsonld() {
    let json = br#"{
        "@id": "https://pod.example/alice/data#me",
        "http://xmlns.com/foaf/0.1/name": "Alice"
    }"#;
    let n = validate_rdf(RdfFormat::JsonLd, json, IRI).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn rejects_malformed_jsonld() {
    let bad = b"{ not valid json";
    let err = validate_rdf(RdfFormat::JsonLd, bad, IRI).unwrap_err();
    assert!(matches!(err, ServerError::BadRequest(_)));
}
