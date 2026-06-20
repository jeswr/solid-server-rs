// AUTHORED-BY Claude Opus 4.8
//! Store-trait tests against the in-memory composite (SPARQ-authoritative metadata + blob bytes),
//! plus the RDF content-type classification + validation.

use axum::body::Bytes;
use solid_server_rs::error::ServerError;
use solid_server_rs::ldp::content::{classify, validate_rdf, RdfFormat};
use solid_server_rs::store::{
    CompositeStore, InMemoryBlobStore, InMemorySparqClient, ResourceMeta, SparqClient, SparqError,
    Store,
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
