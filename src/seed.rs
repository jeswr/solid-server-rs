// AUTHORED-BY Claude Opus 4.8
//! Conformance/dev seeding of the in-memory store.
//!
//! The Solid Conformance Test Harness (CTH) drives the server entirely through HTTP, but it
//! **bootstraps** by dereferencing each test user's WebID (`pim:storage` → the pod root) and then
//! operating inside a `test/` container under that pod. With the in-memory store doubles nothing
//! exists at boot, so this module seeds the minimum the harness needs to begin:
//!
//! - the root container `/`,
//! - per-user `/{u}/`, `/{u}/profile/`, `/{u}/test/` containers,
//! - each user's WebID profile document `/{u}/profile/card` (the `#me` subject carries `pim:storage`
//!   → the pod root and `solid:oidcIssuer` → the trusted realm, which is what the harness reads).
//!
//! It is **dev/conformance only**, gated behind `SOLID_SERVER_SEED_CONFORMANCE=1` in [`main`]. It
//! never runs against a real (SPARQ/S3) backend in production.
//!
//! ## RDF construction
//! The WebID profile is built as `oxrdf::Triple`s and serialised with the server's own
//! [`serialize_triples`](crate::ldp::content::serialize_triples) (oxttl) — the house rule of never
//! hand-concatenating RDF. The container records are created through the public [`Store`] API
//! (`write` to mint the container's metadata record, `create_in_container` to wire containment), so
//! seeding exercises the same code path a real write would.

use axum::body::Bytes;
use oxrdf::{NamedNode, Triple};

use crate::error::ServerResult;
use crate::ldp::content::{serialize_triples, RdfFormat};
use crate::store::Store;

/// The conformance test users. Each maps to a Keycloak service-account client whose token carries
/// the matching `webid` claim (`https://<base>/{u}/profile/card#me`).
pub const SEED_USERS: [&str; 2] = ["alice", "bob"];

/// Seed the store with the root container, the per-user container tree, and each user's WebID
/// profile. Idempotent-ish: intended to run once at boot on a fresh in-memory store.
///
/// `base_url` is the server's public origin without a trailing slash (e.g. `https://localhost:3000`).
/// `issuer` is the trusted token issuer recorded as each WebID's `solid:oidcIssuer`.
pub async fn seed_conformance<S: Store>(
    store: &S,
    base_url: &str,
    issuer: &str,
) -> ServerResult<()> {
    let base = base_url.trim_end_matches('/');

    // The root container must exist first (it is the parent of every per-user container, and the
    // harness GETs `/` to confirm the storage root).
    let root = format!("{base}/");
    ensure_container(store, &root, None).await?;

    for user in SEED_USERS {
        let pod = format!("{base}/{user}/");
        let profile = format!("{base}/{user}/profile/");
        let test = format!("{base}/{user}/test/");
        let card = format!("{base}/{user}/profile/card");
        let webid = format!("{card}#me");

        // Container tree: /{u}/ ⊂ / ; /{u}/profile/ ⊂ /{u}/ ; /{u}/test/ ⊂ /{u}/.
        ensure_container(store, &pod, Some(&root)).await?;
        ensure_container(store, &profile, Some(&pod)).await?;
        ensure_container(store, &test, Some(&pod)).await?;

        // The WebID profile document `/{u}/profile/card`, wired as a child of /{u}/profile/.
        let body = webid_profile_turtle(&webid, &pod, issuer)?;
        store
            .create_in_container(
                &profile,
                &card,
                Bytes::from(body),
                RdfFormat::Turtle.media_type(),
            )
            .await?;
    }

    Ok(())
}

/// Create a container's metadata record (so it `exists`) and wire it into `parent`'s containment.
///
/// A container is seeded as an empty `text/turtle` resource whose IRI ends in `/`; the LDP read path
/// renders its `ldp:contains` listing from the authoritative membership at GET time. When `parent`
/// is given, the container is recorded as the parent's child; the root (`parent: None`) is written
/// standalone.
async fn ensure_container<S: Store>(
    store: &S,
    iri: &str,
    parent: Option<&str>,
) -> ServerResult<()> {
    if store.exists(iri).await? {
        return Ok(());
    }
    match parent {
        // The root (or any parentless container): a plain write mints its record.
        None => {
            store
                .write(iri, Bytes::new(), RdfFormat::Turtle.media_type())
                .await?;
        }
        // A nested container: record it as a child of its parent (containment edge + record together).
        Some(p) => {
            store
                .create_in_container(p, iri, Bytes::new(), RdfFormat::Turtle.media_type())
                .await?;
        }
    }
    Ok(())
}

/// Build a minimal WebID profile document as Turtle, via `oxrdf` triples (never hand-concatenated).
///
/// The `#me` subject is typed `foaf:Person` + `solid:Account`-style and carries the two statements
/// the harness reads to bootstrap: `pim:storage` (→ the pod root) and `solid:oidcIssuer` (→ the
/// trusted realm). The card document itself (`foaf:PrimaryTopic`) points at `#me`.
fn webid_profile_turtle(webid: &str, pod_root: &str, issuer: &str) -> ServerResult<Vec<u8>> {
    const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
    const FOAF_PERSON: &str = "http://xmlns.com/foaf/0.1/Person";
    const FOAF_PRIMARY_TOPIC: &str = "http://xmlns.com/foaf/0.1/primaryTopic";
    const PIM_STORAGE: &str = "http://www.w3.org/ns/pim/space#storage";
    const SOLID_OIDC_ISSUER: &str = "http://www.w3.org/ns/solid/terms#oidcIssuer";

    // The card document subject (the resource URL, no fragment) and the `#me` agent subject.
    let card_doc = webid.split('#').next().unwrap_or(webid);

    // Helper: an owned NamedNode from a validated IRI string (these are all server-constructed, so
    // they are well-formed; map any (unreachable) error to a storage error rather than panic).
    let nn = |s: &str| -> ServerResult<NamedNode> {
        NamedNode::new(s)
            .map_err(|e| crate::error::ServerError::Storage(format!("invalid seed IRI {s}: {e}")))
    };

    let triples = vec![
        // <card> foaf:primaryTopic <#me> .
        Triple::new(nn(card_doc)?, nn(FOAF_PRIMARY_TOPIC)?, nn(webid)?),
        // <#me> a foaf:Person .
        Triple::new(nn(webid)?, nn(RDF_TYPE)?, nn(FOAF_PERSON)?),
        // <#me> pim:storage <pod_root> .
        Triple::new(nn(webid)?, nn(PIM_STORAGE)?, nn(pod_root)?),
        // <#me> solid:oidcIssuer <issuer> .
        Triple::new(nn(webid)?, nn(SOLID_OIDC_ISSUER)?, nn(issuer)?),
    ];

    serialize_triples(RdfFormat::Turtle, &triples)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CompositeStore, InMemoryBlobStore, InMemorySparqClient};

    fn store() -> CompositeStore<InMemorySparqClient, InMemoryBlobStore> {
        CompositeStore::new(InMemorySparqClient::new(), InMemoryBlobStore::new())
    }

    #[tokio::test]
    async fn seeds_root_users_and_webids() {
        let s = store();
        let base = "https://localhost:3000";
        let issuer = "http://localhost:8080/realms/solid";
        seed_conformance(&s, base, issuer).await.unwrap();

        // Root + per-user containers exist.
        assert!(s.exists("https://localhost:3000/").await.unwrap());
        for u in SEED_USERS {
            assert!(s
                .exists(&format!("https://localhost:3000/{u}/"))
                .await
                .unwrap());
            assert!(s
                .exists(&format!("https://localhost:3000/{u}/profile/"))
                .await
                .unwrap());
            assert!(s
                .exists(&format!("https://localhost:3000/{u}/test/"))
                .await
                .unwrap());
            assert!(s
                .exists(&format!("https://localhost:3000/{u}/profile/card"))
                .await
                .unwrap());
        }

        // The WebID card carries pim:storage + solid:oidcIssuer.
        let card = s
            .read("https://localhost:3000/alice/profile/card")
            .await
            .unwrap();
        let body = String::from_utf8(card.body.to_vec()).unwrap();
        assert!(body.contains("pim/space#storage"));
        assert!(body.contains("solid/terms#oidcIssuer"));
        assert!(body.contains("https://localhost:3000/alice/"));
        assert!(body.contains(issuer));
    }

    #[tokio::test]
    async fn webid_profile_is_valid_turtle() {
        let body = webid_profile_turtle(
            "https://localhost:3000/alice/profile/card#me",
            "https://localhost:3000/alice/",
            "http://localhost:8080/realms/solid",
        )
        .unwrap();
        // Re-parse to confirm well-formed Turtle (round-trips through oxttl).
        let n = crate::ldp::content::validate_rdf(
            RdfFormat::Turtle,
            &body,
            "https://localhost:3000/alice/profile/card",
        )
        .unwrap();
        assert_eq!(n, 4, "four triples in the seeded profile");
    }

    #[tokio::test]
    async fn seeding_is_idempotent() {
        let s = store();
        let base = "https://localhost:3000";
        let issuer = "http://localhost:8080/realms/solid";
        seed_conformance(&s, base, issuer).await.unwrap();
        // A second run must not error (already-exists short-circuits).
        seed_conformance(&s, base, issuer).await.unwrap();
        assert!(s
            .exists("https://localhost:3000/alice/test/")
            .await
            .unwrap());
    }
}
