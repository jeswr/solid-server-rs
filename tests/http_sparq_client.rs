// AUTHORED-BY Claude Opus 4.8
//! Unit/integration tests for the live [`HttpSparqClient`] against an **in-process mock SPARQL HTTP
//! endpoint** — no running SPARQ needed.
//!
//! The mock is a tiny axum server that classifies each request the way `sparq-server`'s `/sparql`
//! route does (POST `application/sparql-query` → results-JSON/CONSTRUCT; POST
//! `application/sparql-update` → 204) and returns canned `application/sparql-results+json` / Turtle
//! bodies driven by the SPARQL the client sent. This exercises the full HTTP plumbing (request
//! shaping, status classification, bounded body read, JSON parsing) deterministically.
//!
//! The mock keeps a small in-memory "store" so the atomic `create_child` round-trip (the guarded
//! update + the follow-up create-marker confirm the client issues) is meaningfully exercised,
//! including the container-EXISTS-guard rejection path.
//!
//! A LIVE integration test against a real SPARQ is at the bottom, `#[ignore]`'d + env-gated
//! (`PSS_LIVE_SPARQ_URL`) — running it needs a SPARQ instance (a `needs:user` item).

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

use solid_server_rs::store::{
    BodyObject, DeleteOutcome, HttpSparqClient, ResourceMeta, SparqClient, SparqError,
};

// ---------------------------------------------------------------------------
// The in-process mock SPARQL endpoint.
// ---------------------------------------------------------------------------

/// How the mock should behave, for the per-test variations (errors, timeouts, malformed bodies).
#[derive(Clone, Default)]
struct MockMode {
    /// Force every response to this status (with a body) — for the 5xx / 4xx tests.
    force_status: Option<StatusCode>,
    /// When `force_status` is set, make its body large (> the client's read bound is impractical in
    /// a test, so this just proves a non-empty error body does not flip the retryable classification).
    force_status_with_body: bool,
    /// Return a malformed (non-JSON) body for SELECT/ASK — for the malformed-response test.
    malformed: bool,
    /// Return a `SELECT ?child` body whose single row is MISSING the `child` binding — for the
    /// list_children malformed-row fatal test.
    children_row_missing_binding: bool,
    /// Sleep this long BEFORE sending any response (headers + body) — for the whole-request timeout.
    delay: Option<Duration>,
}

/// The mock's tiny store: resource IRI → its index record; container IRI → child IRIs; resource IRI
/// → its inserted body triples (raw N-Triples-ish lines) for the insert→construct round-trip.
#[derive(Default)]
struct MockStore {
    /// resource graph IRI → (contentType, blobKey, etag).
    meta: HashMap<String, (String, String, String)>,
    /// container graph IRI → child IRIs (ldp:contains).
    children: HashMap<String, Vec<String>>,
    /// resource graph IRI → its body triples, stored as already-rendered N-Triples lines.
    body: HashMap<String, Vec<String>>,
    /// child graph IRI → its per-operation create-marker nonces (the race-resistant create confirm).
    markers: HashMap<String, Vec<String>>,
    /// container IRI → its per-operation DELETE-marker nonces (the race-resistant empty-delete confirm,
    /// stored in a separate scratch graph keyed by the container IRI as the marker subject).
    delete_markers: HashMap<String, Vec<String>>,
    /// The last SPARQL string the mock received (so a test can assert on the query text/escaping).
    last_sparql: Option<String>,
}

#[derive(Clone)]
struct MockState {
    mode: Arc<Mutex<MockMode>>,
    store: Arc<Mutex<MockStore>>,
}

/// Spawn the mock server on an ephemeral port; returns the `/sparql` URL + the shared state handle.
async fn spawn_mock() -> (String, MockState) {
    let state = MockState {
        mode: Arc::new(Mutex::new(MockMode::default())),
        store: Arc::new(Mutex::new(MockStore::default())),
    };
    let app = Router::new()
        .route("/sparql", post(handle_sparql))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/sparql"), state)
}

/// The mock `/sparql` handler — classifies query vs update + answers from the tiny store.
async fn handle_sparql(
    State(state): State<MockState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mode = state.mode.lock().unwrap().clone();
    if let Some(delay) = mode.delay {
        tokio::time::sleep(delay).await;
    }
    if let Some(status) = mode.force_status {
        // A non-empty error body (the realistic case) must NOT flip the retryable classification —
        // the client classifies on status from headers first.
        let body = if mode.force_status_with_body {
            "x".repeat(64 * 1024) // a chunky-but-bounded error body
        } else {
            r#"{"error":"forced"}"#.to_string()
        };
        return (status, body).into_response();
    }
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let sparql = String::from_utf8_lossy(&body).to_string();
    state.store.lock().unwrap().last_sparql = Some(sparql.clone());

    if ct.starts_with("application/sparql-update") {
        apply_update(&state, &sparql);
        return StatusCode::NO_CONTENT.into_response();
    }
    // Otherwise a query (application/sparql-query). Answer ASK / SELECT / CONSTRUCT.
    if mode.malformed {
        return results_json("this is not json{");
    }
    if mode.children_row_missing_binding && sparql.starts_with("SELECT ?child") {
        // A SELECT-children result whose row is missing the `child` binding (a malformed backend).
        return results_json(
            r#"{"head":{"vars":["child"]},"results":{"bindings":[{"other":{"type":"uri","value":"http://x"}}]}}"#,
        );
    }
    answer_query(&state, &sparql)
}

/// Apply a (mock) SPARQL update by recognising the client's fixed-shape statements. This is NOT a
/// SPARQL engine — it pattern-matches the specific updates [`solid_server_rs::store::sparql`] emits.
fn apply_update(state: &MockState, sparql: &str) {
    let mut store = state.store.lock().unwrap();
    // delete_container_if_empty: a `;`-joined update that (1) conditionally empties the container's
    // graph (record only) iff it EXISTS and has NO `ldp:contains` member, and (2) writes a delete
    // marker into the scratch graph under the SAME guard. Recognise it by the `deleteMarker` predicate
    // (distinguishing it from create_child's `createMarker`). The guard is evaluated against the mock
    // store: delete iff the container has an index record AND no children.
    if sparql.contains("deleteMarker") && sparql.starts_with("DELETE {") {
        // The container graph is the FIRST GRAPH IRI; the marker nonce is the (only) string literal.
        let container = first_graph_iri(sparql).unwrap_or_default();
        let nonce = extract_literals(sparql)
            .first()
            .cloned()
            .unwrap_or_default();
        let exists = store.meta.contains_key(&container);
        // Empty iff there is no non-empty child set (MSRV 1.81: `map_or(true, …)`, not `is_none_or`).
        let empty = store
            .children
            .get(&container)
            .map_or(true, |kids| kids.is_empty());
        if exists && empty {
            // Empty + present ⇒ drop the record + its (empty) containment entry, and record THIS op's
            // delete marker in the scratch graph (keyed by the container IRI) so the confirm sees it.
            store.meta.remove(&container);
            store.children.remove(&container);
            store.body.remove(&container);
            store
                .delete_markers
                .entry(container)
                .or_default()
                .push(nonce);
        }
        // Non-empty or absent ⇒ NOTHING is deleted and NO marker is written (the safety invariant).
        return;
    }
    // create_child: `DELETE { GRAPH <child> {…stale record…} } INSERT { GRAPH <child> {…record…}
    //                GRAPH <container> { <record> <ldp:contains> <child> } }
    //                WHERE { GRAPH <container> { <record> <contentType> ?anyCt } OPTIONAL … }`
    if sparql.contains("ldp#contains")
        && sparql.starts_with("DELETE {")
        && sparql.contains("INSERT {")
        && sparql.contains("WHERE {")
    {
        // child graph = first GRAPH IRI (in the DELETE block); container = first GRAPH IRI in WHERE.
        let child = first_graph_iri(sparql).unwrap_or_default();
        let where_pos = sparql.find("WHERE {").unwrap();
        let container = first_iri_after(sparql, where_pos).unwrap_or_default();
        // The guard: only create if the container has an index record (contentType) in the store.
        if store.meta.contains_key(&container) {
            // Replace any stale child record (the DELETE-before-INSERT semantics), then add the edge
            // (idempotent) + record THIS operation's marker nonce. The INSERT literals are, in order:
            // contentType, blobKey, etag, createMarker-nonce.
            let lits = extract_literals(sparql);
            let g = |i: usize| lits.get(i).cloned().unwrap_or_default();
            store.meta.insert(child.clone(), (g(0), g(1), g(2)));
            let nonce = g(3);
            // Markers are APPEND-ONLY (no DELETE of markers), so a same-child create never removes an
            // earlier op's nonce — each op confirms its own.
            store.markers.entry(child.clone()).or_default().push(nonce);
            let kids = store.children.entry(container).or_default();
            if !kids.contains(&child) {
                kids.push(child);
            }
        }
        return;
    }
    // insert_body: `INSERT DATA { GRAPH <r> { <s> <p> <o> . … } }` (no leading DROP/DELETE) — store
    // the body triple lines for the construct round-trip.
    if sparql.starts_with("INSERT DATA") && !sparql.contains("contentType") {
        if let Some(resource) = first_graph_iri(sparql) {
            // Capture each `<s> <p> <o> .` triple as a raw line (the IRIs/literals as rendered).
            let inner = inside_graph_block(sparql).unwrap_or_default();
            for line in inner.split(" . ") {
                let t = line.trim().trim_end_matches('.').trim();
                if !t.is_empty() {
                    store
                        .body
                        .entry(resource.clone())
                        .or_default()
                        .push(t.to_string());
                }
            }
        }
        return;
    }
    // put_meta: three `DELETE WHERE { GRAPH <r> { <record> <pred> ?old } }` then
    // `INSERT DATA { GRAPH <r> { <record> <contentType> "ct" ; … } }` — replaces ONLY the reserved
    // record triples, leaving children + RDF intact. The mock store keys metadata by resource, so it
    // upserts the record without touching `children` (the bug roborev flagged would be a `.remove`).
    if sparql.starts_with("DELETE WHERE") && sparql.contains("INSERT DATA") {
        // The resource graph IRI is the first GRAPH IRI (same across all clauses).
        if let Some(resource) = first_graph_iri(sparql) {
            let (ct, bk, et) = parse_record_literals(sparql);
            store.meta.insert(resource, (ct, bk, et));
        }
        return;
    }
    // delete_resource: `DROP SILENT GRAPH <r>` — removes the whole resource (record + children + RDF
    // + markers).
    if sparql.starts_with("DROP SILENT GRAPH") {
        if let Some(resource) = extract_iris(sparql).first().cloned() {
            store.meta.remove(&resource);
            store.children.remove(&resource);
            store.body.remove(&resource);
            store.markers.remove(&resource);
        }
        return;
    }
    // remove_child: `DELETE WHERE { GRAPH <container> { <record> <ldp:contains> <child> } }`
    if sparql.starts_with("DELETE WHERE") && sparql.contains("ldp#contains") {
        let iris = extract_iris(sparql);
        // The graph IRI is first; the child IRI is the last.
        if let (Some(container), Some(child)) = (iris.first().cloned(), iris.last().cloned()) {
            if let Some(v) = store.children.get_mut(&container) {
                v.retain(|c| c != &child);
            }
        }
    }
}

/// Answer a query (ASK exists / SELECT meta / SELECT children / CONSTRUCT) from the store.
fn answer_query(state: &MockState, sparql: &str) -> Response {
    let store = state.store.lock().unwrap();
    if sparql.starts_with("ASK") {
        let graph = first_graph_iri(sparql).unwrap_or_default();
        let boolean = if sparql.contains("deleteMarker") {
            // ask_delete_marker: ASK { GRAPH <scratch> { <container> <deleteMarker> "nonce" } } — true
            // iff that exact nonce was recorded for the container. The graph here is the SCRATCH graph;
            // the container is the SUBJECT (the first <...> IRI INSIDE the graph block), and the nonce
            // is the literal. (`first_graph_iri` returns the scratch graph, so re-extract the subject.)
            let iris = extract_iris(sparql);
            // tokens: [scratchGraph, container, deleteMarkerPredicate] — the container is index 1.
            let container = iris.get(1).cloned().unwrap_or_default();
            let nonce = extract_literals(sparql)
                .first()
                .cloned()
                .unwrap_or_default();
            store
                .delete_markers
                .get(&container)
                .is_some_and(|ns| ns.contains(&nonce))
        } else if sparql.contains("createMarker") {
            // ask_create_marker: ASK { GRAPH <child> { <record> <createMarker> "nonce" } } — true iff
            // that exact nonce was recorded for the child (the race-resistant create confirm).
            let nonce = extract_literals(sparql)
                .first()
                .cloned()
                .unwrap_or_default();
            store
                .markers
                .get(&graph)
                .is_some_and(|ns| ns.contains(&nonce))
        } else if sparql.contains("ldp#contains") {
            // ask_contains_edge: ASK { GRAPH <container> { <record> <ldp:contains> <child> } } —
            // true iff that exact containment edge is present. The child is the last <...> IRI.
            let child = extract_iris(sparql).last().cloned().unwrap_or_default();
            store
                .children
                .get(&graph)
                .is_some_and(|kids| kids.contains(&child))
        } else {
            // ask_exists: ASK { GRAPH <r> { <record> <contentType> ?ct } } — true iff `r` is indexed.
            store.meta.contains_key(&graph)
        };
        return results_json(&format!(r#"{{"head":{{}},"boolean":{boolean}}}"#));
    }
    if sparql.starts_with("SELECT ?ct") {
        // select_meta
        let resource = first_graph_iri(sparql).unwrap_or_default();
        return match store.meta.get(&resource) {
            Some((ct, bk, et)) => results_json(&select_meta_json(ct, bk, et)),
            None => {
                results_json(r#"{"head":{"vars":["ct","bk","etag"]},"results":{"bindings":[]}}"#)
            }
        };
    }
    if sparql.starts_with("SELECT ?child") {
        // select_children
        let container = first_graph_iri(sparql).unwrap_or_default();
        let kids = store.children.get(&container).cloned().unwrap_or_default();
        return results_json(&select_children_json(&kids));
    }
    if sparql.starts_with("CONSTRUCT") {
        // CONSTRUCT — return the resource's ACTUAL inserted body triples (a real round-trip), as
        // N-Triples. Empty if nothing was inserted.
        let resource = first_graph_iri(sparql).unwrap_or_default();
        let mut body = String::new();
        if let Some(lines) = store.body.get(&resource) {
            for t in lines {
                body.push_str(t);
                body.push_str(" .\n");
            }
        }
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/n-triples; charset=utf-8")],
            body,
        )
            .into_response();
    }
    results_json(r#"{"head":{},"boolean":false}"#)
}

/// Extract the text inside the FIRST `GRAPH <...> { ... }` block — the triples body. Returns the
/// content between the matching braces (single-level; the client's INSERT DATA bodies are flat).
fn inside_graph_block(sparql: &str) -> Option<String> {
    let g = sparql.find("GRAPH ")?;
    let open = sparql[g..].find('{')? + g;
    // Find the matching close brace for this block.
    let mut depth = 0i32;
    for (i, ch) in sparql[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(sparql[open + 1..open + i].trim().to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn results_json(body: &str) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/sparql-results+json")],
        body.to_string(),
    )
        .into_response()
}

fn select_meta_json(ct: &str, bk: &str, et: &str) -> String {
    format!(
        r#"{{"head":{{"vars":["ct","bk","etag"]}},"results":{{"bindings":[
            {{"ct":{{"type":"literal","value":{ct}}},
             "bk":{{"type":"literal","value":{bk}}},
             "etag":{{"type":"literal","value":{et}}}}}
        ]}}}}"#,
        ct = json_str(ct),
        bk = json_str(bk),
        et = json_str(et),
    )
}

fn select_children_json(kids: &[String]) -> String {
    let bindings: Vec<String> = kids
        .iter()
        .map(|k| format!(r#"{{"child":{{"type":"uri","value":{}}}}}"#, json_str(k)))
        .collect();
    format!(
        r#"{{"head":{{"vars":["child"]}},"results":{{"bindings":[{}]}}}}"#,
        bindings.join(",")
    )
}

/// JSON-encode a string value (so canned bodies are valid JSON even with quotes inside).
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

// ----- tiny SPARQL-text extraction helpers for the mock (NOT a parser) -----

/// All `<...>` IRI tokens in order (the inner text, unbracketed).
fn extract_iris(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(end) = s[i + 1..].find('>') {
                out.push(s[i + 1..i + 1 + end].to_string());
                i = i + 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// The IRI of the first `GRAPH <...>` occurrence.
fn first_graph_iri(s: &str) -> Option<String> {
    let pos = s.find("GRAPH ")?;
    first_iri_after(s, pos)
}

/// The first `<...>` IRI at or after byte offset `from`.
fn first_iri_after(s: &str, from: usize) -> Option<String> {
    let rest = &s[from..];
    let lt = rest.find('<')?;
    let gt = rest[lt + 1..].find('>')?;
    Some(rest[lt + 1..lt + 1 + gt].to_string())
}

/// Best-effort: the three string literals of an index record, in INSERT order (ct, bk, etag).
/// Returns their UNESCAPED lexical values.
fn parse_record_literals(s: &str) -> (String, String, String) {
    let lits = extract_literals(s);
    let g = |i: usize| lits.get(i).cloned().unwrap_or_default();
    (g(0), g(1), g(2))
}

/// All `"..."` string literals (unescaped), in order.
fn extract_literals(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' {
            let mut val = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    // Unescape the SPARQL string escapes the builder emits.
                    let next = chars[i + 1];
                    val.push(match next {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        c => c,
                    });
                    i += 2;
                    continue;
                }
                val.push(chars[i]);
                i += 1;
            }
            out.push(val);
            i += 1; // skip closing quote
            continue;
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Tests against the mock.
// ---------------------------------------------------------------------------

const CONTAINER: &str = "https://pod.example/alice/";
const CHILD: &str = "https://pod.example/alice/note1";
const RES: &str = "https://pod.example/alice/data";

fn meta() -> ResourceMeta {
    ResourceMeta {
        content_type: "text/turtle".into(),
        blob_key: "blob-key-1".into(),
        etag: "\"etag-1\"".into(),
    }
}

#[tokio::test]
async fn exists_is_false_then_true() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    assert!(!c.exists(RES).await.unwrap());
    c.put_meta(RES, meta()).await.unwrap();
    assert!(c.exists(RES).await.unwrap());
}

#[tokio::test]
async fn put_then_get_meta_round_trips() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    c.put_meta(RES, meta()).await.unwrap();
    let got = c.get_meta(RES).await.unwrap();
    assert_eq!(got, meta());
}

#[tokio::test]
async fn get_meta_of_absent_is_not_found() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    let err = c.get_meta(RES).await.unwrap_err();
    assert!(matches!(err, SparqError::NotFound));
}

#[tokio::test]
async fn insert_body_then_construct_round_trips() {
    // A REAL round-trip: write triples through the client (insert_body → INSERT DATA), then read them
    // back via CONSTRUCT. This exercises both the insert_body_data builder and construct_resource end
    // to end (no canned body — the mock returns exactly what was inserted).
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    let triples = vec![
        (
            format!("{RES}#me"),
            "http://xmlns.com/foaf/0.1/name".to_string(),
            BodyObject::PlainLiteral("Alice".into()),
        ),
        (
            format!("{RES}#me"),
            "http://xmlns.com/foaf/0.1/knows".to_string(),
            BodyObject::Iri(format!("{RES}#bob")),
        ),
    ];
    c.insert_body(RES, &triples).await.unwrap();

    let body = c.construct_resource_ntriples(RES).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        text.contains("<https://pod.example/alice/data#me>"),
        "got: {text}"
    );
    assert!(text.contains("\"Alice\""), "got: {text}");
    assert!(
        text.contains("<https://pod.example/alice/data#bob>"),
        "got: {text}"
    );
}

#[tokio::test]
async fn insert_body_of_no_triples_is_a_noop() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    // An empty triple set issues no request and is Ok.
    c.insert_body(RES, &[]).await.unwrap();
    let body = c.construct_resource_ntriples(RES).await.unwrap();
    assert!(body.is_empty(), "no triples inserted ⇒ empty construct");
}

#[tokio::test]
async fn create_child_is_atomic_and_lists() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    // The container must be indexed first (the EXISTS guard).
    c.put_meta(CONTAINER, meta()).await.unwrap();
    c.create_child(CONTAINER, CHILD, meta()).await.unwrap();

    assert!(c.exists(CHILD).await.unwrap());
    let kids = c.list_children(CONTAINER).await.unwrap();
    assert_eq!(kids, vec![CHILD.to_string()]);
}

#[tokio::test]
async fn create_child_in_missing_container_is_not_found() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    // The container was never indexed: the EXISTS guard rejects ⇒ nothing inserted ⇒ the follow-up
    // existence-confirm fails ⇒ NotFound. Fail-closed (no fabricated success).
    let err = c.create_child(CONTAINER, CHILD, meta()).await.unwrap_err();
    assert!(matches!(err, SparqError::NotFound));
    assert!(!c.exists(CHILD).await.unwrap());
    assert!(c.list_children(CONTAINER).await.unwrap().is_empty());
}

#[tokio::test]
async fn repeated_same_child_create_each_confirms_its_own_marker() {
    // Regression for the round-5 finding: markers are APPEND-ONLY, so a second create on the same
    // child does NOT remove the first op's marker. Two sequential creates (each with its own unique
    // nonce) both succeed — neither false-NotFounds because the other cleared its marker.
    let (url, state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    c.put_meta(CONTAINER, meta()).await.unwrap();
    c.create_child(CONTAINER, CHILD, meta()).await.unwrap();
    // A second create on the SAME child must also succeed (idempotent membership, fresh marker).
    c.create_child(CONTAINER, CHILD, meta()).await.unwrap();
    // Both operations' markers are retained (append-only) — proof neither cleared the other's.
    let markers = state
        .store
        .lock()
        .unwrap()
        .markers
        .get(CHILD)
        .cloned()
        .unwrap_or_default();
    assert_eq!(markers.len(), 2, "both markers retained: {markers:?}");
    // Membership stays a single edge (idempotent).
    assert_eq!(
        c.list_children(CONTAINER).await.unwrap(),
        vec![CHILD.to_string()]
    );
}

#[tokio::test]
async fn create_child_with_missing_container_but_preexisting_child_still_not_found() {
    // Regression for the roborev finding: confirming via the CONTAINMENT EDGE (not `exists(child)`).
    // The child already exists in its own right, but its container was never indexed — so the guarded
    // insert adds NO edge and create_child must STILL report NotFound (never a false success).
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    c.put_meta(CHILD, meta()).await.unwrap(); // the child exists on its own
    assert!(c.exists(CHILD).await.unwrap());

    let err = c.create_child(CONTAINER, CHILD, meta()).await.unwrap_err();
    assert!(
        matches!(err, SparqError::NotFound),
        "missing container must yield NotFound even when the child already exists"
    );
    // And no spurious containment edge was recorded.
    assert!(c.list_children(CONTAINER).await.unwrap().is_empty());
}

#[tokio::test]
async fn put_meta_rewrite_preserves_container_children() {
    // Regression for the roborev finding: a metadata re-write on a container must NOT erase its
    // `ldp:contains` children (the earlier `DROP SILENT GRAPH` would have).
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    c.put_meta(CONTAINER, meta()).await.unwrap();
    c.create_child(CONTAINER, CHILD, meta()).await.unwrap();
    assert_eq!(c.list_children(CONTAINER).await.unwrap().len(), 1);

    // Re-write the container's metadata (e.g. a new ETag) — children must survive.
    let updated = ResourceMeta {
        content_type: "text/turtle".into(),
        blob_key: "blob-key-2".into(),
        etag: "\"etag-2\"".into(),
    };
    c.put_meta(CONTAINER, updated.clone()).await.unwrap();
    assert_eq!(
        c.list_children(CONTAINER).await.unwrap(),
        vec![CHILD.to_string()],
        "put_meta must not erase containment edges"
    );
    assert_eq!(c.get_meta(CONTAINER).await.unwrap(), updated);
}

#[tokio::test]
async fn delete_removes_the_resource() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    c.put_meta(RES, meta()).await.unwrap();
    assert!(c.exists(RES).await.unwrap());
    c.delete_meta(RES).await.unwrap();
    assert!(!c.exists(RES).await.unwrap());
}

#[tokio::test]
async fn delete_meta_is_idempotent_on_absent() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    // DROP SILENT on an absent graph is a no-op success.
    c.delete_meta(RES).await.unwrap();
}

#[tokio::test]
async fn delete_meta_if_empty_over_http_reports_all_three_outcomes() {
    // The live client's atomic empty-container delete (a single guarded conditional UPDATE + a
    // race-resistant delete-marker confirm) must map to NotFound / NotEmpty / Deleted correctly via
    // the mock — and crucially leave a NON-EMPTY container untouched (the safety invariant).
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);

    // Absent ⇒ NotFound (no marker written ⇒ confirm ASK false ⇒ exists ASK false).
    assert_eq!(
        c.delete_meta_if_empty(CONTAINER).await.unwrap(),
        DeleteOutcome::NotFound
    );

    // Populated ⇒ NotEmpty, and the container + child both survive (nothing deleted).
    c.put_meta(CONTAINER, meta()).await.unwrap();
    c.create_child(CONTAINER, CHILD, meta()).await.unwrap();
    assert_eq!(
        c.delete_meta_if_empty(CONTAINER).await.unwrap(),
        DeleteOutcome::NotEmpty
    );
    assert!(
        c.exists(CONTAINER).await.unwrap(),
        "a NotEmpty result must not delete the container"
    );
    assert_eq!(
        c.list_children(CONTAINER).await.unwrap(),
        vec![CHILD.to_string()],
        "a NotEmpty result must leave the membership intact"
    );

    // Empty it, then Deleted ⇒ the container's record is gone.
    c.remove_child(CONTAINER, CHILD).await.unwrap();
    assert_eq!(
        c.delete_meta_if_empty(CONTAINER).await.unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(!c.exists(CONTAINER).await.unwrap());
}

#[tokio::test]
async fn remove_child_detaches_membership() {
    let (url, _state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    c.put_meta(CONTAINER, meta()).await.unwrap();
    c.create_child(CONTAINER, CHILD, meta()).await.unwrap();
    assert_eq!(c.list_children(CONTAINER).await.unwrap().len(), 1);
    c.remove_child(CONTAINER, CHILD).await.unwrap();
    assert!(c.list_children(CONTAINER).await.unwrap().is_empty());
}

#[tokio::test]
async fn server_5xx_is_a_retryable_backend_error() {
    let (url, state) = spawn_mock().await;
    state.mode.lock().unwrap().force_status = Some(StatusCode::SERVICE_UNAVAILABLE);
    let c = HttpSparqClient::new(url);
    let err = c.exists(RES).await.unwrap_err();
    match err {
        SparqError::Backend(msg) => assert!(msg.starts_with("retryable:"), "got: {msg}"),
        other => panic!("expected retryable Backend, got {other:?}"),
    }
}

#[tokio::test]
async fn server_5xx_with_a_body_is_still_retryable() {
    // Regression: classification is from the STATUS (header) first, so a 5xx carrying a non-trivial
    // body is still retryable — the body read never flips it to a fatal `Body`/`Malformed`.
    let (url, state) = spawn_mock().await;
    {
        let mut m = state.mode.lock().unwrap();
        m.force_status = Some(StatusCode::INTERNAL_SERVER_ERROR);
        m.force_status_with_body = true;
    }
    let c = HttpSparqClient::new(url);
    let err = c.exists(RES).await.unwrap_err();
    match err {
        SparqError::Backend(msg) => assert!(msg.starts_with("retryable:"), "got: {msg}"),
        other => panic!("expected retryable Backend, got {other:?}"),
    }
}

#[tokio::test]
async fn list_children_row_missing_binding_is_fatal() {
    // Regression: a SELECT-children row missing the `child` binding is a malformed backend response,
    // surfaced as a fatal error — NOT silently dropped (which could shorten the list + wrongly let a
    // non-empty container be deleted).
    let (url, state) = spawn_mock().await;
    state.mode.lock().unwrap().children_row_missing_binding = true;
    let c = HttpSparqClient::new(url);
    let err = c.list_children(CONTAINER).await.unwrap_err();
    match err {
        SparqError::Backend(msg) => assert!(msg.starts_with("fatal:"), "got: {msg}"),
        other => panic!("expected fatal Backend, got {other:?}"),
    }
}

#[tokio::test]
async fn client_4xx_is_a_fatal_backend_error() {
    let (url, state) = spawn_mock().await;
    state.mode.lock().unwrap().force_status = Some(StatusCode::BAD_REQUEST);
    let c = HttpSparqClient::new(url);
    let err = c.exists(RES).await.unwrap_err();
    match err {
        SparqError::Backend(msg) => assert!(msg.starts_with("fatal:"), "got: {msg}"),
        other => panic!("expected fatal Backend, got {other:?}"),
    }
}

#[tokio::test]
async fn malformed_response_is_a_fatal_error() {
    let (url, state) = spawn_mock().await;
    state.mode.lock().unwrap().malformed = true;
    let c = HttpSparqClient::new(url);
    let err = c.exists(RES).await.unwrap_err();
    match err {
        SparqError::Backend(msg) => assert!(msg.starts_with("fatal:"), "got: {msg}"),
        other => panic!("expected fatal Backend, got {other:?}"),
    }
}

#[tokio::test]
async fn a_slow_endpoint_times_out_retryably() {
    let (url, state) = spawn_mock().await;
    state.mode.lock().unwrap().delay = Some(Duration::from_millis(500));
    let c = HttpSparqClient::with_timeout(url, Duration::from_millis(50));
    let err = c.exists(RES).await.unwrap_err();
    match err {
        SparqError::Backend(msg) => assert!(msg.starts_with("retryable:"), "got: {msg}"),
        other => panic!("expected retryable timeout Backend, got {other:?}"),
    }
}

#[tokio::test]
async fn an_injection_crafted_iri_is_rejected_fail_closed() {
    let (url, state) = spawn_mock().await;
    let c = HttpSparqClient::new(url);
    // A resource IRI crafted to break out of the IRI term and inject a DROP. It is an INVALID IRIREF
    // (contains `>`, spaces, `{`), so the client REJECTS it fail-closed (a fatal Backend error) — NO
    // request is ever sent, so the injection can never reach the endpoint. Rejecting (not escaping) is
    // what keeps the IRI->graph mapping injective (no aliasing).
    let attack = "https://pod.example/x> } ; DROP GRAPH <https://victim> ; ASK { GRAPH <https://pod.example/x";
    let err = c.exists(attack).await.unwrap_err();
    match err {
        SparqError::Backend(msg) => assert!(msg.starts_with("fatal:"), "got: {msg}"),
        other => panic!("expected fatal Backend (rejected IRI), got {other:?}"),
    }
    // No request reached the mock — the build failed before any HTTP call.
    assert!(
        state.store.lock().unwrap().last_sparql.is_none(),
        "a rejected IRI must never hit the wire"
    );
}

// Confirm the unused-`Infallible` import is intentional plumbing (axum handler return types use it
// transitively); keep this so clippy/-D warnings does not flag an unused import in some toolchains.
#[allow(dead_code)]
fn _assert_infallible_is_used() -> Result<(), Infallible> {
    Ok(())
}

// ---------------------------------------------------------------------------
// LIVE integration test (ignored): needs a real SPARQ.
// ---------------------------------------------------------------------------

/// End-to-end against a REAL SPARQ `/sparql` endpoint. `#[ignore]` + env-gated: provide
/// `PSS_LIVE_SPARQ_URL` (e.g. `http://localhost:8080/sparql`) and run with
/// `cargo test --test http_sparq_client -- --ignored`. Standing up a SPARQ instance is a
/// `needs:user` item, so this never runs in the standard `cargo test` gate.
#[tokio::test]
#[ignore = "needs a live SPARQ instance (set PSS_LIVE_SPARQ_URL); needs:user"]
async fn live_sparq_round_trip() {
    let url = match std::env::var("PSS_LIVE_SPARQ_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!("PSS_LIVE_SPARQ_URL not set; skipping live SPARQ test");
            return;
        }
    };
    let c = HttpSparqClient::new(url);

    let container = "https://live.example/c/";
    let child = "https://live.example/c/item1";
    let m = ResourceMeta {
        content_type: "text/turtle".into(),
        blob_key: "live-blob-1".into(),
        etag: "\"live-etag-1\"".into(),
    };

    // Clean slate.
    c.delete_meta(child).await.ok();
    c.delete_meta(container).await.ok();

    // exists false → put → exists true → get round-trips.
    assert!(!c.exists(container).await.unwrap());
    c.put_meta(container, m.clone()).await.unwrap();
    assert!(c.exists(container).await.unwrap());
    assert_eq!(c.get_meta(container).await.unwrap(), m);

    // Atomic create_child + listing.
    c.create_child(container, child, m.clone()).await.unwrap();
    assert!(c.exists(child).await.unwrap());
    let kids = c.list_children(container).await.unwrap();
    assert!(kids.contains(&child.to_string()), "kids: {kids:?}");

    // create_child into a missing container ⇒ NotFound.
    let err = c
        .create_child(
            "https://live.example/missing/",
            "https://live.example/missing/x",
            m.clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SparqError::NotFound));

    // Atomic empty-container delete: while the child is present it is NotEmpty (nothing deleted);
    // after detaching the child it is Deleted.
    assert_eq!(
        c.delete_meta_if_empty(container).await.unwrap(),
        DeleteOutcome::NotEmpty
    );
    assert!(c.exists(container).await.unwrap());

    // remove_child + delete clean up.
    c.remove_child(container, child).await.unwrap();
    assert!(c.list_children(container).await.unwrap().is_empty());
    c.delete_meta(child).await.unwrap();
    assert_eq!(
        c.delete_meta_if_empty(container).await.unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(!c.exists(container).await.unwrap());
    // A second empty-delete of the now-absent container ⇒ NotFound.
    assert_eq!(
        c.delete_meta_if_empty(container).await.unwrap(),
        DeleteOutcome::NotFound
    );
}
