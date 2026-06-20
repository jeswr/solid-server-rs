// AUTHORED-BY Claude Opus 4.8
//! The Solid **N3 Patch** engine (`text/n3`).
//!
//! Implements the Solid Protocol N3 Patch document shape
//! (<https://solidproject.org/TR/protocol#n3-patch>): a single `solid:InsertDeletePatch` resource
//! with `solid:inserts`, `solid:deletes`, and `solid:where` formula objects (each a `{ … }` graph).
//! The patch is applied to the target resource's existing graph and the result re-serialised.
//!
//! ## What this slice implements (and what is deferred — explicitly, never silently)
//!
//! - **`solid:inserts` + `solid:deletes`** (concrete triples, no variables): FULLY implemented —
//!   the delete-then-insert set operations over the target graph, with the spec's preconditions
//!   (every `deletes` triple must be present; an `InsertDeletePatch` must carry at least one of
//!   inserts/deletes).
//! - **`solid:where`** with VARIABLES (the templated/conditional form): **DEFERRED** — a patch that
//!   carries a non-empty `solid:where` is rejected with a clear 422 (`UnprocessablePatch`), NOT
//!   silently ignored. The full `where` solver (variable binding against the target graph, then
//!   instantiating inserts/deletes per binding) is the next patch slice; the seam is marked below.
//!   An EMPTY `solid:where { }` is accepted (it constrains nothing).
//!
//! Per the house rule, the patch document is parsed with the vetted `oxttl` N3 parser (formulas →
//! blank-node-named graphs), never hand-parsed.

use oxrdf::{GraphName, NamedOrBlankNode, Term, Triple};
use oxttl::n3::{N3Parser, N3Quad, N3Term};

use crate::error::ServerError;

/// The Solid terms vocabulary IRIs used by an N3 Patch.
const SOLID_INSERTS: &str = "http://www.w3.org/ns/solid/terms#inserts";
const SOLID_DELETES: &str = "http://www.w3.org/ns/solid/terms#deletes";
const SOLID_WHERE: &str = "http://www.w3.org/ns/solid/terms#where";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const SOLID_INSERT_DELETE_PATCH: &str = "http://www.w3.org/ns/solid/terms#InsertDeletePatch";

/// A parsed N3 Patch: the concrete triples to delete then insert.
#[derive(Debug, Default, Clone)]
pub struct N3Patch {
    pub deletes: Vec<Triple>,
    pub inserts: Vec<Triple>,
}

/// Parse a `text/n3` Solid N3 Patch document, resolving relative IRIs against `base_iri`.
///
/// Returns the concrete delete/insert triple sets. A document that is not a well-formed single
/// `InsertDeletePatch` — or that uses the deferred `where`/variable form — is an error (4xx), never
/// silently dropped.
pub fn parse_n3_patch(body: &[u8], base_iri: &str) -> Result<N3Patch, ServerError> {
    let parser = N3Parser::new()
        .with_base_iri(base_iri)
        .map_err(|e| ServerError::BadRequest(format!("invalid base IRI: {e}")))?;

    let mut quads: Vec<N3Quad> = Vec::new();
    for q in parser.for_slice(body) {
        let q = q.map_err(|e| ServerError::UnprocessablePatch(format!("invalid N3: {e}")))?;
        quads.push(q);
    }

    // Partition into the default graph (the patch description) and the formula graphs (the `{ … }`
    // blocks, each a distinct blank-node graph name).
    let mut description: Vec<&N3Quad> = Vec::new();
    for q in &quads {
        if q.graph_name == GraphName::DefaultGraph {
            description.push(q);
        }
    }

    // Find the patch resource's formula references: subject patch -> solid:inserts/deletes/where ->
    // a formula (blank-node graph name). Reject a patch that names an unknown predicate shape.
    let mut inserts_formula: Option<GraphName> = None;
    let mut deletes_formula: Option<GraphName> = None;
    let mut where_formula: Option<GraphName> = None;
    let mut declared_patch_type = false;

    for q in &description {
        let pred_iri = match &q.predicate {
            N3Term::NamedNode(n) => n.as_str(),
            // A variable/blank predicate in the patch description is not a valid patch shape.
            _ => {
                return Err(ServerError::UnprocessablePatch(
                    "patch description predicate must be an IRI".into(),
                ))
            }
        };
        match pred_iri {
            SOLID_INSERTS => inserts_formula = Some(formula_graph(&q.object)?),
            SOLID_DELETES => deletes_formula = Some(formula_graph(&q.object)?),
            SOLID_WHERE => where_formula = Some(formula_graph(&q.object)?),
            RDF_TYPE => {
                if matches!(&q.object, N3Term::NamedNode(n) if n.as_str() == SOLID_INSERT_DELETE_PATCH)
                {
                    declared_patch_type = true;
                }
            }
            // Any other predicate on the patch description is ignored (forward-compat), but we do not
            // accept a patch that declares NONE of inserts/deletes (checked below).
            _ => {}
        }
    }

    // The type triple is conventional; we do not hard-require it (some clients omit it), but if NO
    // patch operation is present at all the document is not an actionable patch.
    let _ = declared_patch_type;

    // The `where` form (variable binding) is deferred. An empty `where { }` is fine; a non-empty one
    // is rejected with a clear status rather than mis-applied.
    if let Some(ref wf) = where_formula {
        let where_triples = triples_in_formula(&quads, wf);
        if !where_triples.is_empty() {
            // M2-next: implement the `solid:where` variable solver — bind the where-graph variables
            // against the target graph, then instantiate inserts/deletes per binding. Until then a
            // templated patch is explicitly unprocessable (never silently ignored).
            return Err(ServerError::UnprocessablePatch(
                "solid:where with conditions/variables is not yet supported".into(),
            ));
        }
    }

    let deletes = match deletes_formula {
        Some(g) => concrete_triples(&quads, &g)?,
        None => Vec::new(),
    };
    let inserts = match inserts_formula {
        Some(g) => concrete_triples(&quads, &g)?,
        None => Vec::new(),
    };

    if deletes.is_empty() && inserts.is_empty() {
        return Err(ServerError::UnprocessablePatch(
            "an N3 patch must specify at least one of solid:inserts / solid:deletes".into(),
        ));
    }

    Ok(N3Patch { deletes, inserts })
}

/// Apply a parsed patch to the target's existing triples, returning the new triple set.
///
/// Semantics (RFC-/Solid-aligned): every `deletes` triple MUST be present in the target (else the
/// patch fails with 409 Conflict — a precondition violation, not a no-op), they are removed, then
/// the `inserts` are added. The result preserves the surviving triples' relative order and appends
/// new inserts, de-duplicated; the set semantics make a repeated apply idempotent.
///
/// `oxrdf::Triple` is `Eq + Hash` but NOT `Ord`, so set membership is a linear scan over the (small)
/// graph rather than a `BTreeSet`; for a single resource's triples this is correct and adequate.
pub fn apply_patch(existing: &[Triple], patch: &N3Patch) -> Result<Vec<Triple>, ServerError> {
    // Preconditions: every delete must be present (a missing one is a 409, not a silent no-op).
    for d in &patch.deletes {
        if !existing.contains(d) {
            return Err(ServerError::Conflict(
                "a solid:deletes triple is not present in the resource".into(),
            ));
        }
    }

    // Keep the survivors (everything not in `deletes`), preserving order + de-duplicating.
    let mut result: Vec<Triple> = Vec::with_capacity(existing.len() + patch.inserts.len());
    for t in existing {
        if patch.deletes.contains(t) {
            continue;
        }
        if !result.contains(t) {
            result.push(t.clone());
        }
    }
    // Append inserts that are not already present (set union).
    for i in &patch.inserts {
        if !result.contains(i) {
            result.push(i.clone());
        }
    }
    Ok(result)
}

/// Extract the blank-node graph name a formula object refers to. In oxttl's N3 model a `{ … }`
/// formula is encoded as a blank node whose triples live in the graph of that name.
fn formula_graph(object: &N3Term) -> Result<GraphName, ServerError> {
    match object {
        N3Term::BlankNode(b) => Ok(GraphName::BlankNode(b.clone())),
        N3Term::NamedNode(n) => Ok(GraphName::NamedNode(n.clone())),
        _ => Err(ServerError::UnprocessablePatch(
            "solid:inserts/deletes/where object must be a formula".into(),
        )),
    }
}

/// All quads whose graph-name is the given formula graph (used to test where-emptiness).
fn triples_in_formula<'a>(quads: &'a [N3Quad], graph: &GraphName) -> Vec<&'a N3Quad> {
    quads.iter().filter(|q| &q.graph_name == graph).collect()
}

/// Collect the CONCRETE (variable-free) triples in a formula graph, converting each N3 term to a
/// plain RDF term. A variable anywhere in an inserts/deletes formula is the templated form and is
/// deferred (422) — only concrete triples are supported in this slice.
fn concrete_triples(quads: &[N3Quad], graph: &GraphName) -> Result<Vec<Triple>, ServerError> {
    let mut out = Vec::new();
    for q in quads.iter().filter(|q| &q.graph_name == graph) {
        let subject = n3_subject(&q.subject)?;
        let predicate = match &q.predicate {
            N3Term::NamedNode(n) => n.clone(),
            N3Term::Variable(_) => return Err(deferred_variable()),
            _ => {
                return Err(ServerError::UnprocessablePatch(
                    "patch triple predicate must be an IRI".into(),
                ))
            }
        };
        let object = n3_object(&q.object)?;
        out.push(Triple::new(subject, predicate, object));
    }
    Ok(out)
}

/// Convert an N3 subject term to an RDF subject (named or blank node).
fn n3_subject(t: &N3Term) -> Result<NamedOrBlankNode, ServerError> {
    match t {
        N3Term::NamedNode(n) => Ok(NamedOrBlankNode::NamedNode(n.clone())),
        N3Term::BlankNode(b) => Ok(NamedOrBlankNode::BlankNode(b.clone())),
        N3Term::Variable(_) => Err(deferred_variable()),
        N3Term::Literal(_) => Err(ServerError::UnprocessablePatch(
            "a patch triple subject cannot be a literal".into(),
        )),
    }
}

/// Convert an N3 object term to an RDF term.
fn n3_object(t: &N3Term) -> Result<Term, ServerError> {
    match t {
        N3Term::NamedNode(n) => Ok(Term::NamedNode(n.clone())),
        N3Term::BlankNode(b) => Ok(Term::BlankNode(b.clone())),
        N3Term::Literal(l) => Ok(Term::Literal(l.clone())),
        N3Term::Variable(_) => Err(deferred_variable()),
    }
}

/// The deferred-feature error for a variable found in a concrete inserts/deletes formula.
fn deferred_variable() -> ServerError {
    ServerError::UnprocessablePatch(
        "variables in solid:inserts / solid:deletes (templated patch) are not yet supported".into(),
    )
}

/// Classify a PATCH `Content-Type`: only `text/n3` is supported on this slice. Any other type is a
/// 415 (an unsupported PATCH must NOT be silently accepted).
pub fn classify_patch_media_type(content_type: Option<&str>) -> Result<(), ServerError> {
    let raw = content_type
        .ok_or_else(|| ServerError::UnsupportedMediaType("missing PATCH content-type".into()))?;
    let essence = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match essence.as_str() {
        "text/n3" => Ok(()),
        // M2-next: `application/sparql-update` is the other Solid PATCH media type; deferred. It is a
        // 415 (unsupported), never a silent accept.
        other => Err(ServerError::UnsupportedMediaType(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://pod.example/alice/data";

    const PREFIXES: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n";

    fn triple(s: &str, p: &str, o_literal: &str) -> Triple {
        Triple::new(
            oxrdf::NamedNode::new(s).unwrap(),
            oxrdf::NamedNode::new(p).unwrap(),
            oxrdf::Literal::new_simple_literal(o_literal),
        )
    }

    #[test]
    fn media_type_only_text_n3() {
        assert!(classify_patch_media_type(Some("text/n3")).is_ok());
        assert!(classify_patch_media_type(Some("text/n3; charset=utf-8")).is_ok());
        // SPARQL Update is deferred ⇒ 415, not a silent accept.
        let err = classify_patch_media_type(Some("application/sparql-update")).unwrap_err();
        assert_eq!(err.status().as_u16(), 415);
        assert_eq!(
            classify_patch_media_type(None)
                .unwrap_err()
                .status()
                .as_u16(),
            415
        );
    }

    #[test]
    fn parses_insert_and_delete() {
        let doc = format!(
            "{PREFIXES}\
            _:patch a solid:InsertDeletePatch;\n\
              solid:deletes {{ <#me> foaf:name \"Old\" . }};\n\
              solid:inserts {{ <#me> foaf:name \"New\" . }}.\n"
        );
        let patch = parse_n3_patch(doc.as_bytes(), BASE).unwrap();
        assert_eq!(patch.deletes.len(), 1);
        assert_eq!(patch.inserts.len(), 1);
        // The relative <#me> resolved against the base.
        assert_eq!(
            patch.inserts[0],
            triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "New"
            )
        );
    }

    #[test]
    fn insert_only_patch_is_valid() {
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:inserts {{ <#me> foaf:name \"Alice\" . }}.\n"
        );
        let patch = parse_n3_patch(doc.as_bytes(), BASE).unwrap();
        assert!(patch.deletes.is_empty());
        assert_eq!(patch.inserts.len(), 1);
    }

    #[test]
    fn empty_patch_is_rejected() {
        let doc = format!("{PREFIXES}_:patch a solid:InsertDeletePatch.\n");
        let err = parse_n3_patch(doc.as_bytes(), BASE).unwrap_err();
        assert_eq!(err.status().as_u16(), 422);
    }

    #[test]
    fn non_empty_where_is_deferred_422() {
        let doc = format!(
            "{PREFIXES}\
            @prefix var: <http://example.org/var#> .\n\
            _:patch solid:where {{ ?s foaf:name ?name . }};\n\
              solid:deletes {{ ?s foaf:name ?name . }}.\n"
        );
        let err = parse_n3_patch(doc.as_bytes(), BASE).unwrap_err();
        // Templated where ⇒ unprocessable (422), explicitly not silently ignored.
        assert_eq!(err.status().as_u16(), 422);
    }

    #[test]
    fn variables_in_inserts_are_deferred() {
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:inserts {{ ?s foaf:name \"x\" . }}.\n"
        );
        let err = parse_n3_patch(doc.as_bytes(), BASE).unwrap_err();
        assert_eq!(err.status().as_u16(), 422);
    }

    #[test]
    fn malformed_n3_is_rejected() {
        let err = parse_n3_patch(b"this is not n3 <<<", BASE).unwrap_err();
        // Either 422 (unprocessable patch parse) — never a silent accept.
        assert_eq!(err.status().as_u16(), 422);
    }

    #[test]
    fn apply_inserts_and_deletes() {
        let existing = vec![
            triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "Old",
            ),
            triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/age",
                "30",
            ),
        ];
        let patch = N3Patch {
            deletes: vec![triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "Old",
            )],
            inserts: vec![triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "New",
            )],
        };
        let result = apply_patch(&existing, &patch).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&triple(
            "https://pod.example/alice/data#me",
            "http://xmlns.com/foaf/0.1/name",
            "New"
        )));
        assert!(!result.contains(&triple(
            "https://pod.example/alice/data#me",
            "http://xmlns.com/foaf/0.1/name",
            "Old"
        )));
    }

    #[test]
    fn deleting_an_absent_triple_is_a_conflict() {
        let existing = vec![triple(
            "https://pod.example/alice/data#me",
            "http://xmlns.com/foaf/0.1/name",
            "Alice",
        )];
        let patch = N3Patch {
            deletes: vec![triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "NotThere",
            )],
            inserts: vec![],
        };
        let err = apply_patch(&existing, &patch).unwrap_err();
        assert_eq!(err.status().as_u16(), 409);
    }

    #[test]
    fn apply_is_idempotent_for_inserts() {
        let existing = vec![triple(
            "https://pod.example/alice/data#me",
            "http://xmlns.com/foaf/0.1/name",
            "Alice",
        )];
        let patch = N3Patch {
            deletes: vec![],
            inserts: vec![triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "Alice",
            )],
        };
        // Inserting an existing triple is a no-op (set union), not a duplicate.
        let result = apply_patch(&existing, &patch).unwrap();
        assert_eq!(result.len(), 1);
    }
}
