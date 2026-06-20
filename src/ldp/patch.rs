// AUTHORED-BY Claude Opus 4.8
//! The Solid **N3 Patch** engine (`text/n3`).
//!
//! Implements the Solid Protocol N3 Patch document shape
//! (<https://solidproject.org/TR/protocol#n3-patch>): a single `solid:InsertDeletePatch` resource
//! with `solid:inserts`, `solid:deletes`, and `solid:where` formula objects (each a `{ … }` graph).
//! The patch is applied to the target resource's existing graph and the result re-serialised.
//!
//! ## What this implements
//!
//! - **`solid:inserts` + `solid:deletes`** (concrete triples, no variables): the delete-then-insert
//!   set operations over the target graph, with the spec's preconditions (every `deletes` triple
//!   must be present; an `InsertDeletePatch` must carry at least one of inserts/deletes).
//! - **`solid:where`** (the templated/conditional form): the variable solver. The `where` formula is
//!   a basic graph pattern (BGP) of triple *patterns* (terms may be SPARQL variables). It is matched
//!   against the target's graph by conjunctive variable unification; the **single** resulting binding
//!   substitutes into the `inserts`/`deletes` templates, which are then applied. See the precise
//!   spec-faithful solution-count rule below.
//!
//! ## Spec-faithful solution-count semantics (the load-bearing call)
//!
//! The Solid Protocol §N3 Patch is explicit and unambiguous: *"If `?conditions` is non-empty, find
//! all (possibly empty) variable mappings such that all of the resulting triples occur in the
//! dataset. **If no such mapping exists, or if multiple mappings exist, the server MUST respond with
//! a `409` status code.**"* So a non-empty `where` requires **exactly one** solution — **zero** and
//! **more-than-one** are *both* a `409 Conflict`, NOT a no-op and NOT a per-solution fan-out. (This
//! differs from a SPARQL `DELETE/INSERT … WHERE`, which fans out over every solution; the Solid N3
//! Patch deliberately does not.) The where's templates therefore apply exactly once, with the unique
//! binding. An *empty* `where { }` constrains nothing and the patch must be fully concrete.
//!
//! ## Static (parse-time) constraints, per spec
//!
//! - The `inserts`/`deletes` formulae **MUST NOT contain variables that do not occur in the
//!   `where` formula** — a free (unbound) variable in a template is a structural error (`422`), never
//!   silently left as a variable in the output graph.
//! - The `inserts`/`deletes` formulae **MUST NOT contain blank nodes** (`422`). (Blank nodes in the
//!   target graph and in the `where` pattern are fine.)
//!
//! Per the house rule, the patch document is parsed with the vetted `oxttl` N3 parser (formulas →
//! blank-node-named graphs), never hand-parsed.

use std::collections::HashMap;

use oxrdf::{GraphName, NamedOrBlankNode, Term, Triple, Variable};
use oxttl::n3::{N3Parser, N3Quad, N3Term};

use crate::error::ServerError;

/// The Solid terms vocabulary IRIs used by an N3 Patch.
const SOLID_INSERTS: &str = "http://www.w3.org/ns/solid/terms#inserts";
const SOLID_DELETES: &str = "http://www.w3.org/ns/solid/terms#deletes";
const SOLID_WHERE: &str = "http://www.w3.org/ns/solid/terms#where";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const SOLID_INSERT_DELETE_PATCH: &str = "http://www.w3.org/ns/solid/terms#InsertDeletePatch";

/// A term in a triple pattern: a concrete RDF term or a (named) SPARQL variable.
///
/// Used uniformly for the `where`, `inserts`, and `deletes` formulae. A formula with no variables
/// collapses to all-`Term` patterns, which is exactly the concrete (un-templated) patch case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatTerm {
    /// A concrete RDF term (named node, blank node, or literal).
    Term(Term),
    /// A SPARQL variable (`?x`) — to be bound by the `where` solver.
    Var(Variable),
}

/// A triple pattern (subject/predicate/object, each possibly a variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatTriple {
    pub subject: PatTerm,
    pub predicate: PatTerm,
    pub object: PatTerm,
}

/// A parsed N3 Patch: the `where` basic graph pattern plus the delete/insert templates.
///
/// When `where` is empty, `deletes`/`inserts` are guaranteed (by parse-time validation) to be
/// variable-free, i.e. concrete triples.
#[derive(Debug, Default, Clone)]
pub struct N3Patch {
    /// The `solid:where` basic graph pattern (empty ⇒ an unconditional, fully-concrete patch).
    pub conditions: Vec<PatTriple>,
    /// The `solid:deletes` template.
    pub deletes: Vec<PatTriple>,
    /// The `solid:inserts` template.
    pub inserts: Vec<PatTriple>,
}

/// Parse a `text/n3` Solid N3 Patch document, resolving relative IRIs against `base_iri`.
///
/// Returns the where/delete/insert templates. A document that is not a well-formed single
/// `InsertDeletePatch`, or that violates a static spec constraint (an unbound template variable, a
/// blank node in a template), is an error (4xx) — never silently dropped.
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

    // The `where` BGP: triple patterns, variables allowed (blank nodes allowed here per spec).
    let conditions = match where_formula {
        Some(g) => pattern_triples(&quads, &g, FormulaKind::Where)?,
        None => Vec::new(),
    };
    // The deletes/inserts TEMPLATES: triple patterns, variables allowed but blank nodes forbidden.
    let deletes = match deletes_formula {
        Some(g) => pattern_triples(&quads, &g, FormulaKind::Template)?,
        None => Vec::new(),
    };
    let inserts = match inserts_formula {
        Some(g) => pattern_triples(&quads, &g, FormulaKind::Template)?,
        None => Vec::new(),
    };

    if deletes.is_empty() && inserts.is_empty() {
        return Err(ServerError::UnprocessablePatch(
            "an N3 patch must specify at least one of solid:inserts / solid:deletes".into(),
        ));
    }

    // Spec: the inserts/deletes formulae MUST NOT contain variables that do not occur in `where`.
    // A free template variable can never be bound ⇒ a 422 structural error, not a runtime surprise.
    let where_vars = collect_vars(&conditions);
    for t in deletes.iter().chain(inserts.iter()) {
        for v in pat_triple_vars(t) {
            if !where_vars.contains(v.as_str()) {
                return Err(ServerError::UnprocessablePatch(format!(
                    "variable ?{} appears in solid:inserts/deletes but not in solid:where",
                    v.as_str()
                )));
            }
        }
    }

    Ok(N3Patch {
        conditions,
        deletes,
        inserts,
    })
}

/// Apply a parsed patch to the target's existing triples, returning the new triple set.
///
/// Semantics (Solid-Protocol-aligned):
///
/// 1. If `where` (conditions) is non-empty, solve the BGP against `existing`. Per spec, there MUST be
///    **exactly one** solution: **zero** or **multiple** solutions ⇒ `409 Conflict`.
/// 2. Substitute the unique binding into the `deletes`/`inserts` templates. (An empty `where` ⇒ the
///    templates are already concrete, used as-is with the empty binding.)
/// 3. Every resulting `deletes` triple MUST be present in `existing` (else `409 Conflict` — a
///    precondition violation, not a silent no-op); they are removed, then `inserts` are added.
///
/// The result preserves the surviving triples' relative order and appends new inserts, de-duplicated;
/// the set semantics make a repeated apply idempotent.
///
/// `oxrdf::Triple` is `Eq + Hash` but NOT `Ord`, so set membership is a linear scan over the (small)
/// graph rather than a `BTreeSet`; for a single resource's triples this is correct and adequate.
pub fn apply_patch(existing: &[Triple], patch: &N3Patch) -> Result<Vec<Triple>, ServerError> {
    // 1+2: resolve the (single) binding and instantiate the templates into concrete triples.
    let binding = if patch.conditions.is_empty() {
        // No conditions: the templates are already concrete (validated at parse time). Use the empty
        // binding; instantiation is then a 1:1 conversion of every PatTerm::Term.
        Binding::default()
    } else {
        let solutions = solve_bgp(&patch.conditions, existing);
        match solutions.len() {
            1 => solutions.into_iter().next().unwrap(),
            // Spec: zero OR multiple mappings ⇒ 409 (NOT a no-op, NOT a per-solution fan-out).
            0 => {
                return Err(ServerError::Conflict(
                    "the solid:where clause has no solution against the target graph".into(),
                ))
            }
            _ => {
                return Err(ServerError::Conflict(
                    "the solid:where clause has multiple solutions; exactly one is required".into(),
                ))
            }
        }
    };

    let deletes = instantiate_all(&patch.deletes, &binding)?;
    let inserts = instantiate_all(&patch.inserts, &binding)?;

    // 3: every delete must be present (a missing one is a 409, not a silent no-op).
    for d in &deletes {
        if !existing.contains(d) {
            return Err(ServerError::Conflict(
                "a solid:deletes triple is not present in the resource".into(),
            ));
        }
    }

    // Keep the survivors (everything not in `deletes`), preserving order + de-duplicating.
    let mut result: Vec<Triple> = Vec::with_capacity(existing.len() + inserts.len());
    for t in existing {
        if deletes.contains(t) {
            continue;
        }
        if !result.contains(t) {
            result.push(t.clone());
        }
    }
    // Append inserts that are not already present (set union).
    for i in &inserts {
        if !result.contains(i) {
            result.push(i.clone());
        }
    }
    Ok(result)
}

// --- the BGP solver ----------------------------------------------------------------------------

/// A variable binding: variable-name → concrete RDF term.
type Binding = HashMap<String, Term>;

/// Solve a basic graph pattern (conjunction of triple patterns) against the graph, returning every
/// distinct, complete variable mapping under which all pattern triples occur in `graph`.
///
/// This is a straight backtracking join: for each pattern in turn, scan the graph for triples that
/// unify with the pattern under the partial binding so far, extend the binding, and recurse. The
/// graph for one resource is small, so the naive nested scan is correct and adequate (no index).
fn solve_bgp(patterns: &[PatTriple], graph: &[Triple]) -> Vec<Binding> {
    let mut solutions: Vec<Binding> = Vec::new();
    solve_from(patterns, 0, Binding::default(), graph, &mut solutions);
    solutions
}

/// Recursive backtracking step over the pattern list from index `idx`.
fn solve_from(
    patterns: &[PatTriple],
    idx: usize,
    binding: Binding,
    graph: &[Triple],
    out: &mut Vec<Binding>,
) {
    if idx == patterns.len() {
        // A complete mapping. De-duplicate (two patterns can bind identically) so the spec's
        // "multiple mappings" count is over DISTINCT solutions, not repeated identical ones.
        if !out.contains(&binding) {
            out.push(binding);
        }
        return;
    }
    let pat = &patterns[idx];
    for t in graph {
        if let Some(extended) = unify_triple(pat, t, &binding) {
            solve_from(patterns, idx + 1, extended, graph, out);
        }
    }
}

/// Try to unify a single triple pattern against a concrete triple under the current binding.
/// Returns the extended binding on success, `None` on a clash.
fn unify_triple(pat: &PatTriple, t: &Triple, binding: &Binding) -> Option<Binding> {
    let mut b = binding.clone();
    unify_term(&pat.subject, &subject_as_term(&t.subject), &mut b)?;
    unify_term(
        &pat.predicate,
        &Term::NamedNode(t.predicate.clone()),
        &mut b,
    )?;
    unify_term(&pat.object, &t.object, &mut b)?;
    Some(b)
}

/// Unify one pattern term against a concrete term, mutating the binding. Returns `None` on a clash
/// (a concrete-term mismatch, or a variable already bound to a different term).
fn unify_term(pat: &PatTerm, concrete: &Term, binding: &mut Binding) -> Option<()> {
    match pat {
        PatTerm::Term(expected) => {
            if expected == concrete {
                Some(())
            } else {
                None
            }
        }
        PatTerm::Var(v) => match binding.get(v.as_str()) {
            Some(already) if already == concrete => Some(()),
            Some(_) => None, // bound to a different term ⇒ clash
            None => {
                binding.insert(v.as_str().to_string(), concrete.clone());
                Some(())
            }
        },
    }
}

/// Lift an `oxrdf` subject (named/blank node) into a `Term` so it unifies uniformly with an object.
fn subject_as_term(s: &NamedOrBlankNode) -> Term {
    match s {
        NamedOrBlankNode::NamedNode(n) => Term::NamedNode(n.clone()),
        NamedOrBlankNode::BlankNode(b) => Term::BlankNode(b.clone()),
    }
}

// --- template instantiation --------------------------------------------------------------------

/// Instantiate every template triple pattern under the binding into a concrete triple.
fn instantiate_all(template: &[PatTriple], binding: &Binding) -> Result<Vec<Triple>, ServerError> {
    template.iter().map(|t| instantiate(t, binding)).collect()
}

/// Instantiate a single template triple under the binding. Every variable in a template is
/// guaranteed (by parse-time validation) to occur in `where`; if the where matched it is therefore
/// bound. A missing binding here would be an internal invariant break, surfaced as a 422 rather than
/// a panic.
fn instantiate(pat: &PatTriple, binding: &Binding) -> Result<Triple, ServerError> {
    let subject = match resolve(&pat.subject, binding)? {
        Term::NamedNode(n) => NamedOrBlankNode::NamedNode(n),
        Term::BlankNode(b) => NamedOrBlankNode::BlankNode(b),
        Term::Literal(_) => {
            return Err(ServerError::UnprocessablePatch(
                "a patch triple subject cannot be a literal".into(),
            ))
        }
    };
    let predicate = match resolve(&pat.predicate, binding)? {
        Term::NamedNode(n) => n,
        _ => {
            return Err(ServerError::UnprocessablePatch(
                "a patch triple predicate must be an IRI".into(),
            ))
        }
    };
    let object = resolve(&pat.object, binding)?;
    Ok(Triple::new(subject, predicate, object))
}

/// Resolve a pattern term to a concrete term under the binding.
fn resolve(pat: &PatTerm, binding: &Binding) -> Result<Term, ServerError> {
    match pat {
        PatTerm::Term(t) => Ok(t.clone()),
        PatTerm::Var(v) => binding.get(v.as_str()).cloned().ok_or_else(|| {
            // Should be unreachable given parse-time validation, but never silently drop a variable.
            ServerError::UnprocessablePatch(format!(
                "variable ?{} in a template was not bound by solid:where",
                v.as_str()
            ))
        }),
    }
}

// --- formula parsing ---------------------------------------------------------------------------

/// Whether a formula is the `where` BGP (blank nodes allowed) or an inserts/deletes template
/// (blank nodes forbidden per spec).
#[derive(Clone, Copy, PartialEq, Eq)]
enum FormulaKind {
    Where,
    Template,
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

/// Collect the triple PATTERNS in a formula graph (terms may be variables), converting each N3 term.
/// For a `Template` formula a blank node is a spec violation (422); for a `Where` formula it is fine.
fn pattern_triples(
    quads: &[N3Quad],
    graph: &GraphName,
    kind: FormulaKind,
) -> Result<Vec<PatTriple>, ServerError> {
    let mut out = Vec::new();
    for q in quads.iter().filter(|q| &q.graph_name == graph) {
        let subject = pat_term(&q.subject, kind, Position::Subject)?;
        let predicate = pat_term(&q.predicate, kind, Position::Predicate)?;
        let object = pat_term(&q.object, kind, Position::Object)?;
        out.push(PatTriple {
            subject,
            predicate,
            object,
        });
    }
    Ok(out)
}

/// Triple position, used to reject a literal/blank in an illegal slot.
#[derive(Clone, Copy)]
enum Position {
    Subject,
    Predicate,
    Object,
}

/// Convert an N3 term to a pattern term, enforcing position + formula-kind constraints.
///
/// NB: oxttl's `N3Term::Triple` (RDF 1.2 quoted triples) exists only with its `rdf-12` feature,
/// which is OFF for this crate's oxttl dependency — so the enum has no such variant here and this
/// match is exhaustive without it. If `rdf-12` is ever enabled, the compiler will flag the missing
/// arm and a reject branch must be added (quoted triples are not part of N3 Patch).
fn pat_term(t: &N3Term, kind: FormulaKind, pos: Position) -> Result<PatTerm, ServerError> {
    match t {
        N3Term::NamedNode(n) => Ok(PatTerm::Term(Term::NamedNode(n.clone()))),
        N3Term::Literal(l) => match pos {
            Position::Object => Ok(PatTerm::Term(Term::Literal(l.clone()))),
            Position::Subject => Err(ServerError::UnprocessablePatch(
                "a patch triple subject cannot be a literal".into(),
            )),
            Position::Predicate => Err(ServerError::UnprocessablePatch(
                "a patch triple predicate must be an IRI".into(),
            )),
        },
        N3Term::BlankNode(b) => {
            if kind == FormulaKind::Template {
                // Spec: the inserts/deletes formulae MUST NOT contain blank nodes.
                return Err(ServerError::UnprocessablePatch(
                    "blank nodes are not allowed in solid:inserts / solid:deletes".into(),
                ));
            }
            match pos {
                Position::Predicate => Err(ServerError::UnprocessablePatch(
                    "a patch triple predicate must be an IRI".into(),
                )),
                _ => Ok(PatTerm::Term(Term::BlankNode(b.clone()))),
            }
        }
        N3Term::Variable(v) => {
            // A variable predicate is permitted in a BGP pattern; on a real graph the predicate is
            // always an IRI, so a predicate variable simply binds to an IRI during the join.
            Ok(PatTerm::Var(v.clone()))
        }
    }
}

// --- variable bookkeeping ----------------------------------------------------------------------

/// The set of variable names occurring anywhere in a set of triple patterns.
fn collect_vars(patterns: &[PatTriple]) -> std::collections::HashSet<String> {
    let mut s = std::collections::HashSet::new();
    for t in patterns {
        for v in pat_triple_vars(t) {
            s.insert(v.as_str().to_string());
        }
    }
    s
}

/// The variables occurring in a single triple pattern.
fn pat_triple_vars(t: &PatTriple) -> impl Iterator<Item = &Variable> {
    [&t.subject, &t.predicate, &t.object]
        .into_iter()
        .filter_map(|term| match term {
            PatTerm::Var(v) => Some(v),
            PatTerm::Term(_) => None,
        })
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

    /// A triple whose object is a named node (for where-binding tests where vars bind to IRIs).
    fn triple_obj_iri(s: &str, p: &str, o: &str) -> Triple {
        Triple::new(
            oxrdf::NamedNode::new(s).unwrap(),
            oxrdf::NamedNode::new(p).unwrap(),
            oxrdf::NamedNode::new(o).unwrap(),
        )
    }

    /// Build a concrete (variable-free) triple pattern with a literal object, for the programmatic
    /// `N3Patch` construction tests below.
    fn concrete_pat_triple(s: &str, p: &str, o_literal: &str) -> PatTriple {
        PatTriple {
            subject: PatTerm::Term(Term::NamedNode(oxrdf::NamedNode::new(s).unwrap())),
            predicate: PatTerm::Term(Term::NamedNode(oxrdf::NamedNode::new(p).unwrap())),
            object: PatTerm::Term(Term::Literal(oxrdf::Literal::new_simple_literal(o_literal))),
        }
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
        assert!(patch.conditions.is_empty());
        // Apply it and confirm the concrete instantiation resolved <#me> against the base.
        let existing = vec![triple(
            "https://pod.example/alice/data#me",
            "http://xmlns.com/foaf/0.1/name",
            "Old",
        )];
        let result = apply_patch(&existing, &patch).unwrap();
        assert_eq!(
            result,
            vec![triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "New"
            )]
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

    // --- where-clause solver tests -------------------------------------------------------------

    /// A `where` matching exactly one solution drives a templated delete+insert (the happy path).
    #[test]
    fn where_single_binding_drives_delete_insert() {
        // The classic "rename" patch: bind ?name to the current value, delete it, insert the new one.
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:where   {{ <#me> foaf:name ?name . }};\n\
              solid:deletes {{ <#me> foaf:name ?name . }};\n\
              solid:inserts {{ <#me> foaf:name \"New\" . }}.\n"
        );
        let patch = parse_n3_patch(doc.as_bytes(), BASE).unwrap();
        assert_eq!(patch.conditions.len(), 1);

        let existing = vec![triple(
            "https://pod.example/alice/data#me",
            "http://xmlns.com/foaf/0.1/name",
            "Old",
        )];
        let result = apply_patch(&existing, &patch).unwrap();
        assert_eq!(result.len(), 1);
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

    /// A multi-pattern `where` conjunctively joins on a shared variable and binds it once.
    #[test]
    fn where_conjunctive_join_on_shared_var() {
        // where { <#me> foaf:knows ?p . ?p foaf:name ?n } — join ?p across two patterns.
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:where {{ <#me> foaf:knows ?p . ?p foaf:name ?n . }};\n\
              solid:inserts {{ <#me> foaf:name ?n . }}.\n"
        );
        let patch = parse_n3_patch(doc.as_bytes(), BASE).unwrap();
        let existing = vec![
            triple_obj_iri(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/knows",
                "https://pod.example/bob#me",
            ),
            triple(
                "https://pod.example/bob#me",
                "http://xmlns.com/foaf/0.1/name",
                "Bob",
            ),
        ];
        let result = apply_patch(&existing, &patch).unwrap();
        // ?n bound to "Bob" via the join ⇒ inserts <#me> foaf:name "Bob".
        assert!(result.contains(&triple(
            "https://pod.example/alice/data#me",
            "http://xmlns.com/foaf/0.1/name",
            "Bob"
        )));
    }

    /// Spec: a `where` with ZERO solutions ⇒ 409 Conflict (NOT a silent no-op).
    #[test]
    fn where_zero_solutions_is_409() {
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:where   {{ <#me> foaf:name ?name . }};\n\
              solid:deletes {{ <#me> foaf:name ?name . }};\n\
              solid:inserts {{ <#me> foaf:name \"New\" . }}.\n"
        );
        let patch = parse_n3_patch(doc.as_bytes(), BASE).unwrap();
        // Target has NO foaf:name triple ⇒ the where can't be satisfied.
        let existing = vec![triple(
            "https://pod.example/alice/data#me",
            "http://xmlns.com/foaf/0.1/age",
            "30",
        )];
        let err = apply_patch(&existing, &patch).unwrap_err();
        assert_eq!(err.status().as_u16(), 409);
    }

    /// Spec: a `where` with MULTIPLE solutions ⇒ 409 Conflict (Solid N3 Patch requires exactly one
    /// mapping — it does NOT fan out per solution the way a SPARQL DELETE/INSERT WHERE would).
    #[test]
    fn where_multiple_solutions_is_409() {
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:where   {{ <#me> foaf:name ?name . }};\n\
              solid:deletes {{ <#me> foaf:name ?name . }}.\n"
        );
        let patch = parse_n3_patch(doc.as_bytes(), BASE).unwrap();
        // Two foaf:name values ⇒ two distinct bindings of ?name ⇒ multiple solutions ⇒ 409.
        let existing = vec![
            triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "Alice",
            ),
            triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "Alicia",
            ),
        ];
        let err = apply_patch(&existing, &patch).unwrap_err();
        assert_eq!(err.status().as_u16(), 409);
    }

    /// A `where` that binds a variable used to FILTER which delete applies: only the matched triple
    /// is removed, the other foaf:name-on-a-different-subject triple survives.
    #[test]
    fn where_filters_which_delete_applies() {
        // where { ?s foaf:age "30" . ?s foaf:name ?n } — pins ?s to the person aged 30, then deletes
        // only THAT person's name. A second person's name (different subject) is untouched.
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:where   {{ ?s foaf:age \"30\" . ?s foaf:name ?n . }};\n\
              solid:deletes {{ ?s foaf:name ?n . }}.\n"
        );
        let patch = parse_n3_patch(doc.as_bytes(), BASE).unwrap();
        let alice_name = triple(
            "https://pod.example/alice/data#alice",
            "http://xmlns.com/foaf/0.1/name",
            "Alice",
        );
        let bob_name = triple(
            "https://pod.example/alice/data#bob",
            "http://xmlns.com/foaf/0.1/name",
            "Bob",
        );
        let existing = vec![
            triple(
                "https://pod.example/alice/data#alice",
                "http://xmlns.com/foaf/0.1/age",
                "30",
            ),
            alice_name.clone(),
            bob_name.clone(),
        ];
        let result = apply_patch(&existing, &patch).unwrap();
        // Alice (aged 30) loses her name; Bob keeps his; Alice's age survives.
        assert!(!result.contains(&alice_name));
        assert!(result.contains(&bob_name));
        assert!(result.contains(&triple(
            "https://pod.example/alice/data#alice",
            "http://xmlns.com/foaf/0.1/age",
            "30"
        )));
    }

    /// Spec: a variable in inserts/deletes that does NOT occur in `where` is a static 422.
    #[test]
    fn unbound_template_variable_is_422() {
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:where   {{ <#me> foaf:name ?name . }};\n\
              solid:inserts {{ <#me> foaf:nick ?missing . }}.\n"
        );
        let err = parse_n3_patch(doc.as_bytes(), BASE).unwrap_err();
        assert_eq!(err.status().as_u16(), 422);
    }

    /// A variable in inserts/deletes WITHOUT any `where` clause is unbound ⇒ 422 (was the old
    /// "variables in inserts/deletes are deferred" rejection; now it's the spec's unbound-var rule).
    #[test]
    fn variable_in_template_without_where_is_422() {
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:inserts {{ ?s foaf:name \"x\" . }}.\n"
        );
        let err = parse_n3_patch(doc.as_bytes(), BASE).unwrap_err();
        assert_eq!(err.status().as_u16(), 422);
    }

    /// Spec: blank nodes are forbidden in the inserts/deletes templates (422).
    #[test]
    fn blank_node_in_template_is_422() {
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:inserts {{ <#me> foaf:knows _:someone . }}.\n"
        );
        let err = parse_n3_patch(doc.as_bytes(), BASE).unwrap_err();
        assert_eq!(err.status().as_u16(), 422);
    }

    /// An EMPTY where { } constrains nothing; the patch must then be fully concrete and applies as
    /// an unconditional insert/delete.
    #[test]
    fn empty_where_is_unconditional() {
        let doc = format!(
            "{PREFIXES}\
            _:patch solid:where {{ }};\n\
              solid:inserts {{ <#me> foaf:name \"Alice\" . }}.\n"
        );
        let patch = parse_n3_patch(doc.as_bytes(), BASE).unwrap();
        assert!(patch.conditions.is_empty());
        let result = apply_patch(&[], &patch).unwrap();
        assert_eq!(result.len(), 1);
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
            conditions: vec![],
            deletes: vec![concrete_pat_triple(
                "https://pod.example/alice/data#me",
                "http://xmlns.com/foaf/0.1/name",
                "Old",
            )],
            inserts: vec![concrete_pat_triple(
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
            conditions: vec![],
            deletes: vec![concrete_pat_triple(
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
            conditions: vec![],
            deletes: vec![],
            inserts: vec![concrete_pat_triple(
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
