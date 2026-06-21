// AUTHORED-BY Claude Opus 4.8
//! SPARQL injection-safe term builders + the queries the [`SparqClient`](super::SparqClient) data
//! path issues.
//!
//! This is the SPARQL analogue of the suite's RDF-injection guard: an untrusted IRI or literal is
//! **never** string-concatenated into a query — every term goes through [`iri`] / [`literal`], which
//! validate + escape per the SPARQL 1.1 grammar so a crafted resource IRI (or content-type/blob-key)
//! cannot break out of its term position and inject clauses. The builders are pure + total: a value
//! that cannot be safely represented is escaped to a form that still parses as the same term, never
//! as syntax.
//!
//! The data model (the maintainer's "tight SPARQ integration" direction, per the
//! `solid-server-rs-wac.md` design): every resource is a **named graph whose graph IRI equals the
//! resource IRI**; the resource's authoritative index record (content type + blob-key byte-pointer +
//! ETag) and its containment edges live as triples *in that graph* under the reserved `pss:` vocab.
//! Existence/metadata/listing are SELECT/ASK over those graphs; the resource RDF itself is the rest
//! of the graph (read via CONSTRUCT). See the module docs in [`super::http`] for the live-endpoint
//! deviation note (today's `sparq-server` HTTP store folds named graphs into one default graph, so
//! the isolation the model assumes is enforced at the engine layer but not yet over HTTP — FR-4).

/// The reserved metadata vocabulary namespace for the index records this server writes (mirrors the
/// production server's `pss:` index predicates). Kept as one constant so the predicate IRIs below
/// cannot drift apart.
pub const PSS_NS: &str = "urn:pss:index#";

/// `ldp:contains`, the containment predicate.
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";

/// Predicate: a resource's stored RDF content type (a literal).
pub fn p_content_type() -> String {
    format!("{PSS_NS}contentType")
}
/// Predicate: a resource's opaque blob-store byte-pointer (a literal).
pub fn p_blob_key() -> String {
    format!("{PSS_NS}blobKey")
}
/// Predicate: a resource's opaque entity tag (a literal).
pub fn p_etag() -> String {
    format!("{PSS_NS}etag")
}
/// Predicate: a per-operation create marker (a unique-nonce literal), written atomically with a
/// guarded `create_child` so the success confirm is race-resistant (no other op touches it).
pub fn p_create_marker() -> String {
    format!("{PSS_NS}createMarker")
}
/// Predicate: a per-operation **delete** marker (a unique-nonce literal), written atomically with the
/// guarded empty-container delete into a SEPARATE scratch graph so the "did the empty+exists guard
/// match?" confirm is race-resistant (no other op writes or removes THIS nonce).
pub fn p_delete_marker() -> String {
    format!("{PSS_NS}deleteMarker")
}
/// The reserved scratch graph that per-operation delete markers are written into. It is a DISTINCT
/// graph from any resource's own graph, so dropping a resource's graph never touches a marker, and a
/// marker can confirm a delete whose own graph is gone. (Markers are operation-scoped + pruned by the
/// reconciler — M3-next.)
pub fn g_delete_markers() -> String {
    format!("{PSS_NS}deleteMarkers")
}
/// The subject every index record hangs off, *within* a resource's own named graph: a stable,
/// reserved IRI so the record triples never collide with the resource's own RDF.
pub fn s_record() -> String {
    format!("{PSS_NS}record")
}

/// An error rendering an untrusted value into a SPARQL term — surfaced as a fatal backend error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    /// The value is not a valid SPARQL `IRIREF` (it contains an IRIREF-forbidden character).
    #[error("invalid IRI for a SPARQL term: contains a forbidden character")]
    InvalidIri,
    /// A language tag is empty or contains a character outside the BCP-47-subset
    /// (`[A-Za-z0-9-]`, non-empty) — rejected fail-closed rather than silently rewritten.
    #[error("invalid language tag for a SPARQL literal")]
    InvalidLangTag,
    /// A body triple touches a RESERVED metadata term (the `urn:pss:index#record` subject or a
    /// `urn:pss:index#` predicate) — rejected so untrusted RDF can never corrupt/spoof the index
    /// records that share the resource's named graph.
    #[error("body triple collides with a reserved metadata term")]
    ReservedTermCollision,
}

/// Render a string as a **SPARQL IRI reference** (`<...>`), REJECTING any IRIREF-forbidden character
/// rather than escaping it.
///
/// Per the SPARQL 1.1 `IRIREF` production an IRI ref may not contain `<`, `>`, `"`, `{`, `}`, `|`,
/// `^`, `` ` ``, `\`, or any char ≤ U+0020. A well-formed resource IRI (the server's own
/// target-parsed absolute IRI) never contains these; a value that DOES is rejected with
/// [`BuildError::InvalidIri`] — NOT percent-escaped. Rejection (not escaping) is what keeps the
/// mapping **injective**: percent-escaping a raw `>` to `%3E` would alias it onto a distinct IRI that
/// already literally contained `%3E` (two different resources → the same graph IRI — the round-4
/// finding). Because forbidden chars are refused, the surviving output is the input wrapped verbatim
/// in `<...>`: a single well-formed IRI term that cannot terminate early or inject. Fail-closed.
pub fn iri(value: &str) -> Result<String, BuildError> {
    for ch in value.chars() {
        let forbidden = matches!(ch, '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\')
            || (ch as u32) <= 0x20;
        if forbidden {
            return Err(BuildError::InvalidIri);
        }
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('<');
    out.push_str(value);
    out.push('>');
    Ok(out)
}

/// Render a string as a **safely-escaped SPARQL string literal** (`"..."`), with the optional
/// datatype/lang left to the caller (these data-path literals are plain `xsd:string`).
///
/// Escapes per the SPARQL `STRING_LITERAL_QUOTE` production: `"`, `\`, and the line terminators
/// `\n`/`\r` (and `\t` for cleanliness). A literal value containing `" . } DROP …` is therefore
/// rendered as inert escaped characters inside one string term — it can never close the literal and
/// inject syntax. The output is ALWAYS a single well-formed `"..."` token.
pub fn literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Map a 4-bit nibble to an uppercase hex digit (for the injective bnode-label byte escapes).
fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + (n - 10)) as char,
    }
}

// ---------------------------------------------------------------------------
// Query/Update builders — every untrusted value flows through the fallible `iri` / `literal`.
//
// All builders return `Result<String, BuildError>`: an untrusted IRI that is not a valid IRIREF is
// REJECTED (fail-closed), never escaped-and-aliased. The reserved-vocab constants (`s_record()`,
// the `p_*()` predicates, `LDP_CONTAINS`) are known-valid by construction, so they go through
// `iri_const` — an infallible wrapper that ASSERTS validity (a panic there is a build-time bug, not a
// runtime/untrusted-input path).
// ---------------------------------------------------------------------------

/// Wrap a KNOWN-VALID reserved-vocab IRI (a compile-time-fixed constant or a `pss:`/`ldp:` IRI this
/// crate mints) into a `<...>` term. These never contain IRIREF-forbidden chars, so an error here is
/// a programming bug — surfaced via `expect`, never reachable from untrusted input.
fn iri_const(value: &str) -> String {
    iri(value).expect("reserved-vocab IRI must be a valid IRIREF (build-time invariant)")
}

/// ASK whether a resource is indexed: its graph holds the reserved index record.
pub fn ask_exists(resource: &str) -> Result<String, BuildError> {
    Ok(format!(
        "ASK {{ GRAPH {g} {{ {s} {p} ?ct }} }}",
        g = iri(resource)?,
        s = iri_const(&s_record()),
        p = iri_const(&p_content_type()),
    ))
}

/// ASK whether a specific `container ldp:contains child` edge exists — the *containment-edge*
/// confirmation [`update_create_child`] needs.
///
/// This is the correct post-create check (NOT `ask_exists(child)`): the atomic guarded insert only
/// adds the edge when the container existed, so the presence of the EDGE — not merely the child's
/// own existence — is what distinguishes "guard matched, child created here" from "guard rejected
/// (container missing) while a same-named child happened to already exist". Fail-closed.
pub fn ask_contains_edge(container: &str, child: &str) -> Result<String, BuildError> {
    Ok(format!(
        "ASK {{ GRAPH {g} {{ {s} {p} {c} }} }}",
        g = iri(container)?,
        s = iri_const(&s_record()),
        p = iri_const(LDP_CONTAINS),
        c = iri(child)?,
    ))
}

/// ASK whether a unique per-operation marker triple is present in a child's graph — the
/// *race-resistant* create-confirmation [`update_create_child`] uses.
///
/// The marker is written ATOMICALLY with the guarded create (only when the container existed), under
/// a reserved predicate with a caller-supplied unique nonce object. Unlike the containment edge, NO
/// other operation (`remove_child`, a sibling create) ever writes or removes THIS marker, so a
/// concurrent containment mutation between the create and the confirm cannot flip the result — the
/// marker's presence is an operation-scoped success signal. Fail-closed.
pub fn ask_create_marker(child: &str, nonce: &str) -> Result<String, BuildError> {
    Ok(format!(
        "ASK {{ GRAPH {g} {{ {s} {p} {n} }} }}",
        g = iri(child)?,
        s = iri_const(&s_record()),
        p = iri_const(&p_create_marker()),
        n = literal(nonce),
    ))
}

/// SELECT a resource's index-record metadata (content type, blob-key, ETag) from its graph.
pub fn select_meta(resource: &str) -> Result<String, BuildError> {
    Ok(format!(
        "SELECT ?ct ?bk ?etag WHERE {{ GRAPH {g} {{ \
            {s} {pct} ?ct ; {pbk} ?bk ; {pet} ?etag . }} }} LIMIT 1",
        g = iri(resource)?,
        s = iri_const(&s_record()),
        pct = iri_const(&p_content_type()),
        pbk = iri_const(&p_blob_key()),
        pet = iri_const(&p_etag()),
    ))
}

/// CONSTRUCT the resource's own RDF (everything in its graph EXCEPT the reserved index record).
pub fn construct_resource(resource: &str) -> Result<String, BuildError> {
    Ok(format!(
        "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH {g} {{ ?s ?p ?o . \
            FILTER (?s != {rec}) }} }}",
        g = iri(resource)?,
        rec = iri_const(&s_record()),
    ))
}

/// SELECT the direct children of a container (its `ldp:contains` members), held in the container's
/// own graph against the reserved record subject.
pub fn select_children(container: &str) -> Result<String, BuildError> {
    Ok(format!(
        "SELECT ?child WHERE {{ GRAPH {g} {{ {s} {p} ?child }} }}",
        g = iri(container)?,
        s = iri_const(&s_record()),
        p = iri_const(LDP_CONTAINS),
    ))
}

/// UPDATE: create-or-replace ONLY a resource's reserved index-record triples (content type, blob-key,
/// ETag) — leaving everything else in the graph (containment `ldp:contains` edges, the resource's own
/// RDF) untouched.
///
/// This must NOT `DROP` the whole graph: a container's graph also holds its `ldp:contains` edges, and
/// a resource's graph holds its user RDF, so a blanket drop would silently erase children / body
/// data on every metadata re-write (the bug roborev flagged). Instead it `DELETE`s only the three
/// reserved predicates hanging off the reserved record subject (each via an OPTIONAL-free
/// `DELETE WHERE`, idempotent on an absent record), then `INSERT DATA`s the new record. The three
/// `DELETE WHERE` + the `INSERT DATA` are submitted as ONE SPARQL update (`;`-separated), so they
/// commit atomically as a single generation on the server.
pub fn update_put_meta(
    resource: &str,
    content_type: &str,
    blob_key: &str,
    etag: &str,
) -> Result<String, BuildError> {
    let g = iri(resource)?;
    let s = iri_const(&s_record());
    let pct = iri_const(&p_content_type());
    let pbk = iri_const(&p_blob_key());
    let pet = iri_const(&p_etag());
    Ok(format!(
        "DELETE WHERE {{ GRAPH {g} {{ {s} {pct} ?oldCt }} }} ; \
         DELETE WHERE {{ GRAPH {g} {{ {s} {pbk} ?oldBk }} }} ; \
         DELETE WHERE {{ GRAPH {g} {{ {s} {pet} ?oldEt }} }} ; \
         INSERT DATA {{ GRAPH {g} {{ {s} {pct} {ct} ; {pbk} {bk} ; {pet} {et} . }} }}",
        g = g,
        s = s,
        pct = pct,
        ct = literal(content_type),
        pbk = pbk,
        bk = literal(blob_key),
        pet = pet,
        et = literal(etag),
    ))
}

/// UPDATE: ATOMICALLY create-or-replace a child record + its container-containment edge, guarded by a
/// `container`-EXISTS check — in ONE SPARQL `DELETE/INSERT … WHERE` update.
///
/// `DELETE/INSERT … WHERE` is a single atomic operation whose `WHERE` clause requires the container's
/// index record to be present; if it is absent the pattern yields no solution and **neither the
/// DELETE nor the INSERT runs** (the LDP layer maps "edge not present afterwards ⇒ container missing"
/// to a 404). When it matches:
/// - the DELETE clause first removes any PRE-EXISTING reserved record predicates of the child (so a
///   re-create — or a same-IRI race that already landed a record — leaves EXACTLY ONE
///   `contentType`/`blobKey`/`etag` triple, never an accumulation that would make
///   `select_meta(... LIMIT 1)` nondeterministic — the round-3 finding), and
/// - the INSERT clause writes the child's fresh record AND the `container ldp:contains child` edge
///   together — there is no window in which the edge exists without the child's metadata, mirroring
///   the in-memory atomic impl.
///
/// Because DELETE + INSERT share the SAME `WHERE` (container-EXISTS), the stale-record cleanup only
/// happens when the container actually exists — a create against a missing container touches nothing.
/// `OPTIONAL` binds the old values so the DELETE is a no-op when the child is genuinely new.
///
/// It ALSO writes a per-operation **create marker** (`createMarker <nonce>`) into the child graph in
/// the same atomic INSERT. The caller confirms success by ASKing for THAT exact nonce (via
/// [`ask_create_marker`]) — a signal no concurrent `remove_child`/sibling create ever touches — so the
/// confirm is immune to a containment-edge race between the update and the check.
///
/// The marker is **APPEND-ONLY**: it is NOT in the DELETE/OPTIONAL clause, so a concurrent same-child
/// create can never remove an earlier operation's marker (the round-5 finding — deleting all markers
/// let operation B clear operation A's nonce before A confirmed, giving A a false `NotFound`). Each
/// operation only ever ASKs for its OWN unique nonce, so leftover markers from other operations are
/// harmless; pruning them is a reconciler-GC concern (M3-next). Only the single-valued record
/// predicates (`contentType`/`blobKey`/`etag`) are DELETE-replaced (so `select_meta(... LIMIT 1)`
/// stays deterministic — the round-3 finding); the marker is purely additive.
pub fn update_create_child(
    container: &str,
    child: &str,
    content_type: &str,
    blob_key: &str,
    etag: &str,
    nonce: &str,
) -> Result<String, BuildError> {
    let cg = iri(child)?;
    let crec = iri_const(&s_record());
    let pct = iri_const(&p_content_type());
    let pbk = iri_const(&p_blob_key());
    let pet = iri_const(&p_etag());
    let pmark = iri_const(&p_create_marker());
    let pg = iri(container)?;
    let prec = iri_const(&s_record());
    let contains = iri_const(LDP_CONTAINS);
    let childi = iri(child)?;
    Ok(format!(
        "DELETE {{ \
            GRAPH {cg} {{ {crec} {pct} ?oldCt ; {pbk} ?oldBk ; {pet} ?oldEt . }} \
         }} INSERT {{ \
            GRAPH {cg} {{ {crec} {pct} {ct} ; {pbk} {bk} ; {pet} {et} ; {pmark} {nce} . }} \
            GRAPH {pg} {{ {prec} {contains} {childi} . }} \
         }} WHERE {{ \
            GRAPH {pg} {{ {prec} {pct} ?anyCt }} \
            OPTIONAL {{ GRAPH {cg} {{ {crec} {pct} ?oldCt }} }} \
            OPTIONAL {{ GRAPH {cg} {{ {crec} {pbk} ?oldBk }} }} \
            OPTIONAL {{ GRAPH {cg} {{ {crec} {pet} ?oldEt }} }} \
         }}",
        cg = cg,
        crec = crec,
        pct = pct,
        ct = literal(content_type),
        pbk = pbk,
        bk = literal(blob_key),
        pet = pet,
        et = literal(etag),
        pmark = pmark,
        nce = literal(nonce),
        pg = pg,
        prec = prec,
        contains = contains,
        childi = childi,
    ))
}

/// Whether an IRI is a RESERVED metadata term this server owns within a resource's graph: the index
/// record subject (`urn:pss:index#record`) or any `urn:pss:index#` predicate. Body RDF must never
/// write these, else untrusted data could corrupt/spoof the index records that share the graph.
fn is_reserved_term(value: &str) -> bool {
    value == s_record() || value.starts_with(PSS_NS)
}

/// UPDATE: insert a resource's parsed body triples (already validated RDF) into its graph, as one
/// `INSERT DATA` block. Each term is rendered through the safe (fallible) builders — an
/// IRIREF-invalid subject/predicate/object IRI is rejected. Empty input ⇒ `Ok("")` (the caller skips
/// the request).
///
/// A body triple whose subject/predicate (or an IRI object) touches a RESERVED metadata term — the
/// `urn:pss:index#record` subject or a `urn:pss:index#` predicate — is REJECTED with
/// [`BuildError::ReservedTermCollision`]. The resource's RDF and its index records share ONE named
/// graph (the single-graph model), so without this guard untrusted body data could overwrite/spoof
/// the index record (or be silently deleted by `put_meta` / hidden from `construct_resource`). Fail
/// closed: a colliding triple aborts the whole insert.
pub fn insert_body_data(
    resource: &str,
    ntriples_lines: &[(String, String, BodyObject)],
) -> Result<String, BuildError> {
    if ntriples_lines.is_empty() {
        return Ok(String::new());
    }
    let g = iri(resource)?;
    let mut body = String::new();
    for (s, p, o) in ntriples_lines {
        // Reject any triple touching the reserved metadata terms (subject, predicate, or an IRI
        // object that names a reserved term).
        if is_reserved_term(s) || is_reserved_term(p) || o.touches_reserved_term() {
            return Err(BuildError::ReservedTermCollision);
        }
        body.push_str(&iri(s)?);
        body.push(' ');
        body.push_str(&iri(p)?);
        body.push(' ');
        body.push_str(&o.render()?);
        body.push_str(" . ");
    }
    Ok(format!("INSERT DATA {{ GRAPH {g} {{ {body} }} }}", g = g))
}

/// UPDATE: drop a resource's whole graph (its index record + RDF) — the DELETE byte-pointer lookup
/// happens first via [`select_meta`]. `DROP SILENT` is idempotent on an absent graph.
///
/// For a CONTAINER target this is also what clears the container's `ldp:contains` set: the container's
/// own named graph holds both its index record and its containment edges, so dropping the graph
/// removes the (by-then-empty, per the handler's empty-container precondition) membership too. The
/// container's edge in its PARENT's graph is detached separately by [`update_remove_child`].
pub fn update_delete_resource(resource: &str) -> Result<String, BuildError> {
    Ok(format!("DROP SILENT GRAPH {g}", g = iri(resource)?))
}

/// UPDATE: ATOMICALLY delete a container's whole graph ONLY IF it exists AND is empty (no
/// `ldp:contains` member), writing a per-operation **delete marker** into a SEPARATE scratch graph in
/// the SAME atomic update IFF the guard matched — so the caller can confirm the outcome race-free.
///
/// This is ONE SPARQL update (`;`-joined) that commits as a single generation, so the empty-check and
/// the delete cannot be split by a concurrent `create_child`:
/// - The first statement is a `DELETE { GRAPH <g> { ?s ?p ?o } } WHERE { GRAPH <g> { ?s ?p ?o }
///   GRAPH <g> { <record> contentType ?anyCt }  FILTER NOT EXISTS { GRAPH <g> { <record> contains
///   ?c } } }` — it removes EVERY triple of the container's graph (its index record; an empty
///   container holds no other reserved triples) ONLY when the record EXISTS (the container-exists
///   guard) AND there is NO `ldp:contains` member (the empty guard). A non-empty or absent container ⇒
///   the WHERE yields no solution ⇒ nothing is deleted (the safety invariant: a non-empty container is
///   NEVER deleted).
/// - The second statement writes `<g> <deleteMarker> "nonce"` into the reserved `deleteMarkers`
///   scratch graph under the SAME empty+exists guard, so the marker is present **iff** the delete
///   actually ran. The caller ASKs for THIS nonce ([`ask_delete_marker`]) to learn `Deleted`; its
///   absence + an [`ask_exists`] check splits `NotEmpty` (record still present) from `NotFound` (record
///   absent). The marker is in a distinct graph, so the graph-emptying DELETE never removes it.
///
/// The marker graph is NEVER a resource graph, so this can't collide with user data; the IRI builders
/// reject any IRIREF-invalid container, fail-closed.
pub fn update_delete_container_if_empty(
    container: &str,
    nonce: &str,
) -> Result<String, BuildError> {
    let g = iri(container)?;
    let rec = iri_const(&s_record());
    let pct = iri_const(&p_content_type());
    let contains = iri_const(LDP_CONTAINS);
    let mg = iri_const(&g_delete_markers());
    let pmark = iri_const(&p_delete_marker());
    // ONE `;`-joined update; both statements share the SAME EXISTS+empty guard. (1) conditionally
    // empties the container's graph (record only — an empty container holds no other triples); (2)
    // writes this op's delete marker into the separate scratch graph under the same guard. NO `//`
    // line comments here — this string is sent verbatim to the SPARQL endpoint.
    Ok(format!(
        "DELETE {{ GRAPH {g} {{ ?s ?p ?o }} }} WHERE {{ \
            GRAPH {g} {{ ?s ?p ?o }} \
            GRAPH {g} {{ {rec} {pct} ?anyCt }} \
            FILTER NOT EXISTS {{ GRAPH {g} {{ {rec} {contains} ?anyChild }} }} \
         }} ; \
         INSERT {{ GRAPH {mg} {{ {g} {pmark} {nce} }} }} WHERE {{ \
            GRAPH {g} {{ {rec} {pct} ?anyCt2 }} \
            FILTER NOT EXISTS {{ GRAPH {g} {{ {rec} {contains} ?anyChild2 }} }} \
         }}",
        g = g,
        rec = rec,
        pct = pct,
        contains = contains,
        mg = mg,
        pmark = pmark,
        nce = literal(nonce),
    ))
}

/// ASK whether a per-operation delete marker for `container` with `nonce` is present in the reserved
/// scratch graph — the race-resistant "the empty+exists guard matched, so the delete ran" confirm.
/// No other operation ever writes or removes THIS nonce, so a concurrent containment mutation cannot
/// flip the result. Fail-closed.
pub fn ask_delete_marker(container: &str, nonce: &str) -> Result<String, BuildError> {
    Ok(format!(
        "ASK {{ GRAPH {mg} {{ {g} {p} {n} }} }}",
        mg = iri_const(&g_delete_markers()),
        g = iri(container)?,
        p = iri_const(&p_delete_marker()),
        n = literal(nonce),
    ))
}

/// UPDATE: remove a `container ldp:contains child` edge (idempotent — a `DELETE WHERE` of an absent
/// edge is a no-op).
pub fn update_remove_child(container: &str, child: &str) -> Result<String, BuildError> {
    Ok(format!(
        "DELETE WHERE {{ GRAPH {pg} {{ {prec} {contains} {childi} }} }}",
        pg = iri(container)?,
        prec = iri_const(&s_record()),
        contains = iri_const(LDP_CONTAINS),
        childi = iri(child)?,
    ))
}

/// An object position for [`insert_body_data`]: either an IRI/bnode node or a literal (with its
/// datatype/lang preserved). Rendered through the safe builders so untrusted RDF cannot inject.
#[derive(Debug, Clone)]
pub enum BodyObject {
    /// A named node (IRI).
    Iri(String),
    /// A blank node, by label (rendered `_:label` with the label sanitised to bnode-safe chars).
    Blank(String),
    /// A plain `xsd:string` (or implicitly-typed) literal.
    PlainLiteral(String),
    /// A language-tagged literal: (lexical, lang).
    LangLiteral(String, String),
    /// A typed literal: (lexical, datatype IRI).
    TypedLiteral(String, String),
}

impl BodyObject {
    /// Whether this object (when an IRI / datatype-IRI) names a reserved metadata term.
    fn touches_reserved_term(&self) -> bool {
        match self {
            BodyObject::Iri(v) => is_reserved_term(v),
            BodyObject::TypedLiteral(_, dt) => is_reserved_term(dt),
            _ => false,
        }
    }

    /// Render this object term safely. Fallible because an IRI / datatype-IRI that is not a valid
    /// IRIREF is rejected (never escaped-and-aliased), and a malformed language tag is rejected
    /// (never silently rewritten — fail-closed).
    pub fn render(&self) -> Result<String, BuildError> {
        Ok(match self {
            BodyObject::Iri(v) => iri(v)?,
            BodyObject::Blank(label) => render_bnode(label),
            BodyObject::PlainLiteral(v) => literal(v),
            BodyObject::LangLiteral(v, lang) => {
                format!("{}@{}", literal(v), validate_lang(lang)?)
            }
            BodyObject::TypedLiteral(v, dt) => format!("{}^^{}", literal(v), iri(dt)?),
        })
    }
}

/// Render a blank-node label as a SPARQL `BLANK_NODE_LABEL` using an INJECTIVE, grammar-safe
/// encoding: ONLY `[A-Za-z0-9]` pass through; EVERY other byte (including `-`, `.`, `_`) is hex-escaped
/// as `_xXX_`. Escaping `-`/`.`/`_` too (not just the unsafe ones) keeps the encoding both injective
/// (distinct labels never collapse — the round-3 finding) AND always-grammar-valid in EVERY position,
/// so it can never emit an illegal leading/trailing `-`/`.` (the round-4 finding: a SPARQL bnode label
/// may not end with `.`). The fixed `b` prefix keeps the first char legal. The output is always a
/// single well-formed `_:...` token, so it cannot inject.
fn render_bnode(label: &str) -> String {
    let mut out = String::with_capacity(label.len() + 3);
    out.push_str("_:b"); // fixed prefix: a grammar-legal leading label char
    for &byte in label.as_bytes() {
        if byte.is_ascii_alphanumeric() {
            out.push(byte as char);
        } else {
            // `_xXX_` — the `_` introducer + 2 hex + `_` closer keeps the run grammar-internal (the
            // trailing `_` is a legal interior PN_CHARS char and never a `.`/`-`), so no position is
            // ever invalid.
            out.push_str("_x");
            out.push(nibble_hex(byte >> 4));
            out.push(nibble_hex(byte & 0x0f));
            out.push('_');
        }
    }
    out
}

/// VALIDATE a language tag against the SPARQL `LANGTAG` grammar
/// (`'@' [a-zA-Z]+ ('-' [a-zA-Z0-9]+)*`) and return it unchanged, or [`BuildError::InvalidLangTag`].
///
/// The shape (NOT merely "alphanumeric + hyphen"): an ALPHABETIC primary subtag of length ≥ 1,
/// followed by zero or more `-`-separated subtags each of length ≥ 1 and alphanumeric. So `en`,
/// `en-US`, `zh-Hans-CN` pass; `1`/`1x` (non-alpha primary), `en-` (empty trailing subtag),
/// `en--US` (empty interior subtag), `` (empty) are REJECTED. Fail-CLOSED: a malformed tag is
/// refused, never silently rewritten (the round-6 finding) and never emits invalid query text.
fn validate_lang(lang: &str) -> Result<&str, BuildError> {
    let mut subtags = lang.split('-');
    // Primary subtag: alphabetic, non-empty.
    match subtags.next() {
        Some(primary)
            if !primary.is_empty() && primary.chars().all(|c| c.is_ascii_alphabetic()) => {}
        _ => return Err(BuildError::InvalidLangTag),
    }
    // Each remaining subtag: alphanumeric, non-empty.
    for sub in subtags {
        if sub.is_empty() || !sub.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(BuildError::InvalidLangTag);
        }
    }
    Ok(lang)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iri_rejects_injection_delimiters() {
        // A crafted IRI trying to break out of the `<...>` term must be REJECTED (not escaped), so it
        // can never alias another IRI nor inject.
        let attack = "http://e/x> } ; DROP GRAPH <http://victim> ; INSERT DATA { GRAPH <http://e/x";
        assert_eq!(iri(attack), Err(BuildError::InvalidIri));
        // A clean IRI is wrapped verbatim.
        assert_eq!(iri("http://e/a").unwrap(), "<http://e/a>");
    }

    #[test]
    fn iri_rejects_control_and_space() {
        assert_eq!(iri("http://e/a b"), Err(BuildError::InvalidIri)); // space
        assert_eq!(iri("http://e/a\nc"), Err(BuildError::InvalidIri)); // control
        assert_eq!(iri("http://e/a\\b"), Err(BuildError::InvalidIri)); // backslash
    }

    #[test]
    fn iri_is_injective_no_aliasing() {
        // A raw `>` is rejected; a literal `%3E` is a DISTINCT, valid IRI that passes through verbatim
        // — so the two can never alias (the round-4 finding: percent-escaping would collapse them).
        assert_eq!(iri("http://e/a>b"), Err(BuildError::InvalidIri));
        assert_eq!(iri("http://e/a%3Eb").unwrap(), "<http://e/a%3Eb>");
    }

    #[test]
    fn literal_escapes_quote_and_backslash_and_newlines() {
        let attack = "x\" . } ; DROP GRAPH <http://victim> ; INSERT { \"";
        let rendered = literal(attack);
        assert!(rendered.starts_with('"') && rendered.ends_with('"'));
        assert!(rendered.contains("\\\""), "inner quote escaped: {rendered}");
        // The breakout invariant: in the INTERIOR (between the delimiting quotes), every `"` is
        // escaped — i.e. there is NO unescaped `"` that could close the literal early.
        let interior = &rendered[1..rendered.len() - 1];
        let bytes = interior.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'"' {
                assert!(
                    i > 0 && bytes[i - 1] == b'\\',
                    "an unescaped quote at interior byte {i} could break out: {rendered}"
                );
            }
        }
        let nl = literal("a\nb\\c");
        assert!(nl.contains("\\n") && nl.contains("\\\\"));
        assert!(!nl.contains('\n'));
    }

    #[test]
    fn builders_wrap_every_untrusted_value() {
        // The container-exists-guarded create: the child IRI + literals are all bracketed/quoted.
        let q = update_create_child(
            "http://pod/c/",
            "http://pod/c/note",
            "text/turtle",
            "blob-key",
            "\"etag\"",
            "op-1",
        )
        .unwrap();
        assert!(q.contains("INSERT {"));
        assert!(q.contains("WHERE {"));
        assert!(q.contains(&iri_const(LDP_CONTAINS)));
        // The user-controlled etag literal "\"etag\"" must be escaped inside one literal.
        assert!(q.contains("\\\"etag\\\""), "etag escaped: {q}");
    }

    #[test]
    fn create_child_rejects_an_invalid_child_iri() {
        // An IRIREF-invalid child IRI is rejected, fail-closed (never escaped-and-aliased).
        let r = update_create_child(
            "http://pod/c/",
            "http://pod/c/no te", // a space — invalid IRIREF
            "text/turtle",
            "bk",
            "\"e\"",
            "op-1",
        );
        assert_eq!(r, Err(BuildError::InvalidIri));
    }

    #[test]
    fn put_meta_does_not_drop_the_whole_graph() {
        // The metadata re-write must DELETE only the three reserved record predicates, never the
        // whole graph (which would erase containment edges + user RDF — the roborev finding).
        let q = update_put_meta("http://pod/c/", "text/turtle", "bk", "\"e\"").unwrap();
        assert!(!q.contains("DROP"), "must not DROP the graph: {q}");
        // It targets exactly the three reserved predicates for deletion, then re-inserts.
        assert_eq!(
            q.matches("DELETE WHERE").count(),
            3,
            "three targeted deletes: {q}"
        );
        assert!(q.contains("INSERT DATA"));
        assert!(q.contains(&iri_const(&p_content_type())));
        assert!(q.contains(&iri_const(&p_blob_key())));
        assert!(q.contains(&iri_const(&p_etag())));
        // It must NOT mention ldp:contains (it leaves containment untouched).
        assert!(
            !q.contains(LDP_CONTAINS),
            "put_meta must not touch containment: {q}"
        );
    }

    #[test]
    fn ask_contains_edge_targets_the_exact_edge() {
        let q = ask_contains_edge("http://pod/c/", "http://pod/c/note").unwrap();
        assert!(q.starts_with("ASK"));
        assert!(q.contains(&iri_const("http://pod/c/")));
        assert!(q.contains(&iri_const(LDP_CONTAINS)));
        assert!(q.contains(&iri_const("http://pod/c/note")));
    }

    #[test]
    fn ask_create_marker_targets_the_nonce() {
        let q = ask_create_marker("http://pod/c/note", "op-abc").unwrap();
        assert!(q.starts_with("ASK"));
        assert!(q.contains(&iri_const(&p_create_marker())));
        assert!(q.contains("\"op-abc\""), "nonce as a literal: {q}");
    }

    #[test]
    fn body_object_renders_each_term_safely() {
        assert_eq!(
            BodyObject::Iri("http://e/a".into()).render().unwrap(),
            "<http://e/a>"
        );
        assert_eq!(
            BodyObject::PlainLiteral("a\"b".into()).render().unwrap(),
            "\"a\\\"b\""
        );
        assert_eq!(
            BodyObject::LangLiteral("hi".into(), "en-US".into())
                .render()
                .unwrap(),
            "\"hi\"@en-US"
        );
        assert_eq!(
            BodyObject::TypedLiteral(
                "5".into(),
                "http://www.w3.org/2001/XMLSchema#integer".into()
            )
            .render()
            .unwrap(),
            "\"5\"^^<http://www.w3.org/2001/XMLSchema#integer>"
        );
        // A crafted lang tag is REJECTED fail-closed (never silently rewritten).
        assert_eq!(
            BodyObject::LangLiteral("x".into(), "en> } DROP".into()).render(),
            Err(BuildError::InvalidLangTag)
        );
        // An empty lang tag is rejected too (would otherwise emit invalid `"x"@`).
        assert_eq!(
            BodyObject::LangLiteral("x".into(), "".into()).render(),
            Err(BuildError::InvalidLangTag)
        );
        // An IRIREF-invalid object IRI / datatype IRI is rejected.
        assert_eq!(
            BodyObject::Iri("http://e/a>b".into()).render(),
            Err(BuildError::InvalidIri)
        );
        // A crafted bnode label is INJECTIVELY encoded (every non-alphanumeric byte hex-escaped
        // `_xXX_`), never lossily stripped + always grammar-valid (no trailing `.`/`-`).
        // `a b> .` => b + a + _x20_ (space) + b + _x3E_ ('>') + _x20_ (space) + _x2E_ ('.').
        assert_eq!(
            BodyObject::Blank("a b> .".into()).render().unwrap(),
            "_:ba_x20_b_x3E__x20__x2E_"
        );
    }

    #[test]
    fn render_bnode_is_injective_and_always_valid() {
        // Distinct labels the OLD lossy filter would have collapsed must now differ.
        let a = BodyObject::Blank("a b".into()).render().unwrap();
        let b = BodyObject::Blank("ab".into()).render().unwrap();
        assert_ne!(a, b, "distinct labels must not collapse: {a} vs {b}");
        // A label ending in `.` must NOT produce an invalid trailing-dot bnode (round-4 finding):
        // the `.` is hex-escaped, so the last char is the `_` closer (a legal interior char).
        let trailing_dot = BodyObject::Blank("foo.".into()).render().unwrap();
        assert!(
            !trailing_dot.ends_with('.'),
            "no invalid trailing dot: {trailing_dot}"
        );
        assert_eq!(trailing_dot, "_:bfoo_x2E_");
        // An all-unsafe label still yields a well-formed, non-empty bnode.
        let weird = BodyObject::Blank("> } .".into()).render().unwrap();
        assert!(weird.starts_with("_:b"));
        assert!(!weird.contains(' ') && !weird.contains('>') && !weird.contains('}'));
    }

    #[test]
    fn create_child_atomically_replaces_a_stale_child_record() {
        // The guarded create must DELETE any pre-existing child reserved-record predicates (incl. the
        // marker) before INSERTing, so a re-create can't accumulate duplicate metadata.
        let q = update_create_child(
            "http://pod/c/",
            "http://pod/c/note",
            "text/turtle",
            "bk",
            "\"e\"",
            "op-1",
        )
        .unwrap();
        assert!(
            q.starts_with("DELETE {"),
            "must DELETE stale child record first: {q}"
        );
        assert!(q.contains("INSERT {"));
        assert!(q.contains("WHERE {"));
        assert!(q.contains("OPTIONAL"), "old values bound via OPTIONAL: {q}");
        assert!(q.contains(&iri_const(LDP_CONTAINS)));
        // The per-operation marker (nonce) is written + its predicate referenced.
        assert!(q.contains(&iri_const(&p_create_marker())));
        assert!(q.contains("\"op-1\""), "marker nonce literal present: {q}");
        // The marker is APPEND-ONLY: it must NOT appear in the DELETE block (round-5 finding — a
        // concurrent same-child create deleting markers could clear another op's nonce). Split at
        // INSERT and assert the marker predicate is only in the INSERT half, never the DELETE half.
        let delete_block = q.split("INSERT {").next().unwrap();
        assert!(
            !delete_block.contains(&iri_const(&p_create_marker())),
            "marker must not be in the DELETE block (append-only): {q}"
        );
    }

    #[test]
    fn delete_container_if_empty_is_one_guarded_atomic_update() {
        // The conditional delete must be a SINGLE `;`-joined update: (1) empty the graph only when it
        // EXISTS (a record contentType) AND has NO `ldp:contains` member (FILTER NOT EXISTS), and (2)
        // write the per-op delete marker under the SAME guard. The marker keeps the confirm race-free.
        let q = update_delete_container_if_empty("http://pod/c/", "op-7").unwrap();
        assert!(
            q.starts_with("DELETE {"),
            "starts with the guarded delete: {q}"
        );
        // The empty guard + the exists guard are both present.
        assert!(q.contains("FILTER NOT EXISTS"), "empty guard present: {q}");
        assert!(
            q.contains(LDP_CONTAINS),
            "empty guard targets ldp:contains: {q}"
        );
        assert!(
            q.contains(&iri_const(&p_content_type())),
            "exists guard present: {q}"
        );
        // The two statements are `;`-joined (one atomic update) and the second writes the marker.
        assert!(q.contains(" ; "), "two `;`-joined statements: {q}");
        assert!(
            q.contains(&iri_const(&p_delete_marker())),
            "marker predicate present: {q}"
        );
        assert!(
            q.contains(&iri_const(&g_delete_markers())),
            "marker scratch graph present: {q}"
        );
        assert!(q.contains("\"op-7\""), "the op nonce is a literal: {q}");
        // It must NOT use a blanket DROP (which would unconditionally erase a non-empty container).
        assert!(!q.contains("DROP"), "must not blanket-DROP the graph: {q}");
        // No `//`-style line comment leaked into the query text (the IRIs legitimately contain `//`,
        // so check for a comment introducer — `//` followed by a space — which only a stray comment
        // would produce; an IRI's `//` is always followed by a host character, never a space).
        assert!(
            !q.contains("// "),
            "no `//`-comment markers in the query text: {q}"
        );
    }

    #[test]
    fn delete_container_if_empty_rejects_an_invalid_container_iri() {
        // An IRIREF-invalid container IRI is rejected fail-closed (never escaped-and-aliased), so an
        // injection can never reach the endpoint.
        assert_eq!(
            update_delete_container_if_empty("http://pod/c d/", "op-1"),
            Err(BuildError::InvalidIri)
        );
    }

    #[test]
    fn ask_delete_marker_targets_the_scratch_graph_subject_and_nonce() {
        let q = ask_delete_marker("http://pod/c/", "op-abc").unwrap();
        assert!(q.starts_with("ASK"));
        assert!(
            q.contains(&iri_const(&g_delete_markers())),
            "scratch graph: {q}"
        );
        assert!(
            q.contains(&iri_const("http://pod/c/")),
            "container subject: {q}"
        );
        assert!(
            q.contains(&iri_const(&p_delete_marker())),
            "marker predicate: {q}"
        );
        assert!(q.contains("\"op-abc\""), "nonce as a literal: {q}");
    }

    #[test]
    fn insert_body_data_is_empty_for_no_triples() {
        assert_eq!(insert_body_data("http://e/r", &[]).unwrap(), "");
    }

    #[test]
    fn insert_body_data_rejects_an_invalid_iri() {
        let triples = vec![(
            "http://e/s".to_string(),
            "http://e/p".to_string(),
            BodyObject::Iri("http://e/o>x".into()),
        )];
        assert_eq!(
            insert_body_data("http://e/r", &triples),
            Err(BuildError::InvalidIri)
        );
    }

    #[test]
    fn insert_body_data_rejects_reserved_term_collisions() {
        // A body triple touching the reserved record subject, a `pss:` predicate, or a `pss:` IRI
        // object is rejected — untrusted RDF must not corrupt/spoof the index records that share the
        // resource's graph (the round-6 finding).
        let res = "http://e/r";
        // reserved subject
        let s = vec![(
            s_record(),
            "http://e/p".to_string(),
            BodyObject::PlainLiteral("x".into()),
        )];
        assert_eq!(
            insert_body_data(res, &s),
            Err(BuildError::ReservedTermCollision)
        );
        // reserved predicate
        let p = vec![(
            "http://e/s".to_string(),
            p_content_type(),
            BodyObject::PlainLiteral("x".into()),
        )];
        assert_eq!(
            insert_body_data(res, &p),
            Err(BuildError::ReservedTermCollision)
        );
        // reserved IRI object
        let o = vec![(
            "http://e/s".to_string(),
            "http://e/p".to_string(),
            BodyObject::Iri(s_record()),
        )];
        assert_eq!(
            insert_body_data(res, &o),
            Err(BuildError::ReservedTermCollision)
        );
        // a clean triple is fine.
        let ok = vec![(
            "http://e/s".to_string(),
            "http://e/p".to_string(),
            BodyObject::PlainLiteral("x".into()),
        )];
        assert!(insert_body_data(res, &ok).is_ok());
    }

    #[test]
    fn lang_tag_is_validated_fail_closed() {
        // Valid per the SPARQL LANGTAG grammar.
        assert_eq!(validate_lang("en"), Ok("en"));
        assert_eq!(validate_lang("en-US"), Ok("en-US"));
        assert_eq!(validate_lang("zh-Hans-CN"), Ok("zh-Hans-CN"));
        // Invalid: empty, whitespace/forbidden char, non-alpha primary, empty trailing/interior
        // subtag — all rejected fail-closed (round-7 finding).
        assert_eq!(validate_lang(""), Err(BuildError::InvalidLangTag));
        assert_eq!(validate_lang("en US"), Err(BuildError::InvalidLangTag));
        assert_eq!(validate_lang("en>"), Err(BuildError::InvalidLangTag));
        assert_eq!(validate_lang("1"), Err(BuildError::InvalidLangTag));
        assert_eq!(validate_lang("1x"), Err(BuildError::InvalidLangTag));
        assert_eq!(validate_lang("en-"), Err(BuildError::InvalidLangTag));
        assert_eq!(validate_lang("en--US"), Err(BuildError::InvalidLangTag));
        assert_eq!(validate_lang("-en"), Err(BuildError::InvalidLangTag));
    }
}
