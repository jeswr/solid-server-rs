# solid-server-rs

> ## ⚠️ EXPERIMENTAL — NOT a production server
>
> This is an **experimental, parallel-track** Rust reimplementation of a Solid/LDP server. It
> **does NOT replace** and must **NEVER touch** the production TypeScript server
> [`prod-solid-server`](https://github.com/jeswr/prod-solid-server) — that remains the live,
> supported, conformance-tested, compliance-audited server. This crate is a research vehicle for the
> [Rust-migration spike](https://github.com/jeswr/prod-solid-server/blob/main/docs/spikes/rust-migration-spike.md)
> (which recommends **against** a full rewrite today and instead funds bounded carve-outs). Do not
> deploy this. Do not point real pods at it.

A from-scratch Rust Solid server skeleton on **axum** (hyper 1.x + tokio), with DPoP-bound
Solid-OIDC auth **delegated** to the standalone
[`solid-oidc-verifier`](https://github.com/jeswr/solid-oidc-verifier) crate.

## Architecture (the maintainer's directive + the spike)

```
client (DPoP) → axum (rustls/aws-lc-rs)
                 │
                 ▼
   auth middleware ── delegates to ──▶ solid-oidc-verifier  (DPoP/Solid-OIDC; NOT reimplemented)
                 │                      (git dependency; verifies at+jwt + DPoP proof, fail-closed)
                 ▼
   LDP handlers (GET / HEAD / PUT)
                 │
                 ▼
   Store trait ──┬──▶ SparqClient   ── SPARQ is AUTHORITATIVE for RDF data + metadata + (M2) ACL
                 │                      (queried over its HTTP API)
                 └──▶ BlobStore     ── object_store/S3 is BACKUP-ONLY for resource bytes
```

The two load-bearing architectural rules, straight from the directive:

1. **SPARQ is the authoritative source** for RDF data, metadata, containment, and (M2) access-control
   evaluation — queried over its HTTP API behind the [`SparqClient`](src/store/sparq.rs) trait.
2. **`object_store`/S3 is backup-only** for resource bytes — behind the
   [`BlobStore`](src/store/blob.rs) trait.

Auth is **not reimplemented here**: token + DPoP-proof verification is delegated wholesale to
`solid-oidc-verifier` (consumed as a `git` dependency), using its `JwksProvider` / `ReplayStore`
trait seams. This crate only adapts HTTP requests to/from the verifier.

## What's in this slice (M1)

A coherent, compiling vertical slice with clean trait seams and unit tests:

- An **axum server skeleton** ([`src/main.rs`](src/main.rs), [`src/app.rs`](src/app.rs)) that boots
  (rustls/aws-lc-rs crypto provider installed; plain-TCP listener in M1, TLS termination is M2).
- **DPoP-bound auth middleware** ([`src/auth.rs`](src/auth.rs)) that calls the verifier on every
  request and either injects the verified caller identity or returns the verifier's own 401/503 +
  `WWW-Authenticate` challenge unchanged.
- A **minimal LDP path** — GET / HEAD / PUT on a single resource ([`src/ldp/`](src/ldp/)) over a
  [`Store`](src/store/mod.rs) trait whose composite impl reads/writes metadata via SPARQ
  (authoritative) and bytes via `object_store` (backup). Each seam has an **in-memory test double**,
  so the whole stack runs without a SPARQ / S3 / IdP. **Writes fail closed**: with no ACL engine yet
  (M2), a PUT from a public/unauthenticated caller is rejected (403) rather than allowed.
- **LDP target/URL parsing** ([`src/ldp/target.rs`](src/ldp/target.rs)) and **Turtle / JSON-LD**
  content-type handling + RDF validation via `oxttl` / `oxjsonld` ([`src/ldp/content.rs`](src/ldp/content.rs)).
- **Unit + end-to-end tests** for the auth middleware (valid / invalid / missing / replayed token
  via the verifier), LDP target parsing, the Store trait against the in-memory impl, content-type
  handling, and the full PUT→GET HTTP path.

### Deferred to later slices (`// M2:`-marked seams in the code)

Full WAC evaluation, the rest of the LDP verb set (POST / DELETE / PATCH / Range / conditional /
full conneg), notifications (WebSocketChannel2023), the reconciler, TLS termination, the
**live SPARQ HTTP client** (needs a running SPARQ instance — an integration test), and **live JWKS**
(needs the verifier's M2 network adapters). The code carries `M2:` seam comments where each plugs in.

## Build & run

Requires a recent stable Rust toolchain and a C toolchain (`cmake`) for `aws-lc-rs`.

```bash
cargo build                 # compile
cargo test                  # run the unit + e2e tests (no SPARQ/S3/IdP needed)
cargo run                   # boot the experimental server (defaults to 127.0.0.1:3000)

# configurable via env:
SOLID_SERVER_BIND=127.0.0.1:3000 \
SOLID_SERVER_BASE_URL=http://localhost:3000 \
SOLID_SERVER_TRUSTED_ISSUER=https://idp.example/realms/solid \
  cargo run
```

The M1 server boots with in-memory storage and a static (empty) JWKS, so an authenticated request
needs a token whose issuer key is registered in the JWKS provider — see the tests
([`tests/`](tests/)) for how tokens + DPoP proofs are minted and verified end-to-end.

## Gate

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build
```

`cargo-deny` ([`deny.toml`](deny.toml)) governs the supply chain (advisories / licenses / sources).
Cargo has no install-time hooks, but `build.rs` + proc-macros run code at *build* time, so this is
not "supply-chain solved" — `cargo-deny` is the governance for that build-time surface.

## Security & provenance

- `#![forbid(unsafe_code)]` crate-wide.
- Auth is delegated to the security-reviewed `solid-oidc-verifier` (asymmetric-only, fail-closed,
  proof-of-possession, issuer-agnostic). **Known narrowing: ES512** is rejected (the verifier's
  `jsonwebtoken` primitive cannot verify it) rather than silently accepted — a maintainer decision.
- TLS is `rustls` on the `aws-lc-rs` backend (FIPS-capable; the CMVP cert/version must be verified
  before any "FIPS-approved" claim).
- Every commit is auto-reviewed by **roborev** (codex, a non-Anthropic model — see `.roborev.toml`).
- Authored by **Claude Opus 4.8**; new source files carry an `// AUTHORED-BY Claude Opus 4.8` marker.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
