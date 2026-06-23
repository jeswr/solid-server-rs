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
   LDP handlers (GET / HEAD / PUT / POST / DELETE / PATCH)
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
`solid-oidc-verifier` (consumed as a `git` dependency), using its `JwksProvider` / `WebIdResolver` /
`ReplayStore` trait seams. This crate only adapts HTTP requests to/from the verifier. The binary
wires the verifier's **network adapters** (the `network` feature) so verification is REAL: OIDC
discovery + JWKS fetch (`NetworkJwksProvider`) and the bidirectional WebID↔issuer check
(`NetworkWebIdResolver`) both run over the verifier's DNS-pinned, SSRF-guarded `SafeFetcher`. Unit
tests still drive the verification core through the in-memory test doubles.

## What's in this slice

A coherent, compiling vertical slice with clean trait seams and unit tests:

- An **axum server skeleton** ([`src/main.rs`](src/main.rs), [`src/app.rs`](src/app.rs)) that boots
  (rustls/aws-lc-rs crypto provider installed; plain-TCP listener for now, TLS termination is later).
- **DPoP-bound auth middleware** ([`src/auth.rs`](src/auth.rs)) that calls the verifier on every
  request and either injects the verified caller identity or returns the verifier's own 401/503 +
  `WWW-Authenticate` challenge unchanged.
- **The LDP verb surface** ([`src/ldp/`](src/ldp/)) over a [`Store`](src/store/mod.rs) trait whose
  composite impl reads/writes metadata via SPARQ (authoritative) and bytes via `object_store`
  (backup). Each seam has an **in-memory test double**, so the whole stack runs without a SPARQ / S3
  / IdP:
  - **GET / HEAD** with `Accept`-driven **content negotiation** (Turtle ↔ JSON-LD re-serialisation)
    and single-range **`Range: bytes=…`** support (206 + `Content-Range`, 416 when unsatisfiable).
  - **PUT** (create-or-replace) and **POST** (create a child in a container — honours `Slug`, mints
    a server URI otherwise, 201 + `Location`; 409 on POST to a non-container).
  - **DELETE** of a resource OR a container (404 on a missing target; `If-Match` honoured). A
    container is deletable **only when empty** — a non-empty container is a **409 Conflict**, not a
    cascade. This is the conservative LDP-permitted spec choice (LDP §5.2.5.1; matches CSS's default)
    and avoids one request silently destroying an arbitrary subtree. Deleting an empty container
    removes its own record + its (empty) `ldp:contains` set and detaches it from its parent. A
    recursive/cascade delete is intentionally **not** offered.
  - **PATCH** — the Solid **N3 Patch** engine (`text/n3`, [`src/ldp/patch.rs`](src/ldp/patch.rs)):
    `solid:inserts` + `solid:deletes` plus the **`solid:where` variable solver** — a basic-graph-pattern
    matcher (conjunctive variable unification) over the target graph whose single binding instantiates
    the templates. Spec-faithful: a non-empty `where` MUST have exactly one solution (zero or multiple ⇒
    409), template variables MUST occur in `where` and templates MUST NOT contain blank nodes (422). A
    non-`text/n3` PATCH is a 415.
  - **Conditional requests** — strong `ETag` on responses; `If-Match` / `If-None-Match` honoured on
    PUT/PATCH/DELETE (412 on mismatch; `If-None-Match: *` create-guard) —
    [`src/ldp/conditional.rs`](src/ldp/conditional.rs).
  - **Writes fail closed**: with no ACL engine yet, a mutation from a public/unauthenticated caller
    is rejected (403) rather than allowed — the WAC decision plugs into that seam.
- **LDP target/URL parsing** ([`src/ldp/target.rs`](src/ldp/target.rs)) and **Turtle / JSON-LD**
  content handling, validation, re-serialisation + `Accept` negotiation via `oxttl` / `oxjsonld`
  ([`src/ldp/content.rs`](src/ldp/content.rs)).
- **Unit + end-to-end tests** for the auth middleware (valid / invalid / missing / replayed token
  via the verifier), LDP target parsing, the Store trait against the in-memory impl, content
  handling + negotiation, range + conditional logic, the N3-Patch engine, and the full HTTP path for
  every verb (happy + error cases).

### Deferred to later slices (`// M2-next:`-marked seams in the code)

Full **WAC authorization** evaluation (gated on `sparq#992` — the SPARQ access-control design),
**multipart Range**, **SPARQL-Update PATCH**, recursive/cascade container delete (deliberately not
offered — see DELETE above), notifications (WebSocketChannel2023), the reconciler, TLS termination
(the `rustls`/`aws-lc-rs` provider is installed; a config-gated TLS listener is the next slice —
terminate at a reverse proxy until then), and the **live SPARQ HTTP client + `object_store` blob
store** in the binary (the `HttpSparqClient` exists and is tested against a mock endpoint; the binary
still boots the in-memory store doubles — wiring it in needs a running SPARQ/S3 for the IT). Live
JWKS / WebID resolution are now **wired** (the verifier's network adapters). The code carries
seam comments where each remaining piece plugs in.

## Build & run

Requires a recent stable Rust toolchain and a C toolchain (`cmake`) for `aws-lc-rs`.

```bash
cargo build                 # compile
cargo test                  # run the unit + e2e tests (no SPARQ/S3/IdP needed)
cargo run                   # boot the experimental server (defaults to 127.0.0.1:3000)

# Configurable via env (the whole block below is one `\`-continued command, so it is copy-paste-safe
# — the per-variable notes are here, NOT inline after a trailing `\` where they would break it):
#   SOLID_SERVER_AUDIENCE             RFC 9068 `aud` (defaults to the base URL)
#   SOLID_SERVER_BIDIRECTIONAL        WebID<->issuer check: strict (default) | warn | off
#   SOLID_SERVER_JWKS_CACHE_TTL_SECS  JWKS cache TTL in seconds (default 300)
#   SOLID_SERVER_ALLOW_LOOPBACK       dev/IT ONLY: permit http:/loopback IdP+WebID (default 0)
#   SOLID_SERVER_TLS_CERT             PEM cert-chain file path; set WITH _TLS_KEY to terminate HTTPS
#   SOLID_SERVER_TLS_KEY              PEM private-key file path; set WITH _TLS_CERT (both-or-neither)
SOLID_SERVER_BIND=127.0.0.1:3000 \
SOLID_SERVER_BASE_URL=https://pod.example \
SOLID_SERVER_TRUSTED_ISSUER=https://idp.example/realms/solid \
SOLID_SERVER_AUDIENCE=https://pod.example \
SOLID_SERVER_BIDIRECTIONAL=strict \
SOLID_SERVER_JWKS_CACHE_TTL_SECS=300 \
SOLID_SERVER_ALLOW_LOOPBACK=0 \
  cargo run
```

### TLS termination (optional, config-gated)

By default the server serves plain HTTP and you terminate TLS at a reverse proxy. To terminate
HTTPS **in-process** (over the house rustls/aws-lc-rs stack via `axum-server`), set BOTH TLS env
vars to PEM file paths — a cert chain and a private key:

```bash
SOLID_SERVER_TLS_CERT=/etc/tls/fullchain.pem \
SOLID_SERVER_TLS_KEY=/etc/tls/privkey.pem \
SOLID_SERVER_BIND=0.0.0.0:443 \
  cargo run
```

It is **both-or-neither**: setting exactly one is a boot error (a half-configured TLS server is
never silently downgraded to plaintext), as is a missing / empty / malformed PEM file — each fails
fast with a clear message. No auto-cert / ACME this slice (a future seam: an ACME provider would
produce the same in-memory rustls config, addable behind a third env var without reshaping the
serve path); supply cert files yourself or front the server with a proxy that does ACME.

### Horizontal scaling — the distributed Redis DPoP-`jti` replay store (opt-in)

The default DPoP-`jti` replay store is **per-instance** (an in-memory set): correct for a single
node, but if the server is scaled horizontally behind a load balancer, a `jti` consumed on instance
A is invisible to instance B, so a captured DPoP proof could be replayed against a different instance
within its freshness window. The fix is a **shared** replay set in Redis (`SET NX PX` — an atomic
one-round-trip check-and-set: the `NX` reply IS the New/Replay signal). It is behind the opt-in
`redis-replay` build feature (so the default build, tests, and conformance carry no Redis dependency
and are byte-identical), selected at runtime by a Redis URL:

```bash
cargo build --features redis-replay
SOLID_SERVER_REPLAY_REDIS_URL=redis://redis:6379 \
SOLID_SERVER_BIND=0.0.0.0:3000 \
  ./target/release/solid-server-rs --features redis-replay   # (build with the feature; run normally)
```

ALL instances behind the load balancer MUST point at the SAME Redis. It is **fail-closed**: any
Redis error (unreachable, timeout, command failure) makes the verifier return 503 — it NEVER fails
open (a fail-open outage would be a global replay-protection bypass). An unreachable Redis fails the
server at boot rather than running with silently-disabled replay protection. Redis I/O runs on a
dedicated thread (off the async runtime, mirroring the verifier's `net.rs` pattern) with a tight
op timeout, so a slow Redis becomes a fast 503, never a worker pile-up. The integration test
(`tests/redis_replay.rs`, behind the feature + the `PSS_IT_REDIS_URL` env gate) proves the
cross-instance replay rejection, the fail-closed posture, and TTL expiry. Bring up the test Redis
with `docker compose up -d redis`. The Redis-outage failure mode + the async-replication-on-failover
hazard + HA topology are documented in the project issue tracker.

Auth is **real**: the server performs live OIDC discovery + JWKS fetch against the trusted issuer
(over the DNS-pinned SSRF-guarded fetcher) and, by default, the strict bidirectional WebID↔issuer
check. So an authenticated request needs a DPoP-bound token signed by the trusted IdP. For a local
dev IdP on `http://`/loopback, set `SOLID_SERVER_ALLOW_LOOPBACK=1` (production refuses non-HTTPS /
private-host IdP+WebID hosts). Storage is still the in-memory doubles (no SPARQ/S3 needed to boot).
See the tests ([`tests/`](tests/)) for how tokens + DPoP proofs are minted and verified end-to-end
against the verification core.

## Gate

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps   # rustdoc, deny warnings
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
