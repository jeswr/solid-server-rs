# `bench/` — reproducible HTTPS load benchmark for solid-server-rs

A self-contained harness that measures the server's **highly-concurrent throughput** (max sustained
RPS + the saturation concurrency) and **latency** (p50/p99/p999) over **HTTPS**, against the
in-memory store (no S3, no live SPARQ), so later optimization rounds have a baseline to beat.

This directory is **measurement only** — it does not change server request behaviour. The one server
`src/` touch is dev-only bench *seeding* (`SOLID_SERVER_SEED_BENCH`, default-off — see "Fixtures").

## Quick start

```bash
# Prereq (a local DEV tool, NOT a project dependency — do not add it to Cargo.toml):
brew install oha

# From the repo root:
./bench/run.sh
```

`run.sh`:
1. builds `--release` if the binary is missing;
2. generates a self-signed `localhost` cert into `bench/tls/` (`gen-cert.sh`, idempotent);
3. boots the server in-memory over HTTPS, **bench-seeded** (a public doc + a public listing container
   with N children + an owner-private doc);
4. verifies the fixtures (public=200, listing=200, private=401-anonymous) — fails loudly otherwise;
5. runs an `oha` concurrency sweep (`1 8 16 32 64 128 256 512` by default), one discarded warm-up
   per scenario, 10s per level;
6. writes `bench/results/results.tsv` (the summary) + per-level `bench/results/*.json` (raw oha) +
   `bench/results/server.log`.

`bench/tls/` + `bench/results/` are gitignored (DEV artifacts — regenerate by re-running).

## Knobs (env overrides)

| env | default | meaning |
|---|---|---|
| `BENCH_PORT` | `3210` | server port |
| `BENCH_CHILDREN` | `100` | children seeded into the listing container (`SOLID_SERVER_SEED_BENCH`). Use `>=2` for an explicit count: `1` is the bare-truthy "enable with the DEFAULT count" form (= the default, not one child) so it doubles as the on-switch — a one-child listing is not a meaningful render benchmark. |
| `BENCH_DURATION` | `10s` | `oha -z` per concurrency level |
| `BENCH_WARMUP` | `3s` | discarded warm-up before each scenario's sweep |
| `BENCH_CONCURRENCY` | `1 8 16 32 64 128 256 512` | space-separated `oha -c` levels |
| `BENCH_CONNECT_HOST` | `127.0.0.1` | the IPv4 literal the load tool dials (see the IPv6 note below) |
| `SERVER_BIN` | `target/release/solid-server-rs` | override the binary |

## Scenarios

`bench/run.sh` (auth-free `oha`) measures:

- **(a) `public-doc`** — `GET /bench/public/doc`: the TLS/pipeline ceiling (no auth, no RDF render).
- **(b) `listing`** — `GET /bench/listing/`: the RDF container-membership render path (N children).

`bench/run-auth.sh` (the round-2 authenticated harness, see **"Authenticated benchmark"** below)
measures the realistic **production** path:

- **(c) `authed-private-doc`** — authenticated `GET` of an owner-private document over DPoP: the
  auth-verify hot path (token verify + DPoP verify + JWKS-cache lookup + the single ACL read/parse).
- **(d) `authed-listing`** — authenticated `GET` of an owner-private container listing: auth + RDF
  render combined.

It ALSO runs an anonymous comparison sweep (same client, no token) so the **auth overhead** is
measured apples-to-apples on the same box/binary/run. Results → `bench/AUTH-BASELINE.md`.

## Tool

`oha` 1.14.0 — an HTTP/1.1 load generator with clean p50/p99/p999 + an RPS histogram and a JSON output
mode (`--output-format json`) the harness parses. The server is **HTTP/1.1 only** (no h2 ALPN), so an
HTTP/1.1 tool is required; `oha` is invoked with keep-alive (default) and `--insecure` (self-signed
cert). State the exact tool + version when you cite numbers — they live in `BASELINE.md`.

## The IPv6 `localhost` trap (why we dial `127.0.0.1`)

The server binds **IPv4** `127.0.0.1`. On macOS, `localhost` resolves to **IPv6 `::1` first** — and
`oha` connects to `::1` and gets `Connection refused (os error 61)` (unlike `curl`, it does NOT fall
back to IPv4). So the harness dials the **IPv4 literal** `127.0.0.1` for load + readiness probes
(`BENCH_CONNECT_HOST`); the self-signed cert's SAN includes `127.0.0.1` and `--insecure` is set
regardless. The server's `BASE_URL` stays `https://localhost:PORT` (the DPoP `htu` / audience
identity) — only the dial target differs. If a sweep reports `successRate=0` with all errors
"Connection refused", this is the cause.

## Fixtures (`SOLID_SERVER_SEED_BENCH`)

The bench seed (`src/seed.rs::seed_bench`, gated by the `SOLID_SERVER_SEED_BENCH` env var in
`main.rs`, **default-off**) writes, into the in-memory store at boot:

- a **public-read** pod `/bench/` (its pod-root `.acl` grants `foaf:Agent acl:Read` by `acl:default`),
- `/bench/public/doc` — a small public RDF document (scenario a),
- `/bench/listing/` — a public container with N children `item-0000 … item-(N-1)` (scenario b),
- `/bench/private/doc` — an **owner-private** RDF document (its own owner-only `.acl` overrides the
  inherited public default, so an anonymous GET answers **401** — the fixture for scenario c).

It is dev-only, additive, and identical in nature to the conformance seed (`seed_conformance`): it
ONLY writes resources and changes no request-handling code path. Conformance stays 41/41 (the gate is
off during conformance runs). Never set `SOLID_SERVER_SEED_BENCH` against a real (SPARQ/S3) backend.

## Authenticated benchmark (`bench/run-auth.sh`) — the round-2 auth path

Measuring the **authenticated** GET (the DPoP/token-verify hot path — the realistic production path)
needs a DPoP-bound RFC 9068 token from the conformance Keycloak `solid` realm AND a **fresh DPoP proof
per request** (RFC 9449 binds the proof to the method + URL + a unique `jti`, and the server enforces
`ath`). `oha` cannot mint a per-request DPoP proof, so this is driven by a small **Rust load client**
(`examples/auth_load.rs`) instead.

### Quick start

```bash
# Prereq: the SAME Keycloak `solid` realm prod-solid-server conformance uses, UP at
# localhost:8080/realms/solid (`docker compose up -d` in prod-solid-server). NOTHING in it is modified.
./bench/run-auth.sh
```

`run-auth.sh`:

1. builds `--release` server + the `auth_load` example;
2. boots the server in-memory over HTTPS, **conformance-seeded** (so alice's WebID + owner-controlled
   pod exist) at `https://localhost:3000` (the base the realm tokens' `aud` expects), with
   `ALLOW_LOOPBACK + http issuer + BIDIRECTIONAL=off` — the **exact auth env conformance/run.sh uses**
   (the verify path is identical), plus the dev-only replay-capacity override (see below);
3. the load client obtains a DPoP-bound token from the realm `conformance-alice` client-credentials
   service account (REUSING `conformance/config/solid-server-rs.env`'s client id/secret/token
   endpoint — no new auth flow invented), PUTs a private fixture document + N private listing children
   into alice's pod, asserts a single **authed GET → 200** AND an **anonymous GET → 401** (genuinely
   private) BEFORE the sweep (a misbuilt proof would otherwise measure the 401 path);
4. sweeps concurrency for **(c) authed-private-doc** + **(d) authed-listing**, each request carrying a
   freshly minted DPoP proof (`htu`=exact URL, `htm`=GET, unique `jti`, `ath`=base64url(SHA-256(token)));
5. re-runs an **anonymous** comparison sweep (same client, no token) on the public bench doc, so the
   auth overhead is measured apples-to-apples;
6. writes `bench/results-auth/{authed,anon}.tsv` + per-level `*.json` (same shape as the `oha` JSON).

### How the token + proof are built

- **Token (once):** the realm requires a DPoP proof ON THE TOKEN REQUEST (DPoP-bound client
  credentials), so the client mints a token-endpoint proof (htu=token endpoint, htm=POST, no `ath`),
  POSTs `grant_type=client_credentials`, and receives a `cnf.jkt`-bound `at+jwt` whose `webid` is
  alice + `aud` the server base URL.
- **Proof (per request):** a fresh proof from the SAME ES256 key (htu=request URL, htm=GET/PUT, unique
  `jti`, `ath` over the token). The `jti` carries a **per-process random nonce** so a fresh client run
  against an already-running server never collides with a prior run's jtis in the replay store (which
  would be rejected as replays). This was a real bug found while building the harness.

### The DPoP replay-store capacity knob (dev/bench only, default-off)

The in-memory jti replay store is capped at **100,000** live jtis within the proof-age TTL window
(`DPOP_PROOF_MAX_AGE_SECS` 300 + clock tolerance 5 = **305 s**) and **fails closed** when full (it
never evicts a live jti). A SUSTAINED high-RPS authed run fills 100k unique jtis in seconds and then —
correctly — rejects every further proof (the single-instance safety bound). That is a real production
behaviour (recorded as a round-3 finding in `AUTH-BASELINE.md`), but it would CONTAMINATE the
steady-state verify-cost measurement. So the server gained a **default-off, conformance-neutral** env
override `SOLID_SERVER_REPLAY_MAX_ENTRIES` (UNSET ⇒ 100_000 unchanged) that ONLY raises the capacity
number — no request-handling logic changes; the fail-closed semantics are untouched; `0`/invalid keeps
the default so a typo can never weaken replay protection. `run-auth.sh` raises it for the bench run so
every level measures the genuine verify path at 100% success. **Never set it in production.**

### Knobs (env overrides)

| env | default | meaning |
|---|---|---|
| `AUTH_BENCH_PORT` | `3000` | server port (3000 == the conformance base the realm tokens' `aud` expects) |
| `AUTH_DURATION_SECS` | `10` | measured window per concurrency level |
| `AUTH_WARMUP_SECS` | `3` | discarded warm-up per scenario |
| `AUTH_CONCURRENCY` | `1 8 16 32 64 128 256 512` | the concurrency sweep |
| `AUTH_LISTING_CHILDREN` | `100` | owner-private children PUT into the authed-listing container (scenario d) |
| `AUTH_CLIENT_ID` / `AUTH_CLIENT_SECRET` | `conformance-alice` / `…-secret` | the realm service-account client |
| `AUTH_REPLAY_MAX_ENTRIES` | `5000000` | the dev/bench replay-cap override (see above) |

## Results

- `bench/BASELINE.md` — the **anonymous** baseline (the `oha` harness): public-doc ceiling + listing
  render path + saturation/concurrency findings + ranked read-path targets.
- `bench/AUTH-BASELINE.md` — the **authenticated** baseline (this harness): scenarios (c)+(d), the
  auth-overhead-vs-anonymous delta, the replay-store saturation finding, and the ranked round-3
  auth-path hot-path targets. Those numbers are generated by `run-auth.sh` — re-run to refresh.
