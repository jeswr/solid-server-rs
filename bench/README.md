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
| `BENCH_CHILDREN` | `100` | children seeded into the listing container (`SOLID_SERVER_SEED_BENCH`) |
| `BENCH_DURATION` | `10s` | `oha -z` per concurrency level |
| `BENCH_WARMUP` | `3s` | discarded warm-up before each scenario's sweep |
| `BENCH_CONCURRENCY` | `1 8 16 32 64 128 256 512` | space-separated `oha -c` levels |
| `BENCH_CONNECT_HOST` | `127.0.0.1` | the IPv4 literal the load tool dials (see the IPv6 note below) |
| `SERVER_BIN` | `target/release/solid-server-rs` | override the binary |

## Scenarios

- **(a) `public-doc`** — `GET /bench/public/doc`: the TLS/pipeline ceiling (no auth, no RDF render).
- **(b) `listing`** — `GET /bench/listing/`: the RDF container-membership render path (N children).
- **(c) authed private GET** — DEFERRED, see below.

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

## Authed follow-up (scenario c)

Measuring the **authenticated** GET (the DPoP/token-verify hot path) needs a DPoP-bound RFC 9068
token from the conformance Keycloak `solid` realm — and a **fresh DPoP proof per request** (RFC 9449
binds the proof to the method + URL + a unique `jti`, and the server enforces `ath`). `oha` cannot
mint a per-request DPoP proof, so a static `-H "Authorization: …"` header would be rejected (replay /
`ath` mismatch). The honest options for the follow-up round:

1. a small Rust load client that mints a fresh DPoP proof per request (reuse the verifier crate's test
   DPoP helpers) against the seeded `/bench/private/doc`; or
2. extend the conformance Keycloak wiring (`conformance/`) to issue a token and drive a
   lower-concurrency authed sweep where per-request proof minting is affordable.

Until then, authenticated throughput is recorded as an explicit TODO in `BASELINE.md`, **not** faked.

## Results

See `bench/BASELINE.md` for the captured baseline table + the saturation/concurrency findings + the
ranked hot-path optimization targets. Those numbers are generated by THIS harness — re-run to refresh.
