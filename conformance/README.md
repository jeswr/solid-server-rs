# Conformance testing — solid-server-rs (EXPERIMENTAL Rust track)

Runs the official [Solid Conformance Test Harness](https://github.com/solid-contrib/conformance-test-harness)
(CTH) against the experimental Rust `solid-server-rs`, booted with the **in-memory store doubles**
(`CompositeStore` over `InMemorySparqClient` + `InMemoryBlobStore` — NO S3, NO live SPARQ; S3 is
explicitly out of scope for this baseline) terminating TLS in-process and seeded with the test users.

The committed config lives in `config/`; the TLS cert/key in `tls/`. The Java harness, the
`solid-contrib/specification-tests` manifests, and generated reports are **not** vendored — `run.sh`
reuses the sibling `prod-solid-server/conformance/` apparatus.

## What is tested

The harness loads the Solid Protocol + WAC manifests from `solid-contrib/specification-tests` and runs
the scenarios our `TestSubject` claims: **41 test cases** (25 Protocol + 16 WAC) after the 3 skip tags
(`acp`, `wac-agent-group`, `http-redirect`). The same suite prod-solid-server runs.

`config/test-subjects.ttl` claims the LDP/Solid surface the Rust server implements (LDP CRUD,
Turtle/JSON-LD content negotiation, conditional + Range requests, n3-patch PATCH, storage description +
`/.well-known/solid` discovery, WebSocketChannel2023 notifications) AND deliberately claims the WAC
suite even though WAC is **not yet implemented** (gated on the SPARQ access-control design, sparq#992):
the WAC scenarios fail by design in this baseline so the gap is measured rather than hidden.

## Reusing the prod-solid-server apparatus (don't rebuild)

`run.sh` reuses, from the sibling `prod-solid-server/conformance/`:

- the **ath-patched CTH docker image** `pss-cth:ath` (the published image omits the RFC 9449 DPoP
  `ath` claim and cannot authenticate against an `ath`-enforcing server — `solid-server-rs` enforces
  `ath` via the verifier),
- the cloned **`specification-tests`** manifests (37 protocol + 17 WAC feature files),
- the **`solid` Keycloak realm** at `localhost:8080/realms/solid` with the `conformance-alice` /
  `conformance-bob` DPoP service-account clients.

Override the locations with `CTH_IMAGE`, `SPEC_TESTS`, `SERVER_BIN`, `ENV_FILE` if your layout differs.

## Auth wiring (Keycloak, the hard part)

The CTH logs its test users in to obtain access tokens. We delegate identity to **Keycloak** (the same
realm prod-solid-server conformance uses) and seed the WebIDs ourselves:

1. **Token path — client-credentials, DPoP-bound.** Each user (alice, bob) maps to a confidential
   Keycloak service-account client (`conformance-alice` / `conformance-bob`) with
   `serviceAccountsEnabled` + `dpop.bound.access.tokens`. The CTH exchanges
   `USERS_<U>_CLIENTID`/`CLIENTSECRET` for a token via the realm token endpoint and adds the DPoP
   proof itself (`Client.withDpopSupport`) — so the token satisfies the verifier's DPoP requirement.
   The token is RFC-9068 `at+jwt`, `iss=http://localhost:8080/realms/solid`,
   `aud=["solid","https://localhost:3000"]`, `webid=https://localhost:3000/<u>/profile/card#me`,
   `cnf.jkt` present. (Verified directly during wiring.)
2. **WebID + container seeding (in lieu of a provisioner).** The Rust server has no provisioner, so it
   seeds the test users at boot when `SOLID_SERVER_SEED_CONFORMANCE=1` (see `src/seed.rs`): the root
   container `/`, each user's `/{u}/`, `/{u}/profile/`, `/{u}/test/` containers, and each WebID profile
   `/{u}/profile/card` whose `#me` subject carries `pim:storage` → the pod root and `solid:oidcIssuer`
   → the realm. The profile is built from `oxrdf` triples + the server's own Turtle serializer (never
   hand-concatenated). The harness dereferences the WebID to find `pim:storage`, then operates in
   `test/`.
3. **Trust + audience.** The server is booted with `SOLID_SERVER_TRUSTED_ISSUER=http://localhost:8080/realms/solid`
   (so it trusts the realm) and `SOLID_SERVER_AUDIENCE=https://localhost:3000` (matching the token's
   mandatory `aud`). `SOLID_SERVER_BIDIRECTIONAL=off` skips the WebID↔issuer cross-check (the seeded
   WebID's `solid:oidcIssuer` does match the realm, but the off switch keeps the in-memory baseline
   independent of WebID-fetch round-trips). `SOLID_SERVER_ALLOW_LOOPBACK=1` permits the http: localhost
   IdP (dev/IT escape hatch).

### Networking (load-bearing — the macOS Docker-Desktop reality)

The token's `iss` is whatever host the harness used for OIDC discovery, because Keycloak echoes its
issuer from the request host. The verifier's SSRF guard permits an `http:` issuer **only if it resolves
to loopback**. So the token `iss` and the server's trusted issuer must BOTH be `localhost:8080` (which
the server, on the host, resolves to loopback). To make the harness mint a `localhost:8080`-issued token
AND reach the server, `run.sh`:

- runs the harness with **`--network host`** — on Docker Desktop this shares the Linux VM's network
  namespace, where Keycloak (a VM container) is reachable at `localhost:8080` and discovery returns
  `iss=http://localhost:8080/realms/solid`;
- starts a **`--network host` `socat` sidecar** that forwards the VM's `localhost:3000` → the macOS
  host's `:3000` (`host.docker.internal`), because the VM cannot otherwise reach a macOS-host-bound
  process via `localhost`.

Net effect: harness, server, and Keycloak all agree on `localhost:3000` / `localhost:8080`, the DPoP
`htu` matches the server's reconstructed URL, and the http issuer resolves to loopback. On a
native-Linux Docker engine `--network host` is the literal host netns and the socat hop is a harmless
passthrough — `run.sh` is portable.

### TLS

The verifier requires the server reachable over **https** (the harness dereferences the https WebID).
The server terminates TLS in-process (rustls/aws-lc-rs) using the self-signed cert in `tls/`
(`server-cert.pem` / `server-key.pem`), whose SANs cover `host.docker.internal`, `localhost`, and
`127.0.0.1`. The harness trusts it via `ALLOW_SELF_SIGNED_CERTS=true`.

### DPoP `ath` (harness patch)

The published CTH does not send the RFC 9449 DPoP `ath` claim on resource requests, so it cannot
authenticate against a server that enforces `ath` — which `solid-server-rs` does (via the verifier).
`run.sh` uses the `pss-cth:ath` image built from a patched harness clone (see
`prod-solid-server/conformance/README.md` and `patch-harness-ath.sh`). This is an upstream harness bug.

## Running

```sh
# 0. Prereqs: the prod-solid-server stack is up (Keycloak realm at localhost:8080) and the ath-patched
#    image pss-cth:ath exists. From prod-solid-server: `docker compose up -d` + build pss-cth:ath.
cargo build --release                     # build solid-server-rs
./conformance/run.sh                      # boots server (in-memory, TLS, seeded) + drives the harness
```

Reports land in `conformance/reports/` (`report.html`, `report.ttl` EARL, plus the Karate
`target/karate-reports/` inside the report dir). The booted server's log is `reports/server.log`.

Override knobs (all optional): `CTH_IMAGE`, `SPEC_TESTS`, `SERVER_BIN`, `ENV_FILE`.

## Baseline score

See `SCORE.md` for the captured baseline (per-suite + per-failing-test breakdown) and the ordered
fix-list mapping each failure to a concrete server fix.
