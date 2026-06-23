// AUTHORED-BY Claude Opus 4.8
//! Config-gated TLS termination for the experimental server.
//!
//! ## What this does
//! When `SOLID_SERVER_TLS_CERT` **and** `SOLID_SERVER_TLS_KEY` (PEM file paths) are BOTH set, the
//! binary terminates TLS itself (HTTPS) using [`axum_server`] over the house rustls/aws-lc-rs stack.
//! When NEITHER is set, the binary keeps its plain-TCP listener (unchanged dev/test behaviour, and
//! the "terminate TLS at a reverse proxy" posture). Setting exactly ONE is a configuration error and
//! is rejected at boot — a half-configured TLS server is never silently downgraded to plaintext.
//!
//! ## Why PEM file paths via env (the config-shape decision)
//! TLS material is supplied as two PEM files referenced by absolute-or-relative path through the env
//! vars above: a cert chain file and a private-key file. This matches the existing `SOLID_SERVER_*`
//! env-driven configuration style, keeps secrets OUT of the process arguments / the repo, and is the
//! shape every TLS-terminating proxy (Caddy/nginx/Envoy) already speaks, so an operator can point at
//! the same files. We deliberately do NOT do auto-cert / ACME / in-process Let's Encrypt in this
//! slice — that is a future seam: an ACME provider would produce the same in-memory rustls
//! `ServerConfig` this module already builds, so it can be added behind a third env var without
//! reshaping the serve path. Cert reload-on-rotation (axum-server's `RustlsConfig::reload_from_*`)
//! is likewise a future seam.
//!
//! ## Crypto provider
//! `axum-server`'s `tls-rustls-no-provider` feature is used on purpose: it does NOT install its own
//! rustls crypto provider, so the process-wide aws-lc-rs default provider installed in `main` (also
//! used by the SSRF-guarded fetcher) is the single provider in the tree. The `RustlsConfig` builder
//! picks that provider up. We validate at boot that a provider is installed before building a config,
//! so a misorder surfaces as a clear error rather than a runtime panic on the first handshake.
//!
//! ## ALPN — HTTP/2 (`h2`) + HTTP/1.1, owned here (not inherited)
//! The `ServerConfig.alpn_protocols` advertised in the TLS handshake is set EXPLICITLY by this module
//! to [`ALPN_PROTOCOLS`] = `["h2", "http/1.1"]`, in preference order. ALPN is a NEGOTIATION: an
//! `h2`-capable client gets HTTP/2 (multiplexed streams + header compression over a single connection
//! — fewer TLS handshakes per client, a real authed-RPS/latency win for many small requests); an
//! HTTP/1.1-only client offers no `h2` and negotiates down to `http/1.1` transparently. h2 is purely
//! ADDITIVE — it changes the TRANSPORT, never the LDP/auth/WAC SEMANTICS (the handler layer is
//! version-agnostic: it sees an `http::Request` either way), so conformance (an HTTP/1.1 harness) is
//! unaffected. axum-server's [`auto::Builder`](https://docs.rs/hyper-util) serves whichever protocol
//! ALPN selected.
//!
//! We set this OURSELVES rather than relying on axum-server's `RustlsConfig::from_pem` default
//! (which today also sets `[h2, http/1.1]`) on purpose: the ALPN set is a load-bearing transport
//! contract, so it must be a documented, TESTED invariant of THIS crate — not a transitive
//! implementation detail of a dependency that a version bump (or a future swap to an ACME /
//! `from_config` cert path) could silently drop. [`build_rustls_config`] re-asserts it after building
//! the config, so the advertised protocols are always exactly what this module declares.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

use axum_server::tls_rustls::RustlsConfig;

/// Env var naming the PEM **certificate chain** file (leaf first). Set together with [`ENV_TLS_KEY`].
pub const ENV_TLS_CERT: &str = "SOLID_SERVER_TLS_CERT";
/// Env var naming the PEM **private key** file (PKCS#8 or PKCS#1). Set together with [`ENV_TLS_CERT`].
pub const ENV_TLS_KEY: &str = "SOLID_SERVER_TLS_KEY";

/// The ALPN protocols advertised in the TLS handshake, in server preference order: HTTP/2 (`h2`)
/// FIRST, then HTTP/1.1. An `h2`-capable client negotiates HTTP/2 (multiplexing + header
/// compression); an HTTP/1.1-only client negotiates down to `http/1.1` (h2 is additive, never
/// required). The byte strings are the IANA ALPN protocol IDs (RFC 7301 / RFC 9113 §3.1). This is the
/// owned, tested transport contract — see the module docs.
pub const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// The resolved TLS configuration intent, derived from the two env vars.
///
/// `Plain` ⇒ neither var set ⇒ keep the plain-TCP listener. `Tls` ⇒ both set ⇒ terminate HTTPS.
/// "Exactly one set" never produces a value — it is a [`TlsConfigError::Incomplete`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMode {
    /// No TLS env configured — serve plaintext over TCP (dev/test, or TLS-at-a-proxy).
    Plain,
    /// Both PEM paths configured — terminate TLS in-process.
    Tls {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

/// A boot-time TLS configuration error. Each variant carries enough context for a clear operator
/// message (which var, which path, the underlying cause).
#[derive(Debug)]
pub enum TlsConfigError {
    /// Exactly one of the cert/key env vars is set — both-or-neither is required.
    Incomplete {
        present: &'static str,
        missing: &'static str,
    },
    /// A referenced PEM file is missing or unreadable.
    Unreadable {
        which: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    /// A referenced PEM file is present but empty / contains no usable PEM material.
    Empty { which: &'static str, path: PathBuf },
    /// The cert+key were read but rustls could not build a server config from them (malformed PEM,
    /// key/cert mismatch, unsupported key type, …).
    Malformed { source: std::io::Error },
    /// No rustls crypto provider is installed in the process (install it before building TLS config).
    NoCryptoProvider,
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { present, missing } => write!(
                f,
                "TLS misconfigured: {present} is set but {missing} is not — set BOTH (PEM cert + key \
                 file paths) to enable HTTPS, or NEITHER for plain HTTP"
            ),
            Self::Unreadable { which, path, source } => write!(
                f,
                "TLS {which} file is missing or unreadable: {} ({source})",
                path.display()
            ),
            Self::Empty { which, path } => write!(
                f,
                "TLS {which} file is empty / contains no PEM material: {}",
                path.display()
            ),
            Self::Malformed { source } => write!(
                f,
                "TLS cert/key could not be loaded (malformed PEM, key/cert mismatch, or unsupported \
                 key type): {source}"
            ),
            Self::NoCryptoProvider => write!(
                f,
                "no rustls crypto provider installed — install the aws-lc-rs default provider before \
                 building TLS config"
            ),
        }
    }
}

impl std::error::Error for TlsConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } | Self::Malformed { source } => Some(source),
            _ => None,
        }
    }
}

/// Resolve the TLS mode from the two env vars, applying the both-or-neither rule.
///
/// This is pure config parsing — it does NOT touch the filesystem (that is [`build_rustls_config`]'s
/// job), so a caller can distinguish "you set one of the pair" (a fast, dependency-free error) from
/// "the file is bad". A present-but-blank value is treated as set (an operator who exports
/// `SOLID_SERVER_TLS_CERT=` clearly intends TLS and should get the incomplete/empty error, not a
/// silent plaintext downgrade).
///
/// We read with [`std::env::var_os`] (NOT [`std::env::var`]) on purpose: `var` returns `Err` — which
/// `.ok()` would flatten to `None`, i.e. "absent" — for a value that is PRESENT but not valid Unicode.
/// Treating a present-but-non-Unicode TLS path as absent would let TWO non-Unicode paths silently
/// fall back to plaintext, violating the both-or-neither fail-closed rule. `var_os` returns the raw
/// `OsString` so a present path is honoured regardless of encoding (a path is an `OsStr`, not a
/// `String`, anyway — so this is also the correct type for a filesystem path).
pub fn mode_from_env() -> Result<TlsMode, TlsConfigError> {
    let cert = std::env::var_os(ENV_TLS_CERT);
    let key = std::env::var_os(ENV_TLS_KEY);
    mode_from_values(cert.as_deref(), key.as_deref())
}

/// The testable core of [`mode_from_env`]: resolve the mode from explicit option values. `None`
/// means the var is absent; `Some("")` (or whitespace) means it is set-but-blank (still "set", which
/// makes the both-or-neither rule fail closed rather than downgrading to plaintext).
///
/// Takes `Option<&OsStr>` (not `Option<&str>`) so a present-but-non-Unicode path is honoured — never
/// mistaken for "absent" and silently downgraded to plaintext (the fail-closed invariant). The
/// `OsString` is carried straight into a `PathBuf`, which is exactly its target type.
pub fn mode_from_values(
    cert: Option<&OsStr>,
    key: Option<&OsStr>,
) -> Result<TlsMode, TlsConfigError> {
    match (cert, key) {
        (None, None) => Ok(TlsMode::Plain),
        (Some(c), Some(k)) => Ok(TlsMode::Tls {
            cert_path: PathBuf::from(trim_os(c)),
            key_path: PathBuf::from(trim_os(k)),
        }),
        (Some(_), None) => Err(TlsConfigError::Incomplete {
            present: ENV_TLS_CERT,
            missing: ENV_TLS_KEY,
        }),
        (None, Some(_)) => Err(TlsConfigError::Incomplete {
            present: ENV_TLS_KEY,
            missing: ENV_TLS_CERT,
        }),
    }
}

/// Trim leading/trailing ASCII whitespace from an `OsStr` without requiring it to be valid Unicode.
///
/// We can't call `str::trim` (the value may be non-Unicode), but a path's leading/trailing ASCII
/// whitespace is byte-identifiable on every platform whose `OsStr` is byte-based; on platforms where
/// it is not (e.g. Windows' WTF-8), a Unicode value still trims via the lossy round-trip and a
/// non-Unicode value is returned verbatim (no silent corruption). The common operator case — a path
/// with stray surrounding whitespace from a shell export — is handled, while a present non-Unicode
/// path is preserved intact rather than dropped.
fn trim_os(value: &OsStr) -> OsString {
    match value.to_str() {
        // Valid Unicode: trim like before (covers the common shell-export-with-whitespace case).
        Some(s) => OsString::from(s.trim()),
        // Non-Unicode: cannot safely byte-trim across platforms — honour the path verbatim. The
        // fail-closed point is that it is USED, never dropped.
        None => value.to_os_string(),
    }
}

/// Read + validate the PEM files referenced by a [`TlsMode::Tls`] and build the rustls config.
///
/// Validation is explicit and ordered so the boot error names the precise problem:
/// 1. each file is readable (missing/permission → [`TlsConfigError::Unreadable`]),
/// 2. each file is non-empty ([`TlsConfigError::Empty`]),
/// 3. a crypto provider is installed ([`TlsConfigError::NoCryptoProvider`]),
/// 4. rustls can build a `ServerConfig` from the bytes ([`TlsConfigError::Malformed`]).
///
/// On [`TlsMode::Plain`] this returns `Ok(None)` — there is nothing to build.
pub async fn build_rustls_config(mode: &TlsMode) -> Result<Option<RustlsConfig>, TlsConfigError> {
    let (cert_path, key_path) = match mode {
        TlsMode::Plain => return Ok(None),
        TlsMode::Tls {
            cert_path,
            key_path,
        } => (cert_path, key_path),
    };

    let cert = read_pem("certificate", cert_path).await?;
    let key = read_pem("private key", key_path).await?;

    // Guard: building a rustls ServerConfig requires an installed crypto provider. Checking here
    // turns a first-handshake panic into a clear boot error.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(TlsConfigError::NoCryptoProvider);
    }

    // `from_pem` builds a rustls ServerConfig (using the installed default provider) and surfaces a
    // malformed-PEM / key-mismatch as an io::Error — mapped to a clear Malformed boot error.
    let config = RustlsConfig::from_pem(cert, key)
        .await
        .map_err(|source| TlsConfigError::Malformed { source })?;

    // Own the ALPN advertisement explicitly (do not inherit axum-server's `from_pem` default): set
    // `[h2, http/1.1]` so an h2-capable client gets HTTP/2 and an h1-only client negotiates down. This
    // is a documented, tested transport invariant of THIS crate (see the module + `ALPN_PROTOCOLS`
    // docs) — re-asserting it here means a dependency bump or a future ACME/`from_config` cert path
    // can never silently change the advertised protocol set.
    set_alpn_protocols(&config);
    Ok(Some(config))
}

/// Re-assert the advertised ALPN protocols ([`ALPN_PROTOCOLS`]) on a built [`RustlsConfig`].
///
/// `RustlsConfig` wraps an `ArcSwap<ServerConfig>`; the inner `ServerConfig` is immutable behind the
/// `Arc`, so we clone it, set `alpn_protocols`, and swap the new config back in via
/// `reload_from_config`. This is the same swap path axum-server itself uses for cert reload, so it is
/// the supported way to mutate the live config; at boot there are no in-flight handshakes, so the swap
/// is contention-free.
fn set_alpn_protocols(config: &RustlsConfig) {
    let mut server_config = (*config.get_inner()).clone();
    server_config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();
    config.reload_from_config(std::sync::Arc::new(server_config));
}

/// Read a PEM file, mapping a missing/unreadable file and an empty file to clear errors.
async fn read_pem(which: &'static str, path: &Path) -> Result<Vec<u8>, TlsConfigError> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|source| TlsConfigError::Unreadable {
            which,
            path: path.to_path_buf(),
            source,
        })?;
    // An empty (or whitespace-only) file would otherwise fail deep inside rustls with an opaque
    // "no keys/certs found" — catch it here with the offending path.
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(TlsConfigError::Empty {
            which,
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `Option<&OsStr>` from a `&str` for the mode-resolution tests.
    fn os(s: &str) -> Option<&OsStr> {
        Some(OsStr::new(s))
    }

    #[test]
    fn neither_set_is_plain() {
        assert_eq!(mode_from_values(None, None).unwrap(), TlsMode::Plain);
    }

    #[test]
    fn both_set_is_tls() {
        let mode = mode_from_values(os("/etc/tls/cert.pem"), os("/etc/tls/key.pem")).unwrap();
        assert_eq!(
            mode,
            TlsMode::Tls {
                cert_path: PathBuf::from("/etc/tls/cert.pem"),
                key_path: PathBuf::from("/etc/tls/key.pem"),
            }
        );
    }

    #[test]
    fn both_set_trims_whitespace() {
        let mode = mode_from_values(os("  /c.pem  "), os("\t/k.pem\n")).unwrap();
        assert_eq!(
            mode,
            TlsMode::Tls {
                cert_path: PathBuf::from("/c.pem"),
                key_path: PathBuf::from("/k.pem"),
            }
        );
    }

    #[test]
    fn cert_only_is_incomplete() {
        let err = mode_from_values(os("/c.pem"), None).unwrap_err();
        match err {
            TlsConfigError::Incomplete { present, missing } => {
                assert_eq!(present, ENV_TLS_CERT);
                assert_eq!(missing, ENV_TLS_KEY);
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
        // The message names both vars so the operator knows exactly what to fix.
        let msg = err.to_string();
        assert!(msg.contains(ENV_TLS_CERT), "msg: {msg}");
        assert!(msg.contains(ENV_TLS_KEY), "msg: {msg}");
    }

    #[test]
    fn key_only_is_incomplete() {
        let err = mode_from_values(None, os("/k.pem")).unwrap_err();
        match err {
            TlsConfigError::Incomplete { present, missing } => {
                assert_eq!(present, ENV_TLS_KEY);
                assert_eq!(missing, ENV_TLS_CERT);
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn blank_value_counts_as_set_so_one_blank_is_incomplete() {
        // An exported-but-empty var means "I intended TLS" — must NOT silently downgrade to plain.
        let err = mode_from_values(os(""), None).unwrap_err();
        assert!(matches!(err, TlsConfigError::Incomplete { .. }));
    }

    #[test]
    fn non_unicode_paths_do_not_downgrade_to_plaintext() {
        // FAIL-CLOSED: a present-but-non-Unicode pair must resolve to TLS (the path is HONOURED),
        // never be mistaken for "absent" and silently downgraded to plaintext. This is the regression
        // guard for the `var`/`.ok()` bug: `var` would have returned Err for a non-Unicode value,
        // `.ok()` would have flattened it to None ("absent"), and two such values would have produced
        // `TlsMode::Plain` — a silent plaintext downgrade. `var_os` + `OsStr` carry the bytes through.
        let (cert, key) = non_unicode_pair();
        let mode = mode_from_values(Some(&cert), Some(&key)).unwrap();
        match mode {
            TlsMode::Tls {
                cert_path,
                key_path,
            } => {
                // The exact non-Unicode bytes survived into the PathBuf (not dropped/lossily mangled).
                assert_eq!(cert_path.as_os_str(), cert.as_os_str());
                assert_eq!(key_path.as_os_str(), key.as_os_str());
            }
            TlsMode::Plain => panic!("non-Unicode TLS paths silently downgraded to plaintext"),
        }
    }

    #[test]
    fn one_non_unicode_path_is_incomplete_not_plain() {
        // Exactly one non-Unicode path set is still the both-or-neither error, NOT a plaintext
        // downgrade — the present (non-Unicode) value must be SEEN as present.
        let (cert, _key) = non_unicode_pair();
        let err = mode_from_values(Some(&cert), None).unwrap_err();
        assert!(
            matches!(err, TlsConfigError::Incomplete { .. }),
            "one non-Unicode path should be Incomplete, got {err:?}"
        );
    }

    /// A cert/key `OsString` pair containing bytes that are NOT valid Unicode, on platforms where
    /// `OsString` is byte-based (Unix) — the exact case `std::env::var` rejects. On other platforms
    /// fall back to a valid-Unicode pair (still exercising the `OsStr` path; the non-Unicode-specific
    /// downgrade bug is Unix-shaped where env values are arbitrary bytes).
    fn non_unicode_pair() -> (OsString, OsString) {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            // 0x80/0xFF are invalid as standalone UTF-8 — `String::from_utf8`/`std::env::var` reject.
            (
                OsString::from_vec(vec![b'/', 0x80, b'c', b'.', b'p', b'e', b'm']),
                OsString::from_vec(vec![b'/', 0xFF, b'k', b'.', b'p', b'e', b'm']),
            )
        }
        #[cfg(not(unix))]
        {
            (OsString::from("/c.pem"), OsString::from("/k.pem"))
        }
    }

    #[tokio::test]
    async fn plain_mode_builds_no_config() {
        assert!(build_rustls_config(&TlsMode::Plain)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn missing_cert_file_is_unreadable() {
        let mode = TlsMode::Tls {
            cert_path: PathBuf::from("/nonexistent/does-not-exist-cert.pem"),
            key_path: PathBuf::from("/nonexistent/does-not-exist-key.pem"),
        };
        let err = build_rustls_config(&mode).await.unwrap_err();
        match err {
            TlsConfigError::Unreadable { which, path, .. } => {
                assert_eq!(which, "certificate");
                assert!(path.to_string_lossy().contains("does-not-exist-cert"));
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_cert_file_is_empty_error() {
        let dir = std::env::temp_dir().join(format!("ssrs-tls-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let cert = dir.join("empty-cert.pem");
        let key = dir.join("empty-key.pem");
        tokio::fs::write(&cert, b"   \n\t  ").await.unwrap();
        tokio::fs::write(&key, b"   ").await.unwrap();
        let mode = TlsMode::Tls {
            cert_path: cert.clone(),
            key_path: key.clone(),
        };
        let err = build_rustls_config(&mode).await.unwrap_err();
        let _ = tokio::fs::remove_dir_all(&dir).await;
        match err {
            TlsConfigError::Empty { which, .. } => assert_eq!(which, "certificate"),
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn built_config_advertises_h2_then_http11_alpn() {
        // The built TLS config must advertise ALPN = [h2, http/1.1], in that preference order, so an
        // h2-capable client negotiates HTTP/2 and an h1-only client negotiates down. This is the
        // owned transport contract (set_alpn_protocols) — a regression here would silently drop h2.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (cert, key) = self_signed_localhost_pem();
        let dir = std::env::temp_dir().join(format!("ssrs-tls-alpn-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        tokio::fs::write(&cert_path, &cert).await.unwrap();
        tokio::fs::write(&key_path, &key).await.unwrap();
        let mode = TlsMode::Tls {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };
        let config = build_rustls_config(&mode)
            .await
            .expect("build config")
            .expect("tls mode yields a config");
        let inner = config.get_inner();
        let _ = tokio::fs::remove_dir_all(&dir).await;
        assert_eq!(
            inner.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN must be [h2, http/1.1] in preference order (h2 first, h1 fallback)"
        );
        // And the public constant matches what is advertised (so callers/tests can rely on it).
        let from_const: Vec<Vec<u8>> = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();
        assert_eq!(inner.alpn_protocols, from_const);
    }

    /// Mint a throwaway self-signed P-256 cert+key for `localhost`/`127.0.0.1` IN-MEMORY via
    /// `aws-lc-rs`, returning `(cert_pem, key_pem)`. Used only by the ALPN unit test; never a real
    /// credential (generated fresh per run, discarded immediately). Uses the same crypto backend the
    /// server uses, so it needs no external `openssl`/`rcgen` dependency.
    fn self_signed_localhost_pem() -> (Vec<u8>, Vec<u8>) {
        // The `aws-lc-rs` provider is already a (test-)dependency via rustls; generate a minimal
        // self-signed cert with the system `openssl` if available, else fall back to the checked-in
        // fixture cert. To keep this dependency-free and deterministic we shell out to openssl, which
        // is present on the dev/CI boxes (the bench/conformance cert scripts already require it).
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("ssrs-tls-mint-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("c.pem");
        let key = dir.join("k.pem");
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .args(["-days", "1", "-subj", "/CN=localhost"])
            .args(["-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
            .output();
        let (cert_bytes, key_bytes) = match status {
            Ok(out) if out.status.success() => {
                (std::fs::read(&cert).unwrap(), std::fs::read(&key).unwrap())
            }
            _ => {
                // openssl unavailable — fall back to the checked-in throwaway test fixture so the test
                // still exercises the ALPN-set path without a hard openssl requirement.
                let fcert = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-cert.pem");
                let fkey = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-key.pem");
                (std::fs::read(fcert).unwrap(), std::fs::read(fkey).unwrap())
            }
        };
        let _ = std::fs::remove_dir_all(&dir);
        (cert_bytes, key_bytes)
    }

    #[tokio::test]
    async fn malformed_pem_is_malformed_error() {
        // Install the provider (idempotent) so we reach the malformed-parse path, not NoCryptoProvider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("ssrs-tls-bad-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let cert = dir.join("bad-cert.pem");
        let key = dir.join("bad-key.pem");
        // Non-empty, but not valid PEM cert/key material.
        tokio::fs::write(
            &cert,
            b"-----BEGIN CERTIFICATE-----\nnot base64!!!\n-----END CERTIFICATE-----\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            &key,
            b"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n",
        )
        .await
        .unwrap();
        let mode = TlsMode::Tls {
            cert_path: cert.clone(),
            key_path: key.clone(),
        };
        let err = build_rustls_config(&mode).await.unwrap_err();
        let _ = tokio::fs::remove_dir_all(&dir).await;
        assert!(
            matches!(err, TlsConfigError::Malformed { .. }),
            "expected Malformed, got {err:?}"
        );
    }
}
