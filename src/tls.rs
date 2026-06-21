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

use std::fmt;
use std::path::{Path, PathBuf};

use axum_server::tls_rustls::RustlsConfig;

/// Env var naming the PEM **certificate chain** file (leaf first). Set together with [`ENV_TLS_KEY`].
pub const ENV_TLS_CERT: &str = "SOLID_SERVER_TLS_CERT";
/// Env var naming the PEM **private key** file (PKCS#8 or PKCS#1). Set together with [`ENV_TLS_CERT`].
pub const ENV_TLS_KEY: &str = "SOLID_SERVER_TLS_KEY";

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
/// "the file is bad". The env values are trimmed; a present-but-blank value is treated as set (an operator who
/// exports `SOLID_SERVER_TLS_CERT=` clearly intends TLS and should get the incomplete/empty error,
/// not a silent plaintext downgrade).
pub fn mode_from_env() -> Result<TlsMode, TlsConfigError> {
    let cert = std::env::var(ENV_TLS_CERT).ok();
    let key = std::env::var(ENV_TLS_KEY).ok();
    mode_from_values(cert.as_deref(), key.as_deref())
}

/// The testable core of [`mode_from_env`]: resolve the mode from explicit option values. `None`
/// means the var is absent; `Some("")` (or whitespace) means it is set-but-blank (still "set", which
/// makes the both-or-neither rule fail closed rather than downgrading to plaintext).
pub fn mode_from_values(cert: Option<&str>, key: Option<&str>) -> Result<TlsMode, TlsConfigError> {
    match (cert, key) {
        (None, None) => Ok(TlsMode::Plain),
        (Some(c), Some(k)) => Ok(TlsMode::Tls {
            cert_path: PathBuf::from(c.trim()),
            key_path: PathBuf::from(k.trim()),
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
    RustlsConfig::from_pem(cert, key)
        .await
        .map(Some)
        .map_err(|source| TlsConfigError::Malformed { source })
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

    #[test]
    fn neither_set_is_plain() {
        assert_eq!(mode_from_values(None, None).unwrap(), TlsMode::Plain);
    }

    #[test]
    fn both_set_is_tls() {
        let mode = mode_from_values(Some("/etc/tls/cert.pem"), Some("/etc/tls/key.pem")).unwrap();
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
        let mode = mode_from_values(Some("  /c.pem  "), Some("\t/k.pem\n")).unwrap();
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
        let err = mode_from_values(Some("/c.pem"), None).unwrap_err();
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
        let err = mode_from_values(None, Some("/k.pem")).unwrap_err();
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
        let err = mode_from_values(Some(""), None).unwrap_err();
        assert!(matches!(err, TlsConfigError::Incomplete { .. }));
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
