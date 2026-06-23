#!/usr/bin/env bash
# AUTHORED-BY Claude Opus 4.8
# Generate a self-signed `localhost` TLS cert/key into bench/tls/ for the HTTPS load benchmark.
#
# The benchmark terminates TLS in-process via the server's rustls listener (src/tls.rs), which needs
# a PEM cert + key. This mints a throwaway self-signed cert valid for `localhost` + `127.0.0.1` (the
# only host the local benchmark hits). It is IDEMPOTENT: an existing, still-valid cert is reused so
# repeat runs do not churn it. The cert is a DEV artifact — bench/tls/ is gitignored.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TLS_DIR="$HERE/tls"
CERT="$TLS_DIR/server-cert.pem"
KEY="$TLS_DIR/server-key.pem"
SAN="$TLS_DIR/san.cnf"

mkdir -p "$TLS_DIR"

# Reuse an existing cert if it is present AND still valid for at least one more day.
if [ -f "$CERT" ] && [ -f "$KEY" ] && openssl x509 -in "$CERT" -checkend 86400 -noout >/dev/null 2>&1; then
  echo ">> Reusing existing valid cert at $CERT"
  exit 0
fi

cat > "$SAN" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = localhost
[v3]
subjectAltName = @alt
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
[alt]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

echo ">> Generating a self-signed localhost cert (EC P-256) into $TLS_DIR ..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$KEY" -out "$CERT" \
  -days 365 -nodes -config "$SAN" >/dev/null 2>&1

echo ">> Wrote $CERT + $KEY"
