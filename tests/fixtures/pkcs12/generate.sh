#!/usr/bin/env bash
# Regenerates the PKCS#12 fixtures with the OpenSSL CLI, so the tests run
# against files produced by a real exporter rather than by pkijs itself.
# Every key here is a throwaway generated on the spot. Requires OpenSSL 3.x.
set -euo pipefail
cd "$(dirname "$0")"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/root.key" -out "$work/root.pem" -days 36500 \
  -subj '/CN=PFX Fixture Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/leaf.key" -out "$work/leaf.csr" \
  -subj '/CN=pfx.example.test' 2>/dev/null

openssl x509 -req -in "$work/leaf.csr" -CA "$work/root.pem" -CAkey "$work/root.key" \
  -out "$work/leaf.pem" -days 36500 -set_serial 2 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:pfx.example.test\n') \
  2>/dev/null

export_pfx() {
  local out=$1
  shift
  openssl pkcs12 -export -inkey "$work/leaf.key" -in "$work/leaf.pem" \
    -certfile "$work/root.pem" -name 'pfx fixture' -out "$out" "$@"
}

# OpenSSL 3 defaults: PBES2 (PBKDF2 + AES-256-CBC), HMAC-SHA256 MAC.
export_pfx modern.p12 -passout pass:secret
export_pfx unicode-password.p12 -passout 'pass:zażółć'
export_pfx empty-password.p12 -passout pass:
# Certificates stored in the clear; only the key is encrypted.
export_pfx plain-certs.p12 -passout pass:secret -certpbe NONE
# No MAC (and -nomac alone would drop certificate encryption too), so a wrong
# password can only show up as a failed decryption.
export_pfx no-mac.p12 -passout pass:secret -nomac -certpbe AES-256-CBC
# RC2-40 / 3DES with the PKCS#12 KDF — not supported yet.
export_pfx legacy.p12 -passout pass:secret -legacy
