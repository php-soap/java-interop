#!/usr/bin/env bash
#
# (Re)generates the shared crypto material used by BOTH interop peers: the Java oracle (WSS4J) and
# the PHP middleware. Pure openssl, idempotent — safe to re-run; it overwrites in place.
#
# Output (all under this certs/ dir):
#   ca.key / ca.crt              the shared CA (trust anchor for both sides)
#   php-client.key / .crt        leaf the PHP middleware signs/decrypts with (loaded as PEM)
#   php-client.pem               php-client cert + key + CA chain in one PEM (PHP convenience)
#   php-client.p12               php-client leaf as PKCS12
#   java-server.key / .crt       leaf the Java oracle signs/decrypts with
#   ec-client.key / .crt / .pem  EC P-256 leaf for the ECDSA-SHA256 interop axis (both sides trust it)
#   interop.p12                  oracle keystore: java-server key/cert + CA trust
#   interop-recipients.p12       oracle keystore the server loads: java-server key + CA trust
#                                + php-client CERT (encrypt recipient + SKI/IssuerSerial resolution)
#                                + ec-client KEY (so the oracle can sign/verify ECDSA-SHA256)
#   untrusted-ca.* / untrusted-client.* / untrusted.p12   issued by a DIFFERENT CA, for negative tests
#
# Both real leaves are issued by the same CA, so each side trusts the other's signature.
#
# Requirements: openssl. A few PKCS12 trusted-cert entries (the CA alias and the php-client
# recipient cert) need keytool, because openssl cannot write aliased trusted-cert bags a Java
# KeyStore will read back. This script uses a host keytool if one is on PATH with a working JRE,
# otherwise it transparently falls back to keytool inside the maven:3-eclipse-temurin-17 image
# (so it works on a host with openssl + docker but no JDK). Everything else is pure openssl.
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${CERT_DIR}"

STOREPASS="${STOREPASS:-changeit}"
DAYS="${DAYS:-3650}"
MVN_IMG="${MVN_IMG:-maven:3-eclipse-temurin-17}"

# keytool wrapper: native if it can actually run, else via docker (the cert dir is the cwd, mounted).
KEYTOOL_MODE=""
detect_keytool() {
  if command -v keytool >/dev/null 2>&1 && keytool -help >/dev/null 2>&1; then
    KEYTOOL_MODE="native"
  elif command -v docker >/dev/null 2>&1; then
    KEYTOOL_MODE="docker"
  else
    KEYTOOL_MODE="none"
  fi
}
keytool_run() { # all args after the keystore path are relative to CERT_DIR
  case "${KEYTOOL_MODE}" in
    native) keytool "$@" ;;
    docker) docker run --rm -v "${CERT_DIR}:/certs" -w /certs "${MVN_IMG}" keytool "$@" ;;
    *) return 1 ;;
  esac
}

gen_ca() { # <name> <cn>
  local name="$1" cn="$2"
  openssl genrsa -out "${name}.key" 4096
  openssl req -x509 -new -nodes -key "${name}.key" -sha256 -days "${DAYS}" \
    -subj "/C=BE/O=php-soap interop/CN=${cn}" \
    -out "${name}.crt"
}

gen_leaf() { # <name> <cn> <ca>
  local name="$1" cn="$2" ca="$3"
  openssl genrsa -out "${name}.key" 2048
  openssl req -new -key "${name}.key" \
    -subj "/C=BE/O=php-soap interop/CN=${cn}" \
    -out "${name}.csr"
  openssl x509 -req -in "${name}.csr" -CA "${ca}.crt" -CAkey "${ca}.key" -CAcreateserial \
    -days "${DAYS}" -sha256 -out "${name}.crt"
  rm -f "${name}.csr"
}

gen_ec_leaf() { # <name> <cn> <ca>  — EC P-256 leaf for the ECDSA-SHA256 interop axis
  local name="$1" cn="$2" ca="$3"
  openssl ecparam -name prime256v1 -genkey -noout -out "${name}.key"
  openssl req -new -key "${name}.key" \
    -subj "/C=BE/O=php-soap interop/CN=${cn}" \
    -out "${name}.csr"
  openssl x509 -req -in "${name}.csr" -CA "${ca}.crt" -CAkey "${ca}.key" -CAcreateserial \
    -days "${DAYS}" -sha256 -out "${name}.crt"
  rm -f "${name}.csr"
}

import_cert() { # <p12> <alias> <cert.crt>  — add an aliased trusted-cert entry (Merlin needs the alias)
  local p12="$1" alias="$2" cert="$3"
  keytool_run -importcert -noprompt -trustcacerts \
    -alias "${alias}" -file "${cert}" \
    -keystore "${p12}" -storetype PKCS12 -storepass "${STOREPASS}" 2>/dev/null \
    || echo "    (${alias} already present in ${p12}, or keytool unavailable — continuing)"
}

detect_keytool
if [ "${KEYTOOL_MODE}" = "none" ]; then
  echo "ERROR: need keytool (a JDK on PATH) or docker to build the aliased PKCS12 trust entries." >&2
  exit 1
fi
echo "==> keytool mode: ${KEYTOOL_MODE}"

echo "==> 1. Shared CA"
gen_ca ca "php-soap interop CA"

echo "==> 2. PHP client leaf (PHP middleware signs/decrypts with this)"
gen_leaf php-client "php-soap client" ca
# Combined PEM (cert + key + CA) for PHP setups that load a single file.
cat php-client.crt php-client.key ca.crt > php-client.pem
openssl pkcs12 -export -inkey php-client.key -in php-client.crt -certfile ca.crt \
  -name php-client -passout "pass:${STOREPASS}" -out php-client.p12

echo "==> 3. Java server leaf (Java oracle signs/decrypts with this)"
gen_leaf java-server "java-server" ca

echo "==> 4. Oracle keystore (interop.p12): java-server key/cert + CA trust"
rm -f interop.p12
openssl pkcs12 -export -inkey java-server.key -in java-server.crt -certfile ca.crt \
  -name java-server -passout "pass:${STOREPASS}" -out interop.p12
import_cert interop.p12 interop-ca ca.crt

echo "==> 5. Oracle recipients keystore (interop-recipients.p12): + php-client CERT"
# Same as interop.p12 but also holds the php-client certificate as an aliased entry, so the oracle can
# (a) name it as the encrypt recipient and (b) resolve a php-signed message's SKI/IssuerSerial KeyInfo.
rm -f interop-recipients.p12
openssl pkcs12 -export \
  -inkey java-server.key -in java-server.crt -certfile ca.crt \
  -name java-server -passout "pass:${STOREPASS}" -out interop-recipients.p12
import_cert interop-recipients.p12 interop-ca ca.crt
import_cert interop-recipients.p12 php-client php-client.crt

echo "==> 5b. EC client leaf (ECDSA-SHA256 axis): EC P-256 key, CA-signed"
# An elliptic-curve leaf issued by the shared CA so both stacks trust an ECDSA signature. The PHP side
# signs/verifies with ec-client.pem; the oracle signs/verifies with the ec-client entry in its keystore.
gen_ec_leaf ec-client "php-soap ec client" ca
cat ec-client.crt ec-client.key ca.crt > ec-client.pem
# Add the EC key (for the oracle to sign ECDSA) and cert (recipient/SKI resolution) to the recipients store.
rm -f ec-client.p12
openssl pkcs12 -export -inkey ec-client.key -in ec-client.crt -certfile ca.crt \
  -name ec-client -passout "pass:${STOREPASS}" -out ec-client.p12
# Merge the ec-client key entry into the oracle keystore so a single Crypto can sign with java-server (RSA)
# or ec-client (ECDSA), selected per request by alias.
keytool_run -importkeystore -noprompt \
  -srckeystore ec-client.p12 -srcstoretype PKCS12 -srcstorepass "${STOREPASS}" -srcalias ec-client \
  -destkeystore interop-recipients.p12 -deststoretype PKCS12 -deststorepass "${STOREPASS}" -destalias ec-client \
  2>/dev/null || echo "    (ec-client already present in interop-recipients.p12, or keytool unavailable — continuing)"

echo "==> 6. Untrusted CA + client (negative tests: signer the oracle must reject)"
gen_ca untrusted-ca "php-soap untrusted CA"
gen_leaf untrusted-client "php-soap untrusted client" untrusted-ca
cat untrusted-client.crt untrusted-client.key untrusted-ca.crt > untrusted-client.pem
openssl pkcs12 -export -inkey untrusted-client.key -in untrusted-client.crt -certfile untrusted-ca.crt \
  -name untrusted-client -passout "pass:${STOREPASS}" -out untrusted.p12

echo
echo "Done. Files in ${CERT_DIR}:"
ls -1 "${CERT_DIR}" | grep -vE '\.srl$'
echo
echo "PHP side loads:  certs/php-client.pem (or php-client.key + php-client.crt + ca.crt)"
echo "Oracle loads:    certs/interop-recipients.p12 (storepass=${STOREPASS}) + certs/ca.crt"
