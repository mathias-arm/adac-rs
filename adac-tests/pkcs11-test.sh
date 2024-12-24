#!/usr/bin/env bash

set -e

PKCS11_MODULE="${PKCS11_MODULE:-/opt/homebrew/lib/softhsm/libsofthsm2.so}"
PKCS11_SLOT=test-token
PKCS11_PIN=1234
PKCS11_SOPIN=4321

if [ -z "$ADAC_CLI" ] ; then \
  echo "Set ADAC_CLI variable with path to 'adac-cli' binary" ; \
  exit 1 ; \
fi

TEST_DIR=$(dirname "$0")
CFG_FILE=$(realpath "$TEST_DIR")/test-config.toml
TEST_DIR=$(realpath "$TEST_DIR")/softhsm2

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR/tokens"
cat <<EOF > "${TEST_DIR}/softhsm2.conf"
directories.tokendir = ${TEST_DIR}/tokens
objectstore.backend = file
objectstore.umask = 0077
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
export SOFTHSM2_CONF="${TEST_DIR}/softhsm2.conf"

SOFTHSM2_CONF="${SOFTHSM2_CONF}" softhsm2-util --show-slots
softhsm2-util --init-token --free --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" --so-pin "${PKCS11_SOPIN}"

# Generate Key 0
"${ADAC_CLI}" --output-format json pkcs11-keygen --key-type EcdsaP384Sha384 \
  --module "${PKCS11_MODULE}" --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" > "${TEST_DIR}/key0.json"
KEY0_ID=$(jq -r '.pkcs11_generate.kid' "${TEST_DIR}/key0.json")
jq -r '.pkcs11_generate.pem' "${TEST_DIR}/key0.json" > "${TEST_DIR}/key0.pub"

# Generate Key 1
"${ADAC_CLI}" --output-format json pkcs11-keygen --key-type EcdsaP384Sha384 \
  --module "${PKCS11_MODULE}" --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" > "${TEST_DIR}/key1.json"
KEY1_ID=$(jq -r '.pkcs11_generate.kid' "${TEST_DIR}/key1.json")
jq -r '.pkcs11_generate.pem' "${TEST_DIR}/key1.json" > "${TEST_DIR}/key1.pub"

# Generate Key 2
"${ADAC_CLI}" --output-format json pkcs11-keygen --key-type EcdsaP384Sha384 \
  --module "${PKCS11_MODULE}" --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" > "${TEST_DIR}/key2.json"
KEY2_ID=$(jq -r '.pkcs11_generate.kid' "${TEST_DIR}/key2.json")
jq -r '.pkcs11_generate.pem' "${TEST_DIR}/key2.json" > "${TEST_DIR}/key2.pub"

"${ADAC_CLI}" sign -c "${CFG_FILE}" --module "${PKCS11_MODULE}" --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" \
    -k "${KEY0_ID}" -r "${TEST_DIR}/key0.pub" -s root -o "${TEST_DIR}/root.crt"

"${ADAC_CLI}" sign -c "${CFG_FILE}" --module "${PKCS11_MODULE}" --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" \
    -k  "${KEY0_ID}" -r "${TEST_DIR}/key1.pub" -s intermediate -i "${TEST_DIR}/root.crt" -o "${TEST_DIR}/inter.crt"

### Sign Test 1 certificate
echo ""
"${ADAC_CLI}" sign -c "${CFG_FILE}" --module "${PKCS11_MODULE}" --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" \
    -k  "${KEY1_ID}" -r "${TEST_DIR}/key2.pub" -s crt1 -i "${TEST_DIR}/inter.crt" -o "${TEST_DIR}/crt1.crt"
"${ADAC_CLI}" verify -p "${TEST_DIR}/crt1.crt"

### Sign Test 2 certificate
echo ""
"${ADAC_CLI}" sign -c "${CFG_FILE}" --module "${PKCS11_MODULE}" --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" \
    -k  "${KEY1_ID}" -r "${TEST_DIR}/key2.pub" -s crt2 -i "${TEST_DIR}/inter.crt" -o "${TEST_DIR}/crt2.crt"
"${ADAC_CLI}" verify -p "${TEST_DIR}/crt2.crt"

### Sign Test 3 certificate
echo ""
"${ADAC_CLI}" sign -c "${CFG_FILE}" --module "${PKCS11_MODULE}" --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" \
    -k  "${KEY1_ID}" -r "${TEST_DIR}/key2.pub" -s crt3 -i "${TEST_DIR}/inter.crt" -o "${TEST_DIR}/crt3.crt"
"${ADAC_CLI}" verify -p "${TEST_DIR}/crt3.crt"
