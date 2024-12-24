#!/usr/bin/env bash

set -e

if [ -z "$ADAC_CLI" ] ; then \
  echo "Set ADAC_CLI variable with path to 'adac-cli' binary" ; \
  exit 1 ; \
fi

TEST_DIR=$(dirname "$0")
KEYS_DIR=$(realpath "$TEST_DIR")/resources/keys
CFG_FILE=$(realpath "$TEST_DIR")/test-config.toml
TEST_DIR=$(realpath "$TEST_DIR")/offline

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

openssl pkey -in "${KEYS_DIR}/EcdsaP384Key-0.pk8" -pubout -out "${TEST_DIR}/EcdsaP384Key-0.pub" 
openssl pkey -in "${KEYS_DIR}/EcdsaP384Key-1.pk8" -pubout -out "${TEST_DIR}/EcdsaP384Key-1.pub"

# Self-signed Root CA
"${ADAC_CLI}" sign -c "${CFG_FILE}" --private "${KEYS_DIR}/EcdsaP384Key-0.pk8" \
  -r "${TEST_DIR}/EcdsaP384Key-0.pub" -s root -o "${TEST_DIR}/root.crt"

# Create pre-certificate +  TBS file + Hash file
"${ADAC_CLI}" offline-prepare -c "${CFG_FILE}" \
    -r "${TEST_DIR}/EcdsaP384Key-1.pub" -s intermediate \
    -o "${TEST_DIR}/inter-off.pre" -t "${TEST_DIR}/inter-off.tbs" --hash "${TEST_DIR}/inter-off.hash"

# Sign TBS
openssl pkeyutl -sign -in "${TEST_DIR}/inter-off.tbs" -inkey "${KEYS_DIR}/EcdsaP384Key-0.pk8" \
  -out "${TEST_DIR}/inter-off.sig" -digest sha384

# Merge TBS signature
"${ADAC_CLI}" offline-merge -i "${TEST_DIR}/root.crt" \
  --request "${TEST_DIR}/inter-off.pre" -s "${TEST_DIR}/inter-off.sig" -o "${TEST_DIR}/inter-off.crt"
"${ADAC_CLI}" verify -p "${TEST_DIR}/inter-off.crt"

# Sign Hash
openssl pkeyutl -sign -in "${TEST_DIR}/inter-off.hash" -inkey "${KEYS_DIR}/EcdsaP384Key-0.pk8" \
  -out "${TEST_DIR}/inter-off.sig" -pkeyopt digest:sha384

# Merge Hash signature
"${ADAC_CLI}" offline-merge -i "${TEST_DIR}/root.crt" \
  --request "${TEST_DIR}/inter-off.pre" -s "${TEST_DIR}/inter-off.sig" -o "${TEST_DIR}/inter-off.crt"
"${ADAC_CLI}" verify -p "${TEST_DIR}/inter-off.crt"
