#!/usr/bin/env bash

set -e

PKCS11_SLOT=test-token
PKCS11_PIN=1234
PKCS11_SOPIN=4321

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

cargo test --workspace
