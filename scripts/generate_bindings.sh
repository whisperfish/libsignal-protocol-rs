#!/bin/sh

SCRIPT=$(readlink -f $0)
PROJECT_DIR=$(dirname $(dirname $SCRIPT))
SYS_CRATE="$PROJECT_DIR/libsignal-protocol-sys"
C_LIBRARY="$SYS_CRATE/libsignal-protocol-c"
WRAPPER_H="$PROJECT_DIR/libsignal-protocol-sys/wrapper.h"

exec bindgen $WRAPPER_H \
--blacklist-function "fingerprint_generator_create" \
--blacklist-type "_.*" \
--whitelist-function "alice_.*" \
--whitelist-function "bob_.*" \
--whitelist-function "ciphertext_.*" \
--whitelist-function "curve_.*" \
--whitelist-function "device_.*" \
--whitelist-function "displayable_.*" \
--whitelist-function "ec_.*" \
--whitelist-function "fingerprint_.*" \
--whitelist-function "group_cipher_.*" \
--whitelist-function "group_session_.*" \
--whitelist-function "hkdf_.*" \
--whitelist-function "pre_key_.*" \
--whitelist-function "ratchet_.*" \
--whitelist-function "ratcheting_.*" \
--whitelist-function "scannable_.*" \
--whitelist-function "sender_.*" \
--whitelist-function "session_.*" \
--whitelist-function "signal_.*" \
--whitelist-function "symmetric_.*" \
--whitelist-var "CIPHERTEXT_.*" \
--whitelist-var "CURVE_.*" \
--whitelist-var "KEY_EXCHANGE_.*" \
--whitelist-var "PRE_KEY_.*" \
--whitelist-var "RATCHET_.*" \
--whitelist-var "SG_.*" \
-- \
"-I$C_LIBRARY/src" > "$SYS_CRATE/bindings.rs"