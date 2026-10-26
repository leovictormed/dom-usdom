#!/usr/bin/env bash
set -euo pipefail
# These entrypoints handle reusable wallet/RPC/TPM credentials.  Refuse shell
# tracing inherited from `bash -x`, suppress Rust panic backtraces, and prevent
# children from writing memory-bearing core dumps.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
# Drop caller-owned descriptors before any child can inherit evidence, lock or
# logging handles. Bash keeps the script itself on fd 255 and marks it CLOEXEC.
for fd_path in /proc/$$/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ "$inherited_fd" =~ ^[0-9]+$ ]] || exit 1
  ((inherited_fd > 2)) || continue
  [[ "$inherited_fd" == 255 ]] && continue
  exec {inherited_fd}>&-
done
# Prevent ambient loader/toolchain/proxy/debug settings from changing children
# that receive wallet, TPM, bearer or witness inputs.
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
  RUST_LOG RUSTFLAGS RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER \
  CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in ${!LD_@}; do unset "$inherited_name"; done
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent drill:closed-mainnet-wallet-recovery' >&2
  exit 2
fi

LAB_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPOSITORY_ROOT=$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
RUNTIME_ROOT="$LAB_ROOT/evidence/native-runtime"
WITNESS_ROOT="$LAB_ROOT/evidence/finalized-deposit-witness"
CHECKPOINT_ROOT="$LAB_ROOT/evidence/finalized-burn-source"
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"
DEPOSIT_WITNESS="$WITNESS_ROOT/finalized-deposit-witness.bin"
DEPOSIT_INDEX="$WITNESS_ROOT/finalized-deposit-witness-index.json"
CHECKPOINT_WITNESS="$CHECKPOINT_ROOT/checkpoint-witness.bin"

if [[ -z "${HOME:-}" || "$HOME" != /* || ! -d "$HOME" || -L "$HOME" \
  || $(stat -c '%u' "$HOME") != "$(id -u)" ]]; then
  printf '%s\n' 'HOME must be a current-user direct absolute directory.' >&2
  exit 1
fi

WALLET_ROOT="$HOME/.local/share/dom-usdom/mainnet-wallet"
RECOVERY="$WALLET_ROOT/recovery.usdom"
PUBLIC_IDENTITY="$WALLET_ROOT/public-identity.json"
KEYSTORE_CREDENTIAL="$WALLET_ROOT/tpm2-keystore-credential.usdom"
KEYSTORE_EVIDENCE="$WALLET_ROOT/tpm2-keystore-v1.json"
RECOVERY_OUTPUT="$WALLET_ROOT/recovery-drill-v1"
RPC_TOKEN="$HOME/.local/share/dom-usdom/mainnet-node/rpc.token"
TPM_RUNTIME="/dev/shm/dom-usdom-tpm-$(id -u)"
KEYSTORE_LOCK="$TPM_RUNTIME/keystore.lock"
for command in sha256sum cut stat cargo node realpath dirname id timeout; do command -v "$command" >/dev/null; done
NODE_BIN=$(realpath "$(command -v node)")
test -x "$NODE_BIN"; test -f "$NODE_BIN"; test ! -L "$NODE_BIN"
node_owner=$(stat -Lc '%u' "$NODE_BIN"); test "$node_owner" = 0 || test "$node_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$NODE_BIN")" = 1
node_size=$(stat -Lc '%s' "$NODE_BIN"); (( node_size > 0 && node_size <= 512 * 1024 * 1024 ))
node_mode=$(stat -Lc '%a' "$NODE_BIN"); (( (8#$node_mode & 8#022) == 0 ))
node_directory=$(dirname "$NODE_BIN"); test "$(realpath "$node_directory")" = "$node_directory"
node_directory_owner=$(stat -Lc '%u' "$node_directory"); test "$node_directory_owner" = 0 || test "$node_directory_owner" = "$(id -u)"
node_directory_mode=$(stat -Lc '%a' "$node_directory"); (( (8#$node_directory_mode & 8#022) == 0 ))
node_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$node_directory")
node_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")
node_sha256=$(sha256sum "$NODE_BIN" | cut -d ' ' -f 1)
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")" = "$node_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
assert_node_unchanged() {
  test "$(realpath "$(command -v node)")" = "$NODE_BIN"
  test "$(realpath "$node_directory")" = "$node_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")" = "$node_identity"
  test "$(sha256sum "$NODE_BIN" | cut -d ' ' -f 1)" = "$node_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")" = "$node_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
}
CARGO_BIN=$(realpath "$(command -v cargo)")
test -x "$CARGO_BIN"; test -f "$CARGO_BIN"; test ! -L "$CARGO_BIN"
cargo_owner=$(stat -Lc '%u' "$CARGO_BIN"); test "$cargo_owner" = 0 || test "$cargo_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$CARGO_BIN")" = 1
cargo_size=$(stat -Lc '%s' "$CARGO_BIN"); (( cargo_size > 0 && cargo_size <= 512 * 1024 * 1024 ))
cargo_mode=$(stat -Lc '%a' "$CARGO_BIN"); (( (8#$cargo_mode & 8#022) == 0 ))
cargo_directory=$(dirname "$CARGO_BIN"); test "$(realpath "$cargo_directory")" = "$cargo_directory"
cargo_directory_owner=$(stat -Lc '%u' "$cargo_directory"); test "$cargo_directory_owner" = 0 || test "$cargo_directory_owner" = "$(id -u)"
cargo_directory_mode=$(stat -Lc '%a' "$cargo_directory"); (( (8#$cargo_directory_mode & 8#022) == 0 ))
cargo_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$cargo_directory")
cargo_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$CARGO_BIN")
cargo_sha256=$(sha256sum "$CARGO_BIN" | cut -d ' ' -f 1)
assert_cargo_unchanged() {
 test "$(realpath "$(command -v cargo)")" = "$CARGO_BIN"; test "$(realpath "$cargo_directory")" = "$cargo_directory"
 test "$(stat -Lc '%d:%i:%u:%a' "$cargo_directory")" = "$cargo_directory_identity"; test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$CARGO_BIN")" = "$cargo_identity"
 test "$(sha256sum "$CARGO_BIN" | cut -d ' ' -f 1)" = "$cargo_sha256"; test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$CARGO_BIN")" = "$cargo_identity"
 test "$(stat -Lc '%d:%i:%u:%a' "$cargo_directory")" = "$cargo_directory_identity"
}

for tool in /usr/bin/tpm2_nvread /usr/bin/tpm2_nvreadpublic; do
  if [[ ! -x "$tool" || -L "$tool" ]]; then
    printf 'Required direct TPM2 tool is unavailable: %s\n' "$tool" >&2
    exit 1
  fi
done
if [[ ! -c /dev/tpmrm0 || ! -r /dev/tpmrm0 || ! -w /dev/tpmrm0 ]]; then
  printf '%s\n' 'The current login must have read/write access to /dev/tpmrm0.' >&2
  exit 1
fi
for directory in "$WALLET_ROOT" "$TPM_RUNTIME"; do
  if [[ ! -d "$directory" || -L "$directory" \
    || $(stat -c '%u:%a' "$directory") != "$(id -u):700" ]]; then
    printf 'Required directory is not current-user direct mode 0700: %s\n' "$directory" >&2
    exit 1
  fi
done
if [[ -e "$RECOVERY_OUTPUT" || -L "$RECOVERY_OUTPUT" ]]; then
  printf 'Recovery-drill output already exists; refusing to replace it: %s\n' "$RECOVERY_OUTPUT" >&2
  exit 1
fi
for public_input in "$MANIFEST" "$MANIFEST_PIN" "$DEPOSIT_WITNESS" "$DEPOSIT_INDEX" \
  "$CHECKPOINT_WITNESS"; do
  if [[ ! -f "$public_input" || -L "$public_input" ]]; then
    printf 'Required public evidence is missing or indirect: %s\n' "$public_input" >&2
    exit 1
  fi
done
for private_input in "$RECOVERY" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" \
  "$KEYSTORE_EVIDENCE" "$RPC_TOKEN"; do
  if [[ ! -f "$private_input" || -L "$private_input" \
    || $(stat -c '%u:%a:%h' "$private_input") != "$(id -u):600:1" ]]; then
    printf 'Required private input is not a current-user 0600 single-link file: %s\n' "$private_input" >&2
    exit 1
  fi
done
SECRET_DIRECTORY=$(mktemp -d -p /dev/shm usdom-wallet-recovery.XXXXXXXX)
chmod 0700 -- "$SECRET_DIRECTORY"
RECOVERY_PASSWORD_FILE="$SECRET_DIRECTORY/recovery-password"
STATE_PASSWORD_FILE="$SECRET_DIRECTORY/state-password"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  unset recovery_password
  if [[ "$SECRET_DIRECTORY" == /dev/shm/usdom-wallet-recovery.* \
    && -d "$SECRET_DIRECTORY" && ! -L "$SECRET_DIRECTORY" ]]; then
    assert_node_unchanged &&
      "$NODE_BIN" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$SECRET_DIRECTORY" || status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST" \
  > "$SECRET_DIRECTORY/native-usdom-v2.json"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST_PIN" \
  > "$SECRET_DIRECTORY/native-usdom-v2.manifest.sha256"
chmod 0600 -- "$SECRET_DIRECTORY/native-usdom-v2.json" \
  "$SECRET_DIRECTORY/native-usdom-v2.manifest.sha256"
MANIFEST="$SECRET_DIRECTORY/native-usdom-v2.json"
MANIFEST_PIN="$SECRET_DIRECTORY/native-usdom-v2.manifest.sha256"
IFS= read -r manifest_sha256 < "$MANIFEST_PIN"
if [[ ! "$manifest_sha256" =~ ^[0-9a-f]{64}$ \
  || $(wc -l < "$MANIFEST_PIN") -ne 1 \
  || $(sha256sum -- "$MANIFEST" | cut -d ' ' -f 1) != "$manifest_sha256" ]]; then
  printf '%s\n' 'Native runtime manifest does not match its exact SHA-256 pin.' >&2
  exit 1
fi
fixed_input_commitment() {
  sha256sum -- "$MANIFEST" "$MANIFEST_PIN" "$DEPOSIT_WITNESS" "$DEPOSIT_INDEX" \
    "$CHECKPOINT_WITNESS" "$RECOVERY" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" \
    "$KEYSTORE_EVIDENCE" "$RPC_TOKEN" | sha256sum | cut -d ' ' -f 1
}
input_commitment=$(fixed_input_commitment)
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Wallet recovery drill requires an interactive terminal.' >&2
  exit 2
fi

cd "$REPOSITORY_ROOT"
assert_cargo_unchanged
CC_BIN=$(realpath "$(command -v cc)"); test -f "$CC_BIN"; test -x "$CC_BIN"; test ! -L "$CC_BIN"
cc_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$CC_BIN"); cc_sha256=$(sha256sum "$CC_BIN"|cut -d ' ' -f 1)
FD_EXEC="$SECRET_DIRECTORY/usdom-fd-exec"
FD_EXEC_SOURCE="$SECRET_DIRECTORY/usdom-fd-exec.c"
FD_EXEC_SOURCE_SHA256=e3eacf90ba359bc4baa1c43a05c244367b1c5d3488d623624ac0a606a176f3ed
"$NODE_BIN" -e 'require("fs").copyFileSync(process.argv[1],process.argv[2])' \
  "$LAB_ROOT/tools/usdom-fd-exec.c" "$FD_EXEC_SOURCE"
test "$(sha256sum "$FD_EXEC_SOURCE"|cut -d ' ' -f 1)" = "$FD_EXEC_SOURCE_SHA256"
unset LD_PRELOAD LD_LIBRARY_PATH
"$CC_BIN" -O2 -Wall -Wextra -Werror "$FD_EXEC_SOURCE" -lcrypto -o "$FD_EXEC"
test "$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$CC_BIN")" = "$cc_identity"
test "$(sha256sum "$CC_BIN"|cut -d ' ' -f 1)" = "$cc_sha256"
test "$(sha256sum "$FD_EXEC_SOURCE"|cut -d ' ' -f 1)" = "$FD_EXEC_SOURCE_SHA256"
run_pinned_timeout --signal=TERM --kill-after=30s 3600s "$CARGO_BIN" build --quiet --release --locked -p dom-node \
  --features usdom-wallet-operator \
  --bin dom-usdom-wallet-tpm-keystore \
  --bin dom-usdom-recover-wallet-at-checkpoint </dev/null
assert_cargo_unchanged
keystore_binary="$REPOSITORY_ROOT/target/release/dom-usdom-wallet-tpm-keystore"
recovery_binary="$REPOSITORY_ROOT/target/release/dom-usdom-recover-wallet-at-checkpoint"
for built_binary in "$keystore_binary" "$recovery_binary"; do
  test -f "$built_binary"; test -x "$built_binary"; test ! -L "$built_binary"
  test "$(realpath "$built_binary")" = "$built_binary"
  test "$(stat -Lc '%h' "$built_binary")" = 1
  built_owner=$(stat -Lc '%u' "$built_binary")
  test "$built_owner" = 0 || test "$built_owner" = "$(id -u)"
  built_mode=$(stat -Lc '%a' "$built_binary"); (( (8#$built_mode & 8#022) == 0 ))
done
built_binary_directory=$(dirname "$keystore_binary")
test "$built_binary_directory" = "$(dirname "$recovery_binary")"
test "$(realpath "$built_binary_directory")" = "$built_binary_directory"
built_directory_owner=$(stat -Lc '%u' "$built_binary_directory")
test "$built_directory_owner" = 0 || test "$built_directory_owner" = "$(id -u)"
built_directory_mode=$(stat -Lc '%a' "$built_binary_directory"); (( (8#$built_directory_mode & 8#022) == 0 ))
built_binary_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$built_binary_directory")
keystore_binary_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$keystore_binary")
recovery_binary_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$recovery_binary")
keystore_binary_sha256=$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)
recovery_binary_sha256=$(sha256sum -- "$recovery_binary" | cut -d ' ' -f 1)

IFS= read -r -s -p 'Native USDOM recovery password: ' recovery_password
printf '\n' >&2
printf '%s' "$recovery_password" > "$RECOVERY_PASSWORD_FILE"
chmod 0600 -- "$RECOVERY_PASSWORD_FILE"
unset recovery_password
exec </dev/null

test "$(fixed_input_commitment)" = "$input_commitment"
test -f "$keystore_binary"; test -x "$keystore_binary"; test ! -L "$keystore_binary"
test "$(realpath "$keystore_binary")" = "$keystore_binary"
test "$(stat -Lc '%d:%i:%u:%a' "$built_binary_directory")" = "$built_binary_directory_identity"
test "$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$keystore_binary")" = "$keystore_binary_identity"
test "$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)" = "$keystore_binary_sha256"
run_pinned_timeout --signal=TERM --kill-after=5s 300s "$FD_EXEC" "$REPOSITORY_ROOT" \
  "target/release/dom-usdom-wallet-tpm-keystore" "$keystore_binary_sha256" -- unlock \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --recovery-file "$RECOVERY" \
  --public-identity-file "$PUBLIC_IDENTITY" \
  --recovery-password-file "$RECOVERY_PASSWORD_FILE" \
  --credential-file "$KEYSTORE_CREDENTIAL" \
  --keystore-lock-file "$KEYSTORE_LOCK" \
  --evidence-file "$KEYSTORE_EVIDENCE" \
  --output-password-file "$STATE_PASSWORD_FILE"

test "$(fixed_input_commitment)" = "$input_commitment"
test -f "$recovery_binary"; test -x "$recovery_binary"; test ! -L "$recovery_binary"
test "$(realpath "$recovery_binary")" = "$recovery_binary"
test "$(stat -Lc '%d:%i:%u:%a' "$built_binary_directory")" = "$built_binary_directory_identity"
test "$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$recovery_binary")" = "$recovery_binary_identity"
test "$(sha256sum -- "$recovery_binary" | cut -d ' ' -f 1)" = "$recovery_binary_sha256"
test ! -e "$RECOVERY_OUTPUT"; test ! -L "$RECOVERY_OUTPUT"
run_pinned_timeout --signal=TERM --kill-after=5s 300s "$FD_EXEC" "$REPOSITORY_ROOT" \
  "target/release/dom-usdom-recover-wallet-at-checkpoint" "$recovery_binary_sha256" -- \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --deposit-witness-file "$DEPOSIT_WITNESS" \
  --deposit-witness-index-file "$DEPOSIT_INDEX" \
  --checkpoint-witness-file "$CHECKPOINT_WITNESS" \
  --recovery-file "$RECOVERY" \
  --recovery-password-file "$RECOVERY_PASSWORD_FILE" \
  --state-password-file "$STATE_PASSWORD_FILE" \
  --rpc-token-file "$RPC_TOKEN" \
  --output-directory "$RECOVERY_OUTPUT"
test -d "$RECOVERY_OUTPUT"; test ! -L "$RECOVERY_OUTPUT"
test "$(stat -c '%u' "$RECOVERY_OUTPUT")" = "$(id -u)"
recovery_mode=$(stat -c '%a' "$RECOVERY_OUTPUT")
((8#$recovery_mode & 077)) && { printf '%s\n' 'Recovery-drill output mode is unsafe.' >&2; exit 1; }
