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
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent register:finalized-deposit-wallet' >&2
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
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"
WITNESS="$WITNESS_ROOT/finalized-deposit-witness.bin"
WITNESS_INDEX="$WITNESS_ROOT/finalized-deposit-witness-index.json"

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
STATE_DIRECTORY="$WALLET_ROOT/registered-state-v1"
TPM_RUNTIME="/dev/shm/dom-usdom-tpm-$(id -u)"
KEYSTORE_LOCK="$TPM_RUNTIME/keystore.lock"
for command in sha256sum cut stat cmp curl cargo node realpath dirname id timeout; do command -v "$command" >/dev/null; done
NODE_BIN=$(realpath "$(command -v node)")
test -x "$NODE_BIN"; test -f "$NODE_BIN"; test ! -L "$NODE_BIN"
node_owner=$(stat -Lc '%u' "$NODE_BIN"); test "$node_owner" = 0 || test "$node_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$NODE_BIN")" = 1
node_size=$(stat -Lc '%s' "$NODE_BIN"); (( node_size > 0 && node_size <= 512 * 1024 * 1024 ))
node_mode=$(stat -Lc '%a' "$NODE_BIN"); (( (8#$node_mode & 8#022) == 0 ))
node_directory=$(dirname "$NODE_BIN")
test "$(realpath "$node_directory")" = "$node_directory"
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
CURL_BIN=$(realpath "$(command -v curl)")
test -x "$CURL_BIN"; test -f "$CURL_BIN"; test ! -L "$CURL_BIN"
curl_owner=$(stat -Lc '%u' "$CURL_BIN"); test "$curl_owner" = 0 || test "$curl_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$CURL_BIN")" = 1
curl_mode=$(stat -Lc '%a' "$CURL_BIN"); (( (8#$curl_mode & 8#022) == 0 ))
curl_directory=$(dirname "$CURL_BIN")
curl_directory_owner=$(stat -Lc '%u' "$curl_directory"); test "$curl_directory_owner" = 0 || test "$curl_directory_owner" = "$(id -u)"
curl_directory_mode=$(stat -Lc '%a' "$curl_directory"); (( (8#$curl_directory_mode & 8#022) == 0 ))
curl_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$CURL_BIN")
curl_sha256=$(sha256sum "$CURL_BIN" | cut -d ' ' -f 1)
assert_curl_unchanged() {
  test "$(realpath "$(command -v curl)")" = "$CURL_BIN"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$CURL_BIN")" = "$curl_identity"
  test "$(sha256sum "$CURL_BIN" | cut -d ' ' -f 1)" = "$curl_sha256"
}
CARGO_BIN=$(realpath "$(command -v cargo)")
test -x "$CARGO_BIN"; test -f "$CARGO_BIN"; test ! -L "$CARGO_BIN"
cargo_owner=$(stat -Lc '%u' "$CARGO_BIN"); test "$cargo_owner" = 0 || test "$cargo_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$CARGO_BIN")" = 1
cargo_size=$(stat -Lc '%s' "$CARGO_BIN"); (( cargo_size > 0 && cargo_size <= 512 * 1024 * 1024 ))
cargo_mode=$(stat -Lc '%a' "$CARGO_BIN"); (( (8#$cargo_mode & 8#022) == 0 ))
cargo_directory=$(dirname "$CARGO_BIN")
test "$(realpath "$cargo_directory")" = "$cargo_directory"
cargo_directory_owner=$(stat -Lc '%u' "$cargo_directory"); test "$cargo_directory_owner" = 0 || test "$cargo_directory_owner" = "$(id -u)"
cargo_directory_mode=$(stat -Lc '%a' "$cargo_directory"); (( (8#$cargo_directory_mode & 8#022) == 0 ))
cargo_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$cargo_directory")
cargo_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$CARGO_BIN")
cargo_sha256=$(sha256sum "$CARGO_BIN" | cut -d ' ' -f 1)
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$CARGO_BIN")" = "$cargo_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$cargo_directory")" = "$cargo_directory_identity"
assert_cargo_unchanged() {
  test "$(realpath "$(command -v cargo)")" = "$CARGO_BIN"
  test "$(realpath "$cargo_directory")" = "$cargo_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$cargo_directory")" = "$cargo_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$CARGO_BIN")" = "$cargo_identity"
  test "$(sha256sum "$CARGO_BIN" | cut -d ' ' -f 1)" = "$cargo_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$CARGO_BIN")" = "$cargo_identity"
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
if [[ ! -d "$WALLET_ROOT" || -L "$WALLET_ROOT" \
  || $(stat -c '%u:%a' "$WALLET_ROOT") != "$(id -u):700" \
  || ! -d "$TPM_RUNTIME" || -L "$TPM_RUNTIME" \
  || $(stat -c '%u:%a' "$TPM_RUNTIME") != "$(id -u):700" ]]; then
  printf '%s\n' 'Wallet and TPM runtime roots must be current-user direct mode-0700 directories.' >&2
  exit 1
fi
for required in "$WITNESS" "$WITNESS_INDEX" "$RECOVERY" "$PUBLIC_IDENTITY" \
  "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Missing direct regular file: %s\n' "$required" >&2
    exit 1
  fi
done
for private in "$RECOVERY" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE"; do
  if [[ $(stat -c '%u:%a:%h' "$private") != "$(id -u):600:1" ]]; then
    printf 'Wallet input is not a current-user 0600 single-link file: %s\n' "$private" >&2
    exit 1
  fi
done
SECRET_DIRECTORY=$(mktemp -d -p /dev/shm usdom-wallet-register.XXXXXXXX)
chmod 0700 -- "$SECRET_DIRECTORY"
RECOVERY_PASSWORD_FILE="$SECRET_DIRECTORY/recovery-password"
STATE_PASSWORD_FILE="$SECRET_DIRECTORY/state-password"
NODE_IDENTITY="$SECRET_DIRECTORY/node-identity"
NODE_IDENTITY_RECHECK="$SECRET_DIRECTORY/node-identity-recheck"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  unset recovery_password
  if [[ "$SECRET_DIRECTORY" == /dev/shm/usdom-wallet-register.* \
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
if [[ ! -f "$MANIFEST" || -L "$MANIFEST" || ! -f "$MANIFEST_PIN" || -L "$MANIFEST_PIN" ]]; then
  printf '%s\n' 'Native runtime manifest or its pin is missing.' >&2
  exit 1
fi
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
  sha256sum -- "$MANIFEST" "$MANIFEST_PIN" "$WITNESS" "$WITNESS_INDEX" \
    "$RECOVERY" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE" \
    | sha256sum | cut -d ' ' -f 1
}
input_commitment=$(fixed_input_commitment)
if [[ -e "$STATE_DIRECTORY" || -L "$STATE_DIRECTORY" ]]; then
  printf '%s\n' 'Registered wallet state already exists; refusing replacement.' >&2
  exit 1
fi
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Wallet registration requires an interactive terminal.' >&2
  exit 2
fi

cd "$REPOSITORY_ROOT"
assert_cargo_unchanged
run_pinned_timeout --signal=TERM --kill-after=30s 3600s "$CARGO_BIN" build --quiet --release --locked -p dom-node \
  --features usdom-wallet-operator \
  --bin dom-usdom-wallet-tpm-keystore \
  --bin dom-usdom-register-finalized-deposit </dev/null
assert_cargo_unchanged
keystore_binary="$REPOSITORY_ROOT/target/release/dom-usdom-wallet-tpm-keystore"
register_binary="$REPOSITORY_ROOT/target/release/dom-usdom-register-finalized-deposit"
keystore_binary_sha256=$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)
register_binary_sha256=$(sha256sum -- "$register_binary" | cut -d ' ' -f 1)

assert_curl_unchanged
"$CURL_BIN" --fail --silent --show-error --max-time 10 --max-filesize 65536 --proto '=http' \
  --output "$NODE_IDENTITY" 'http://127.0.0.1:33372/chain/identity'
assert_curl_unchanged
"$CURL_BIN" --fail --silent --show-error --max-time 10 --max-filesize 65536 --proto '=http' \
  --output "$NODE_IDENTITY_RECHECK" 'http://127.0.0.1:33372/chain/identity'
assert_curl_unchanged
cmp -s "$NODE_IDENTITY" "$NODE_IDENTITY_RECHECK"
chmod 0600 -- "$NODE_IDENTITY"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/check-dom-mainnet-identity-file.mjs" "$NODE_IDENTITY"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/check-dom-mainnet-identity-file.mjs" "$NODE_IDENTITY_RECHECK"
cmp -s "$NODE_IDENTITY" "$NODE_IDENTITY_RECHECK"
IFS= read -r -s -p 'Native USDOM recovery password: ' recovery_password
printf '\n' >&2
printf '%s' "$recovery_password" > "$RECOVERY_PASSWORD_FILE"
chmod 0600 -- "$RECOVERY_PASSWORD_FILE"
unset recovery_password
exec </dev/null

test "$(fixed_input_commitment)" = "$input_commitment"
test "$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)" = "$keystore_binary_sha256"
run_pinned_timeout --signal=TERM --kill-after=5s 300s "$keystore_binary" unlock \
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
test "$(sha256sum -- "$register_binary" | cut -d ' ' -f 1)" = "$register_binary_sha256"
test ! -e "$STATE_DIRECTORY"; test ! -L "$STATE_DIRECTORY"
run_pinned_timeout --signal=TERM --kill-after=5s 300s "$register_binary" \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --witness-file "$WITNESS" \
  --witness-index-file "$WITNESS_INDEX" \
  --recovery-file "$RECOVERY" \
  --recovery-password-file "$RECOVERY_PASSWORD_FILE" \
  --state-password-file "$STATE_PASSWORD_FILE" \
  --node-identity-file "$NODE_IDENTITY" \
  --state-directory "$STATE_DIRECTORY"
test -d "$STATE_DIRECTORY"; test ! -L "$STATE_DIRECTORY"
test "$(stat -c '%u' "$STATE_DIRECTORY")" = "$(id -u)"
state_mode=$(stat -c '%a' "$STATE_DIRECTORY")
((8#$state_mode & 077)) && { printf '%s\n' 'Registered wallet state mode is unsafe.' >&2; exit 1; }
