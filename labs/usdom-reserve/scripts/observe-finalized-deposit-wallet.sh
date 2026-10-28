#!/usr/bin/env bash
set -euo pipefail
# These entrypoints handle reusable wallet/RPC/TPM credentials.  Refuse shell
# tracing inherited from `bash -x`, suppress Rust panic backtraces, and prevent
# children from writing memory-bearing core dumps.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
# Drop caller-owned descriptors before any child can inherit evidence, lock or
# logging handles. Bash keeps the script itself on fd 255 and marks it CLOEXEC.
for fd_path in /proc/"$$"/fd/*; do
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
  printf '%s\n' 'Usage: npm run --silent observe:finalized-deposit-wallet' >&2
  exit 2
fi

LAB_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPOSITORY_ROOT=$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
RUNTIME_ROOT="$LAB_ROOT/evidence/native-runtime"
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"
WALLET_ROOT="$HOME/.local/share/dom-usdom/mainnet-wallet"
RECOVERY="$WALLET_ROOT/recovery.usdom"
PUBLIC_IDENTITY="$WALLET_ROOT/public-identity.json"
KEYSTORE_CREDENTIAL="$WALLET_ROOT/tpm2-keystore-credential.usdom"
KEYSTORE_EVIDENCE="$WALLET_ROOT/tpm2-keystore-v1.json"
REGISTERED_STATE="$WALLET_ROOT/registered-state-v1"
OBSERVED_STATE="$WALLET_ROOT/observed-state-v1"
TOKEN_FILE="$HOME/.local/share/dom-usdom/mainnet-node/rpc.token"
TPM_RUNTIME="/dev/shm/dom-usdom-tpm-$(id -u)"
KEYSTORE_LOCK="$TPM_RUNTIME/keystore.lock"
for command in sha256sum find sort xargs cut stat cmp curl cargo node realpath dirname id timeout; do command -v "$command" >/dev/null; done
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
SECRET_DIRECTORY=$(mktemp -d -p /dev/shm usdom-wallet-observe.XXXXXXXX)
chmod 0700 -- "$SECRET_DIRECTORY"
SECRET_DIRECTORY_IDENTITY=$(stat -c '%u:%d:%i:%a' "$SECRET_DIRECTORY")
RECOVERY_PASSWORD_FILE="$SECRET_DIRECTORY/recovery-password"
STATE_PASSWORD_FILE="$SECRET_DIRECTORY/state-password"
IDENTITY_FILE="$SECRET_DIRECTORY/node-identity"
IDENTITY_RECHECK_FILE="$SECRET_DIRECTORY/node-identity-recheck"
IDENTITY_AFTER_FILE="$SECRET_DIRECTORY/node-identity-after"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  unset recovery_password
  if [[ "$SECRET_DIRECTORY" == /dev/shm/usdom-wallet-observe.* \
    && $(stat -c '%u:%d:%i:%a' "$SECRET_DIRECTORY" 2>/dev/null) == "$SECRET_DIRECTORY_IDENTITY" ]]; then
    if assert_node_unchanged &&
      run_pinned_timeout --foreground --signal=TERM --kill-after=5s 30s \
        "$NODE_BIN" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' \
        "$SECRET_DIRECTORY" > /dev/null 2> /dev/null &&
      assert_node_unchanged && assert_runtime_tool timeout && test ! -e "$SECRET_DIRECTORY"; then
      :
    else
      status=1
    fi
  else
    # A replaced path is outside this observation's cleanup authority.
    status=1
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
for directory in "$WALLET_ROOT" "$REGISTERED_STATE" "$TPM_RUNTIME"; do
  if [[ ! -d "$directory" || -L "$directory" \
    || $(stat -c '%u' "$directory") != "$(id -u)" \
    || $(stat -c '%a' "$directory") != 700 ]]; then
    printf 'Required directory is not current-user direct mode 0700: %s\n' "$directory" >&2
    exit 1
  fi
done
if [[ -e "$OBSERVED_STATE" || -L "$OBSERVED_STATE" ]]; then
  [[ -d "$OBSERVED_STATE" && ! -L "$OBSERVED_STATE" \
    && $(stat -c '%u:%a' "$OBSERVED_STATE") == "$(id -u):700" ]] || {
    printf 'Observed state is not a direct owner-only directory: %s\n' "$OBSERVED_STATE" >&2; exit 1; }
fi
for file in "$RECOVERY" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE" "$TOKEN_FILE"; do
  if [[ ! -f "$file" || -L "$file" \
    || $(stat -c '%u:%a:%h' "$file") != "$(id -u):600:1" ]]; then
    printf 'Required secret/evidence input is not a current-user 0600 file: %s\n' "$file" >&2
    exit 1
  fi
done
registered_state_commitment() {
  (cd "$REGISTERED_STATE" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) \
    | sha256sum | cut -d ' ' -f 1
}
fixed_input_commitment() {
  {
    sha256sum -- "$MANIFEST" "$MANIFEST_PIN" "$RECOVERY" "$PUBLIC_IDENTITY" \
      "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE" "$TOKEN_FILE"
    registered_state_commitment
  } | sha256sum | cut -d ' ' -f 1
}
if find "$REGISTERED_STATE" -type l -o -type f ! -links 1 | grep -q .; then
  printf '%s\n' 'Registered wallet state contains a symbolic link or multiply-linked file.' >&2
  exit 1
fi
input_commitment=$(fixed_input_commitment)
# The registered state is the durable source; observed state is derived. Make
# the prior derived generation durably absent before password entry or RPC.
assert_node_unchanged
run_pinned_timeout --foreground --signal=TERM --kill-after=5s 30s \
  "$NODE_BIN" "$LAB_ROOT/scripts/remove-private-directory-durable.mjs" "$OBSERVED_STATE" \
  > /dev/null 2> /dev/null
assert_node_unchanged
assert_runtime_tool timeout
test ! -e "$OBSERVED_STATE"
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Finalized-deposit observation requires an interactive terminal.' >&2
  exit 2
fi

cd "$REPOSITORY_ROOT"
assert_cargo_unchanged
run_pinned_timeout --signal=TERM --kill-after=30s 3600s "$CARGO_BIN" build --quiet --release --locked -p dom-node \
  --features usdom-wallet-operator \
  --bin dom-usdom-wallet-tpm-keystore \
  --bin dom-usdom-observe-finalized-deposit </dev/null
assert_cargo_unchanged
keystore_binary="$REPOSITORY_ROOT/target/release/dom-usdom-wallet-tpm-keystore"
observer_binary="$REPOSITORY_ROOT/target/release/dom-usdom-observe-finalized-deposit"
keystore_binary_sha256=$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)
observer_binary_sha256=$(sha256sum -- "$observer_binary" | cut -d ' ' -f 1)

assert_curl_unchanged
"$CURL_BIN" --fail --silent --show-error --max-time 10 --max-filesize 65536 --proto '=http' \
  --output "$IDENTITY_FILE" 'http://127.0.0.1:33372/chain/identity'
assert_curl_unchanged
"$CURL_BIN" --fail --silent --show-error --max-time 10 --max-filesize 65536 --proto '=http' \
  --output "$IDENTITY_RECHECK_FILE" 'http://127.0.0.1:33372/chain/identity'
assert_curl_unchanged
cmp -s "$IDENTITY_FILE" "$IDENTITY_RECHECK_FILE"
chmod 0600 -- "$IDENTITY_FILE"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/check-dom-mainnet-identity-file.mjs" "$IDENTITY_FILE"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/check-dom-mainnet-identity-file.mjs" "$IDENTITY_RECHECK_FILE"
cmp -s "$IDENTITY_FILE" "$IDENTITY_RECHECK_FILE"
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
test "$(sha256sum -- "$observer_binary" | cut -d ' ' -f 1)" = "$observer_binary_sha256"
test ! -e "$OBSERVED_STATE"; test ! -L "$OBSERVED_STATE"
run_pinned_timeout --signal=TERM --kill-after=5s 300s "$observer_binary" \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --password-file "$STATE_PASSWORD_FILE" \
  --rpc-token-file "$TOKEN_FILE" \
  --node-identity-file "$IDENTITY_FILE" \
  --registered-state-directory "$REGISTERED_STATE" \
  --observed-state-directory "$OBSERVED_STATE"
# Continuous mining is disabled for the closed pilot. Any identity change here
# is a reorg, replacement node or unauthorized block; reject the derived state.
assert_curl_unchanged
"$CURL_BIN" --fail --silent --show-error --max-time 10 --max-filesize 65536 --proto '=http' \
  --output "$IDENTITY_AFTER_FILE" 'http://127.0.0.1:33372/chain/identity'
assert_curl_unchanged
chmod 0600 -- "$IDENTITY_AFTER_FILE"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/check-dom-mainnet-identity-file.mjs" "$IDENTITY_AFTER_FILE"
cmp -s "$IDENTITY_FILE" "$IDENTITY_AFTER_FILE" || {
  printf '%s\n' 'DOM mainnet identity changed during finalized-deposit observation.' >&2
  exit 1
}
test -d "$OBSERVED_STATE"; test ! -L "$OBSERVED_STATE"
test "$(stat -c '%u' "$OBSERVED_STATE")" = "$(id -u)"
observed_mode=$(stat -c '%a' "$OBSERVED_STATE")
((8#$observed_mode & 077)) && { printf '%s\n' 'Observed wallet state mode is unsafe.' >&2; exit 1; }
