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
# Never resolve credential-bearing helpers from an operator-controlled PATH.
# In particular, sha256sum reads recovery and TPM credential files below.
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/home/leonardov/.foundry/bin:/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent bootstrap:closed-mainnet-tpm-authority' >&2
  exit 2
fi

LAB_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPOSITORY_ROOT=$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
pin_runtime_tool cargo
cargo() { assert_runtime_tool cargo; "$cargo_bin" "$@"; }
RUNTIME_ROOT="$LAB_ROOT/evidence/native-runtime"
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"

if [[ -z "${HOME:-}" || "$HOME" != /* || ! -d "$HOME" || -L "$HOME" \
  || $(stat -c '%u' "$HOME") != "$(id -u)" ]]; then
  printf '%s\n' 'HOME must be a current-user direct absolute directory.' >&2
  exit 1
fi

WALLET_ROOT="$HOME/.local/share/dom-usdom/mainnet-wallet"
RECOVERY_FILE="$WALLET_ROOT/recovery.usdom"
PUBLIC_IDENTITY="$WALLET_ROOT/public-identity.json"
KEYSTORE_CREDENTIAL="$WALLET_ROOT/tpm2-keystore-credential.usdom"
KEYSTORE_EVIDENCE="$WALLET_ROOT/tpm2-keystore-v1.json"
REGISTERED_STATE="$WALLET_ROOT/registered-state-v1"
OBSERVED_STATE="$WALLET_ROOT/observed-state-v1"
PREPARED_STATE="$WALLET_ROOT/prepared-burn-state-v1"
CREDENTIAL_FILE="$WALLET_ROOT/tpm2-authority-credential.usdom"
EVIDENCE_FILE="$WALLET_ROOT/tpm2-authority-bootstrap-v1.json"
TPM_RUNTIME="/dev/shm/dom-usdom-tpm-$(id -u)"
AUTHORITY_LOCK="$TPM_RUNTIME/authority.lock"
KEYSTORE_LOCK="$TPM_RUNTIME/keystore.lock"

for command in node realpath stat dirname sha256sum cut id timeout; do command -v "$command" >/dev/null; done
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
TPM_TOOLS=(/usr/bin/tpm2_nvdefine /usr/bin/tpm2_nvread /usr/bin/tpm2_nvreadpublic /usr/bin/tpm2_nvwrite)
TPM_TOOL_IDENTITIES=()
TPM_TOOL_PARENT_IDENTITIES=()
TPM_TOOL_HASHES=()
for tool in "${TPM_TOOLS[@]}"; do
  if [[ ! -x "$tool" || -L "$tool" ]]; then
    printf 'Required direct TPM2 tool is unavailable: %s\n' "$tool" >&2
    exit 1
  fi
  tool_size=$(stat -Lc '%s' "$tool"); (( tool_size > 0 && tool_size <= 64 * 1024 * 1024 ))
  tool_owner=$(stat -Lc '%u' "$tool"); [[ $tool_owner == 0 || $tool_owner == "$(id -u)" ]]
  [[ $(stat -Lc '%h' "$tool") == 1 ]]
  tool_mode=$(stat -Lc '%a' "$tool"); (( (8#$tool_mode & 8#022) == 0 ))
  tool_parent=$(dirname "$tool"); [[ $(realpath "$tool_parent") == "$tool_parent" ]]
  parent_owner=$(stat -Lc '%u' "$tool_parent"); [[ $parent_owner == 0 || $parent_owner == "$(id -u)" ]]
  parent_mode=$(stat -Lc '%a' "$tool_parent"); (( (8#$parent_mode & 8#022) == 0 ))
  TPM_TOOL_IDENTITIES+=("$(stat -Lc '%d:%i:%s:%Y:%Z' "$tool")")
  TPM_TOOL_PARENT_IDENTITIES+=("$(stat -Lc '%d:%i:%u:%a' "$tool_parent")")
  TPM_TOOL_HASHES+=("$(sha256sum "$tool" | cut -d ' ' -f 1)")
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$tool") == "${TPM_TOOL_IDENTITIES[-1]}" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$tool_parent") == "${TPM_TOOL_PARENT_IDENTITIES[-1]}" ]]
done
assert_tpm_tools_unchanged() {
  local index tool tool_parent
  for index in "${!TPM_TOOLS[@]}"; do
    tool=${TPM_TOOLS[$index]}; tool_parent=$(dirname "$tool")
    [[ $(realpath "$tool_parent") == "$tool_parent" ]]
    [[ $(stat -Lc '%d:%i:%u:%a' "$tool_parent") == "${TPM_TOOL_PARENT_IDENTITIES[$index]}" ]]
    [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$tool") == "${TPM_TOOL_IDENTITIES[$index]}" ]]
    [[ $(sha256sum "$tool" | cut -d ' ' -f 1) == "${TPM_TOOL_HASHES[$index]}" ]]
    [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$tool") == "${TPM_TOOL_IDENTITIES[$index]}" ]]
    [[ $(stat -Lc '%d:%i:%u:%a' "$tool_parent") == "${TPM_TOOL_PARENT_IDENTITIES[$index]}" ]]
  done
}
if [[ ! -c /dev/tpmrm0 || ! -r /dev/tpmrm0 || ! -w /dev/tpmrm0 ]]; then
  printf '%s\n' 'The current login must have read/write access to /dev/tpmrm0.' >&2
  exit 1
fi
for directory in "$WALLET_ROOT" "$REGISTERED_STATE" "$OBSERVED_STATE" "$PREPARED_STATE"; do
  if [[ ! -d "$directory" || -L "$directory" \
    || $(stat -c '%u' "$directory") != "$(id -u)" ]]; then
    printf 'Wallet directory is not a current-user owner-only direct directory: %s\n' "$directory" >&2
    exit 1
  fi
  directory_mode=$(stat -c '%a' "$directory")
  if ((8#$directory_mode & 077)); then
    printf 'Wallet directory is not current-user owner-only: %s\n' "$directory" >&2
    exit 1
  fi
done
for output in "$CREDENTIAL_FILE" "$EVIDENCE_FILE"; do
  if [[ -e "$output" || -L "$output" ]]; then
    printf 'TPM authority output already exists; refusing to replace it: %s\n' "$output" >&2
    exit 1
  fi
done
for required in "$RECOVERY_FILE" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE"; do
  if [[ ! -f "$required" || -L "$required" \
    || $(stat -c '%u:%a:%h' "$required") != "$(id -u):600:1" ]]; then
    printf 'Required TPM keystore input is not a current-user 0600 file: %s\n' "$required" >&2
    exit 1
  fi
done
SECRET_DIRECTORY=$(mktemp -d -p /dev/shm usdom-tpm-bootstrap.XXXXXXXX)
chmod 0700 -- "$SECRET_DIRECTORY"
SECRET_DIRECTORY_IDENTITY=$(stat -c '%u:%d:%i:%a' "$SECRET_DIRECTORY")
RECOVERY_PASSWORD_FILE="$SECRET_DIRECTORY/recovery-password"
STATE_PASSWORD_FILE="$SECRET_DIRECTORY/state-password"
OWNER_AUTH_FILE="$SECRET_DIRECTORY/tpm-owner-auth"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  unset recovery_password tpm_owner_authorization
  if [[ "$SECRET_DIRECTORY" == /dev/shm/usdom-tpm-bootstrap.* \
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
    # The TPM bootstrap may erase only the secret directory it created.
    status=1
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
state_tree_commitment() {
  local directory unsafe_entries="$SECRET_DIRECTORY/unsafe-state-tree-entries"
  for directory in "$REGISTERED_STATE" "$OBSERVED_STATE" "$PREPARED_STATE"; do
    : > "$unsafe_entries"
    chmod 0600 -- "$unsafe_entries"
    # The former `find -type f` commitment silently omitted symlinks, device
    # nodes, sockets and hard-linked files.  Refuse every uncommitted entry so
    # an attacker cannot change the state tree without changing its digest.
    (cd "$directory" && find . -mindepth 1 \
      \( -type d -o \( -type f -links 1 \) \) -user "$(id -u)" ! -perm /022 \
      -o -print0 > "$unsafe_entries")
    if [[ -s "$unsafe_entries" ]]; then
      printf 'Native state tree contains an unsafe or uncommitted entry: %s\n' "$directory" >&2
      return 1
    fi
    (cd "$directory" && find . -type f -links 1 -print0 | sort -z | xargs -0 -r sha256sum)
  done | sha256sum | cut -d ' ' -f 1
}
fixed_input_commitment() {
  sha256sum -- "$MANIFEST" "$MANIFEST_PIN" "$RECOVERY_FILE" "$PUBLIC_IDENTITY" \
    "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE" | sha256sum | cut -d ' ' -f 1
}
tpm_tool_commitment() {
  sha256sum -- "${TPM_TOOLS[@]}" | sha256sum | cut -d ' ' -f 1
}
input_commitment=$(fixed_input_commitment)
states_commitment=$(state_tree_commitment)
tpm_tools_sha256=$(tpm_tool_commitment)
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'TPM authority bootstrap requires an interactive terminal.' >&2
  exit 2
fi

if [[ ! -e "$TPM_RUNTIME" ]]; then
  mkdir -m 0700 -- "$TPM_RUNTIME"
fi
if [[ ! -d "$TPM_RUNTIME" || -L "$TPM_RUNTIME" \
  || $(stat -c '%u' "$TPM_RUNTIME") != "$(id -u)" \
  || $(stat -c '%a' "$TPM_RUNTIME") != 700 ]]; then
  printf '%s\n' 'TPM runtime directory is not a direct current-user 0700 directory.' >&2
  exit 1
fi

cd "$REPOSITORY_ROOT"
run_pinned_timeout --signal=TERM --kill-after=30s 3600s cargo build --quiet --release --locked --offline --no-default-features -p dom-node \
  --features usdom-wallet-operator \
  --bin dom-usdom-wallet-tpm-keystore \
  --bin dom-usdom-bootstrap-tpm-wallet-authority </dev/null
keystore_binary="$REPOSITORY_ROOT/target/release/dom-usdom-wallet-tpm-keystore"
bootstrap_binary="$REPOSITORY_ROOT/target/release/dom-usdom-bootstrap-tpm-wallet-authority"
for binary in "$keystore_binary" "$bootstrap_binary"; do
  test -x "$binary"; test ! -L "$binary"
done
keystore_binary_sha256=$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)
bootstrap_binary_sha256=$(sha256sum -- "$bootstrap_binary" | cut -d ' ' -f 1)

IFS= read -r -s -p 'Native USDOM recovery password: ' recovery_password
printf '\n' >&2
printf '%s' "$recovery_password" > "$RECOVERY_PASSWORD_FILE"
chmod 0600 -- "$RECOVERY_PASSWORD_FILE"
unset recovery_password
IFS= read -r -s -p 'TPM owner authorization (press Enter if unset): ' tpm_owner_authorization
printf '\n' >&2
printf '%s' "$tpm_owner_authorization" > "$OWNER_AUTH_FILE"
chmod 0600 -- "$OWNER_AUTH_FILE"
unset tpm_owner_authorization
exec </dev/null

test "$(fixed_input_commitment)" = "$input_commitment"
test "$(state_tree_commitment)" = "$states_commitment"
assert_tpm_tools_unchanged
test "$(tpm_tool_commitment)" = "$tpm_tools_sha256"
test "$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)" = "$keystore_binary_sha256"
run_pinned_timeout --signal=TERM --kill-after=5s 300s "$keystore_binary" unlock \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --recovery-file "$RECOVERY_FILE" \
  --public-identity-file "$PUBLIC_IDENTITY" \
  --recovery-password-file "$RECOVERY_PASSWORD_FILE" \
  --credential-file "$KEYSTORE_CREDENTIAL" \
  --keystore-lock-file "$KEYSTORE_LOCK" \
  --evidence-file "$KEYSTORE_EVIDENCE" \
  --output-password-file "$STATE_PASSWORD_FILE"

test "$(fixed_input_commitment)" = "$input_commitment"
test "$(state_tree_commitment)" = "$states_commitment"
assert_tpm_tools_unchanged
test "$(tpm_tool_commitment)" = "$tpm_tools_sha256"
test "$(sha256sum -- "$bootstrap_binary" | cut -d ' ' -f 1)" = "$bootstrap_binary_sha256"
for output in "$CREDENTIAL_FILE" "$EVIDENCE_FILE"; do
  test ! -e "$output"; test ! -L "$output"
done
run_pinned_timeout --signal=TERM --kill-after=5s 300s "$bootstrap_binary" \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --registered-state-directory "$REGISTERED_STATE" \
  --observed-state-directory "$OBSERVED_STATE" \
  --prepared-state-directory "$PREPARED_STATE" \
  --password-file "$STATE_PASSWORD_FILE" \
  --owner-auth-file "$OWNER_AUTH_FILE" \
  --credential-file "$CREDENTIAL_FILE" \
  --authority-lock-file "$AUTHORITY_LOCK" \
  --evidence-file "$EVIDENCE_FILE"
for output in "$CREDENTIAL_FILE" "$EVIDENCE_FILE"; do
  test -f "$output"; test ! -L "$output"
  test "$(stat -c '%u:%a:%h' "$output")" = "$(id -u):600:1"
done
