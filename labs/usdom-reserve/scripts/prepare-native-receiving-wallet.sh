#!/usr/bin/env bash
# These entrypoints handle reusable wallet/RPC/TPM credentials.  Refuse shell
# tracing inherited from `bash -x`, suppress Rust panic backtraces, and prevent
# children from writing memory-bearing core dumps.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
set -euo pipefail
set +o history 2>/dev/null || true
unset HISTFILE BASH_ENV ENV CDPATH \
  LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
  PYTHONPATH PYTHONHOME PERL5LIB RUBYLIB GEM_HOME BUNDLE_GEMFILE \
  SSH_AUTH_SOCK SSH_AGENT_PID GPG_AGENT_INFO \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
export HISTFILE=/dev/null
for fd_path in /proc/$$/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ $inherited_fd =~ ^[0-9]+$ ]] || exit 1
  (( inherited_fd <= 2 )) && continue
  [[ $inherited_fd == 255 ]] && continue
  exec {inherited_fd}>&-
done
unset fd_path inherited_fd
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'This command accepts no arguments or secret overrides.' >&2
  exit 2
fi

SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
RESERVE_DIRECTORY=$(CDPATH='' cd -- "$SCRIPT_DIRECTORY/.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout; do command -v "$tool_boundary_command" >/dev/null; done
source "$RESERVE_DIRECTORY/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
REPOSITORY=$(CDPATH='' cd -- "$RESERVE_DIRECTORY/../.." && pwd -P)
RELEASE_CONFIG="$RESERVE_DIRECTORY/config/proof-reserve.unconfigured.json"
REQUIREMENTS="$RESERVE_DIRECTORY/config/production-requirements.json"

if [[ -z "${HOME:-}" || "$HOME" != /* || ! -d "$HOME" || -L "$HOME" \
  || $(stat -c '%u' "$HOME") != "$(id -u)" ]]; then
  printf '%s\n' 'HOME must be a current-user direct absolute directory.' >&2
  exit 1
fi

for command_name in jq cargo python3 node realpath stat sha256sum dirname id; do
  command -v "$command_name" >/dev/null
done
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
umask 077
export LC_ALL=C
command -v timeout >/dev/null

SECRET_DIRECTORY=$(mktemp -d -p /dev/shm usdom-wallet-passphrase.XXXXXX)
chmod 0700 -- "$SECRET_DIRECTORY"
SECRET_DIRECTORY_IDENTITY=$(stat -c '%u:%d:%i:%a' "$SECRET_DIRECTORY")
PASSWORD_FILE="$SECRET_DIRECTORY/password"
RAW_OUTPUT="$SECRET_DIRECTORY/public-output"
RELEASE_CONFIG_SNAPSHOT="$SECRET_DIRECTORY/release-config.json"
REQUIREMENTS_SNAPSHOT="$SECRET_DIRECTORY/production-requirements.json"
BACKUP_SNAPSHOT="$SECRET_DIRECTORY/recovery.usdom"
IDENTITY_SNAPSHOT="$SECRET_DIRECTORY/public-identity.json"
CANDIDATE_IDENTITY="$SECRET_DIRECTORY/candidate-public-identity.json"
PUBLIC_OBSERVATION="$SECRET_DIRECTORY/observation-public"
PRIVATE_OBSERVATION="$SECRET_DIRECTORY/observation-private"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  unset PASSPHRASE_FIRST PASSPHRASE_SECOND
  if [[ "$SECRET_DIRECTORY" == /dev/shm/usdom-wallet-passphrase.* \
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
    # Do not erase a pathname that was replaced after collecting passphrases.
    status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

capture_public() {
  assert_node_unchanged
  "$NODE_BIN" "$SCRIPT_DIRECTORY/read-release-config-file-stdout.mjs" "$1" > "$2"
}
capture_private() {
  assert_node_unchanged
  "$NODE_BIN" "$SCRIPT_DIRECTORY/read-private-file-stdout.mjs" "$1" > "$2"
}
assert_public_unchanged() {
  local source=$1 snapshot=$2
  capture_public "$source" "$PUBLIC_OBSERVATION"
  cmp -s -- "$snapshot" "$PUBLIC_OBSERVATION"
  rm -f -- "$PUBLIC_OBSERVATION"
}
assert_private_unchanged() {
  local source=$1 snapshot=$2
  capture_private "$source" "$PRIVATE_OBSERVATION"
  cmp -s -- "$snapshot" "$PRIVATE_OBSERVATION"
  rm -f -- "$PRIVATE_OBSERVATION"
}

capture_public "$RELEASE_CONFIG" "$RELEASE_CONFIG_SNAPSHOT"
capture_public "$REQUIREMENTS" "$REQUIREMENTS_SNAPSHOT"

DOM_DOMAIN=$(jq -er '
  .domDomain
  | select(type == "string" and test("^0x[0-9a-f]{64}$"))
  | ltrimstr("0x")
' "$RELEASE_CONFIG_SNAPSHOT")
PRIVACY_POLICY_HASH=$(jq -er '
  .native_privacy_policy_hash
  | select(type == "string" and test("^[0-9a-f]{64}$"))
' "$REQUIREMENTS_SNAPSHOT")

PRIVATE_ROOT="$HOME/.local/share/dom-usdom"
WALLET_DIRECTORY="$PRIVATE_ROOT/mainnet-wallet"
python3 "$SCRIPT_DIRECTORY/ensure-private-child-directory.py" "$PRIVATE_ROOT" mainnet-wallet

BACKUP_FILE="$WALLET_DIRECTORY/recovery.usdom"
IDENTITY_FILE="$WALLET_DIRECTORY/public-identity.json"
if [[ -e "$BACKUP_FILE" || -L "$BACKUP_FILE" ]]; then
  if ! capture_private "$BACKUP_FILE" "$BACKUP_SNAPSHOT"; then
    printf '%s\n' 'Existing wallet backup is not a direct owner-only 0600 file.' >&2
    exit 1
  fi
  if [[ -e "$IDENTITY_FILE" || -L "$IDENTITY_FILE" ]]; then
    if ! capture_private "$IDENTITY_FILE" "$IDENTITY_SNAPSHOT"; then
      printf '%s\n' 'Existing public identity is not a direct owner-only 0600 file.' >&2
      exit 1
    fi
    EXPECTED_ADDRESS=$(jq -er '
      .recipientAddress
      | select(type == "string" and test("^[0-9a-f]{208}$"))
    ' "$IDENTITY_SNAPSHOT")
  else
    # A crash after the durable backup was created but before its public
    # identity was installed is recoverable from the authenticated backup.
    EXPECTED_ADDRESS=
  fi
  ACTION=verify
else
  if [[ -e "$IDENTITY_FILE" || -L "$IDENTITY_FILE" ]]; then
    printf '%s\n' 'Public identity exists without its wallet backup.' >&2
    exit 1
  fi
  EXPECTED_ADDRESS=
  ACTION=create
fi

cd "$REPOSITORY"
assert_cargo_unchanged
CC_BIN=$(realpath "$(command -v cc)"); test -f "$CC_BIN"; test -x "$CC_BIN"; test ! -L "$CC_BIN"
cc_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$CC_BIN"); cc_sha256=$(sha256sum "$CC_BIN"|cut -d ' ' -f 1)
FD_EXEC="$SECRET_DIRECTORY/usdom-fd-exec"
FD_EXEC_SOURCE="$SECRET_DIRECTORY/usdom-fd-exec.c"
FD_EXEC_SOURCE_SHA256=e3eacf90ba359bc4baa1c43a05c244367b1c5d3488d623624ac0a606a176f3ed
"$NODE_BIN" -e 'require("fs").copyFileSync(process.argv[1],process.argv[2])' \
  "$RESERVE_DIRECTORY/tools/usdom-fd-exec.c" "$FD_EXEC_SOURCE"
test "$(sha256sum "$FD_EXEC_SOURCE"|cut -d ' ' -f 1)" = "$FD_EXEC_SOURCE_SHA256"
"$CC_BIN" -O2 -Wall -Wextra -Werror "$FD_EXEC_SOURCE" -lcrypto -o "$FD_EXEC"
test "$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$CC_BIN")" = "$cc_identity"
test "$(sha256sum "$CC_BIN"|cut -d ' ' -f 1)" = "$cc_sha256"
test "$(sha256sum "$FD_EXEC_SOURCE"|cut -d ' ' -f 1)" = "$FD_EXEC_SOURCE_SHA256"
run_pinned_timeout --signal=TERM --kill-after=30s 3600s "$CARGO_BIN" build --locked --release -p dom-usdom-wallet --features recovery-cli \
  --bin dom-usdom-wallet-recovery
assert_cargo_unchanged
WALLET_RECOVERY_BIN="$REPOSITORY/target/release/dom-usdom-wallet-recovery"
test -f "$WALLET_RECOVERY_BIN"; test -x "$WALLET_RECOVERY_BIN"; test ! -L "$WALLET_RECOVERY_BIN"
test "$(realpath "$WALLET_RECOVERY_BIN")" = "$WALLET_RECOVERY_BIN"
wallet_recovery_directory=$(dirname "$WALLET_RECOVERY_BIN")
test "$(realpath "$wallet_recovery_directory")" = "$wallet_recovery_directory"
wallet_recovery_directory_owner=$(stat -Lc '%u' "$wallet_recovery_directory")
test "$wallet_recovery_directory_owner" = 0 || test "$wallet_recovery_directory_owner" = "$(id -u)"
wallet_recovery_directory_mode=$(stat -Lc '%a' "$wallet_recovery_directory")
(( (8#$wallet_recovery_directory_mode & 8#022) == 0 ))
wallet_recovery_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$wallet_recovery_directory")
test "$(stat -Lc '%h' "$WALLET_RECOVERY_BIN")" = 1
wallet_recovery_owner=$(stat -Lc '%u' "$WALLET_RECOVERY_BIN")
test "$wallet_recovery_owner" = 0 || test "$wallet_recovery_owner" = "$(id -u)"
wallet_recovery_mode=$(stat -Lc '%a' "$WALLET_RECOVERY_BIN")
(( (8#$wallet_recovery_mode & 8#022) == 0 ))
wallet_recovery_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$WALLET_RECOVERY_BIN")
wallet_recovery_sha256=$(sha256sum -- "$WALLET_RECOVERY_BIN" | cut -d ' ' -f 1)
assert_wallet_recovery_binary_unchanged() {
  test -f "$WALLET_RECOVERY_BIN"; test -x "$WALLET_RECOVERY_BIN"; test ! -L "$WALLET_RECOVERY_BIN"
  test "$(realpath "$WALLET_RECOVERY_BIN")" = "$WALLET_RECOVERY_BIN"
  test "$(stat -Lc '%d:%i:%u:%a' "$wallet_recovery_directory")" = "$wallet_recovery_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' "$WALLET_RECOVERY_BIN")" = "$wallet_recovery_identity"
  test "$(sha256sum -- "$WALLET_RECOVERY_BIN" | cut -d ' ' -f 1)" = "$wallet_recovery_sha256"
}
assert_public_unchanged "$RELEASE_CONFIG" "$RELEASE_CONFIG_SNAPSHOT"
assert_public_unchanged "$REQUIREMENTS" "$REQUIREMENTS_SNAPSHOT"

if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Wallet passphrase entry requires an interactive terminal.' >&2
  exit 2
fi
read -r -s -p 'Digite a senha forte do backup USDOM: ' PASSPHRASE_FIRST
printf '\n' >&2
read -r -s -p 'Repita a senha do backup USDOM: ' PASSPHRASE_SECOND
printf '\n' >&2
if [[ "$PASSPHRASE_FIRST" != "$PASSPHRASE_SECOND" ]]; then
  printf '%s\n' 'As senhas não coincidem.' >&2
  exit 1
fi
if ((${#PASSPHRASE_FIRST} < 16 || ${#PASSPHRASE_FIRST} > 1024)); then
  printf '%s\n' 'A senha deve conter de 16 a 1024 bytes.' >&2
  exit 1
fi
printf '%s\n' "$PASSPHRASE_FIRST" > "$PASSWORD_FILE"
chmod 0600 -- "$PASSWORD_FILE"
unset PASSPHRASE_FIRST PASSPHRASE_SECOND

BACKUP_INPUT="$BACKUP_FILE"
if [[ "$ACTION" == verify ]]; then
  BACKUP_INPUT="$BACKUP_SNAPSHOT"
fi
COMMAND=(
  "$FD_EXEC" "$REPOSITORY" "target/release/dom-usdom-wallet-recovery" "$wallet_recovery_sha256" --
  "$ACTION"
  --backup-file "$BACKUP_INPUT"
  --password-file "$PASSWORD_FILE"
  --dom-domain "$DOM_DOMAIN"
  --privacy-policy-hash "$PRIVACY_POLICY_HASH"
)
if [[ "$ACTION" == verify ]]; then
  if [[ -n "$EXPECTED_ADDRESS" ]]; then
    COMMAND+=(--expected-address "$EXPECTED_ADDRESS")
  fi
fi
assert_wallet_recovery_binary_unchanged
run_pinned_timeout --signal=TERM --kill-after=5s 300s "${COMMAND[@]}" > "$RAW_OUTPUT"

if [[ "$ACTION" == create ]]; then
  capture_private "$BACKUP_FILE" "$BACKUP_SNAPSHOT"
fi
assert_public_unchanged "$RELEASE_CONFIG" "$RELEASE_CONFIG_SNAPSHOT"
assert_public_unchanged "$REQUIREMENTS" "$REQUIREMENTS_SNAPSHOT"
assert_private_unchanged "$BACKUP_FILE" "$BACKUP_SNAPSHOT"
if [[ -s "$IDENTITY_SNAPSHOT" ]]; then
  assert_private_unchanged "$IDENTITY_FILE" "$IDENTITY_SNAPSHOT"
fi

field() {
  local name=$1
  sed -n "s/^${name}: //p" "$RAW_OUTPUT"
}
STATUS=$(field status)
OUTPUT_DOMAIN=$(field dom_domain)
OUTPUT_POLICY=$(field privacy_policy_hash)
CHAIN_SCALAR=$(field chain_scalar)
RECEIVING_COMMITMENT=$(field receiving_commitment)
RECIPIENT_ADDRESS=$(field recipient_address)
[[ "$STATUS" == valid ]]
[[ "$OUTPUT_DOMAIN" == "$DOM_DOMAIN" ]]
[[ "$OUTPUT_POLICY" == "$PRIVACY_POLICY_HASH" ]]
[[ "$CHAIN_SCALAR" =~ ^[0-9a-f]{64}$ && "$CHAIN_SCALAR" != $(printf '0%.0s' {1..64}) ]]
[[ "$RECEIVING_COMMITMENT" =~ ^[0-9a-f]{64}$ \
   && "$RECEIVING_COMMITMENT" != $(printf '0%.0s' {1..64}) ]]
[[ "$RECIPIENT_ADDRESS" =~ ^[0-9a-f]{208}$ ]]

jq -n \
  --arg schema usdom-native-receiving-wallet-public-v1 \
  --arg domDomain "0x$OUTPUT_DOMAIN" \
  --arg privacyPolicyHash "0x$OUTPUT_POLICY" \
  --arg chainScalar "0x$CHAIN_SCALAR" \
  --arg receivingCommitment "0x$RECEIVING_COMMITMENT" \
  --arg recipientAddress "$RECIPIENT_ADDRESS" \
  '{schema:$schema,domDomain:$domDomain,privacyPolicyHash:$privacyPolicyHash,
    chainScalar:$chainScalar,receivingCommitment:$receivingCommitment,
    recipientAddress:$recipientAddress}' \
  > "$CANDIDATE_IDENTITY"

assert_public_unchanged "$RELEASE_CONFIG" "$RELEASE_CONFIG_SNAPSHOT"
assert_public_unchanged "$REQUIREMENTS" "$REQUIREMENTS_SNAPSHOT"
assert_private_unchanged "$BACKUP_FILE" "$BACKUP_SNAPSHOT"
if [[ -s "$IDENTITY_SNAPSHOT" ]]; then
  assert_private_unchanged "$IDENTITY_FILE" "$IDENTITY_SNAPSHOT"
fi
assert_node_unchanged
"$NODE_BIN" "$SCRIPT_DIRECTORY/install-private-file-immutable-stdin.mjs" "$IDENTITY_FILE" \
  < "$CANDIDATE_IDENTITY"
assert_private_unchanged "$IDENTITY_FILE" "$CANDIDATE_IDENTITY"
assert_private_unchanged "$BACKUP_FILE" "$BACKUP_SNAPSHOT"
assert_public_unchanged "$RELEASE_CONFIG" "$RELEASE_CONFIG_SNAPSHOT"
assert_public_unchanged "$REQUIREMENTS" "$REQUIREMENTS_SNAPSHOT"
cat -- "$CANDIDATE_IDENTITY"
