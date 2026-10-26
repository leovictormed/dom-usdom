#!/usr/bin/env bash
set -euo pipefail
# These entrypoints handle reusable wallet/RPC/TPM credentials.  Refuse shell
# tracing inherited from `bash -x`, suppress Rust panic backtraces, and prevent
# children from writing memory-bearing core dumps.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
# Prevent caller-owned descriptors and ambient loader/debug/proxy settings from
# reaching binaries that receive recovery, wallet, proof and TPM credentials.
for fd_path in /proc/$$/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ "$inherited_fd" =~ ^[0-9]+$ ]] || exit 1
  ((inherited_fd > 2)) || continue
  [[ "$inherited_fd" == 255 ]] && continue
  exec {inherited_fd}>&-
done
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
  printf '%s\n' 'Usage: npm run --silent prepare:closed-mainnet-private-burn' >&2
  exit 2
fi

LAB_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPOSITORY_ROOT=$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
RUNTIME_ROOT="$LAB_ROOT/evidence/native-runtime"
WITNESS_ROOT="$LAB_ROOT/evidence/finalized-deposit-witness"
if [[ -z "${HOME:-}" ]]; then
  printf '%s\n' 'HOME must be a current-user direct absolute directory.' >&2
  exit 1
fi
if [[ "$HOME" != /* || ! -d "$HOME" || -L "$HOME" \
  || $(stat -c '%u' "$HOME") != "$(id -u)" ]]; then
  printf '%s\n' 'HOME must be a current-user direct absolute directory.' >&2
  exit 1
fi
WALLET_ROOT="$HOME/.local/share/dom-usdom/mainnet-wallet"
RECOVERY="$WALLET_ROOT/recovery.usdom"
PUBLIC_IDENTITY="$WALLET_ROOT/public-identity.json"
KEYSTORE_CREDENTIAL="$WALLET_ROOT/tpm2-keystore-credential.usdom"
KEYSTORE_EVIDENCE="$WALLET_ROOT/tpm2-keystore-v1.json"
TPM_RUNTIME="/dev/shm/dom-usdom-tpm-$(id -u)"
KEYSTORE_LOCK="$TPM_RUNTIME/keystore.lock"
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"
WITNESS="$WITNESS_ROOT/finalized-deposit-witness.bin"
OBSERVED_STATE="$WALLET_ROOT/observed-state-v1"
PROVING_KEY="$WALLET_ROOT/spend-proving-key.bin"
PROVING_KEY_PIN="$WALLET_ROOT/spend-proving-key.sha256"
OUTPUT_STATE="$WALLET_ROOT/prepared-burn-state-v1"

command -v cast >/dev/null
for command in cargo sha256sum find sort xargs cut stat realpath dirname id; do command -v "$command" >/dev/null; done
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
for directory in "$WALLET_ROOT" "$OBSERVED_STATE" "$TPM_RUNTIME"; do
  if [[ ! -d "$directory" || -L "$directory" \
    || $(stat -c '%u' "$directory") != "$(id -u)" ]]; then
    printf 'Wallet directory is not current-user owner-only: %s\n' "$directory" >&2
    exit 1
  fi
  directory_mode=$(stat -c '%a' "$directory")
  if ((8#$directory_mode & 077)); then
    printf 'Wallet directory is not current-user owner-only: %s\n' "$directory" >&2
    exit 1
  fi
done
for file in "$RECOVERY" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE"; do
  if [[ ! -f "$file" || -L "$file" \
    || $(stat -c '%u:%a:%h' "$file") != "$(id -u):600:1" ]]; then
    printf 'Wallet keystore input is not a current-user 0600 file: %s\n' "$file" >&2
    exit 1
  fi
done
for file in "$MANIFEST" "$MANIFEST_PIN" "$WITNESS"; do
  if [[ ! -f "$file" || -L "$file" || $(stat -c '%h' "$file") != 1 ]]; then
    printf 'Missing direct single-link input: %s\n' "$file" >&2
    exit 1
  fi
done
for file in "$PROVING_KEY" "$PROVING_KEY_PIN"; do
  if [[ ! -f "$file" || -L "$file" \
    || $(stat -c '%u' "$file") != "$(id -u)" \
    || $(stat -c '%h' "$file") != 1 ]]; then
    printf 'Proving-key input is not a current-user owner-only direct file: %s\n' "$file" >&2
    exit 1
  fi
  file_mode=$(stat -c '%a' "$file")
  if ((8#$file_mode & 077)); then
    printf 'Proving-key input is not a current-user owner-only direct file: %s\n' "$file" >&2
    exit 1
  fi
done
if [[ -e "$OUTPUT_STATE" || -L "$OUTPUT_STATE" ]]; then
  printf 'Prepared burn state already exists; refusing to replace it: %s\n' "$OUTPUT_STATE" >&2
  exit 1
fi
SECRET_DIRECTORY=$(mktemp -d -p /dev/shm usdom-private-burn.XXXXXXXX)
chmod 0700 -- "$SECRET_DIRECTORY"
RECOVERY_PASSWORD_FILE="$SECRET_DIRECTORY/recovery-password"
STATE_PASSWORD_FILE="$SECRET_DIRECTORY/state-password"
RECIPIENT_FILE="$SECRET_DIRECTORY/recipient"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  unset recovery_password
  if [[ "$SECRET_DIRECTORY" == /dev/shm/usdom-private-burn.* \
    && -d "$SECRET_DIRECTORY" && ! -L "$SECRET_DIRECTORY" ]]; then
    find "$SECRET_DIRECTORY" -depth -delete 2>/dev/null || true
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
node "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST" \
  > "$SECRET_DIRECTORY/native-usdom-v2.json"
node "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST_PIN" \
  > "$SECRET_DIRECTORY/native-usdom-v2.manifest.sha256"
chmod 0600 -- "$SECRET_DIRECTORY/native-usdom-v2.json" \
  "$SECRET_DIRECTORY/native-usdom-v2.manifest.sha256"
MANIFEST="$SECRET_DIRECTORY/native-usdom-v2.json"
MANIFEST_PIN="$SECRET_DIRECTORY/native-usdom-v2.manifest.sha256"

IFS= read -r manifest_sha256 < "$MANIFEST_PIN"
IFS= read -r proving_key_sha256 < "$PROVING_KEY_PIN"
if [[ ! "$manifest_sha256" =~ ^[0-9a-f]{64}$ \
  || $(wc -l < "$MANIFEST_PIN") -ne 1 \
  || $(sha256sum -- "$MANIFEST" | cut -d ' ' -f 1) != "$manifest_sha256" ]]; then
  printf '%s\n' 'Native runtime manifest does not match its exact SHA-256 pin.' >&2
  exit 1
fi
if [[ ! "$proving_key_sha256" =~ ^[0-9a-f]{64}$ \
  || $(wc -l < "$PROVING_KEY_PIN") -ne 1 \
  || $(sha256sum -- "$PROVING_KEY" | cut -d ' ' -f 1) != "$proving_key_sha256" ]]; then
  printf '%s\n' 'Spend proving key does not match its exact SHA-256 pin.' >&2
  exit 1
fi
observed_state_commitment() {
  (cd "$OBSERVED_STATE" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) \
    | sha256sum | cut -d ' ' -f 1
}
fixed_input_commitment() {
  {
    sha256sum -- "$RECOVERY" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" \
      "$KEYSTORE_EVIDENCE" "$MANIFEST" "$MANIFEST_PIN" "$WITNESS" \
      "$PROVING_KEY" "$PROVING_KEY_PIN"
    observed_state_commitment
  } | sha256sum | cut -d ' ' -f 1
}
if find "$OBSERVED_STATE" -type l -o -type f ! -links 1 | grep -q .; then
  printf '%s\n' 'Observed wallet state contains a symbolic link or multiply-linked file.' >&2
  exit 1
fi
input_commitment=$(fixed_input_commitment)
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Private-burn preparation requires an interactive terminal.' >&2
  exit 2
fi

cd "$REPOSITORY_ROOT"
assert_cargo_unchanged
"$CARGO_BIN" build --quiet --release --locked -p dom-node \
  --features usdom-wallet-operator \
  --bin dom-usdom-wallet-tpm-keystore \
  --bin dom-usdom-build-private-burn
assert_cargo_unchanged
keystore_binary="$REPOSITORY_ROOT/target/release/dom-usdom-wallet-tpm-keystore"
builder_binary="$REPOSITORY_ROOT/target/release/dom-usdom-build-private-burn"
keystore_binary_sha256=$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)
builder_binary_sha256=$(sha256sum -- "$builder_binary" | cut -d ' ' -f 1)

test "$(fixed_input_commitment)" = "$input_commitment"
FIRST_RECIPIENT=$(cast wallet address --ledger)
SECOND_RECIPIENT=$(cast wallet address --ledger)
if [[ ! "$FIRST_RECIPIENT" =~ ^0x[0-9a-fA-F]{40}$ \
  || "$FIRST_RECIPIENT" != "$SECOND_RECIPIENT" ]]; then
  printf '%s\n' 'Ledger returned a missing, malformed or unstable redemption address.' >&2
  exit 1
fi

printf '%s\n' "$FIRST_RECIPIENT" > "$RECIPIENT_FILE"
chmod 0600 -- "$RECIPIENT_FILE"
IFS= read -r -s -p 'Native USDOM recovery password: ' recovery_password
printf '\n' >&2
printf '%s' "$recovery_password" > "$RECOVERY_PASSWORD_FILE"
chmod 0600 -- "$RECOVERY_PASSWORD_FILE"
unset recovery_password
exec </dev/null

test "$(fixed_input_commitment)" = "$input_commitment"
test "$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)" = "$keystore_binary_sha256"
"$keystore_binary" unlock \
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
test "$(sha256sum -- "$builder_binary" | cut -d ' ' -f 1)" = "$builder_binary_sha256"
test ! -e "$OUTPUT_STATE"; test ! -L "$OUTPUT_STATE"
"$builder_binary" \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --deposit-witness-file "$WITNESS" \
  --wallet-state-directory "$OBSERVED_STATE" \
  --password-file "$STATE_PASSWORD_FILE" \
  --proving-key-file "$PROVING_KEY" \
  --proving-key-sha256 "$proving_key_sha256" \
  --recipient-file "$RECIPIENT_FILE" \
  --output-directory "$OUTPUT_STATE"
test -d "$OUTPUT_STATE"; test ! -L "$OUTPUT_STATE"
test "$(stat -c '%u' "$OUTPUT_STATE")" = "$(id -u)"
output_mode=$(stat -c '%a' "$OUTPUT_STATE")
((8#$output_mode & 077)) && { printf '%s\n' 'Prepared burn output mode is unsafe.' >&2; exit 1; }
while IFS= read -r -d '' output_entry; do
  if [[ -d "$output_entry" && ! -L "$output_entry" ]]; then
    test "$(stat -c '%u' "$output_entry")" = "$(id -u)"
    entry_mode=$(stat -c '%a' "$output_entry"); (( (8#$entry_mode & 077) == 0 ))
  elif [[ -f "$output_entry" && ! -L "$output_entry" ]]; then
    test "$(stat -c '%u:%h' "$output_entry")" = "$(id -u):1"
    entry_mode=$(stat -c '%a' "$output_entry"); (( (8#$entry_mode & 077) == 0 ))
  else
    printf 'Prepared burn output contains an unsafe entry: %s\n' "$output_entry" >&2
    exit 1
  fi
done < <(find "$OUTPUT_STATE" -mindepth 1 -print0)
