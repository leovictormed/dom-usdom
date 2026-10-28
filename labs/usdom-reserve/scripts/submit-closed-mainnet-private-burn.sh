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
  printf '%s\n' 'Usage: npm run --silent submit:closed-mainnet-private-burn' >&2
  exit 2
fi

LAB_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPOSITORY_ROOT=$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
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
PREPARED_STATE="$WALLET_ROOT/prepared-burn-state-v1"
CREDENTIAL_FILE="$WALLET_ROOT/tpm2-authority-credential.usdom"
BOOTSTRAP_EVIDENCE="$WALLET_ROOT/tpm2-authority-bootstrap-v1.json"
SUBMISSION_RECEIPT="$WALLET_ROOT/private-burn-submission-v1.json"
SUBMISSION_INTENT="$WALLET_ROOT/private-burn-submission-intent-v1.json"
RPC_TOKEN="$HOME/.local/share/dom-usdom/mainnet-node/rpc.token"
TPM_RUNTIME="/dev/shm/dom-usdom-tpm-$(id -u)"
AUTHORITY_LOCK="$TPM_RUNTIME/authority.lock"
KEYSTORE_LOCK="$TPM_RUNTIME/keystore.lock"

for command in node jq sha256sum find sort xargs stat cut realpath dirname cargo id timeout; do command -v "$command" >/dev/null; done
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

for tool in /usr/bin/tpm2_nvread /usr/bin/tpm2_nvreadpublic /usr/bin/tpm2_nvwrite; do
  if [[ ! -x "$tool" || -L "$tool" ]]; then
    printf 'Required direct TPM2 tool is unavailable: %s\n' "$tool" >&2
    exit 1
  fi
done
if [[ ! -c /dev/tpmrm0 || ! -r /dev/tpmrm0 || ! -w /dev/tpmrm0 ]]; then
  printf '%s\n' 'The current login must have read/write access to /dev/tpmrm0.' >&2
  exit 1
fi
for directory in "$WALLET_ROOT" "$PREPARED_STATE" "$TPM_RUNTIME"; do
  if [[ ! -d "$directory" || -L "$directory" \
    || $(stat -c '%u' "$directory") != "$(id -u)" ]]; then
    printf 'Required directory is not a current-user direct directory: %s\n' "$directory" >&2
    exit 1
  fi
  directory_mode=$(stat -c '%a' "$directory")
  if ((8#$directory_mode & 077)); then
    printf 'Required directory is not current-user owner-only: %s\n' "$directory" >&2
    exit 1
  fi
done
for file in "$RECOVERY_FILE" "$PUBLIC_IDENTITY" "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE" \
  "$CREDENTIAL_FILE" "$BOOTSTRAP_EVIDENCE" "$RPC_TOKEN"; do
  if [[ ! -f "$file" || -L "$file" \
    || $(stat -c '%u' "$file") != "$(id -u)" \
    || $(stat -c '%a' "$file") != 600 \
    || $(stat -c '%h' "$file") != 1 ]]; then
    printf 'Required secret/evidence input is not a direct owner-only 0600 file: %s\n' "$file" >&2
    exit 1
  fi
done
if [[ -e "$SUBMISSION_RECEIPT" || -L "$SUBMISSION_RECEIPT" ]]; then
  if [[ ! -f "$SUBMISSION_RECEIPT" || -L "$SUBMISSION_RECEIPT" \
    || $(stat -c '%u' "$SUBMISSION_RECEIPT") != "$(id -u)" \
    || $(stat -c '%a' "$SUBMISSION_RECEIPT") != 600 \
    || $(stat -c '%h' "$SUBMISSION_RECEIPT") != 1 ]]; then
    printf '%s\n' 'Existing submission receipt is not a direct owner-only 0600 file.' >&2
    exit 1
  fi
fi
# Keep the immutable submission intent, but invalidate the derived receipt
# durably before reading a recovery password or issuing authenticated RPC.
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/remove-private-file-durable.mjs" "$SUBMISSION_RECEIPT"
assert_node_unchanged
SECRET_DIRECTORY=$(mktemp -d -p /dev/shm usdom-burn-submit.XXXXXXXX)
chmod 0700 -- "$SECRET_DIRECTORY"
SECRET_DIRECTORY_IDENTITY=$(stat -c '%u:%d:%i:%a' "$SECRET_DIRECTORY")
RECOVERY_PASSWORD_FILE="$SECRET_DIRECTORY/recovery-password"
STATE_PASSWORD_FILE="$SECRET_DIRECTORY/state-password"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  unset recovery_password
  if [[ "$SECRET_DIRECTORY" == /dev/shm/usdom-burn-submit.* \
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
    # Never erase a pathname that no longer names our private submission directory.
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
prepared_state_commitment() {
  (cd "$PREPARED_STATE" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) \
    | sha256sum | cut -d ' ' -f 1
}
fixed_input_commitment() {
  {
    sha256sum -- "$MANIFEST" "$MANIFEST_PIN" "$RECOVERY_FILE" "$PUBLIC_IDENTITY" \
      "$KEYSTORE_CREDENTIAL" "$KEYSTORE_EVIDENCE" "$CREDENTIAL_FILE" \
      "$BOOTSTRAP_EVIDENCE" "$RPC_TOKEN"
    prepared_state_commitment
  } | sha256sum | cut -d ' ' -f 1
}
if find "$PREPARED_STATE" -type l -o -type f ! -links 1 | grep -q .; then
  printf '%s\n' 'Prepared burn state contains a symbolic link or multiply-linked file.' >&2
  exit 1
fi
while IFS= read -r -d '' prepared_entry; do
  if [[ -d "$prepared_entry" && ! -L "$prepared_entry" ]]; then
    test "$(stat -c '%u' "$prepared_entry")" = "$(id -u)"
    entry_mode=$(stat -c '%a' "$prepared_entry"); (( (8#$entry_mode & 077) == 0 ))
  elif [[ -f "$prepared_entry" && ! -L "$prepared_entry" ]]; then
    test "$(stat -c '%u:%h' "$prepared_entry")" = "$(id -u):1"
    entry_mode=$(stat -c '%a' "$prepared_entry"); (( (8#$entry_mode & 077) == 0 ))
  else
    printf 'Prepared burn state contains an unsafe entry: %s\n' "$prepared_entry" >&2
    exit 1
  fi
done < <(find "$PREPARED_STATE" -mindepth 1 -print0)
input_commitment=$(fixed_input_commitment)
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Private-burn submission requires an interactive terminal.' >&2
  exit 2
fi

cd "$REPOSITORY_ROOT"
assert_cargo_unchanged
run_pinned_timeout --signal=TERM --kill-after=30s 3600s "$CARGO_BIN" build --quiet --release --locked -p dom-node \
  --features usdom-wallet-operator \
  --bin dom-usdom-wallet-tpm-keystore \
  --bin dom-usdom-submit-private-burn </dev/null
assert_cargo_unchanged
keystore_binary="$REPOSITORY_ROOT/target/release/dom-usdom-wallet-tpm-keystore"
submit_binary="$REPOSITORY_ROOT/target/release/dom-usdom-submit-private-burn"
keystore_binary_sha256=$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)
submit_binary_sha256=$(sha256sum -- "$submit_binary" | cut -d ' ' -f 1)

IFS= read -r -s -p 'Native USDOM recovery password: ' recovery_password
printf '\n' >&2
printf '%s' "$recovery_password" > "$RECOVERY_PASSWORD_FILE"
chmod 0600 -- "$RECOVERY_PASSWORD_FILE"
unset recovery_password
exec </dev/null

test "$(fixed_input_commitment)" = "$input_commitment"
test "$(sha256sum -- "$keystore_binary" | cut -d ' ' -f 1)" = "$keystore_binary_sha256"
if ! run_pinned_timeout --signal=TERM --kill-after=5s 300s "$keystore_binary" unlock \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --recovery-file "$RECOVERY_FILE" \
  --public-identity-file "$PUBLIC_IDENTITY" \
  --recovery-password-file "$RECOVERY_PASSWORD_FILE" \
  --credential-file "$KEYSTORE_CREDENTIAL" \
  --keystore-lock-file "$KEYSTORE_LOCK" \
  --evidence-file "$KEYSTORE_EVIDENCE" \
  --output-password-file "$STATE_PASSWORD_FILE" \
  >"$SECRET_DIRECTORY/keystore.stdout" 2>"$SECRET_DIRECTORY/keystore.stderr"; then
  printf '%s\n' 'Native wallet unlock failed; private diagnostics were suppressed.' >&2
  exit 1
fi

test "$(fixed_input_commitment)" = "$input_commitment"
test "$(sha256sum -- "$submit_binary" | cut -d ' ' -f 1)" = "$submit_binary_sha256"
intent_draft="$SECRET_DIRECTORY/submission-intent.json"
jq -n --arg inputs "$input_commitment" --arg manifest "$manifest_sha256" \
  --arg binary "$submit_binary_sha256" '{schema:"usdom-private-burn-submission-intent-v1",
    inputCommitment:$inputs,nativeManifestSha256:$manifest,submitBinarySha256:$binary,
    endpoint:"authenticated-loopback",mines:false,broadcastsEthereum:false}' > "$intent_draft"
chmod 0600 "$intent_draft"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/install-private-file-immutable-stdin.mjs" --json "$SUBMISSION_INTENT" < "$intent_draft"
test "$(fixed_input_commitment)" = "$input_commitment"
if ! run_pinned_timeout --signal=TERM --kill-after=5s 300s "$submit_binary" \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --prepared-state-directory "$PREPARED_STATE" \
  --password-file "$STATE_PASSWORD_FILE" \
  --rpc-token-file "$RPC_TOKEN" \
  --credential-file "$CREDENTIAL_FILE" \
  --authority-lock-file "$AUTHORITY_LOCK" \
  --bootstrap-evidence-file "$BOOTSTRAP_EVIDENCE" \
  --receipt-file "$SUBMISSION_RECEIPT" \
  >"$SECRET_DIRECTORY/submit.stdout" 2>"$SECRET_DIRECTORY/submit.stderr"; then
  printf '%s\n' 'Private burn submission failed; private diagnostics were suppressed.' >&2
  exit 1
fi
test -f "$SUBMISSION_RECEIPT"; test ! -L "$SUBMISSION_RECEIPT"
test "$(stat -c '%u:%a:%h' "$SUBMISSION_RECEIPT")" = "$(id -u):600:1"
jq -e --arg manifest "$manifest_sha256" \
  '.schema=="usdom-closed-mainnet-private-burn-submission-v1"
    and .native_manifest_sha256==$manifest
    and (.authority_binding|test("^[0-9a-f]{64}$"))
    and .tpm_nv_index=="0x01500020"
    and .authorized_snapshot_generation=="4"
    and (.authorized_snapshot_seal|test("^[0-9a-f]+$"))
    and (.transition_id|test("^[0-9a-f]{64}$"))
    and (.candidate_id|test("^[0-9a-f]{64}$"))
    and (.payload_sha256|test("^[0-9a-f]{64}$"))
    and .endpoint=="http://127.0.0.1:33372/"
    and .accepted==true and .state=="queued"
    and .durable_authorization_reissued_each_run==true
    and .submits_to_dom_loopback==true
    and .mines==false and .ethereum_broadcasts==false' "$SUBMISSION_RECEIPT" >/dev/null
test "$(jq -er '.transition_id' "$SUBMISSION_RECEIPT")" = \
  "$(jq -er '.transition_id' "$PREPARED_STATE/private-burn-index.json")"
test "$(jq -er '.payload_sha256' "$SUBMISSION_RECEIPT")" = \
  "$(jq -er '.payload_sha256' "$PREPARED_STATE/private-burn-index.json")"
test "$(sha256sum "$PREPARED_STATE/private-burn-payload.bin" | cut -d ' ' -f 1)" = \
  "$(jq -er '.payload_sha256' "$SUBMISSION_RECEIPT")"
