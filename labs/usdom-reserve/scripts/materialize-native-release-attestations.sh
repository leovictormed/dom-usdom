#!/usr/bin/env bash
set -euo pipefail
# RPC source files can contain reusable provider credentials.  Keep child
# process memory out of tracing, panic backtraces and core artifacts.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing RPC operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE=<absolute-owner-only-file> npm run --silent materialize:native-release-attestations' >&2
  exit 64
fi
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required}"
for command in node jq sha256sum stat realpath mktemp flock sync mv cmp id chmod awk; do command -v "$command" >/dev/null; done
pin_tool() {
 local name=$1 path parent owner mode size parent_owner parent_mode identity_name parent_identity_name
 path=$(realpath "$(command -v "$name")"); [[ -x $path && -f $path && ! -L $path ]]
 owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]; [[ $(stat -Lc '%h' "$path") == 1 ]]
 size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 )); mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
 parent=$(dirname "$path"); [[ $(realpath "$parent") == "$parent" ]]; parent_owner=$(stat -Lc '%u' "$parent"); [[ $parent_owner == 0 || $parent_owner == "$(id -u)" ]]
 parent_mode=$(stat -Lc '%a' "$parent"); (( (8#$parent_mode & 8#022) == 0 ))
 printf -v "${name}_bin" '%s' "$path"; printf -v "${name}_identity" '%s' "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"; printf -v "${name}_parent_identity" '%s' "$(stat -Lc '%d:%i:%u:%a' "$parent")"; printf -v "${name}_sha256" '%s' "$(sha256sum "$path" | cut -d ' ' -f 1)"
 identity_name="${name}_identity"; parent_identity_name="${name}_parent_identity"; [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" && $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
}
assert_tool_unchanged() {
 local name=$1 bin_name="${1}_bin" identity_name="${1}_identity" parent_identity_name="${1}_parent_identity" sha_name="${1}_sha256" path parent; path=${!bin_name}; parent=$(dirname "$path")
 [[ $(realpath "$(command -v "$name")") == "$path" && $(realpath "$parent") == "$parent" && $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
 [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" && $(sha256sum "$path" | cut -d ' ' -f 1) == "${!sha_name}" && $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
}
pin_tool node; pin_tool jq
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
config_directory="$project/config"
metadata="$config_directory/mainnet-release-evidence.unconfigured.json"
output="$project/evidence/native-attestations"
safe_bundle="$project/evidence/control-plane/safe-control-release-evidence-bundle.json"
test -f "$metadata"; test ! -L "$metadata"
test -f "$safe_bundle"; test ! -L "$safe_bundle"
test -d "$output"; test ! -L "$output"; test "$(stat -c '%u:%a' "$output")" = "$(id -u):700"
signatures=(native-privacy-trusted-setup native-scheduled-runtime-activation native-wallet-custody native-wallet-recovery)
for name in "${signatures[@]}"; do
  file="$output/$name-signature.hex"
  test -f "$file"; test ! -L "$file"; test "$(stat -c '%u:%a:%h' "$file")" = "$(id -u):600:1"
done
exec 8<"$config_directory"
flock -n 8 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
exec 9<"$output"
flock -n 9 || { printf '%s\n' 'Another native-attestation writer holds the lock' >&2; exit 75; }
temporary=$(mktemp -d -p "$output" .materialize.XXXXXXXX)
cleanup() { local status=${1:-$?}; trap - EXIT; assert_tool_unchanged node && "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary" || status=1; exit "$status"; }
trap 'cleanup $?' EXIT
snapshot_private() {
  assert_tool_unchanged node
  "$node_bin" "$project/scripts/read-private-file-stdout.mjs" "$1" > "$2"
  chmod 0600 "$2"
}
snapshot_public() {
  assert_tool_unchanged node
  "$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$1" > "$2"
  chmod 0600 "$2"
}
release_config="$config_directory/proof-reserve.unconfigured.json"
request="$output/native-release-attestation-requests.json"
metadata_snapshot="$temporary/mainnet-release-evidence.input.json"
release_config_snapshot="$temporary/proof-reserve.input.json"
request_snapshot="$temporary/native-release-attestation-requests.input.json"
safe_bundle_snapshot="$temporary/safe-control-release-evidence-bundle.input.json"
snapshot_public "$metadata" "$metadata_snapshot"
snapshot_public "$release_config" "$release_config_snapshot"
snapshot_private "$request" "$request_snapshot"
snapshot_private "$safe_bundle" "$safe_bundle_snapshot"
for name in "${signatures[@]}"; do
  snapshot_private "$output/$name-signature.hex" "$temporary/$name-signature.input.hex"
done
assert_inputs_unchanged() {
  snapshot_public "$metadata" "$temporary/mainnet-release-evidence.current.json"
  snapshot_public "$release_config" "$temporary/proof-reserve.current.json"
  snapshot_private "$request" "$temporary/native-release-attestation-requests.current.json"
  snapshot_private "$safe_bundle" "$temporary/safe-control-release-evidence-bundle.current.json"
  cmp -s "$metadata_snapshot" "$temporary/mainnet-release-evidence.current.json"
  cmp -s "$release_config_snapshot" "$temporary/proof-reserve.current.json"
  cmp -s "$request_snapshot" "$temporary/native-release-attestation-requests.current.json"
  cmp -s "$safe_bundle_snapshot" \
    "$temporary/safe-control-release-evidence-bundle.current.json"
  for name in "${signatures[@]}"; do
    snapshot_private "$output/$name-signature.hex" "$temporary/$name-signature.current.hex"
    cmp -s "$temporary/$name-signature.input.hex" "$temporary/$name-signature.current.hex"
  done
}
envelope="$temporary/envelope.json"
assert_tool_unchanged node
"$node_bin" "$project/scripts/check-native-release-attestation-signing-request.mjs" \
  "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
  "$metadata_snapshot" >/dev/null
assert_tool_unchanged node
"$node_bin" scripts/prepare-native-release-attestation-materialization.mjs > "$envelope"
assert_inputs_unchanged
assert_tool_unchanged jq
"$jq_bin" -e '.schema == "usdom-native-release-attestation-materialization/v1"
  and ([.observation.approvals[].valid] | all(. == true))' "$envelope" >/dev/null
declare -A json_names=(
  [nativePrivacyTrustedSetup]=native-privacy-trusted-setup.json
  [nativeScheduledRuntimeActivation]=native-scheduled-runtime-activation.json
  [nativeWalletCustody]=native-wallet-custody.json
  [nativeWalletRecovery]=native-wallet-recovery.json
)
for key in "${!json_names[@]}"; do
  assert_tool_unchanged jq
  "$jq_bin" ".attestations.$key" "$envelope" > "$temporary/${json_names[$key]}"
  chmod 0600 "$temporary/${json_names[$key]}"
done
assert_tool_unchanged jq
"$jq_bin" '.observation' "$envelope" > "$temporary/native-attestation-finalized-observation.json"
chmod 0600 "$temporary/native-attestation-finalized-observation.json"
next_metadata="$temporary/mainnet-release-evidence.json"
assert_tool_unchanged jq
"$jq_bin" \
  --arg privacy_path evidence/native-attestations/native-privacy-trusted-setup.json \
  --arg privacy_sha "$(sha256sum "$temporary/native-privacy-trusted-setup.json" | awk '{print $1}')" \
  --arg runtime_path evidence/native-attestations/native-scheduled-runtime-activation.json \
  --arg runtime_sha "$(sha256sum "$temporary/native-scheduled-runtime-activation.json" | awk '{print $1}')" \
  --arg custody_path evidence/native-attestations/native-wallet-custody.json \
  --arg custody_sha "$(sha256sum "$temporary/native-wallet-custody.json" | awk '{print $1}')" \
  --arg recovery_path evidence/native-attestations/native-wallet-recovery.json \
  --arg recovery_sha "$(sha256sum "$temporary/native-wallet-recovery.json" | awk '{print $1}')" '
  def setdoc($field;$doc):
    if .[$field] == null or .[$field] == $doc then .[$field]=$doc
    else error($field + " already contains a different document") end;
  setdoc("nativePrivacyTrustedSetupAttestationReport";{path:$privacy_path,sha256:$privacy_sha}) |
  setdoc("nativeScheduledRuntimeActivationAttestationReport";{path:$runtime_path,sha256:$runtime_sha}) |
  setdoc("nativeWalletCustodyAttestationReport";{path:$custody_path,sha256:$custody_sha}) |
  setdoc("nativeWalletRecoveryAttestationReport";{path:$recovery_path,sha256:$recovery_sha})
' "$metadata_snapshot" > "$next_metadata"
chmod 0600 "$next_metadata"
publish_immutable() {
  local source=$1 destination=$2
  sync -f "$source"
  assert_tool_unchanged node
  "$node_bin" "$project/scripts/install-private-file-immutable-stdin.mjs" "$destination" < "$source"
  sync -f "$destination"
}
publish_and_verify_immutable() {
  local source=$1 destination=$2 installed=$3
  publish_immutable "$source" "$destination"
  # Every subsequent historical write remains bound to the same complete input
  # set, and an identical retry must read back as the exact prepared document.
  assert_inputs_unchanged
  snapshot_private "$destination" "$installed"
  cmp -s "$source" "$installed"
}
verify_published_outputs() {
  local file
  for file in "${json_names[@]}"; do
    snapshot_private "$output/$file" "$temporary/$file.rechecked"
    cmp -s "$temporary/$file" "$temporary/$file.rechecked"
  done
  snapshot_private "$output/native-attestation-finalized-observation.json" \
    "$temporary/native-attestation-finalized-observation.rechecked.json"
  cmp -s "$temporary/native-attestation-finalized-observation.json" \
    "$temporary/native-attestation-finalized-observation.rechecked.json"
}
assert_inputs_unchanged
assert_tool_unchanged node
"$node_bin" "$project/scripts/check-native-release-attestation-signing-request.mjs" \
  "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
  "$metadata_snapshot" >/dev/null
# Refresh finalized EIP-1271 validity after all local document construction and
# immediately before the first immutable publication. Only the observation may
# advance; all four signed attestations must remain byte-equivalent JSON.
prepublish_envelope="$temporary/envelope.prepublish.json"
assert_tool_unchanged node
"$node_bin" scripts/prepare-native-release-attestation-materialization.mjs > "$prepublish_envelope"
assert_inputs_unchanged
assert_tool_unchanged jq
"$jq_bin" -S '.attestations' "$envelope" > "$temporary/attestations.signed.json"
assert_tool_unchanged jq
"$jq_bin" -S '.attestations' "$prepublish_envelope" > "$temporary/attestations.prepublish.signed.json"
cmp -s "$temporary/attestations.signed.json" "$temporary/attestations.prepublish.signed.json"
assert_tool_unchanged jq
"$jq_bin" -e '([.observation.approvals[].valid] | all(. == true))' \
  "$prepublish_envelope" >/dev/null
assert_tool_unchanged jq
"$jq_bin" '.observation' "$prepublish_envelope" \
  > "$temporary/native-attestation-finalized-observation.json"
chmod 0600 "$temporary/native-attestation-finalized-observation.json"
sync -f "$temporary/native-attestation-finalized-observation.json"
for file in "${json_names[@]}"; do
  publish_and_verify_immutable "$temporary/$file" "$output/$file" \
    "$temporary/$file.installed"
done
publish_and_verify_immutable "$temporary/native-attestation-finalized-observation.json" \
  "$output/native-attestation-finalized-observation.json" \
  "$temporary/native-attestation-finalized-observation.installed.json"
assert_inputs_unchanged
verify_published_outputs
# The aggregate is advanced only after every immutable attestation has been
# re-read and every signing/materialization input has survived a final recheck.
assert_inputs_unchanged
sync -f "$next_metadata"
if ! cmp -s "$next_metadata" "$metadata_snapshot"; then
  assert_tool_unchanged node
  "$node_bin" "$project/scripts/install-release-config-stdin.mjs" "$metadata" < "$next_metadata"
fi
snapshot_public "$metadata" "$temporary/mainnet-release-evidence.installed.json"
cmp -s "$next_metadata" "$temporary/mainnet-release-evidence.installed.json"
# Re-read every immutable precursor after the aggregate completion marker so a
# successful return proves one coherent five-document generation.
verify_published_outputs
sync -f "$metadata"; sync -f "$output"; sync -f "$config_directory"
assert_tool_unchanged jq
"$jq_bin" '{nativePrivacyTrustedSetupAttestationReport,nativeScheduledRuntimeActivationAttestationReport,
  nativeWalletCustodyAttestationReport,nativeWalletRecoveryAttestationReport}' "$next_metadata"
