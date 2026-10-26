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
  printf '%s\n' 'Usage: USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE=<absolute-owner-only-file> npm run --silent materialize:release-authorization' >&2
  exit 64
fi
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required}"
for command in node jq stat realpath mktemp flock sync mv cmp id chmod; do command -v "$command" >/dev/null; done
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
intent_target="$config_directory/operator-intent.json"
output="$project/evidence/authorization"
signature="$output/release-authorization-signature.hex"
safe_bundle="$project/evidence/control-plane/safe-control-release-evidence-bundle.json"
for input in "$intent_target" "$output/release-authorization-request.json" "$signature" \
  "$safe_bundle"; do
  test -f "$input"; test ! -L "$input"; test "$(stat -c '%u' "$input")" = "$(id -u)"
done
test -d "$output"; test ! -L "$output"; test "$(stat -c '%a' "$output")" = 700
test "$(stat -c '%a' "$signature")" = 600
exec 8<"$config_directory"
flock -n 8 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
exec 9<"$output"
flock -n 9 || { printf '%s\n' 'Another release-authorization writer holds the lock' >&2; exit 75; }
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
release_evidence="$config_directory/mainnet-release-evidence.unconfigured.json"
release_config="$config_directory/proof-reserve.unconfigured.json"
request="$output/release-authorization-request.json"
release_evidence_snapshot="$temporary/mainnet-release-evidence.input.json"
release_config_snapshot="$temporary/proof-reserve.input.json"
intent_snapshot="$temporary/operator-intent.input.json"
request_snapshot="$temporary/release-authorization-request.input.json"
signature_snapshot="$temporary/release-authorization-signature.input.hex"
safe_bundle_snapshot="$temporary/safe-control-release-evidence-bundle.input.json"
snapshot_public "$release_evidence" "$release_evidence_snapshot"
snapshot_public "$release_config" "$release_config_snapshot"
snapshot_private "$intent_target" "$intent_snapshot"
snapshot_private "$request" "$request_snapshot"
snapshot_private "$signature" "$signature_snapshot"
snapshot_private "$safe_bundle" "$safe_bundle_snapshot"
assert_inputs_unchanged() {
  snapshot_public "$release_evidence" "$temporary/mainnet-release-evidence.current.json"
  snapshot_public "$release_config" "$temporary/proof-reserve.current.json"
  snapshot_private "$intent_target" "$temporary/operator-intent.current.json"
  snapshot_private "$request" "$temporary/release-authorization-request.current.json"
  snapshot_private "$signature" "$temporary/release-authorization-signature.current.hex"
  snapshot_private "$safe_bundle" "$temporary/safe-control-release-evidence-bundle.current.json"
  cmp -s "$release_evidence_snapshot" "$temporary/mainnet-release-evidence.current.json"
  cmp -s "$release_config_snapshot" "$temporary/proof-reserve.current.json"
  cmp -s "$intent_snapshot" "$temporary/operator-intent.current.json"
  cmp -s "$request_snapshot" "$temporary/release-authorization-request.current.json"
  cmp -s "$signature_snapshot" "$temporary/release-authorization-signature.current.hex"
  cmp -s "$safe_bundle_snapshot" \
    "$temporary/safe-control-release-evidence-bundle.current.json"
}
envelope="$temporary/envelope.json"
next_intent="$temporary/operator-intent.json"
authorization="$temporary/release-authorization.json"
observation="$temporary/release-authorization-finalized-observation.json"
assert_tool_unchanged node
"$node_bin" scripts/prepare-release-authorization-materialization.mjs > "$envelope"
assert_inputs_unchanged
assert_tool_unchanged jq
"$jq_bin" -e '.schema == "usdom-release-authorization-materialization/v1"
  and .authorization.accepted == true
  and .authorization.productionApproved == true
  and .authorization.deployAuthorized == true
  and .authorization.realFundsAuthorized == true
  and .observation.approvals.releaseAuthorization.valid == true' "$envelope" >/dev/null
assert_tool_unchanged jq
"$jq_bin" '.operatorIntent' "$envelope" > "$next_intent"
assert_tool_unchanged jq
"$jq_bin" '.authorization' "$envelope" > "$authorization"
assert_tool_unchanged jq
"$jq_bin" '.observation' "$envelope" > "$observation"
chmod 0600 "$next_intent"
chmod 0600 "$authorization" "$observation"
sync -f "$next_intent"; sync -f "$authorization"; sync -f "$observation"
publish_immutable() {
  local source=$1 destination=$2
  assert_tool_unchanged node
  "$node_bin" "$project/scripts/install-private-file-immutable-stdin.mjs" "$destination" < "$source"
  sync -f "$destination"
}
assert_inputs_unchanged
# Local document preparation can outlive the finalized EIP-1271 observation.
# Refresh it immediately before the first immutable publication, while proving
# that the signed authorization and the aggregate update did not change.
prepublish_envelope="$temporary/envelope.prepublish.json"
assert_tool_unchanged node
"$node_bin" scripts/prepare-release-authorization-materialization.mjs > "$prepublish_envelope"
assert_inputs_unchanged
assert_tool_unchanged jq
"$jq_bin" -S '{operatorIntent,authorization}' "$envelope" > "$temporary/envelope.signed.json"
assert_tool_unchanged jq
"$jq_bin" -S '{operatorIntent,authorization}' "$prepublish_envelope" \
  > "$temporary/envelope.prepublish.signed.json"
cmp -s "$temporary/envelope.signed.json" "$temporary/envelope.prepublish.signed.json"
assert_tool_unchanged jq
"$jq_bin" -e '.observation.approvals.releaseAuthorization.valid == true' \
  "$prepublish_envelope" >/dev/null
assert_tool_unchanged jq
"$jq_bin" '.observation' "$prepublish_envelope" > "$observation"
chmod 0600 "$observation"
sync -f "$observation"
publish_immutable "$authorization" "$output/release-authorization.json"
assert_inputs_unchanged
snapshot_private "$output/release-authorization.json" \
  "$temporary/release-authorization.installed.json"
cmp -s "$authorization" "$temporary/release-authorization.installed.json"
publish_immutable "$observation" "$output/release-authorization-finalized-observation.json"
assert_inputs_unchanged
snapshot_private "$output/release-authorization.json" \
  "$temporary/release-authorization.rechecked.json"
snapshot_private "$output/release-authorization-finalized-observation.json" \
  "$temporary/release-authorization-finalized-observation.installed.json"
cmp -s "$authorization" "$temporary/release-authorization.rechecked.json"
cmp -s "$observation" \
  "$temporary/release-authorization-finalized-observation.installed.json"
# Only advance the mutable aggregate after both immutable records and every
# materialization input have been revalidated under their directory locks.
assert_inputs_unchanged
if ! cmp -s "$next_intent" "$intent_snapshot"; then
  assert_tool_unchanged node
  "$node_bin" "$project/scripts/install-private-file-stdin.mjs" "$intent_target" < "$next_intent"
fi
snapshot_private "$intent_target" "$temporary/operator-intent.installed.json"
cmp -s "$next_intent" "$temporary/operator-intent.installed.json"
# Re-read both immutable precursors after the mutable intent completion marker.
snapshot_private "$output/release-authorization.json" \
  "$temporary/release-authorization.final.json"
snapshot_private "$output/release-authorization-finalized-observation.json" \
  "$temporary/release-authorization-finalized-observation.final.json"
cmp -s "$authorization" "$temporary/release-authorization.final.json"
cmp -s "$observation" \
  "$temporary/release-authorization-finalized-observation.final.json"
sync -f "$intent_target"; sync -f "$output"; sync -f "$config_directory"
assert_tool_unchanged jq
"$jq_bin" '{production_approved,deploy_authorized,real_funds_authorized,residual_risk_acceptance}' \
  "$next_intent"
