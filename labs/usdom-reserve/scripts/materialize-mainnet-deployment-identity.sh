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
  printf '%s\n' 'Usage: npm run --silent materialize:mainnet-deployment-identity' >&2
  exit 64
fi
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required}"
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?USDOM_CONTROL_EVIDENCE_DIRECTORY is required}"
: "${USDOM_MAINNET_DEPLOYER_IDENTITY:?USDOM_MAINNET_DEPLOYER_IDENTITY is required}"
for command in cast node jq stat realpath mktemp flock sync cmp id chmod; do
  command -v "$command" >/dev/null
done
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
for tool_boundary_command in stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
pin_runtime_tool cast
cast() { assert_runtime_tool cast; "$cast_bin" "$@"; }
pin_runtime_tool timeout
pin_runtime_tool python3
python3() { assert_runtime_tool python3; "$python3_bin" "$@"; }
config_directory="$project/config"
target="$config_directory/proof-reserve.unconfigured.json"
evidence_directory=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY")
test -f "$target"; test ! -L "$target"
test "$(stat -c '%u' "$target")" = "$(id -u)"
test "$(stat -c '%a' "$target")" = '644'
test -d "$evidence_directory"; test ! -L "$evidence_directory"
test "$(stat -c '%u' "$evidence_directory")" = "$(id -u)"
test "$(stat -c '%a' "$evidence_directory")" = '700'
exec 9<"$config_directory"
flock -n 9 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
exec 8<"$evidence_directory"
flock -n 8 || { printf '%s\n' 'Another release materializer holds the evidence lock' >&2; exit 75; }
test "$(realpath -e /proc/$$/fd/9)" = "$config_directory"
test "$(realpath -e /proc/$$/fd/8)" = "$evidence_directory"
config_parent_identity=$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/9)
evidence_parent_identity=$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/8)
test "$config_parent_identity" = "$(stat -c '%d:%i:%u:%a' -- "$config_directory")"
test "$evidence_parent_identity" = "$(stat -c '%d:%i:%u:%a' -- "$evidence_directory")"
[[ $config_parent_identity == *":$(id -u):755" ]]
[[ $evidence_parent_identity == *":$(id -u):700" ]]
assert_locked_parents() {
  test "$(realpath -e "$config_directory")" = "$config_directory"
  test "$(realpath -e "$evidence_directory")" = "$evidence_directory"
  test "$(stat -c '%d:%i:%u:%a' -- "$config_directory")" = "$config_parent_identity"
  test "$(stat -c '%d:%i:%u:%a' -- "$evidence_directory")" = "$evidence_parent_identity"
  test "$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/9)" = "$config_parent_identity"
  test "$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/8)" = "$evidence_parent_identity"
}
target_sha256=$(sha256sum "$target" | awk '{print $1}')
parent_device=$(stat -Lc '%d' "$config_directory")
parent_inode=$(stat -Lc '%i' "$config_directory")

temporary=$(mktemp -d -p /dev/shm usdom-deployment-identity.XXXXXXXX)
chmod 0700 "$temporary"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if assert_runtime_tool node && assert_runtime_tool timeout &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' \
      "$temporary" > /dev/null 2> /dev/null &&
    assert_runtime_tool node && assert_runtime_tool timeout && test ! -e "$temporary"; then
    :
  else
    status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
export USDOM_MAINNET_DEPLOYER
USDOM_MAINNET_DEPLOYER=$(node scripts/read-mainnet-gas-relayer-identity.mjs "$USDOM_MAINNET_DEPLOYER_IDENTITY")
envelope="$temporary/envelope.json"
node scripts/prepare-mainnet-deployment-identity-materialization.mjs > "$envelope"
test "$(node scripts/read-mainnet-gas-relayer-identity.mjs "$USDOM_MAINNET_DEPLOYER_IDENTITY")" = "$USDOM_MAINNET_DEPLOYER"
configuration="$temporary/configuration.json"
observation="$temporary/observation.json"
jq '.configuration' "$envelope" > "$configuration"
jq '.observation' "$envelope" > "$observation"
jq -e --arg deployer "$USDOM_MAINNET_DEPLOYER" '
  .productionReady == false and .realFundsAuthorized == false and
  ([.deployer,.verifierDeployer,.checkpointVerifierDeployer,.checkpointRegistryDeployer]
    | all((ascii_downcase) == ($deployer|ascii_downcase))) and
  ([.deployerNonce,.verifierDeployerNonce,.checkpointVerifierDeployerNonce,
    .checkpointRegistryDeployerNonce] | all(type == "string"))' "$configuration" >/dev/null
jq -e --arg deployer "$USDOM_MAINNET_DEPLOYER" '
  .schema == "usdom-mainnet-deployment-identity-observation-v1" and .chainId == "1" and
  (.deployer|ascii_downcase) == ($deployer|ascii_downcase) and
  (.plans|length) == 4 and (.rpcObservations|length) >= 2 and (.rpcObservations|length) <= 5' "$observation" >/dev/null
chmod 0600 "$configuration" "$observation"
test "$(node scripts/read-mainnet-gas-relayer-identity.mjs "$USDOM_MAINNET_DEPLOYER_IDENTITY")" = "$USDOM_MAINNET_DEPLOYER"
node scripts/prepare-mainnet-deployment-identity-materialization.mjs > "$temporary/envelope.final.json"
jq '.configuration' "$temporary/envelope.final.json" > "$temporary/configuration.final.json"
cmp -s "$configuration" "$temporary/configuration.final.json"
observation_target="$evidence_directory/mainnet-deployment-identity-observation.json"
if [[ -e $observation_target ]]; then
  test -f "$observation_target"; test ! -L "$observation_target"
  test "$(stat -c '%u' "$observation_target")" = "$(id -u)"
  test "$(stat -c '%a' "$observation_target")" = '600'
  test "$(stat -c '%h' "$observation_target")" = '1'
fi
assert_locked_parents
node scripts/install-private-file-immutable-stdin.mjs --json "$observation_target" < "$observation"
node scripts/read-private-file-stdout.mjs "$observation_target" \
  > "$temporary/observation.installed.json"
cmp -s "$observation" "$temporary/observation.installed.json"
# Recheck the complete RPC/config/relayer-derived envelope directly before replacing the draft config.
test "$(node scripts/read-mainnet-gas-relayer-identity.mjs "$USDOM_MAINNET_DEPLOYER_IDENTITY")" = "$USDOM_MAINNET_DEPLOYER"
node scripts/prepare-mainnet-deployment-identity-materialization.mjs > "$temporary/envelope.preconfig.json"
jq '.configuration' "$temporary/envelope.preconfig.json" > "$temporary/configuration.preconfig.json"
cmp -s "$configuration" "$temporary/configuration.preconfig.json"
candidate_sha256=$(sha256sum "$configuration" | awk '{print $1}')
assert_locked_parents
node scripts/replace-locked-source-stdin.mjs "$target" \
  "$candidate_sha256" "$target_sha256" "$parent_device" "$parent_inode" \
  "$python3_bin" "$python3_sha256" < "$configuration"
node scripts/read-release-config-file-stdout.mjs "$target" \
  > "$temporary/configuration.installed.json"
cmp -s "$configuration" "$temporary/configuration.installed.json"
# Re-read the precursor after publishing the aggregate completion document so
# a successful return always proves one coherent two-file generation.
node scripts/read-private-file-stdout.mjs "$observation_target" \
  > "$temporary/observation.final.json"
cmp -s "$observation" "$temporary/observation.final.json"
sync -f "$observation_target"
sync -f "$target"
assert_locked_parents
sync -f "$evidence_directory"
sync -f "$config_directory"
# The two-file generation is complete only after both names survive the
# durable-directory boundary with the exact prepared bytes.
node scripts/read-private-file-stdout.mjs "$observation_target" \
  > "$temporary/observation.durable.json"
cmp -s "$observation" "$temporary/observation.durable.json"
node scripts/read-release-config-file-stdout.mjs "$target" \
  > "$temporary/configuration.durable.json"
cmp -s "$configuration" "$temporary/configuration.durable.json"
assert_locked_parents
jq '{deployer,baseNonce,plans,rpcObservations}' "$observation_target"
