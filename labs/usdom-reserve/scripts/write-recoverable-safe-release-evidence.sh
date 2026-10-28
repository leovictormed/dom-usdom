#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent write:recoverable-safe-release-evidence' >&2
  exit 64
fi
: "${USDOM_SAFE_PACKAGE:?USDOM_SAFE_PACKAGE is required}"
: "${USDOM_SAFE_BASELINE:?USDOM_SAFE_BASELINE is required}"
: "${USDOM_SAFE_RECOVERY_REPORT:?USDOM_SAFE_RECOVERY_REPORT is required}"

for command in node jq sha256sum stat realpath mktemp flock sync cmp awk; do
  command -v "$command" >/dev/null
done
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
for tool_boundary_command in stat id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
package_source=$(realpath -ms "$USDOM_SAFE_PACKAGE")
baseline_source=$(realpath -ms "$USDOM_SAFE_BASELINE")
recovery_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_REPORT")

evidence_root="$project/evidence"
output="$evidence_root/control-plane"
if [[ ! -e "$evidence_root" ]]; then mkdir -m 0700 "$evidence_root"; fi
test -d "$evidence_root"; test ! -L "$evidence_root"
test "$(stat -c '%u' "$evidence_root")" = "$(id -u)"
test "$(stat -c '%a' "$evidence_root")" = '700'
if [[ ! -e "$output" ]]; then mkdir -m 0700 "$output"; fi
test -d "$output"; test ! -L "$output"
test "$(stat -c '%u' "$output")" = "$(id -u)"
test "$(stat -c '%a' "$output")" = '700'
exec 9<"$output"
if ! flock -n 9; then
  printf '%s\n' 'Another Safe release-evidence writer holds the output lock' >&2
  exit 75
fi

# The fragment is the completion marker. Make it durably absent first, then
# clear the supporting derived reports. Package/baseline/recovery sources are
# external immutable anti-replay inputs and are never removed here.
for derived in release-evidence-fragment.json governance-configuration.json \
  guardian-configuration.json checkpoint-guardian-configuration.json \
  control-plane-separation.json control-plane-recovery-drill.json \
  safe-control-release-evidence-bundle.json; do
  node "$project/scripts/remove-private-file-durable.mjs" "$output/$derived"
done

temporary=$(mktemp -d -p "$output" .build.XXXXXXXX)
chmod 0700 "$temporary"
temporary_identity=$(/usr/bin/stat -c '%u:%d:%i:%a' -- "$temporary")
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' -- "$temporary" 2>/dev/null) == "$temporary_identity" ]]; then
    /usr/bin/rm -rf -- "$temporary" || { (( status != 0 )) || status=1; }
  else
    (( status != 0 )) || status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
snapshot_private() {
  node "$project/scripts/read-private-file-stdout.mjs" "$1" > "$2"
  chmod 0600 "$2"
}
package_snapshot="$temporary/safe-package.json"
baseline_snapshot="$temporary/safe-baseline.json"
recovery_snapshot="$temporary/safe-recovery-report.json"
snapshot_private "$package_source" "$package_snapshot"
snapshot_private "$baseline_source" "$baseline_snapshot"
snapshot_private "$recovery_source" "$recovery_snapshot"
export USDOM_SAFE_PACKAGE=$package_snapshot
export USDOM_SAFE_BASELINE=$baseline_snapshot
export USDOM_SAFE_RECOVERY_REPORT=$recovery_snapshot
assert_inputs_unchanged() {
  snapshot_private "$package_source" "$temporary/safe-package.current.json"
  snapshot_private "$baseline_source" "$temporary/safe-baseline.current.json"
  snapshot_private "$recovery_source" "$temporary/safe-recovery-report.current.json"
  cmp -s "$package_snapshot" "$temporary/safe-package.current.json"
  cmp -s "$baseline_snapshot" "$temporary/safe-baseline.current.json"
  cmp -s "$recovery_snapshot" "$temporary/safe-recovery-report.current.json"
}
bundle="$temporary/safe-control-release-evidence-bundle.json"
node scripts/prepare-recoverable-safe-release-evidence.mjs > "$bundle"
chmod 0600 "$bundle"
export USDOM_SAFE_RELEASE_EVIDENCE_BUNDLE="$bundle"
node scripts/check-recoverable-safe-release-evidence.mjs >/dev/null

jq -S '.roleReports.governance' "$bundle" > "$temporary/governance-configuration.json"
jq -S '.roleReports.guardian' "$bundle" > "$temporary/guardian-configuration.json"
jq -S '.roleReports.checkpointGuardian' "$bundle" \
  > "$temporary/checkpoint-guardian-configuration.json"
jq -S '.separationReport' "$bundle" > "$temporary/control-plane-separation.json"
jq -S '.recoveryDrillReport' "$bundle" > "$temporary/control-plane-recovery-drill.json"
chmod 0600 "$temporary"/*.json

governance_path=evidence/control-plane/governance-configuration.json
guardian_path=evidence/control-plane/guardian-configuration.json
checkpoint_guardian_path=evidence/control-plane/checkpoint-guardian-configuration.json
separation_path=evidence/control-plane/control-plane-separation.json
recovery_path=evidence/control-plane/control-plane-recovery-drill.json
bundle_path=evidence/control-plane/safe-control-release-evidence-bundle.json
fragment="$temporary/release-evidence-fragment.json"
jq -n -S --slurpfile bundle "$bundle" \
  --arg governance_path "$governance_path" \
  --arg governance_sha "$(sha256sum "$temporary/governance-configuration.json" | awk '{print $1}')" \
  --arg guardian_path "$guardian_path" \
  --arg guardian_sha "$(sha256sum "$temporary/guardian-configuration.json" | awk '{print $1}')" \
  --arg checkpoint_guardian_path "$checkpoint_guardian_path" \
  --arg checkpoint_guardian_sha "$(sha256sum "$temporary/checkpoint-guardian-configuration.json" | awk '{print $1}')" \
  --arg separation_path "$separation_path" \
  --arg separation_sha "$(sha256sum "$temporary/control-plane-separation.json" | awk '{print $1}')" \
  --arg recovery_path "$recovery_path" \
  --arg recovery_sha "$(sha256sum "$temporary/control-plane-recovery-drill.json" | awk '{print $1}')" \
  --arg bundle_path "$bundle_path" \
  --arg bundle_sha "$(sha256sum "$bundle" | awk '{print $1}')" '
  ($bundle[0]) as $b | {
    schema:"usdom-safe-control-release-fragment/v2",
    bundleHash:$b.bundleHash,
    controlPlaneEvidenceBundle:{path:$bundle_path,sha256:$bundle_sha},
    controlPlane:{
      governance:{address:$b.roleReports.governance.address,
        runtimeCodeHash:$b.roleReports.governance.runtimeCodeHash,
        configurationHash:$b.roleReports.governance.configurationHash,
        configurationReport:{path:$governance_path,sha256:$governance_sha}},
      guardian:{address:$b.roleReports.guardian.address,
        runtimeCodeHash:$b.roleReports.guardian.runtimeCodeHash,
        configurationHash:$b.roleReports.guardian.configurationHash,
        configurationReport:{path:$guardian_path,sha256:$guardian_sha}},
      checkpointGuardian:{address:$b.roleReports.checkpointGuardian.address,
        runtimeCodeHash:$b.roleReports.checkpointGuardian.runtimeCodeHash,
        configurationHash:$b.roleReports.checkpointGuardian.configurationHash,
        configurationReport:{path:$checkpoint_guardian_path,sha256:$checkpoint_guardian_sha}}
    },
    controlPlaneSeparationReport:{path:$separation_path,sha256:$separation_sha},
    controlPlaneRecoveryDrillReport:{path:$recovery_path,sha256:$recovery_sha}
  }' > "$fragment"
chmod 0600 "$fragment"

publish_immutable() {
  local source=$1 destination=$2
  sync -f "$source"
  node "$project/scripts/install-private-file-immutable-stdin.mjs" --json "$destination" < "$source"
  sync -f "$destination"
}
publish_and_verify_immutable() {
  local source=$1 destination=$2 installed=$3
  publish_immutable "$source" "$destination"
  assert_inputs_unchanged
  snapshot_private "$destination" "$installed"
  cmp -s "$source" "$installed"
}
verify_supporting_outputs() {
  local file
  for file in governance-configuration.json guardian-configuration.json \
    checkpoint-guardian-configuration.json control-plane-separation.json \
    control-plane-recovery-drill.json safe-control-release-evidence-bundle.json; do
    snapshot_private "$output/$file" "$temporary/$file.rechecked"
    cmp -s "$temporary/$file" "$temporary/$file.rechecked"
  done
}

assert_inputs_unchanged
for file in governance-configuration.json guardian-configuration.json \
  checkpoint-guardian-configuration.json control-plane-separation.json \
  control-plane-recovery-drill.json; do
  publish_and_verify_immutable "$temporary/$file" "$output/$file" \
    "$temporary/$file.installed"
done
publish_and_verify_immutable "$bundle" "$output/safe-control-release-evidence-bundle.json" \
  "$temporary/safe-control-release-evidence-bundle.json.installed"
# The fragment is the completion marker and is intentionally published last.
verify_supporting_outputs
assert_inputs_unchanged
publish_and_verify_immutable "$fragment" "$output/release-evidence-fragment.json" \
  "$temporary/release-evidence-fragment.json.installed"
sync -f "$output"

jq '{schema,bundleHash,controlPlaneEvidenceBundle,controlPlane,controlPlaneSeparationReport,
  controlPlaneRecoveryDrillReport}' "$fragment"
