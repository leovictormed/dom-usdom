#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: bash scripts/write-risc0-trusted-setup-verification-report.sh' >&2
  exit 64
fi
readonly project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
test "$PWD" = "$project"
for command in node jq sha256sum mktemp flock cmp stat sync realpath id dirname cut python3; do command -v "$command" >/dev/null; done
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool jq; pin_runtime_tool python3
node() { assert_runtime_tool node; "$node_bin" "$@"; }
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
readonly evidence_directory="$project/evidence/trusted-setup"
readonly report_target="$evidence_directory/risc0-groth16-ceremony-verification.json"
readonly finalized_target="$project/config/finalized-burn-verifier.unconfigured.json"
readonly checkpoint_target="$project/config/checkpoint-verifier.unconfigured.json"
readonly evidence_target="$project/config/mainnet-release-evidence.unconfigured.json"
if test ! -e "$project/evidence"; then mkdir -m 0700 "$project/evidence"; fi
if test ! -e "$evidence_directory"; then mkdir -m 0700 "$evidence_directory"; fi
for directory in "$project/evidence" "$evidence_directory"; do
  test -d "$directory"; test ! -L "$directory"
  test "$(stat -c '%u:%a' "$directory")" = "$(id -u):700"
done
exec 8<"$project/config"
flock -n 8 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
exec 9<"$evidence_directory"
flock -n 9 || { printf '%s\n' 'Another trusted-setup writer holds the evidence lock' >&2; exit 75; }
temporary=$(mktemp -d -p /dev/shm usdom-risc0-report.XXXXXXXX)
chmod 0700 "$temporary"
temporary_identity=$(stat -c '%u:%d:%i:%a' "$temporary")
cleanup(){
  local status=${1:-$?}; trap - EXIT
  if test "$(stat -c '%u:%d:%i:%a' "$temporary" 2>/dev/null)" = "$temporary_identity"; then
    rm -rf -- "$temporary"
  else status=1; fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

node scripts/prepare-risc0-trusted-setup-verification-report.mjs >"$temporary/report.json"
chmod 0600 "$temporary/report.json"
report_sha=$(sha256sum "$temporary/report.json" | awk '{print $1}')
verification_key_sha=$(jq -er '.artifacts.zkey.verificationKeySha256' "$temporary/report.json")
[[ $report_sha =~ ^[0-9a-f]{64}$ && $verification_key_sha =~ ^[0-9a-f]{64}$ ]]
node scripts/install-private-file-immutable-stdin.mjs --json "$report_target" <"$temporary/report.json"
cmp -s "$temporary/report.json" "$report_target"
sync -f "$report_target"; sync -f "$evidence_directory"

declare -A target_sha256
for name in finalized checkpoint evidence; do
  target_variable="${name}_target"; target=${!target_variable}
  target_sha256[$name]=$(sha256sum "$target" | awk '{print $1}')
  node scripts/read-release-config-file-stdout.mjs "$target" >"$temporary/$name.before.json"
done
parent_device=$(stat -Lc '%d' "$project/config")
parent_inode=$(stat -Lc '%i' "$project/config")
jq --arg key "0x$verification_key_sha" --arg transcript "0x$report_sha" '
  if ((.proofSystem==null or .proofSystem=="risc0-groth16-v3")
      and (.verifyingKeySha256==null or .verifyingKeySha256==$key)
      and (.trustedSetupRequired==null or .trustedSetupRequired==true)
      and (.trustedSetupTranscriptSha256==null or .trustedSetupTranscriptSha256==$transcript))
  then .proofSystem="risc0-groth16-v3" | .verifyingKeySha256=$key
    | .trustedSetupRequired=true | .trustedSetupTranscriptSha256=$transcript
  else error("finalized-burn trusted-setup fields conflict with the verified transcript") end
' "$temporary/finalized.before.json" >"$temporary/finalized.after.json"
jq --arg key "0x$verification_key_sha" --arg transcript "0x$report_sha" '
  if (.proofSystem=="risc0-groth16-v3"
      and (.verifyingKeySha256==null or .verifyingKeySha256==$key)
      and (.trustedSetupRequired==null or .trustedSetupRequired==true)
      and (.trustedSetupTranscriptSha256==null or .trustedSetupTranscriptSha256==$transcript))
  then .verifyingKeySha256=$key | .trustedSetupRequired=true
    | .trustedSetupTranscriptSha256=$transcript
  else error("checkpoint trusted-setup fields conflict with the verified transcript") end
' "$temporary/checkpoint.before.json" >"$temporary/checkpoint.after.json"
readonly report_path=evidence/trusted-setup/risc0-groth16-ceremony-verification.json
jq --arg path "$report_path" --arg sha "$report_sha" '
  ({path:$path,sha256:$sha}) as $document
  | if ((.trustedSetup.required==null or .trustedSetup.required==true)
      and (.checkpointTrustedSetup.required==null or .checkpointTrustedSetup.required==true)
      and (.trustedSetup.transcript==null or .trustedSetup.transcript==$document)
      and (.checkpointTrustedSetup.transcript==null or .checkpointTrustedSetup.transcript==$document))
    then .trustedSetup.required=true | .checkpointTrustedSetup.required=true
      | .trustedSetup.transcript=$document | .checkpointTrustedSetup.transcript=$document
    else error("release evidence trusted-setup fields conflict with the verified transcript") end
' "$temporary/evidence.before.json" >"$temporary/evidence.after.json"
chmod 0600 "$temporary"/*.after.json

# Monotonic, resumable publication: each destination accepts only null fields or
# the exact verified value. An interruption can therefore only leave a prefix
# that the next invocation completes without replacing any committed value.
for name in finalized checkpoint evidence; do
  target_variable="${name}_target"; target=${!target_variable}
  node scripts/read-release-config-file-stdout.mjs "$target" | cmp -s - "$temporary/$name.before.json"
  if ! cmp -s "$temporary/$name.before.json" "$temporary/$name.after.json"; then
    candidate_sha256=$(sha256sum "$temporary/$name.after.json" | awk '{print $1}')
    node scripts/replace-locked-source-stdin.mjs "$target" \
      "$candidate_sha256" "${target_sha256[$name]}" "$parent_device" "$parent_inode" \
      "$python3_bin" "$python3_sha256" <"$temporary/$name.after.json"
  fi
  node scripts/read-release-config-file-stdout.mjs "$target" | cmp -s - "$temporary/$name.after.json"
  sync -f "$target"
done
sync -f "$project/config"
jq -n --arg transcriptSha256 "$report_sha" --arg verificationKeySha256 "$verification_key_sha" \
  '{ok:true,transcriptSha256:$transcriptSha256,verificationKeySha256:$verificationKeySha256}'
