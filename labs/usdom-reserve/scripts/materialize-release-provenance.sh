#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent materialize:release-provenance' >&2
  exit 64
fi
for command in node jq git ssh-keygen stat realpath mktemp flock sync mv cmp python3 awk chmod id; do
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
pin_runtime_tool python3
python3() { assert_runtime_tool python3; "$python3_bin" "$@"; }
pin_runtime_tool git
git() { assert_runtime_tool git; "$git_bin" "$@"; }
pin_runtime_tool ssh-keygen
ssh-keygen() { assert_runtime_tool ssh-keygen; "$ssh_keygen_bin" "$@"; }
repository=$(git -C "$project" rev-parse --show-toplevel)
project_relative=$(realpath --relative-to="$repository" "$project")
git -C "$repository" diff --cached --quiet HEAD --
while IFS= read -r status_line; do
  changed_path=${status_line:3}
  case "$changed_path" in
    "$project_relative/config/mainnet-release-evidence.unconfigured.json"|\
    "$project_relative/config/operator-intent.json"|\
    "$project_relative/evidence/"*) ;;
    *)
      printf 'Source tree contains a non-evidence change: %s\n' "$changed_path" >&2
      exit 1
      ;;
  esac
done < <(git -C "$repository" status --porcelain=v1 --untracked-files=all)
git -C "$repository" cat-file -e "HEAD:$project_relative/MANIFEST.sha256"
python3 scripts/verify-import.py >/dev/null
python3 scripts/source-manifest.py >/dev/null
account_home=$(python3 -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')
case "$account_home" in /*) ;; *) exit 1 ;; esac
test "$account_home" != /; test "$HOME" = "$account_home"
test "$(realpath "$HOME")" = "$account_home"
private_key=${account_home}/.ssh/usdom-release-signing-ed25519
public_key=${private_key}.pub
test -f "$private_key"; test ! -L "$private_key"
test -f "$public_key"; test ! -L "$public_key"
test "$(stat -c '%u:%a:%h' "$private_key")" = "$(id -u):600:1"
test "$(stat -c '%u:%a:%h' "$public_key")" = "$(id -u):600:1"
export USDOM_RELEASE_SIGNING_KEY_FINGERPRINT
USDOM_RELEASE_SIGNING_KEY_FINGERPRINT=$(ssh-keygen -lf "$public_key" -E sha256 | awk 'NR == 1 {print $2}')
test "$(git -C "$repository" config --get user.name)" = 'Soren Planck'
test "$(git -C "$repository" config --get user.email)" = 'sorenplanck@tutamail.com'
test "$(git -C "$repository" config --get gpg.format)" = ssh
test "$(realpath "$(git -C "$repository" config --get user.signingkey)")" = "$(realpath "$private_key")"
config_directory=$project/config
evidence_target=$config_directory/mainnet-release-evidence.unconfigured.json
intent_target=$config_directory/operator-intent.json
for target in "$evidence_target" "$intent_target"; do
  test -f "$target"; test ! -L "$target"
  test "$(stat -c '%u' "$target")" = "$(id -u)"
done
exec 9<"$config_directory"
if ! flock -n 9; then
  printf '%s\n' 'Another release materializer holds the config-directory lock' >&2
  exit 75
fi
evidence_sha256=$(sha256sum "$evidence_target" | awk '{print $1}')
intent_sha256=$(sha256sum "$intent_target" | awk '{print $1}')
parent_device=$(stat -Lc '%d' "$config_directory")
parent_inode=$(stat -Lc '%i' "$config_directory")
envelope=$(mktemp -p "$config_directory" .release-provenance-envelope.XXXXXXXX)
evidence_temporary=$(mktemp -p "$config_directory" .release-provenance-evidence.XXXXXXXX)
intent_temporary=$(mktemp -p "$config_directory" .release-provenance-intent.XXXXXXXX)
evidence_snapshot=$(mktemp -p "$config_directory" .release-provenance-evidence-snapshot.XXXXXXXX)
intent_snapshot=$(mktemp -p "$config_directory" .release-provenance-intent-snapshot.XXXXXXXX)
evidence_observed=$(mktemp -p "$config_directory" .release-provenance-evidence-observed.XXXXXXXX)
intent_observed=$(mktemp -p "$config_directory" .release-provenance-intent-observed.XXXXXXXX)
trap 'rm -f -- "$envelope" "$evidence_temporary" "$intent_temporary" "$evidence_snapshot" "$intent_snapshot" "$evidence_observed" "$intent_observed"' EXIT
node scripts/read-release-config-file-stdout.mjs "$evidence_target" > "$evidence_snapshot"
node scripts/read-private-file-stdout.mjs "$intent_target" > "$intent_snapshot"
chmod 0600 "$evidence_snapshot" "$intent_snapshot" "$evidence_observed" "$intent_observed"

read_current_targets() {
  node scripts/read-release-config-file-stdout.mjs "$evidence_target" > "$evidence_observed"
  node scripts/read-private-file-stdout.mjs "$intent_target" > "$intent_observed"
}

assert_targets_unchanged() {
  read_current_targets
  cmp -s "$evidence_snapshot" "$evidence_observed" || {
    printf '%s\n' 'Release evidence changed while provenance was being materialized' >&2
    exit 75
  }
  cmp -s "$intent_snapshot" "$intent_observed" || {
    printf '%s\n' 'Operator intent changed while provenance was being materialized' >&2
    exit 75
  }
}

node scripts/prepare-release-provenance-materialization.mjs > "$envelope"
jq -e '.schema == "usdom-release-provenance-materialization/v1"' "$envelope" >/dev/null
jq '.releaseEvidence' "$envelope" > "$evidence_temporary"
jq '.operatorIntent' "$envelope" > "$intent_temporary"
jq -e '.schema == 1 and .releaseId != null and .sourceCommit != null and .sourceTag != null' \
  "$evidence_temporary" >/dev/null
jq -e '.schema == 1 and .release_signing_key_fingerprint != null
  and .residual_risk_acceptance.releaseId != null
  and .residual_risk_acceptance.sourceCommit != null' "$intent_temporary" >/dev/null
chmod 0600 "$evidence_temporary" "$intent_temporary"
sync -f "$evidence_temporary"; sync -f "$intent_temporary"
assert_targets_unchanged
if ! cmp -s "$evidence_temporary" "$evidence_target" \
    || [[ $(stat -c '%a' "$evidence_target") != 644 ]]; then
  candidate_sha256=$(sha256sum "$evidence_temporary" | awk '{print $1}')
  node "$project/scripts/replace-locked-source-stdin.mjs" "$evidence_target" \
    "$candidate_sha256" "$evidence_sha256" "$parent_device" "$parent_inode" \
    "$python3_bin" "$python3_sha256" < "$evidence_temporary"
fi
# Do not install the second aggregate over a concurrently changed intent, and
# prove that the first installation contains the exact prepared document.
node scripts/read-release-config-file-stdout.mjs "$evidence_target" > "$evidence_observed"
cmp -s "$evidence_temporary" "$evidence_observed" || {
  printf '%s\n' 'Installed release evidence differs from the prepared provenance' >&2
  exit 75
}
node scripts/read-private-file-stdout.mjs "$intent_target" > "$intent_observed"
cmp -s "$intent_snapshot" "$intent_observed" || {
  printf '%s\n' 'Operator intent changed before its provenance update' >&2
  exit 75
}
if ! cmp -s "$intent_temporary" "$intent_target" \
    || [[ $(stat -c '%a' "$intent_target") != 600 ]]; then
  candidate_sha256=$(sha256sum "$intent_temporary" | awk '{print $1}')
  node "$project/scripts/replace-locked-private-stdin.mjs" "$intent_target" \
    "$candidate_sha256" "$intent_sha256" "$parent_device" "$parent_inode" \
    "$python3_bin" "$python3_sha256" < "$intent_temporary"
fi
read_current_targets
cmp -s "$evidence_temporary" "$evidence_observed" || {
  printf '%s\n' 'Release evidence changed after provenance installation' >&2
  exit 75
}
cmp -s "$intent_temporary" "$intent_observed" || {
  printf '%s\n' 'Operator intent differs from the prepared provenance' >&2
  exit 75
}
sync -f "$evidence_target"; sync -f "$intent_target"; sync -f "$config_directory"
jq '{releaseId,sourceCommit,sourceTag}' "$evidence_target"
jq '{release_signing_key_fingerprint,residual_risk_acceptance:
  {releaseId:.residual_risk_acceptance.releaseId,sourceCommit:.residual_risk_acceptance.sourceCommit}}' \
  "$intent_target"
