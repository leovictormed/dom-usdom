#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent commit:release-evidence' >&2
  exit 64
fi
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Release evidence signing requires an interactive terminal.' >&2
  exit 1
fi
for command in git jq npm node ssh-keygen stat realpath flock grep basename sha256sum mktemp rm awk find python3 id; do
  command -v "$command" >/dev/null
done
git_bin=$(realpath "$(command -v git)")
test -x "$git_bin"; test -f "$git_bin"; test ! -L "$git_bin"
git_owner=$(stat -Lc '%u' "$git_bin")
test "$git_owner" = 0 || test "$git_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$git_bin")" = 1
git_mode=$(stat -Lc '%a' "$git_bin")
(( (8#$git_mode & 8#022) == 0 ))
git_directory_mode=$(stat -Lc '%a' "$(dirname "$git_bin")")
git_directory_owner=$(stat -Lc '%u' "$(dirname "$git_bin")")
test "$git_directory_owner" = 0 || test "$git_directory_owner" = "$(id -u)"
(( (8#$git_directory_mode & 8#022) == 0 ))
git_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$git_bin")
git_sha256=$(sha256sum "$git_bin" | awk '{print $1}')
assert_git_unchanged() {
  test "$(realpath "$(command -v git)")" = "$git_bin"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$git_bin")" = "$git_identity"
  test "$(sha256sum "$git_bin" | awk '{print $1}')" = "$git_sha256"
}
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
for tool_boundary_command in stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
repository=$("$git_bin" -C "$project" rev-parse --show-toplevel)
project_relative=$(realpath --relative-to="$repository" "$project")
git_directory=$(realpath -- "$("$git_bin" -C "$repository" rev-parse --path-format=absolute --git-common-dir)")
test -d "$git_directory"; test ! -L "$git_directory"
test "$(stat -Lc '%u' "$git_directory")" = "$(id -u)"
git_directory_mode=$(stat -Lc '%a' "$git_directory")
(( (8#$git_directory_mode & 8#022) == 0 ))
# Lock the already-existing Git directory inode. A separate pathname lock could
# be redirected through a symlink, truncated before flock, or survive SIGKILL.
exec 9<"$git_directory"
if ! flock -n 9; then
  printf '%s\n' 'Another USDOM release ceremony holds the Git lock' >&2
  exit 75
fi

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
fingerprint=$(ssh-keygen -lf "$public_key" -E sha256 | awk 'NR == 1 {print $2}')
test "$("$git_bin" -C "$repository" config --get user.name)" = 'Soren Planck'
test "$("$git_bin" -C "$repository" config --get user.email)" = 'sorenplanck@tutamail.com'
test "$("$git_bin" -C "$repository" config --get gpg.format)" = ssh
test "$(realpath "$("$git_bin" -C "$repository" config --get user.signingkey)")" = "$(realpath "$private_key")"
test "$("$git_bin" -C "$repository" config --get commit.gpgsign)" = true
test "$("$git_bin" -C "$repository" config --get tag.gpgsign)" = true
"$git_bin" -C "$repository" diff --cached --quiet HEAD --
"$git_bin" -C "$repository" check-ignore -q "$project_relative/docs/CONTINUATION-STATE.md"
"$git_bin" -C "$repository" check-ignore -q "docs/CONTINUATION-STATE.md"

source_commit=$(jq -er '.sourceCommit' config/mainnet-release-evidence.unconfigured.json)
source_tag=$(jq -er '.sourceTag' config/mainnet-release-evidence.unconfigured.json)
release_id=$(jq -er '.releaseId' config/mainnet-release-evidence.unconfigured.json)
test "$source_commit" = "$("$git_bin" -C "$repository" rev-parse --verify HEAD)"
test "$release_id" = "$source_tag"
node --input-type=module - "$source_tag" <<'NODE'
import {isCanonicalReleaseTag} from './sdk/git-signature.mjs';
if(process.argv.length!==3||!isCanonicalReleaseTag(process.argv[2])) process.exit(1);
NODE
if "$git_bin" -C "$repository" rev-parse --verify "refs/tags/$source_tag" >/dev/null 2>&1; then
  printf 'Release tag already exists: %s\n' "$source_tag" >&2
  exit 1
fi
identities=$("$git_bin" -C "$repository" show -s --format='%an <%ae>%n%cn <%ce>' "$source_commit")
test "$identities" = $'Soren Planck <sorenplanck@tutamail.com>\nSoren Planck <sorenplanck@tutamail.com>'
source_verification=$("$git_bin" -C "$repository" verify-commit --raw "$source_commit" 2>&1)
grep -F -- "key $fingerprint" <<<"$source_verification" >/dev/null

jq -e --arg releaseId "$release_id" --arg sourceCommit "$source_commit" \
  --arg fingerprint "$fingerprint" '
  .release_signing_key_fingerprint == $fingerprint
  and .production_approved == true and .deploy_authorized == true
  and .real_funds_authorized == true
  and (.undefined | type == "array" and length == 0)
  and .residual_risk_acceptance.accepted == true
  and .residual_risk_acceptance.releaseId == $releaseId
  and .residual_risk_acceptance.sourceCommit == $sourceCommit' config/operator-intent.json >/dev/null
test -d evidence; test ! -L evidence
test -n "$(find evidence -type f -print -quit)"
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
done < <("$git_bin" -C "$repository" status --porcelain=v1 --untracked-files=all)
if "$git_bin" -C "$repository" diff --quiet "$source_commit" -- \
    "$project_relative/config/mainnet-release-evidence.unconfigured.json"; then
  printf '%s\n' 'Release-evidence metadata was not modified after the source commit' >&2
  exit 1
fi
if "$git_bin" -C "$repository" diff --quiet "$source_commit" -- \
    "$project_relative/config/operator-intent.json"; then
  printf '%s\n' 'Operator-intent metadata was not modified after the source commit' >&2
  exit 1
fi
npm run check:provenance
"$git_bin" -C "$repository" diff --check
authorization_state=$("$git_bin" -C "$repository" rev-parse --verify HEAD; \
  "$git_bin" -C "$repository" status --porcelain=v1 --untracked-files=all)
read -r -p "Digite ASSINO EVIDENCIA E TAG USDOM $source_tag para continuar: " authorization
test "$authorization" = "ASSINO EVIDENCIA E TAG USDOM $source_tag"
assert_git_unchanged
test "$authorization_state" = "$("$git_bin" -C "$repository" rev-parse --verify HEAD; \
  "$git_bin" -C "$repository" status --porcelain=v1 --untracked-files=all)"
! "$git_bin" -C "$repository" rev-parse --verify "refs/tags/$source_tag" >/dev/null 2>&1

staged=false
committed=false
tag_created=false
evidence_commit=''
closed_report=$(mktemp)
real_report=$(mktemp)
rollback() {
  status=$?
  rm -f -- "$closed_report" "$real_report"
  if ((status != 0)); then
    if test "$tag_created" = true \
        && test "$("$git_bin" -C "$repository" rev-parse --verify "refs/tags/$source_tag^{commit}" 2>/dev/null || true)" = "$evidence_commit"; then
      "$git_bin" -C "$repository" tag -d -- "$source_tag" >/dev/null
    fi
    if test "$committed" = true && test -n "$evidence_commit" \
        && test "$("$git_bin" -C "$repository" rev-parse --verify HEAD)" = "$evidence_commit"; then
      "$git_bin" -C "$repository" reset --mixed --quiet "$source_commit"
    elif test "$staged" = true; then
      "$git_bin" -C "$repository" reset --mixed --quiet "$source_commit"
    fi
  fi
  exit "$status"
}
trap rollback EXIT

"$git_bin" -C "$repository" add -A -- \
  "$project_relative/config/mainnet-release-evidence.unconfigured.json" \
  "$project_relative/config/operator-intent.json" \
  "$project_relative/evidence"
staged=true
release_metadata_seen=false
operator_intent_seen=false
while IFS= read -r -d '' status && IFS= read -r -d '' changed_path; do
  case "$changed_path" in
    "$project_relative/config/mainnet-release-evidence.unconfigured.json")
      test "$status" = M; release_metadata_seen=true ;;
    "$project_relative/config/operator-intent.json")
      test "$status" = M; operator_intent_seen=true ;;
    "$project_relative/evidence/"*) case "$status" in A|M) ;; *) exit 1 ;; esac ;;
    *) printf 'Forbidden evidence-commit path: %s\n' "$changed_path" >&2; exit 1 ;;
  esac
  case "$(basename "$changed_path")" in
    .env|.env.*|*.pem|*.p12|*.pfx|*.jks|*.seed|*.mnemonic|*.secret|*.key|*.raw|*.witness|*.tmp|id_rsa|id_ed25519|*private-input*|*private-witness*|*credential*|*owner-auth*|*password*)
      printf 'Sensitive-looking path entered the evidence index: %s\n' "$changed_path" >&2
      exit 1
      ;;
  esac
  "$git_bin" -C "$repository" show ":$changed_path" | node scripts/check-staged-sensitive-content.mjs --path "$changed_path"
  index_entry=$("$git_bin" -C "$repository" ls-files --stage -- "$changed_path")
  mode=${index_entry%% *}
  case "$mode" in 100644|100755) ;; *)
    printf 'Unsupported evidence index mode %s: %s\n' "$mode" "$changed_path" >&2
    exit 1
    ;;
  esac
done < <("$git_bin" -C "$repository" diff --cached --name-status --no-renames -z "$source_commit" --)
test "$release_metadata_seen" = true
test "$operator_intent_seen" = true

export GIT_AUTHOR_NAME='Soren Planck'
export GIT_AUTHOR_EMAIL='sorenplanck@tutamail.com'
export GIT_COMMITTER_NAME='Soren Planck'
export GIT_COMMITTER_EMAIL='sorenplanck@tutamail.com'
assert_git_unchanged
"$git_bin" -C "$repository" commit -S -m "USDOM $source_tag release evidence"
evidence_commit=$("$git_bin" -C "$repository" rev-parse --verify HEAD)
committed=true
test "$("$git_bin" -C "$repository" rev-parse --verify HEAD^)" = "$source_commit"
identities=$("$git_bin" -C "$repository" show -s --format='%an <%ae>%n%cn <%ce>' HEAD)
test "$identities" = $'Soren Planck <sorenplanck@tutamail.com>\nSoren Planck <sorenplanck@tutamail.com>'
evidence_verification=$("$git_bin" -C "$repository" verify-commit --raw HEAD 2>&1)
grep -F -- "key $fingerprint" <<<"$evidence_verification" >/dev/null
assert_git_unchanged
"$git_bin" -C "$repository" tag -s -a -m "USDOM $source_tag release" -- "$source_tag" "$evidence_commit"
tag_created=true
tag_verification=$("$git_bin" -C "$repository" verify-tag --raw -- "$source_tag" 2>&1)
grep -F -- "key $fingerprint" <<<"$tag_verification" >/dev/null
test "$("$git_bin" -C "$repository" rev-parse --verify "refs/tags/$source_tag^{commit}")" = "$evidence_commit"
test -z "$("$git_bin" -C "$repository" status --porcelain=v1 --untracked-files=all)"
export USDOM_RELEASE_SIGNING_KEY_FINGERPRINT=$fingerprint
node scripts/check-mainnet-readiness.mjs closed-mainnet > "$closed_report"
node scripts/check-mainnet-readiness.mjs real-funds > "$real_report"
jq -e '.ready == true and (.blockers | length) == 0' "$closed_report" >/dev/null
jq -e '.ready == true and (.blockers | length) == 0' "$real_report" >/dev/null
trap - EXIT
rm -f -- "$closed_report" "$real_report"
jq -n --arg releaseId "$release_id" --arg sourceCommit "$source_commit" \
  --arg evidenceCommit "$evidence_commit" --arg sourceTag "$source_tag" \
  --arg signingFingerprint "$fingerprint" \
  '{schema:"usdom-release-evidence-commit/v1",releaseId:$releaseId,
    sourceCommit:$sourceCommit,evidenceCommit:$evidenceCommit,sourceTag:$sourceTag,
    signingFingerprint:$signingFingerprint,closedMainnetReady:true,realFundsReady:true}'
