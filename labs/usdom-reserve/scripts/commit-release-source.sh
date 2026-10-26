#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent commit:release-source' >&2
  exit 64
fi
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Release source signing requires an interactive terminal.' >&2
  exit 1
fi
for command in git jq npm node ssh-keygen stat realpath flock grep basename sha256sum awk python3 id; do
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
"$git_bin" -C "$repository" diff --cached --quiet HEAD --
"$git_bin" -C "$repository" check-ignore -q "$project_relative/docs/CONTINUATION-STATE.md"
"$git_bin" -C "$repository" check-ignore -q "docs/CONTINUATION-STATE.md"

jq -e '.releaseId == null and .sourceCommit == null and .sourceTag == null' \
  config/mainnet-release-evidence.unconfigured.json >/dev/null
jq -e '.release_signing_key_fingerprint == null
  and .production_approved == false and .deploy_authorized == false
  and .real_funds_authorized == false
  and .residual_risk_acceptance.accepted == false
  and .residual_risk_acceptance.releaseId == null
  and .residual_risk_acceptance.sourceCommit == null' config/operator-intent.json >/dev/null
jq -e '.productionReady == true and .realFundsAuthorized == true' \
  config/proof-reserve.unconfigured.json >/dev/null
jq -e '.mainnet_ready == true and .deploy_authorized == true
  and .real_funds_authorized == true
  and .production_finality_selected != null
  and .production_finality_approved == true' config/production-requirements.json >/dev/null

npm test
npm run check:provenance
"$git_bin" -C "$repository" diff --check

package_version=$(jq -er '.version' package.json)
source_tag=usdom-v${package_version}
test "$source_tag" != usdom-v0.0.0
node --input-type=module - "$source_tag" <<'NODE'
import {isCanonicalReleaseTag} from './sdk/git-signature.mjs';
if(process.argv.length!==3||!isCanonicalReleaseTag(process.argv[2])) process.exit(1);
NODE
if "$git_bin" -C "$repository" rev-parse --verify "refs/tags/$source_tag" >/dev/null 2>&1; then
  printf 'Release tag already exists: %s\n' "$source_tag" >&2
  exit 1
fi
authorization_state=$("$git_bin" -C "$repository" rev-parse --verify HEAD; \
  "$git_bin" -C "$repository" status --porcelain=v1 --untracked-files=all)
read -r -p "Digite ASSINO COMMIT DE FONTE USDOM $source_tag para continuar: " authorization
test "$authorization" = "ASSINO COMMIT DE FONTE USDOM $source_tag"
assert_git_unchanged
test "$authorization_state" = "$("$git_bin" -C "$repository" rev-parse --verify HEAD; \
  "$git_bin" -C "$repository" status --porcelain=v1 --untracked-files=all)"
! "$git_bin" -C "$repository" rev-parse --verify "refs/tags/$source_tag" >/dev/null 2>&1

before=$("$git_bin" -C "$repository" rev-parse --verify HEAD)
staged=false
committed=false
created=''
rollback() {
  status=$?
  if ((status != 0)); then
    if test "$committed" = true && test -n "$created" \
        && test "$("$git_bin" -C "$repository" rev-parse --verify HEAD)" = "$created"; then
      "$git_bin" -C "$repository" reset --mixed --quiet "$before"
    elif test "$staged" = true; then
      "$git_bin" -C "$repository" reset --mixed --quiet "$before"
    fi
  fi
  exit "$status"
}
trap rollback EXIT

"$git_bin" -C "$repository" add -A -- . \
  ":(top,exclude)$project_relative/evidence/**"
staged=true
if "$git_bin" -C "$repository" diff --cached --quiet "$before" --; then
  printf '%s\n' 'No source change is staged for the immutable release commit' >&2
  exit 1
fi
while IFS= read -r -d '' changed_path; do
  case "$changed_path" in
    "$project_relative/evidence/"*|"$project_relative/docs/CONTINUATION-STATE.md"|docs/CONTINUATION-STATE.md)
      printf 'Evidence-layer path entered the source index: %s\n' "$changed_path" >&2
      exit 1
      ;;
  esac
  case "$(basename "$changed_path")" in
    .env|.env.*|*.pem|*.p12|*.pfx|*.jks|*.seed|*.mnemonic|*.secret|*.key|*.raw|*.witness|*.tmp|id_rsa|id_ed25519|*private-input*|*private-witness*|*credential*|*owner-auth*|*password*)
      printf 'Sensitive-looking path entered the source index: %s\n' "$changed_path" >&2
      exit 1
      ;;
  esac
  "$git_bin" -C "$repository" show ":$changed_path" | node scripts/check-staged-sensitive-content.mjs --path "$changed_path"
  index_entry=$("$git_bin" -C "$repository" ls-files --stage -- "$changed_path")
  if test -n "$index_entry"; then
    mode=${index_entry%% *}
    case "$mode" in 100644|100755) ;; *)
      printf 'Unsupported source index mode %s: %s\n' "$mode" "$changed_path" >&2
      exit 1
      ;;
    esac
  fi
done < <("$git_bin" -C "$repository" diff --cached --name-only --no-renames -z "$before" --)

export GIT_AUTHOR_NAME='Soren Planck'
export GIT_AUTHOR_EMAIL='sorenplanck@tutamail.com'
export GIT_COMMITTER_NAME='Soren Planck'
export GIT_COMMITTER_EMAIL='sorenplanck@tutamail.com'
assert_git_unchanged
"$git_bin" -C "$repository" commit -S -m "USDOM $source_tag immutable source"
created=$("$git_bin" -C "$repository" rev-parse --verify HEAD)
committed=true
test "$("$git_bin" -C "$repository" rev-parse --verify HEAD^)" = "$before"
identities=$("$git_bin" -C "$repository" show -s --format='%an <%ae>%n%cn <%ce>' HEAD)
test "$identities" = $'Soren Planck <sorenplanck@tutamail.com>\nSoren Planck <sorenplanck@tutamail.com>'
verification=$("$git_bin" -C "$repository" verify-commit --raw HEAD 2>&1)
grep -F -- "key $fingerprint" <<<"$verification" >/dev/null
while IFS= read -r status_line; do
  changed_path=${status_line:3}
  case "$changed_path" in "$project_relative/evidence/"*) ;; *)
    printf 'Non-evidence change remains after source commit: %s\n' "$changed_path" >&2
    exit 1
    ;;
  esac
done < <("$git_bin" -C "$repository" status --porcelain=v1 --untracked-files=all)
trap - EXIT
jq -n --arg sourceCommit "$created" --arg sourceTag "$source_tag" \
  --arg signingFingerprint "$fingerprint" \
  '{schema:"usdom-release-source-commit/v1",sourceCommit:$sourceCommit,
    sourceTag:$sourceTag,signingFingerprint:$signingFingerprint}'
