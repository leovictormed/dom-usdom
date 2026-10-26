#!/usr/bin/env bash
set -euo pipefail

component="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
key_name=usdom-release-signing-ed25519
identity="sorenplanck@tutamail.com"

for command_name in git ssh-keygen awk stat chmod dirname python3 node id tail wc realpath sha256sum cut; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'FAIL: required command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done

node_bin=$(realpath "$(command -v node)")
[[ -x $node_bin && -f $node_bin && ! -L $node_bin ]]
node_owner=$(stat -Lc '%u' "$node_bin"); [[ $node_owner == 0 || $node_owner == "$(id -u)" ]]
[[ $(stat -Lc '%h' "$node_bin") == 1 ]]
node_size=$(stat -Lc '%s' "$node_bin"); (( node_size > 0 && node_size <= 512 * 1024 * 1024 ))
node_mode=$(stat -Lc '%a' "$node_bin"); (( (8#$node_mode & 8#022) == 0 ))
node_parent=$(dirname "$node_bin"); [[ $(realpath "$node_parent") == "$node_parent" ]]
node_parent_owner=$(stat -Lc '%u' "$node_parent"); [[ $node_parent_owner == 0 || $node_parent_owner == "$(id -u)" ]]
node_parent_mode=$(stat -Lc '%a' "$node_parent"); (( (8#$node_parent_mode & 8#022) == 0 ))
node_parent_identity=$(stat -Lc '%d:%i:%u:%a' "$node_parent")
node_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$node_bin")
node_sha256=$(sha256sum "$node_bin" | cut -d ' ' -f 1)
assert_node_unchanged() {
  [[ $(realpath "$(command -v node)") == "$node_bin" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$node_parent") == "$node_parent_identity" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$node_bin") == "$node_identity" ]]
  [[ $(sha256sum "$node_bin" | cut -d ' ' -f 1) == "$node_sha256" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$node_bin") == "$node_identity" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$node_parent") == "$node_parent_identity" ]]
}

account_home=$(python3 -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')
case "$account_home" in /*) ;; *) exit 1 ;; esac
test "$account_home" != /; test "$HOME" = "$account_home"
test "$(realpath "$HOME")" = "$account_home"
ssh_directory="$account_home/.ssh"
private_key="$ssh_directory/$key_name"
public_key="$private_key.pub"
allowed_signers="$account_home/.config/git/usdom-release-allowed-signers"

project="$(git -C "$component" rev-parse --show-toplevel 2>/dev/null)" || {
  printf 'FAIL: component is not inside a Git worktree: %s\n' "$component" >&2
  exit 1
}
case "${component}/" in
  "${project}/"*) ;;
  *)
    printf 'FAIL: Git worktree does not contain the USDOM component\n' >&2
    exit 1
    ;;
esac

umask 077

ensure_private_directory() {
  python3 - "$1" <<'PY'
import os,stat,sys

path=os.path.abspath(sys.argv[1])
if path!=os.path.normpath(path) or path=='/':
    raise SystemExit(f'FAIL: unsafe private directory path: {path}')
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
descriptor=os.open('/',flags)
current='/'
try:
    for component in path.split('/')[1:]:
        current=os.path.join(current,component)
        try:
            child=os.open(component,flags,dir_fd=descriptor)
        except FileNotFoundError:
            os.mkdir(component,0o700,dir_fd=descriptor)
            os.fsync(descriptor)
            child=os.open(component,flags,dir_fd=descriptor)
        os.close(descriptor)
        descriptor=child
    metadata=os.fstat(descriptor)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.getuid()
            or stat.S_IMODE(metadata.st_mode)!=0o700):
        raise SystemExit(f'FAIL: private directory must be direct, owner-only 0700: {path}')
    named=os.lstat(path)
    if ((named.st_dev,named.st_ino)!=(metadata.st_dev,metadata.st_ino)
            or os.path.realpath(path)!=path):
        raise SystemExit(f'FAIL: private directory identity mismatch: {path}')
finally:
    os.close(descriptor)
PY
}

ensure_private_directory "$ssh_directory"
cd "$ssh_directory"
ssh_directory_identity=$(stat -Lc '%d:%i' .)

private_present=false
public_present=false
[[ -e "$key_name" || -L "$key_name" ]] && private_present=true
[[ -e "${key_name}.pub" || -L "${key_name}.pub" ]] && public_present=true

if [[ "$private_present" != "$public_present" ]]; then
  printf 'FAIL: incomplete release-signing key pair at %s\n' "$private_key" >&2
  exit 1
fi

if [[ "$private_present" == false ]]; then
  printf 'Creating the dedicated USDOM release-signing key.\n' >&2
  printf 'Enter and confirm a strong passphrase only in the ssh-keygen prompts.\n' >&2
  ssh-keygen -q -t ed25519 -a 100 -C 'Soren Planck <sorenplanck@tutamail.com>' \
    -f "./$key_name"
fi

for key_file in "$key_name" "${key_name}.pub"; do
  if [[ ! -f "$key_file" || -L "$key_file" ]] \
      || [[ $(stat -c '%u:%h' "$key_file") != "$(id -u):1" ]] \
      || [[ $(stat -c '%s' "$key_file") -lt 1 || $(stat -c '%s' "$key_file") -gt 1048576 ]]; then
    printf 'FAIL: release-signing key must be a direct owner-only single-link file: %s\n' \
      "$ssh_directory/$key_file" >&2
    exit 1
  fi
done
chmod 600 "$key_name" "${key_name}.pub"
test "$(stat -c '%u:%a:%h' "$key_name")" = "$(id -u):600:1"
test "$(stat -c '%u:%a:%h' "${key_name}.pub")" = "$(id -u):600:1"
mapfile -t public_lines < "${key_name}.pub"
if [[ ${#public_lines[@]} -ne 1 || $(tail -c 1 "${key_name}.pub" | wc -l) -ne 1 ]]; then
  printf '%s\n' 'FAIL: release-signing public key must contain one canonical line' >&2
  exit 1
fi
public_line=${public_lines[0]}
case "$public_line" in
  ssh-ed25519\ *) ;;
  *)
    printf 'FAIL: release-signing public key is not canonical Ed25519\n' >&2
    exit 1
    ;;
esac

private_fingerprint="$(ssh-keygen -lf "./$key_name" -E sha256 | awk 'NR == 1 {print $2}')"
fingerprint="$(ssh-keygen -lf "./${key_name}.pub" -E sha256 | awk 'NR == 1 {print $2}')"
if [[ "$private_fingerprint" != "$fingerprint" ]]; then
  printf '%s\n' 'FAIL: release-signing public and private keys do not form one pair' >&2
  exit 1
fi
case "$fingerprint" in
  SHA256:???????????????????????????????????????????) ;;
  *)
    printf 'FAIL: release-signing fingerprint is not canonical SHA-256\n' >&2
    exit 1
    ;;
esac

if [[ $(stat -Lc '%d:%i' "$ssh_directory") != "$ssh_directory_identity" ]] \
    || [[ $(pwd -P) != "$ssh_directory" ]]; then
  printf '%s\n' 'FAIL: release-signing directory changed while inspecting the key' >&2
  exit 1
fi
cd "$component"
ensure_private_directory "$(dirname "$allowed_signers")"
printf '%s %s\n' "$identity" "$public_line" \
  | { assert_node_unchanged; "$node_bin" "$component/scripts/install-private-file-stdin.mjs" "$allowed_signers"; }

git -C "$project" config --local user.name 'Soren Planck'
git -C "$project" config --local user.email 'sorenplanck@tutamail.com'
git -C "$project" config --local gpg.format ssh
git -C "$project" config --local user.signingkey "$private_key"
git -C "$project" config --local gpg.ssh.allowedSignersFile "$allowed_signers"
git -C "$project" config --local commit.gpgsign true
git -C "$project" config --local tag.gpgsign true

test "$(git -C "$project" config --get user.name)" = 'Soren Planck'
test "$(git -C "$project" config --get user.email)" = 'sorenplanck@tutamail.com'
test "$(git -C "$project" config --get gpg.format)" = 'ssh'
test "$(git -C "$project" config --get user.signingkey)" = "$private_key"
test "$(git -C "$project" config --get gpg.ssh.allowedSignersFile)" = "$allowed_signers"
test "$(git -C "$project" config --get commit.gpgsign)" = 'true'
test "$(git -C "$project" config --get tag.gpgsign)" = 'true'

printf '{\n'
printf '  "schema": "usdom-release-signing-public-identity-v1",\n'
printf '  "fingerprint": "%s",\n' "$fingerprint"
printf '  "publicKeyFile": "%s",\n' "$public_key"
printf '  "allowedSignersFile": "%s"\n' "$allowed_signers"
printf '}\n'
