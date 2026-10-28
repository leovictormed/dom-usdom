#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent export:dom-preactivation-anchor' >&2
  exit 64
fi
for command in stat realpath mktemp flock sync cmp cargo sha256sum awk dirname id node cut; do command -v "$command" >/dev/null; done
pin_cargo() {
  cargo_bin=$(realpath "$(command -v cargo)")
  [[ -x $cargo_bin && -f $cargo_bin && ! -L $cargo_bin ]]
  [[ $(stat -Lc '%h' "$cargo_bin") == 1 ]]
  cargo_size=$(stat -Lc '%s' "$cargo_bin"); (( cargo_size > 0 && cargo_size <= 512 * 1024 * 1024 ))
  cargo_owner=$(stat -Lc '%u' "$cargo_bin"); [[ $cargo_owner == 0 || $cargo_owner == "$(id -u)" ]]
  cargo_mode=$(stat -Lc '%a' "$cargo_bin"); (( (8#$cargo_mode & 8#022) == 0 ))
  cargo_directory=$(dirname "$cargo_bin"); [[ $(realpath "$cargo_directory") == "$cargo_directory" ]]
  cargo_directory_owner=$(stat -Lc '%u' "$cargo_directory"); [[ $cargo_directory_owner == 0 || $cargo_directory_owner == "$(id -u)" ]]
  cargo_directory_mode=$(stat -Lc '%a' "$cargo_directory"); (( (8#$cargo_directory_mode & 8#022) == 0 ))
  cargo_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$cargo_bin")
  cargo_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$cargo_directory")
  cargo_sha256=$(sha256sum "$cargo_bin" | awk '{print $1}')
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$cargo_bin") == "$cargo_identity" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$cargo_directory") == "$cargo_directory_identity" ]]
}
assert_cargo_unchanged() {
  [[ $(realpath "$(command -v cargo)") == "$cargo_bin" ]]
  [[ $(realpath "$cargo_directory") == "$cargo_directory" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$cargo_directory") == "$cargo_directory_identity" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$cargo_bin") == "$cargo_identity" ]]
  [[ $(sha256sum "$cargo_bin" | awk '{print $1}') == "$cargo_sha256" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$cargo_bin") == "$cargo_identity" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$cargo_directory") == "$cargo_directory_identity" ]]
}
pin_cargo
project=$(realpath "$(dirname "$0")/..")
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
repository=$(realpath "$project/../..")
test "$PWD" = "$project"
node_root="$HOME/.local/share/dom-usdom/mainnet-node"
data_root="$node_root/data"
evidence_directory="$project/evidence/native-preactivation"
anchor="$evidence_directory/dom-anchor.json"
[[ -d "$data_root" && ! -L "$node_root" && ! -L "$data_root" ]] || {
  printf 'Missing safe stopped DOM mainnet data directory: %s\n' "$data_root" >&2
  exit 1
}
test "$(stat -c '%u:%a' "$node_root")" = "$(id -u):700"
test "$(stat -c '%u:%a' "$data_root")" = "$(id -u):700"
mkdir -p -- "$evidence_directory"
test ! -L "$evidence_directory"
exec 8<"$node_root"
flock -n 8 || { printf '%s\n' 'The DOM node is running or another exporter holds its data lock' >&2; exit 75; }
temporary=$(mktemp -p "$evidence_directory" .dom-anchor.XXXXXXXX)
trap 'rm -f -- "$temporary"' EXIT
cd "$repository"
assert_cargo_unchanged
"$cargo_bin" run --quiet --locked -p dom-node --features native-usdom-v4-poc \
  --bin dom-usdom-export-preactivation-anchor -- \
  --data-dir "$data_root" --network mainnet --max-span 390 > "$temporary"
chmod 0600 "$temporary"; sync -f "$temporary"
if [[ -e "$anchor" ]]; then
  test -f "$anchor"; test ! -L "$anchor"; cmp -s "$temporary" "$anchor" || {
    printf '%s\n' 'Existing authenticated DOM anchor differs from the current canonical tip' >&2
    exit 1
  }
else
  node "$project/scripts/install-private-file-immutable-stdin.mjs" "$anchor" < "$temporary"
fi
cmp -s "$temporary" "$anchor"
sync -f "$anchor"; sync -f "$evidence_directory"
cat -- "$anchor"
