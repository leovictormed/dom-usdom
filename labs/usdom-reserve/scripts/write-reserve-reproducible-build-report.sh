#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: bash scripts/write-reserve-reproducible-build-report.sh' >&2
  exit 64
fi
for command in node jq sha256sum stat realpath mktemp flock sync cmp id chmod awk forge; do
  command -v "$command" >/dev/null
done
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool jq; pin_runtime_tool timeout
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
config_directory="$project/config"
metadata="$config_directory/mainnet-release-evidence.unconfigured.json"
evidence_root="$project/evidence"
output="$evidence_root/reproducible-build"
if [[ ! -e "$evidence_root" ]]; then mkdir -m 0700 "$evidence_root"; fi
test -d "$evidence_root"; test ! -L "$evidence_root"
test "$(stat -c '%u' "$evidence_root")" = "$(id -u)"
test "$(stat -c '%a' "$evidence_root")" = 700
if [[ ! -e "$output" ]]; then mkdir -m 0700 "$output"; fi
test -d "$output"; test ! -L "$output"
test "$(stat -c '%u' "$output")" = "$(id -u)"
test "$(stat -c '%a' "$output")" = 700
exec 8<"$config_directory"
flock -n 8 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
exec 9<"$output"
flock -n 9 || { printf '%s\n' 'Another reproducible-build writer holds the output lock' >&2; exit 75; }

invalidation=$(mktemp -p "$output" .invalidate.XXXXXXXX)
trap 'rm -f -- "$invalidation"' EXIT
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" \
 | jq '.reproducibleBuildReport=null' >"$invalidation"
chmod 0600 "$invalidation"; sync -f "$invalidation"
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/install-release-config-stdin.mjs" "$metadata" <"$invalidation"
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/remove-private-file-durable.mjs" \
 "$output/reserve-reproducible-build-report.json"

temporary=$(mktemp -d -p "$output" .build.XXXXXXXX)
trap 'rm -f -- "$invalidation"; rm -rf -- "$temporary"' EXIT
report="$temporary/reserve-reproducible-build-report.json"
next_metadata="$temporary/mainnet-release-evidence.json"
metadata_snapshot="$temporary/mainnet-release-evidence.input.json"
metadata_current="$temporary/mainnet-release-evidence.current.json"
metadata_installed="$temporary/mainnet-release-evidence.installed.json"
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" > "$metadata_snapshot"
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" scripts/prepare-reserve-reproducible-build-report.mjs > "$report"
chmod 0600 "$report"
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" > "$metadata_current"
cmp -s "$metadata_snapshot" "$metadata_current"
report_sha=$(sha256sum "$report" | awk '{print $1}')
report_path=evidence/reproducible-build/reserve-reproducible-build-report.json
jq --arg path "$report_path" --arg sha "$report_sha" '
  ({path:$path,sha256:$sha}) as $document |
  if .reproducibleBuildReport == null or .reproducibleBuildReport == $document
  then .reproducibleBuildReport=$document
  else error("reproducible-build report slot already contains a different document") end
' "$metadata_snapshot" > "$next_metadata"
chmod 0600 "$next_metadata"
target="$output/reserve-reproducible-build-report.json"
sync -f "$report"; sync -f "$next_metadata"
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/install-private-file-immutable-stdin.mjs" "$target" < "$report"
sync -f "$target"
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" > "$metadata_current"
cmp -s "$metadata_snapshot" "$metadata_current"
if ! cmp -s "$next_metadata" "$metadata_snapshot"; then
  assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/install-release-config-stdin.mjs" "$metadata" < "$next_metadata"
fi
assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" > "$metadata_installed"
cmp -s "$next_metadata" "$metadata_installed"
sync -f "$metadata"; sync -f "$output"; sync -f "$config_directory"
jq '{reproducibleBuildReport}' "$next_metadata"
