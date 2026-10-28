#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: bash scripts/write-mainnet-fork-rehearsal-report.sh' >&2
  exit 64
fi
for command in node jq sha256sum stat realpath mktemp flock sync cmp id chmod awk python3; do
  command -v "$command" >/dev/null
done
ROOT=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$ROOT"
for tool_boundary_command in stat id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
pin_runtime_tool python3
python3() { assert_runtime_tool python3; "$python3_bin" "$@"; }
CONFIG="$ROOT/config"
METADATA="$CONFIG/mainnet-release-evidence.unconfigured.json"
EVIDENCE_ROOT="$ROOT/evidence"
if [[ ! -e "$EVIDENCE_ROOT" && ! -L "$EVIDENCE_ROOT" ]]; then mkdir -m 0700 "$EVIDENCE_ROOT"; fi
[[ -d "$EVIDENCE_ROOT" && ! -L "$EVIDENCE_ROOT"
  && "$(stat -c '%u:%a' "$EVIDENCE_ROOT")" == "$(id -u):700" ]] || exit 1
python3 "$ROOT/scripts/ensure-private-child-directory.py" "$EVIDENCE_ROOT" fork-rehearsal
DIRECTORY="$EVIDENCE_ROOT/fork-rehearsal"
RAW="$DIRECTORY/raw/mainnet-fork-rehearsal-observations.json"
[[ -d "$DIRECTORY" && ! -L "$DIRECTORY" && -f "$RAW" && ! -L "$RAW" ]] || {
  printf '%s\n' 'Direct raw fork rehearsal observations are missing' >&2
  exit 1
}
python3 "$ROOT/scripts/ensure-private-child-directory.py" "$DIRECTORY" reports
OUTPUT="$DIRECTORY/reports"
exec 8<"$CONFIG"
flock -n 8 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
exec 9<"$DIRECTORY"
flock -n 9 || { printf '%s\n' 'Another fork rehearsal writer holds the evidence lock' >&2; exit 75; }
metadata_sha256=$(sha256sum "$METADATA" | awk '{print $1}')
parent_device=$(stat -Lc '%d' "$CONFIG")
parent_inode=$(stat -Lc '%i' "$CONFIG")
INVALIDATION=$(mktemp -p "$OUTPUT" .invalidate.XXXXXXXX)
INVALIDATION_IDENTITY=$(/usr/bin/stat -c '%u:%d:%i:%a' -- "$INVALIDATION")
TEMPORARY=''
TEMPORARY_IDENTITY=''
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ -n $TEMPORARY ]]; then
    if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' -- "$TEMPORARY" 2>/dev/null) == "$TEMPORARY_IDENTITY" ]]; then
      /usr/bin/rm -rf -- "$TEMPORARY" || { (( status != 0 )) || status=1; }
    else
      (( status != 0 )) || status=1
    fi
  fi
  if [[ -e $INVALIDATION || -L $INVALIDATION ]]; then
    if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' -- "$INVALIDATION" 2>/dev/null) == "$INVALIDATION_IDENTITY" ]]; then
      /usr/bin/rm -f -- "$INVALIDATION" || { (( status != 0 )) || status=1; }
    else
      (( status != 0 )) || status=1
    fi
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
node "$ROOT/scripts/read-release-config-file-stdout.mjs" "$METADATA" \
  | jq '.mainnetForkRehearsalReport=null' > "$INVALIDATION"
chmod 0600 "$INVALIDATION"; sync -f "$INVALIDATION"
candidate_sha256=$(sha256sum "$INVALIDATION" | awk '{print $1}')
node "$ROOT/scripts/replace-locked-source-stdin.mjs" "$METADATA" \
  "$candidate_sha256" "$metadata_sha256" "$parent_device" "$parent_inode" \
  "$python3_bin" "$python3_sha256" < "$INVALIDATION"
metadata_sha256=$candidate_sha256
node "$ROOT/scripts/remove-private-file-durable.mjs" \
  "$OUTPUT/mainnet-fork-rehearsal-report.json"
sync -f "$METADATA"; sync -f "$OUTPUT"; sync -f "$CONFIG"
TEMPORARY=$(mktemp -d -p "$OUTPUT" .build.XXXXXXXX)
TEMPORARY_IDENTITY=$(/usr/bin/stat -c '%u:%d:%i:%a' -- "$TEMPORARY")
REPORT="$TEMPORARY/mainnet-fork-rehearsal-report.json"
NEXT="$TEMPORARY/mainnet-release-evidence.json"
SNAPSHOT="$TEMPORARY/mainnet-release-evidence.input.json"
CURRENT="$TEMPORARY/mainnet-release-evidence.current.json"
node "$ROOT/scripts/read-release-config-file-stdout.mjs" "$METADATA" >"$SNAPSHOT"
node "$ROOT/scripts/prepare-mainnet-fork-rehearsal-report.mjs" >"$REPORT"
chmod 0600 "$REPORT"
node "$ROOT/scripts/read-release-config-file-stdout.mjs" "$METADATA" >"$CURRENT"
cmp -s "$SNAPSHOT" "$CURRENT"
REPORT_SHA=$(sha256sum "$REPORT" | awk '{print $1}')
REPORT_PATH=evidence/fork-rehearsal/reports/mainnet-fork-rehearsal-report.json
jq --arg path "$REPORT_PATH" --arg sha "$REPORT_SHA" '
  ({path:$path,sha256:$sha}) as $document |
  if .mainnetForkRehearsalReport == null or .mainnetForkRehearsalReport == $document
  then .mainnetForkRehearsalReport=$document
  else error("mainnet fork rehearsal slot already contains a different document") end
' "$SNAPSHOT" >"$NEXT"
chmod 0600 "$NEXT"; sync -f "$REPORT"; sync -f "$NEXT"
TARGET="$OUTPUT/mainnet-fork-rehearsal-report.json"
node "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$TARGET" <"$REPORT"
sync -f "$TARGET"
node "$ROOT/scripts/read-release-config-file-stdout.mjs" "$METADATA" >"$CURRENT"
cmp -s "$SNAPSHOT" "$CURRENT"
if ! cmp -s "$NEXT" "$SNAPSHOT"; then
  candidate_sha256=$(sha256sum "$NEXT" | awk '{print $1}')
  node "$ROOT/scripts/replace-locked-source-stdin.mjs" "$METADATA" \
    "$candidate_sha256" "$metadata_sha256" "$parent_device" "$parent_inode" \
    "$python3_bin" "$python3_sha256" <"$NEXT"
fi
node "$ROOT/scripts/read-release-config-file-stdout.mjs" "$METADATA" >"$CURRENT"
cmp -s "$NEXT" "$CURRENT"
sync -f "$METADATA"; sync -f "$OUTPUT"; sync -f "$CONFIG"
jq '{mainnetForkRehearsalReport}' "$NEXT"
