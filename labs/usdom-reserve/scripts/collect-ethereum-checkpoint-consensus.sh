#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout; do command -v "$tool_boundary_command" >/dev/null; done
source "$ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
for command in node python3 stat id mktemp flock sync ln timeout; do command -v "$command" >/dev/null; done
EVIDENCE_ROOT="$ROOT/evidence"
DIRECTORY="$EVIDENCE_ROOT/native-preactivation"
OUT="$DIRECTORY/ethereum-checkpoint-consensus.json"
if [[ ! -e "$EVIDENCE_ROOT" && ! -L "$EVIDENCE_ROOT" ]]; then
  mkdir -m 0700 -- "$EVIDENCE_ROOT"
fi
[[ -d "$EVIDENCE_ROOT" && ! -L "$EVIDENCE_ROOT" \
  && "$(stat -c '%u:%a' "$EVIDENCE_ROOT")" == "$(id -u):700" ]] || {
  printf '%s\n' 'Evidence root must be a direct caller-owned mode-0700 directory' >&2
  exit 1
}
run_pinned_timeout --signal=TERM --kill-after=2s 30s \
  python3 "$ROOT/scripts/ensure-private-child-directory.py" "$EVIDENCE_ROOT" native-preactivation
[[ -d "$DIRECTORY" && ! -L "$DIRECTORY" \
  && "$(stat -c '%u:%a' "$DIRECTORY")" == "$(id -u):700" ]] || exit 1
exec 9<"$DIRECTORY"
flock -n 9 || { printf '%s\n' 'Another checkpoint collector holds the evidence directory lock' >&2; exit 75; }
tmp=$(mktemp "$DIRECTORY/.ethereum-checkpoint-consensus.XXXXXX")
cleanup() { local status=${1:-$?}; trap - EXIT HUP INT TERM; rm -f -- "$tmp" || status=1; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
if [[ -e "$OUT" || -L "$OUT" ]]; then
  printf '%s\n' 'Ethereum checkpoint consensus evidence already exists; refusing to replace it' >&2
  exit 1
fi
run_pinned_timeout --signal=TERM --kill-after=5s 300s \
  node "$ROOT/scripts/collect-ethereum-checkpoint-consensus.mjs" >"$tmp"
chmod 0600 "$tmp"
if ! ln -- "$tmp" "$OUT"; then
  printf '%s\n' 'Ethereum checkpoint consensus evidence appeared concurrently; refusing to replace it' >&2
  exit 1
fi
rm -f -- "$tmp"
[[ -f "$OUT" && ! -L "$OUT" && "$(stat -c '%u:%a:%h' "$OUT")" == "$(id -u):600:1" ]] || {
  printf '%s\n' 'Installed checkpoint consensus evidence has an unsafe identity' >&2
  exit 1
}
sync -f "$OUT"
sync -f "$DIRECTORY"
trap - EXIT HUP INT TERM
printf '%s\n' "$OUT"
