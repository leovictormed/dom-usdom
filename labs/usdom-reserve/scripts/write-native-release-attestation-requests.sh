#!/usr/bin/env bash
set -euo pipefail
# RPC source files can contain reusable provider credentials.  Keep child
# process memory out of tracing, panic backtraces and core artifacts.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing RPC operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE=<absolute-owner-only-file> npm run --silent write:native-release-attestation-requests' >&2
  exit 64
fi
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required}"
for command in node jq stat realpath mktemp flock sync id chmod cargo; do command -v "$command" >/dev/null; done
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
for tool_boundary_command in stat id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
evidence_root="$project/evidence"
output="$evidence_root/native-attestations"
if [[ ! -e "$evidence_root" ]]; then mkdir -m 0700 "$evidence_root"; fi
test -d "$evidence_root"; test ! -L "$evidence_root"
test "$(stat -c '%u:%a' "$evidence_root")" = "$(id -u):700"
if [[ ! -e "$output" ]]; then mkdir -m 0700 "$output"; fi
test -d "$output"; test ! -L "$output"
test "$(stat -c '%u:%a' "$output")" = "$(id -u):700"
exec 9<"$output"
flock -n 9 || { printf '%s\n' 'Another native-attestation writer holds the lock' >&2; exit 75; }
temporary=$(mktemp -p "$output" .requests.XXXXXXXX)
trap 'rm -f -- "$temporary"' EXIT
node scripts/prepare-native-release-attestation-requests.mjs > "$temporary"
jq -e '.schema == "usdom-native-release-attestation-requests/v2"
  and ([.requests[].attestation.signature] | all(. == null))
  and ([.requests[].digest] | all(test("^0x[0-9a-fA-F]{64}$")))' "$temporary" >/dev/null
chmod 0600 "$temporary"; sync -f "$temporary"
target="$output/native-release-attestation-requests.json"
node "$project/scripts/install-private-file-immutable-stdin.mjs" --json "$target" < "$temporary"
sync -f "$target"; sync -f "$output"
jq '{schema,releaseId,sourceCommit,finalizedAnchor,subjects,
  digests:(.requests | with_entries(.value=.value.digest))}' "$temporary"
