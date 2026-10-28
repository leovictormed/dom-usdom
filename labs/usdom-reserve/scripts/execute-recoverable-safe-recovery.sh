#!/usr/bin/env bash
set -euo pipefail
# RPC source files can contain reusable provider credentials.  Keep child
# process memory out of tracing, panic backtraces and core artifacts.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
# Do not carry caller-owned evidence, lock or logging descriptors into any
# authority child. Bash's script descriptor 255 is internal and CLOEXEC.
for fd_path in /proc/$$/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ "$inherited_fd" =~ ^[0-9]+$ ]] || exit 1
  ((inherited_fd > 2)) || continue
  [[ "$inherited_fd" == 255 ]] && continue
  exec {inherited_fd}>&-
done
# Do not let the operator's ambient toolchain, loader, proxy or debug settings
# alter credential-bearing Node/Cast children. USDOM inputs are exported
# explicitly below; HOME is retained for hardware-wallet integration.
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
  RUST_LOG RUSTFLAGS RUSTC_WRAPPER \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/home/leonardov/.foundry/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C LC_ALL=C TZ=UTC
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing RPC operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent execute:recoverable-safe-recovery' >&2
  exit 64
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  printf '%s\n' 'Safe recovery authorization requires an interactive terminal.' >&2
  exit 1
fi
[[ -c /dev/tty ]] || { printf '%s\n' 'Safe recovery terminal is unavailable.' >&2; exit 1; }
# Noninteractive children receive EOF. Only explicit authorization prompts and
# Explicit authorization prompts reopen the controlling terminal when needed.
exec </dev/null

: "${USDOM_SAFE_PACKAGE:?USDOM_SAFE_PACKAGE is required}"
: "${USDOM_SAFE_BASELINE:?USDOM_SAFE_BASELINE is required}"
: "${USDOM_SAFE_RECOVERY_PLAN:?USDOM_SAFE_RECOVERY_PLAN is required}"
: "${USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS:?USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS is required}"
: "${USDOM_SAFE_RECOVERY_TRANSACTIONS:?USDOM_SAFE_RECOVERY_TRANSACTIONS is required}"
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?USDOM_CONTROL_EVIDENCE_DIRECTORY is required}"
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required}"
: "${USDOM_SAFE_RECOVERY_RELAYER_POLICY:?USDOM_SAFE_RECOVERY_RELAYER_POLICY is required}"

for command in cast jq node stat realpath mktemp cmp timeout setsid sha256sum flock chmod sleep awk dirname id; do
  command -v "$command" >/dev/null
done
account_home=$(/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node -e 'const os=require("os");process.stdout.write(os.userInfo().homedir)')
[[ ${HOME:-} == "$account_home" && $account_home == /* && $account_home != / && -d $account_home && ! -L $account_home ]]
[[ $(stat -Lc '%u' "$account_home") == "$(id -u)" ]]
home_mode=$(stat -Lc '%a' "$account_home"); (( (8#$home_mode & 8#022) == 0 ))
cast_bin=$(realpath "$(command -v cast)")
test -x "$cast_bin"; test -f "$cast_bin"; test ! -L "$cast_bin"
cast_size=$(stat -Lc '%s' "$cast_bin"); (( cast_size > 0 && cast_size <= 512 * 1024 * 1024 ))
cast_owner=$(stat -Lc '%u' "$cast_bin")
test "$cast_owner" = 0 || test "$cast_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$cast_bin")" = 1
cast_mode=$(stat -Lc '%a' "$cast_bin")
(( (8#$cast_mode & 8#022) == 0 ))
cast_directory=$(dirname "$cast_bin")
test "$(realpath "$cast_directory")" = "$cast_directory"
cast_directory_owner=$(stat -Lc '%u' "$cast_directory")
test "$cast_directory_owner" = 0 || test "$cast_directory_owner" = "$(id -u)"
cast_directory_mode=$(stat -Lc '%a' "$cast_directory")
(( (8#$cast_directory_mode & 8#022) == 0 ))
cast_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$cast_directory")
cast_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$cast_bin")
cast_sha256=$(sha256sum "$cast_bin" | awk '{print $1}')
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$cast_bin")" = "$cast_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$cast_directory")" = "$cast_directory_identity"
assert_cast_unchanged() {
  test "$(realpath "$cast_directory")" = "$cast_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$cast_directory")" = "$cast_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$cast_bin")" = "$cast_identity"
  test "$(sha256_file "$cast_bin")" = "$cast_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$cast_bin")" = "$cast_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$cast_directory")" = "$cast_directory_identity"
}
node_bin=$(realpath "$(command -v node)")
test -x "$node_bin"; test -f "$node_bin"; test ! -L "$node_bin"
node_size=$(stat -Lc '%s' "$node_bin"); (( node_size > 0 && node_size <= 512 * 1024 * 1024 ))
node_owner=$(stat -Lc '%u' "$node_bin")
test "$node_owner" = 0 || test "$node_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$node_bin")" = 1
node_mode=$(stat -Lc '%a' "$node_bin")
(( (8#$node_mode & 8#022) == 0 ))
node_directory=$(dirname "$node_bin")
test "$(realpath "$node_directory")" = "$node_directory"
node_directory_owner=$(stat -Lc '%u' "$node_directory")
test "$node_directory_owner" = 0 || test "$node_directory_owner" = "$(id -u)"
node_directory_mode=$(stat -Lc '%a' "$node_directory")
(( (8#$node_directory_mode & 8#022) == 0 ))
node_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$node_directory")
node_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$node_bin")
node_sha256=$(sha256sum "$node_bin" | awk '{print $1}')
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$node_bin")" = "$node_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
assert_node_unchanged() {
  test "$(realpath "$node_directory")" = "$node_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$node_bin")" = "$node_identity"
  test "$(sha256_file "$node_bin")" = "$node_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$node_bin")" = "$node_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
}
jq_bin=$(realpath "$(command -v jq)")
test -x "$jq_bin"; test -f "$jq_bin"; test ! -L "$jq_bin"
jq_size=$(stat -Lc '%s' "$jq_bin"); (( jq_size > 0 && jq_size <= 512 * 1024 * 1024 ))
jq_owner=$(stat -Lc '%u' "$jq_bin")
test "$jq_owner" = 0 || test "$jq_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$jq_bin")" = 1
jq_mode=$(stat -Lc '%a' "$jq_bin")
(( (8#$jq_mode & 8#022) == 0 ))
jq_directory=$(dirname "$jq_bin")
test "$(realpath "$jq_directory")" = "$jq_directory"
jq_directory_owner=$(stat -Lc '%u' "$jq_directory")
test "$jq_directory_owner" = 0 || test "$jq_directory_owner" = "$(id -u)"
jq_directory_mode=$(stat -Lc '%a' "$jq_directory")
(( (8#$jq_directory_mode & 8#022) == 0 ))
jq_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$jq_directory")
jq_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$jq_bin")
jq_sha256=$(sha256sum "$jq_bin" | awk '{print $1}')
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$jq_bin")" = "$jq_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$jq_directory")" = "$jq_directory_identity"
assert_jq_unchanged() {
  test "$(realpath "$jq_directory")" = "$jq_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$jq_directory")" = "$jq_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$jq_bin")" = "$jq_identity"
  test "$(sha256_file "$jq_bin")" = "$jq_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$jq_bin")" = "$jq_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$jq_directory")" = "$jq_directory_identity"
}
sha256_bin=$(realpath "$(command -v sha256sum)")
test -x "$sha256_bin"; test -f "$sha256_bin"; test ! -L "$sha256_bin"
test "$(stat -Lc '%u:%h' "$sha256_bin")" = "0:1" || test "$(stat -Lc '%u:%h' "$sha256_bin")" = "$(id -u):1"
sha256_mode=$(stat -Lc '%a' "$sha256_bin"); (( (8#$sha256_mode & 8#022) == 0 ))
sha256_directory=$(dirname "$sha256_bin")
test "$(stat -Lc '%u' "$sha256_directory")" = 0 || test "$(stat -Lc '%u' "$sha256_directory")" = "$(id -u)"
sha256_directory_mode=$(stat -Lc '%a' "$sha256_directory"); (( (8#$sha256_directory_mode & 8#022) == 0 ))
sha256_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$sha256_bin")
sha256_self_output=$("$sha256_bin" -- "$sha256_bin")
[[ $sha256_self_output != *$'\n'* ]]
sha256_self=${sha256_self_output%% *}; [[ $sha256_self =~ ^[0-9a-f]{64}$ ]]
assert_sha256_unchanged() {
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$sha256_bin")" = "$sha256_identity"
  local output digest
  output=$("$sha256_bin" -- "$sha256_bin"); [[ $output != *$'\n'* ]]
  digest=${output%% *}; test "$digest" = "$sha256_self"
}
sha256_file() {
  local output digest suffix
  assert_sha256_unchanged
  output=$("$sha256_bin" -- "$1"); [[ $output != *$'\n'* ]]
  digest=${output%% *}; suffix=${output#"$digest"}
  [[ $digest =~ ^[0-9a-f]{64}$ && $suffix == "  $1" ]]
  printf '%s\n' "$digest"
}
cmp_bin=$(realpath "$(command -v cmp)")
test -x "$cmp_bin"; test -f "$cmp_bin"; test ! -L "$cmp_bin"
test "$(stat -Lc '%u:%h' "$cmp_bin")" = "0:1" || test "$(stat -Lc '%u:%h' "$cmp_bin")" = "$(id -u):1"
cmp_mode=$(stat -Lc '%a' "$cmp_bin"); (( (8#$cmp_mode & 8#022) == 0 ))
cmp_directory=$(dirname "$cmp_bin")
test "$(stat -Lc '%u' "$cmp_directory")" = 0 || test "$(stat -Lc '%u' "$cmp_directory")" = "$(id -u)"
cmp_directory_mode=$(stat -Lc '%a' "$cmp_directory"); (( (8#$cmp_directory_mode & 8#022) == 0 ))
cmp_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$cmp_bin")
cmp_sha256=$(sha256_file "$cmp_bin")
assert_cmp_unchanged() {
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$cmp_bin")" = "$cmp_identity"
  test "$(sha256_file "$cmp_bin")" = "$cmp_sha256"
}
timeout_bin=$(realpath "$(command -v timeout)")
test -x "$timeout_bin"; test -f "$timeout_bin"; test ! -L "$timeout_bin"
timeout_size=$(stat -Lc '%s' "$timeout_bin"); (( timeout_size > 0 && timeout_size <= 512 * 1024 * 1024 ))
test "$(stat -Lc '%u:%h' "$timeout_bin")" = "0:1" || test "$(stat -Lc '%u:%h' "$timeout_bin")" = "$(id -u):1"
timeout_mode=$(stat -Lc '%a' "$timeout_bin"); (( (8#$timeout_mode & 8#022) == 0 ))
timeout_directory=$(dirname "$timeout_bin")
test "$(realpath "$timeout_directory")" = "$timeout_directory"
test "$(stat -Lc '%u' "$timeout_directory")" = 0 || test "$(stat -Lc '%u' "$timeout_directory")" = "$(id -u)"
timeout_directory_mode=$(stat -Lc '%a' "$timeout_directory"); (( (8#$timeout_directory_mode & 8#022) == 0 ))
timeout_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$timeout_directory")
timeout_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$timeout_bin")
timeout_sha256=$(sha256_file "$timeout_bin")
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$timeout_bin")" = "$timeout_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$timeout_directory")" = "$timeout_directory_identity"
assert_timeout_unchanged() {
  test "$(realpath "$timeout_directory")" = "$timeout_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$timeout_directory")" = "$timeout_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$timeout_bin")" = "$timeout_identity"
  test "$(sha256_file "$timeout_bin")" = "$timeout_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$timeout_bin")" = "$timeout_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$timeout_directory")" = "$timeout_directory_identity"
}
setsid_bin=$(realpath "$(command -v setsid)")
test -x "$setsid_bin"; test -f "$setsid_bin"; test ! -L "$setsid_bin"
test "$(stat -Lc '%u:%h' "$setsid_bin")" = "0:1" || test "$(stat -Lc '%u:%h' "$setsid_bin")" = "$(id -u):1"
setsid_mode=$(stat -Lc '%a' "$setsid_bin"); (( (8#$setsid_mode & 8#022) == 0 ))
setsid_directory=$(dirname "$setsid_bin")
test "$(realpath "$setsid_directory")" = "$setsid_directory"
test "$(stat -Lc '%u' "$setsid_directory")" = 0 || test "$(stat -Lc '%u' "$setsid_directory")" = "$(id -u)"
setsid_directory_mode=$(stat -Lc '%a' "$setsid_directory"); (( (8#$setsid_directory_mode & 8#022) == 0 ))
setsid_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$setsid_directory")
setsid_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$setsid_bin")
setsid_sha256=$(sha256_file "$setsid_bin")
assert_setsid_unchanged() {
  test "$(realpath "$setsid_directory")" = "$setsid_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$setsid_directory")" = "$setsid_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$setsid_bin")" = "$setsid_identity"
  test "$(sha256_file "$setsid_bin")" = "$setsid_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$setsid_bin")" = "$setsid_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$setsid_directory")" = "$setsid_directory_identity"
}
flock_bin=$(realpath "$(command -v flock)")
test -x "$flock_bin"; test -f "$flock_bin"; test ! -L "$flock_bin"
test "$(stat -Lc '%u:%h' "$flock_bin")" = "0:1" || test "$(stat -Lc '%u:%h' "$flock_bin")" = "$(id -u):1"
flock_mode=$(stat -Lc '%a' "$flock_bin"); (( (8#$flock_mode & 8#022) == 0 ))
flock_directory=$(dirname "$flock_bin")
test "$(stat -Lc '%u' "$flock_directory")" = 0 || test "$(stat -Lc '%u' "$flock_directory")" = "$(id -u)"
flock_directory_mode=$(stat -Lc '%a' "$flock_directory"); (( (8#$flock_directory_mode & 8#022) == 0 ))
flock_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$flock_bin")
flock_sha256=$(sha256_file "$flock_bin")
assert_flock_unchanged() {
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$flock_bin")" = "$flock_identity"
  test "$(sha256_file "$flock_bin")" = "$flock_sha256"
}
pin_auxiliary_tool() {
  local name=$1 path directory owner mode directory_owner directory_mode
  path=$(realpath "$(command -v "$name")")
  test -x "$path"; test -f "$path"; test ! -L "$path"
  owner=$(stat -Lc '%u' "$path"); test "$owner" = 0 || test "$owner" = "$(id -u)"
  test "$(stat -Lc '%h' "$path")" = 1
  mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
  directory=$(dirname "$path"); test "$(realpath "$directory")" = "$directory"
  directory_owner=$(stat -Lc '%u' "$directory"); test "$directory_owner" = 0 || test "$directory_owner" = "$(id -u)"
  directory_mode=$(stat -Lc '%a' "$directory"); (( (8#$directory_mode & 8#022) == 0 ))
  printf -v "${name}_bin" '%s' "$path"
  printf -v "${name}_identity" '%s' "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"
  printf -v "${name}_directory_identity" '%s' "$(stat -Lc '%d:%i:%u:%a' "$directory")"
  printf -v "${name}_sha256" '%s' "$(sha256_file "$path")"
}
assert_auxiliary_tool() {
  local name=$1 bin_name="${1}_bin" identity_name="${1}_identity"
  local directory_identity_name="${1}_directory_identity" sha_name="${1}_sha256" path directory
  path=${!bin_name}; directory=$(dirname "$path")
  test "$(realpath "$directory")" = "$directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$directory")" = "${!directory_identity_name}"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")" = "${!identity_name}"
  test "$(sha256_file "$path")" = "${!sha_name}"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")" = "${!identity_name}"
  test "$(stat -Lc '%d:%i:%u:%a' "$directory")" = "${!directory_identity_name}"
}
declare mktemp_bin mktemp_identity mktemp_directory_identity mktemp_sha256
declare chmod_bin chmod_identity chmod_directory_identity chmod_sha256
declare sleep_bin sleep_identity sleep_directory_identity sleep_sha256
for auxiliary_tool in mktemp chmod sleep; do pin_auxiliary_tool "$auxiliary_tool"; done
run_chmod() { assert_auxiliary_tool chmod; "$chmod_bin" "$@"; }
run_sleep() { assert_auxiliary_tool sleep; "$sleep_bin" "$@"; }
# Bootstrap discovery is complete. Every authority-transforming tool is now
# invoked by its authenticated absolute path; retain only the system utility path.
export PATH=/usr/bin:/bin
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
package_source=$(realpath -ms "$USDOM_SAFE_PACKAGE")
baseline_source=$(realpath -ms "$USDOM_SAFE_BASELINE")
plan_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_PLAN")
replacement_proofs_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS")
transactions_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_TRANSACTIONS")
relayer_policy_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_RELAYER_POLICY")
evidence_directory=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY")
test -d "$evidence_directory"
test ! -L "$evidence_directory"
test "$(stat -c '%u' "$evidence_directory")" = "$(id -u)"
test "$(stat -c '%a' "$evidence_directory")" = '700'
export USDOM_CONTROL_EVIDENCE_DIRECTORY=$evidence_directory
exec 9<"$evidence_directory"
assert_flock_unchanged
if ! "$flock_bin" -n 9; then
  printf '%s\n' 'Another Safe recovery executor holds the evidence-directory lock' >&2
  exit 75
fi
test "$(realpath -e /proc/$$/fd/9)" = "$evidence_directory"
evidence_parent_identity=$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/9)
test "$evidence_parent_identity" = "$(stat -c '%d:%i:%u:%a' -- "$evidence_directory")"
assert_evidence_parent() {
  test "$(realpath -e "$evidence_directory")" = "$evidence_directory"
  test "$(realpath -e /proc/$$/fd/9)" = "$evidence_directory"
  test "$(stat -c '%d:%i:%u:%a' -- "$evidence_directory")" = "$evidence_parent_identity"
  test "$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/9)" = "$evidence_parent_identity"
}
assert_node_unchanged
assert_auxiliary_tool mktemp
temporary=$("$mktemp_bin" -d -p /dev/shm usdom-safe-recovery-execute.XXXXXXXX)
run_chmod 0700 "$temporary"
temporary_identity=$(/usr/bin/stat -c '%u:%d:%i:%a' -- "$temporary")
rpc_proxy_pid=''
safe_broadcast_state=clean
stop_rpc_proxy() {
  [[ $rpc_proxy_pid =~ ^[0-9]+$ ]] || return 0
  kill -TERM -- "-$rpc_proxy_pid" 2>/dev/null || true
  for _ in {1..40}; do
    kill -0 -- "-$rpc_proxy_pid" 2>/dev/null || break
    run_sleep 0.05
  done
  kill -KILL -- "-$rpc_proxy_pid" 2>/dev/null || true
  wait "$rpc_proxy_pid" 2>/dev/null || true
  rpc_proxy_pid=''
}
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  stop_rpc_proxy
  if [[ $safe_broadcast_state != clean ]] && (( status != 0 )); then
    printf '%s\n' 'Safe transaction outcome requires exact-hash and finalized-nonce revalidation; do not sign or publish a replacement.' >&2
    status=80
  fi
  if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' -- "$temporary" 2>/dev/null) == "$temporary_identity" ]] &&
    assert_node_unchanged && assert_timeout_unchanged &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' \
      "$temporary" > /dev/null 2> /dev/null &&
    assert_node_unchanged && assert_timeout_unchanged && test ! -e "$temporary"; then
    :
  else
    # Preserve a publish/timeout/signal status so callers retain the fact that
    # an on-chain transition may already have been submitted.
    (( status != 0 )) || status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
remove_derived_private() {
  local name=$1 output="$temporary/remove-$1.stdout" error="$temporary/remove-$1.stderr" status
  [[ $name =~ ^[A-Za-z0-9._-]+$ ]]
  assert_evidence_parent
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
    "$node_bin" "$project/scripts/remove-private-file-durable.mjs" \
    "$evidence_directory/$name" > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status != 0)); then
    printf 'Bounded derived-evidence removal failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test ! -s "$output"
  test ! -s "$error"
  test ! -e "$evidence_directory/$name"
  assert_evidence_parent
}
# Finalized observations/reports are derived completion artifacts and may be
# regenerated at a newer finalized head. Invalidate them under the evidence
# lock before credentials or RPC; preserve raw transactions, hashes and
# envelopes as immutable anti-replay records.
for derived in governance-finalized-execution.json reserveGuardian-finalized-execution.json \
  checkpointGuardian-finalized-execution.json safe-recovery-finalized-report.json \
  safe-recovery-finalized-bundle.json; do
  remove_derived_private "$derived"
done
rpc_proxy_ready="$temporary/rpc-proxy-ready.json"
rpc_proxy_stdout="$temporary/rpc-proxy.stdout"
rpc_proxy_stderr="$temporary/rpc-proxy.stderr"
check_rpc_proxy_channels() {
  local require_empty=$1 output="$temporary/proxy-channel-check.stdout" error="$temporary/proxy-channel-check.stderr" status
  [[ $require_empty == bounded || $require_empty == empty ]]
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=2s 10s \
    "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],65536],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes);if(process.argv[3]==="empty"&&bytes.length!==0)process.exit(1)}' \
    "$rpc_proxy_stdout" "$rpc_proxy_stderr" "$require_empty" \
    > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  if ((status != 0)); then
    printf 'Bounded private RPC channel check failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test ! -s "$output"
  test ! -s "$error"
}
check_rpc_proxy_ready() {
  local output=$1 error="$1.stderr" status
  shift
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
    "$node_bin" scripts/check-private-rpc-proxy-ready.mjs \
    "$rpc_proxy_ready" "$rpc_proxy_pid" "$@" > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status != 0)); then
    printf 'Bounded private RPC readiness failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test -s "$output"
  test ! -s "$error"
  run_chmod 0600 "$output"
}
assert_setsid_unchanged
assert_node_unchanged
assert_timeout_unchanged
"$setsid_bin" /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin USDOM_PRIVATE_RPC_PROXY_LAUNCHER=1 USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$timeout_bin" --signal=TERM --kill-after=2s 24h "$node_bin" scripts/serve-private-rpc-catalog-proxy.mjs "$rpc_proxy_ready" >"$rpc_proxy_stdout" 2>"$rpc_proxy_stderr" &
rpc_proxy_pid=$!
for _ in {1..200}; do
  check_rpc_proxy_channels bounded
  [[ -f $rpc_proxy_ready ]] && break
  if ! kill -0 "$rpc_proxy_pid" 2>/dev/null; then
    if wait "$rpc_proxy_pid"; then rpc_proxy_status=0; else rpc_proxy_status=$?; fi
    stop_rpc_proxy
    check_rpc_proxy_channels bounded
    printf 'Private RPC proxy failed before readiness with status %s\n' "$rpc_proxy_status" >&2
    exit 1
  fi
  run_sleep 0.05
done
check_rpc_proxy_channels empty
test -f "$rpc_proxy_ready" && test ! -L "$rpc_proxy_ready"
test "$(stat -c '%u:%a:%h' "$rpc_proxy_ready")" = "$(id -u):600:1"
rpc_ready_observation="$temporary/rpc-ready.observed.txt"
check_rpc_proxy_ready "$rpc_ready_observation"
mapfile -t rpc_ready < "$rpc_ready_observation"
(( ${#rpc_ready[@]} >= 3 && ${#rpc_ready[@]} <= 6 ))
rpc_proxy_ready_sha=${rpc_ready[0]}
rpc_urls=("${rpc_ready[@]:1}")
primary_rpc=${rpc_urls[0]}
assert_rpc_proxy_alive() {
  kill -0 "$rpc_proxy_pid" 2>/dev/null
  check_rpc_proxy_ready "$temporary/rpc-ready.current.txt" "$rpc_proxy_ready_sha"
  assert_cmp_unchanged; "$cmp_bin" -s "$rpc_ready_observation" \
    "$temporary/rpc-ready.current.txt"
}
rpc() {
  local output_file="$temporary/rpc-output.txt" error_file="$temporary/rpc-error.txt" status message endpoint
  assert_rpc_proxy_alive
  assert_cast_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s \
    "$cast_bin" "$@" >"$output_file" 2>"$error_file"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],2097152],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' \
    "$output_file" "$error_file"
  if ((status != 0)); then
    message=$(<"$error_file")
    for endpoint in "${rpc_urls[@]}"; do message=${message//"$endpoint"/'[redacted RPC URL]'}; done
    printf 'Bounded Safe recovery RPC failed: %s\n' "$message" >&2
    return "$status"
  fi
  test -s "$output_file"
  test ! -s "$error_file"
  assert_node_unchanged
  "$node_bin" "$project/scripts/read-private-file-stdout.mjs" "$output_file"
}
snapshot_private() {
  local source=$1 output=$2 error="$2.stderr" status
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
    "$node_bin" "$project/scripts/read-private-file-stdout.mjs" "$source" \
    > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],2097152],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status != 0)); then
    printf 'Bounded private recovery snapshot failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test -s "$output"
  test ! -s "$error"
  run_chmod 0600 "$output"
}
read_canonical_line() {
  local file=$1 value extra fd
  exec {fd}<"$file"
  if ! IFS= read -r value <&$fd; then exec {fd}<&-; return 1; fi
  if IFS= read -r extra <&$fd; then exec {fd}<&-; return 1; fi
  exec {fd}<&-
  [[ "$value" != *$'\r'* && "$value" != *$'\n'* ]]
  printf '%s\n' "$value"
}
run_node_empty_authority() {
  local label=$1 script=$2 output="$temporary/$1.stdout" error="$temporary/$1.stderr" status
  shift 2
  [[ $label =~ ^[A-Za-z0-9._-]+$ ]]
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s \
    "$node_bin" "$script" "$@" > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status != 0)); then
    printf 'Bounded Safe recovery %s authority failed with status %s\n' "$label" "$status" >&2
    return "$status"
  fi
  test ! -s "$output"
  test ! -s "$error"
}
run_jq_json_authority() {
  local output=$1 error="$1.stderr" status
  shift
  assert_jq_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
    "$jq_bin" "$@" > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],2097152],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status != 0)); then
    printf 'Bounded Safe recovery jq authority failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test -s "$output"
  test ! -s "$error"
  run_chmod 0600 "$output"
  run_node_empty_authority strict-json scripts/check-private-strict-json-file.mjs "$output"
}
run_jq_line_authority() {
  local label=$1 output="$temporary/$1-jq-line.stdout" error="$temporary/$1-jq-line.stderr" status
  shift
  [[ $label =~ ^[A-Za-z0-9._-]+$ ]]
  assert_jq_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
    "$jq_bin" "$@" > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status != 0)); then
    printf 'Bounded Safe recovery jq line failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test -s "$output"
  test ! -s "$error"
  read_canonical_line "$output"
}
run_node_json_authority() {
  local output=$1 script=$2 error="$output.stderr" status
  shift 2
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s \
    "$node_bin" "$script" "$@" > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],2097152],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status != 0)); then
    printf 'Bounded Safe authority helper failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test -s "$output"
  test ! -s "$error"
  run_chmod 0600 "$output"
  run_node_empty_authority strict-json scripts/check-private-strict-json-file.mjs "$output"
}
run_safe_observer() {
  local output=$1 error=$2 status
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s \
    "$node_bin" scripts/observe-recoverable-safe-recovery-execution.mjs \
    > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],2097152],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status == 0)); then
    test -s "$output"
    test ! -s "$error"
    run_chmod 0600 "$output"
    run_node_empty_authority strict-json scripts/check-private-strict-json-file.mjs "$output"
    return 0
  fi
  test ! -s "$output"
  if ((status == 3)); then
    test "$(read_canonical_line "$error")" = 'USDOM_SAFE_RECOVERY_NOT_FINALIZED'
    return 3
  fi
  return "$status"
}
assert_private_snapshot_unchanged() {
  local source=$1 snapshot=$2 current=$3
  snapshot_private "$source" "$current"
  assert_cmp_unchanged; "$cmp_bin" -s "$snapshot" "$current"
}
package_snapshot="$temporary/safe-package.json"
baseline_snapshot="$temporary/safe-baseline.json"
plan_snapshot="$temporary/recovery-plan.json"
replacement_proofs_snapshot="$temporary/recovery-replacement-proofs.json"
transactions_snapshot="$temporary/recovery-transactions.json"
relayer_policy_snapshot="$temporary/recovery-relayer-policy.json"
snapshot_private "$package_source" "$package_snapshot"
snapshot_private "$baseline_source" "$baseline_snapshot"
snapshot_private "$plan_source" "$plan_snapshot"
snapshot_private "$replacement_proofs_source" "$replacement_proofs_snapshot"
snapshot_private "$transactions_source" "$transactions_snapshot"
snapshot_private "$relayer_policy_source" "$relayer_policy_snapshot"
export USDOM_SAFE_PACKAGE=$package_snapshot
export USDOM_SAFE_BASELINE=$baseline_snapshot
export USDOM_SAFE_RECOVERY_PLAN=$plan_snapshot
export USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS=$replacement_proofs_snapshot
export USDOM_SAFE_RECOVERY_TRANSACTIONS=$transactions_snapshot
assert_sources_unchanged() {
  snapshot_private "$package_source" "$temporary/safe-package.current.json"
  snapshot_private "$baseline_source" "$temporary/safe-baseline.current.json"
  snapshot_private "$plan_source" "$temporary/recovery-plan.current.json"
  snapshot_private "$replacement_proofs_source" "$temporary/recovery-replacement-proofs.current.json"
  snapshot_private "$transactions_source" "$temporary/recovery-transactions.current.json"
  snapshot_private "$relayer_policy_source" "$temporary/recovery-relayer-policy.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$package_snapshot" "$temporary/safe-package.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$baseline_snapshot" "$temporary/safe-baseline.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$plan_snapshot" "$temporary/recovery-plan.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$replacement_proofs_snapshot" \
    "$temporary/recovery-replacement-proofs.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$transactions_snapshot" "$temporary/recovery-transactions.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$relayer_policy_snapshot" "$temporary/recovery-relayer-policy.current.json"
}
run_node_empty_authority recovery-plan scripts/check-recoverable-safe-recovery-plan.mjs
run_node_empty_authority recovery-transactions scripts/check-recoverable-safe-recovery-transactions.mjs

assert_private_regular_file() {
  local path=$1
  test -f "$path"
  test ! -L "$path"
  test "$(stat -c '%u' "$path")" = "$(id -u)"
  test "$(stat -c '%a' "$path")" = '600'
  test "$(stat -c '%h' "$path")" = '1'
}

persist_private_new() {
  local source=$1 destination=$2 installed="$temporary/${2##*/}.installed"
  local output="$temporary/${2##*/}.install.stdout" error="$temporary/${2##*/}.install.stderr" status
  assert_evidence_parent
  test ! -e "$destination"
  test ! -L "$destination"
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
    "$node_bin" "$project/scripts/install-private-file-new-stdin.mjs" "$destination" \
    < "$source" > "$output" 2> "$error"; then status=0; else status=$?; fi
  assert_node_unchanged
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes)}' \
    "$output" "$error"
  if ((status != 0)); then
    printf 'Bounded private recovery installation failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test ! -s "$output"
  test ! -s "$error"
  assert_private_regular_file "$destination"
  snapshot_private "$destination" "$installed"
  assert_cmp_unchanged; "$cmp_bin" -s "$source" "$installed"
  assert_evidence_parent
}

persist_private_create_once_or_identical() {
  local source=$1 destination=$2 recorded
  if [[ ! -e "$destination" ]]; then
    persist_private_new "$source" "$destination"
  else
    assert_private_regular_file "$destination"
    recorded="$temporary/${destination##*/}.recorded"
    snapshot_private "$destination" "$recorded"
    assert_cmp_unchanged; "$cmp_bin" -s "$source" "$recorded"
  fi
}

observe_until_finalized() {
  local output="$1" error_output="$2" deadline=$((SECONDS + 1800)) status
  while true; do
    set +e
    run_safe_observer "$output" "$error_output"
    status=$?
    set -e
    if ((status == 0)); then return 0; fi
    if ((status != 3)); then return "$status"; fi
    test "$SECONDS" -lt "$deadline"
    run_sleep 15
  done
}

for role in governance reserveGuardian checkpointGuardian; do
  export USDOM_SAFE_RECOVERY_ROLE="$role"
  export USDOM_SAFE_RELAYER_OWNER
  USDOM_SAFE_RELAYER_OWNER=$(run_node scripts/check-safe-recovery-relayer-policy.mjs \
    "$relayer_policy_snapshot" "$plan_snapshot")
  observed_consensus="$temporary/$role-observed-consensus.json"
  observation_error="$temporary/$role-observation.err"
  raw_file="$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-recovery-raw-transaction.txt"
  hash_file="$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-recovery-submission-hash.txt"
  envelope_file="$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-recovery-envelope.json"
  envelope_snapshot="$temporary/$role-recovery-envelope.snapshot.json"
  raw_snapshot="$temporary/$role-recovery-raw-transaction.snapshot.txt"
  hash_snapshot="$temporary/$role-recovery-submission-hash.snapshot.txt"
  # Classify a prior immutable raw immediately, before any device prompt or
  # observer call can fail. Its absence from current RPC mempools is not proof
  # that an earlier publication never consumed the nonce.
  if [[ -e "$raw_file" ]]; then safe_broadcast_state=signed-unresolved; fi
  if [[ ! -e "$envelope_file" ]]; then
    envelope_draft="$temporary/$role-recovery-envelope.json"
    run_node_json_authority "$envelope_draft" scripts/prepare-recoverable-safe-recovery-envelope.mjs
    export USDOM_SAFE_RECOVERY_ENVELOPE="$envelope_draft"
    run_node_empty_authority recovery-envelope scripts/check-recoverable-safe-recovery-envelope.mjs
    persist_private_create_once_or_identical "$envelope_draft" "$envelope_file"
  fi
  assert_private_regular_file "$envelope_file"
  snapshot_private "$envelope_file" "$envelope_snapshot"
  export USDOM_SAFE_RECOVERY_ENVELOPE="$envelope_snapshot"
  run_node_empty_authority recovery-envelope scripts/check-recoverable-safe-recovery-envelope.mjs
  test "$(run_node scripts/check-safe-recovery-relayer-policy.mjs "$relayer_policy_snapshot" \
    "$plan_snapshot" "$envelope_snapshot")" = "$USDOM_SAFE_RELAYER_OWNER"

  set +e
  run_safe_observer "$observed_consensus" "$observation_error"
  observation_status=$?
  set -e
  if ((observation_status == 0)); then
    :
  elif ((observation_status == 3)); then
    target_consensus="$temporary/$role-target-consensus.json"
    run_node_json_authority "$target_consensus" scripts/check-recoverable-safe-recovery-target.mjs

    private_transaction_input="$temporary/$role-private-transaction-input.json"
    run_node_json_authority "$private_transaction_input" scripts/prepare-safe-recovery-private-input.mjs \
      "$role" "$USDOM_SAFE_RECOVERY_TRANSACTIONS"
    to=$(run_jq_line_authority "$role-to" -er '.to' "$private_transaction_input")
    value=$(run_jq_line_authority "$role-value" -er '.value' "$private_transaction_input")
    data_hash=$(run_jq_line_authority "$role-data-hash" -er '.dataHash' "$private_transaction_input")
    selector=$(run_jq_line_authority "$role-selector" -er '.selector' "$private_transaction_input")
    envelope_hash=$(run_jq_line_authority "$role-envelope-hash" -er '.envelopeHash' "$envelope_snapshot")
    printf 'Papel=%s Safe=%s Valor=%s CalldataHash=%s EnvelopeHash=%s\n' \
      "$role" "$to" "$value" "$data_hash" "$envelope_hash"
    review_gas_limit=$(run_jq_line_authority "$role-review-gas-limit" -er '.gasLimit' "$envelope_snapshot")
    review_max_fee=$(run_jq_line_authority "$role-review-max-fee" -er '.maxFeePerGas' "$envelope_snapshot")
    review_nonce=$(run_jq_line_authority "$role-review-nonce" -er '.nonce' "$envelope_snapshot")
    review_priority=$(run_jq_line_authority "$role-review-priority" -er '.maxPriorityFeePerGas' "$envelope_snapshot")
    printf 'AUTHORIZE REVIEW action=swapOwner role=%s chainId=1 signer=%s target=%s nonce=%s selector=%s valueWei=%s dataHash=%s envelopeHash=%s gasLimit=%s maxFeePerGas=%s maxPriorityFeePerGas=%s maximumGasCostWei=%s\n' \
      "$role" "$USDOM_SAFE_RELAYER_OWNER" "$to" "$review_nonce" "$selector" "$value" "$data_hash" "$envelope_hash" "$review_gas_limit" "$review_max_fee" "$review_priority" \
      "$(run_node -e 'process.stdout.write(String(BigInt(process.argv[1])*BigInt(process.argv[2])))' "$review_gas_limit" "$review_max_fee")"
    read -r -p "Digite AUTORIZO USAR RELAYER SWAPOWNER $role ENVELOPE $envelope_hash: " authorization </dev/tty
    test "$authorization" = "AUTORIZO USAR RELAYER SWAPOWNER $role ENVELOPE $envelope_hash"
    assert_cast_unchanged
    assert_node_unchanged
    assert_jq_unchanged
    assert_sources_unchanged
    assert_private_snapshot_unchanged "$envelope_file" "$envelope_snapshot" \
      "$temporary/$role-recovery-envelope.current.json"
    if [[ ! -e "$raw_file" ]]; then
      relayer_input_file="$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-recovery-relayer-input.json"
      persist_private_create_once_or_identical "$private_transaction_input" "$relayer_input_file"
      printf 'RAW externa do relayer ausente: instale %s por fronteira privada; nenhuma assinatura ou transmissao foi executada.\n' "$raw_file" >&2
      exit 78
    fi
    assert_private_regular_file "$raw_file"
    snapshot_private "$raw_file" "$raw_snapshot"
    export USDOM_SAFE_RECOVERY_RAW_TRANSACTION="$raw_snapshot"
    raw_validation="$temporary/$role-raw-validation.json"
    run_node_json_authority "$raw_validation" scripts/check-recoverable-safe-recovery-raw-transaction.mjs
    transaction_hash=$(run_jq_line_authority "$role-transaction-hash" -er '.transactionHash' "$raw_validation")
    if [[ ! -e "$hash_file" ]]; then
      hash_draft="$temporary/$role-submission-hash.txt"
      printf '%s\n' "$transaction_hash" > "$hash_draft"
      run_chmod 0600 "$hash_draft"
      persist_private_new "$hash_draft" "$hash_file"
    fi
    assert_private_regular_file "$hash_file"
    snapshot_private "$hash_file" "$hash_snapshot"
    recorded_transaction_hash=$(read_canonical_line "$hash_snapshot")
    test "$recorded_transaction_hash" = "$transaction_hash"
    [[ "$transaction_hash" =~ ^0x[0-9a-f]{64}$ ]]
    assert_private_regular_file "$raw_file"
    assert_private_regular_file "$hash_file"
    # The immutable raw/hash pair proves what may have been submitted, but not
    # that a prior process died before publish. Classify it as unresolved until
    # the exact finalized execution evidence becomes durable.
    safe_broadcast_state=signed-unresolved
    export USDOM_SAFE_RECOVERY_RAW_TRANSACTION="$raw_snapshot"
    raw_validation_recheck="$temporary/$role-raw-validation.recheck.json"
    run_node_json_authority "$raw_validation_recheck" \
      scripts/check-recoverable-safe-recovery-raw-transaction.mjs
    test "$(run_jq_line_authority "$role-transaction-hash-recheck" -er '.transactionHash' "$raw_validation_recheck")" = "$transaction_hash"
    assert_private_snapshot_unchanged "$envelope_file" "$envelope_snapshot" \
      "$temporary/$role-recovery-envelope.prepublish.json"
    assert_private_snapshot_unchanged "$raw_file" "$raw_snapshot" \
      "$temporary/$role-recovery-raw-transaction.prepublish.txt"
    assert_private_snapshot_unchanged "$hash_file" "$hash_snapshot" \
      "$temporary/$role-recovery-submission-hash.prepublish.txt"
    assert_rpc_proxy_alive
    assert_sources_unchanged
    # Signing and operator review can take arbitrarily long. Reobserve the
    # complete Safe target immediately before publication and require exact
    # consensus equality with the state against which this role was prepared.
    # This fails closed if a concurrent Safe execution changes nonce, owners,
    # threshold, modules, guard, singleton or the expected safeTxHash.
    run_node_json_authority "$temporary/$role-target-consensus.prepublish.json" \
      scripts/check-recoverable-safe-recovery-target.mjs
    # A later finalized anchor is expected; compare the complete authenticated
    # Safe state while excluding only the observation block identity.
    run_jq_json_authority "$temporary/$role-target-consensus.state.json" \
      -S 'del(.finalizedBlockNumber,.finalizedBlockHash)' "$target_consensus"
    run_jq_json_authority "$temporary/$role-target-consensus.prepublish.state.json" \
      -S 'del(.finalizedBlockNumber,.finalizedBlockHash)' \
      "$temporary/$role-target-consensus.prepublish.json"
    assert_cmp_unchanged; "$cmp_bin" -s "$temporary/$role-target-consensus.state.json" \
      "$temporary/$role-target-consensus.prepublish.state.json"
    # The interactive review and external relayer handoff has a zero-finalized-
    # block validity window. Rebuild the complete envelope immediately before
    # publication and require byte identity. Any advanced/reorganized finalized
    # anchor, nonce, gas, fee or balance change requires a fresh signature; the
    # already signed raw transaction is never rewritten.
    run_node_json_authority "$temporary/$role-recovery-envelope.prepublish.json" \
      scripts/prepare-recoverable-safe-recovery-envelope.mjs
    assert_cmp_unchanged; "$cmp_bin" -s "$envelope_snapshot" "$temporary/$role-recovery-envelope.prepublish.json"
    IFS= read -r raw_transaction < "$raw_snapshot"
    seen_any=false
    seen_index=0
    for endpoint in "${rpc_urls[@]}"; do
      seen_file="$temporary/$role-seen-$seen_index.json"
      rpc rpc eth_getTransactionByHash "$transaction_hash" --rpc-url "$endpoint" \
        > "$seen_file"
      run_node_empty_authority strict-json scripts/check-private-strict-json-file.mjs "$seen_file"
      test "$(run_jq_line_authority "$role-seen-$seen_index-matches" -er \
        --arg hash "$transaction_hash" \
        '. == null or ((.hash|ascii_downcase)==($hash|ascii_downcase))' "$seen_file")" = true
      seen_null=$(run_jq_line_authority "$role-seen-$seen_index-null" -r \
        '. == null' "$seen_file")
      [[ $seen_null == true || $seen_null == false ]]
      if [[ $seen_null == false ]]; then seen_any=true; fi
      ((seen_index+=1))
    done
    if [[ $seen_any == true ]]; then safe_broadcast_state=observed; fi
    if [[ $seen_any == false ]]; then
      assert_cast_unchanged
      assert_node_unchanged
      assert_jq_unchanged
      read -r -p "Digite AUTORIZO TRANSMITIR SWAPOWNER $role TX $transaction_hash: " publication_authorization </dev/tty
      test "$publication_authorization" = "AUTORIZO TRANSMITIR SWAPOWNER $role TX $transaction_hash"
      publish_output="$temporary/$role-publish-output.txt"
      assert_evidence_parent
      safe_broadcast_state=publishing
      "$node_bin" scripts/publish-private-raw-transaction.mjs "$raw_snapshot" \
        "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" \
        "$project/config/mainnet-preflight-rpc-catalog.json" 0 > "$publish_output"
      published=$(read_canonical_line "$publish_output")
      test "$published" = "$transaction_hash"
    fi

    observe_until_finalized "$observed_consensus" "$observation_error"
  else
    exit "$observation_status"
  fi

  assert_rpc_proxy_alive
  assert_sources_unchanged
  run_node_empty_authority "finalized-$role" scripts/check-finalized-safe-recovery-execution.mjs \
    "$observed_consensus" "$role"
  persist_private_create_once_or_identical "$observed_consensus" \
    "$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-finalized-execution.json"
  safe_broadcast_state=clean
done

assert_sources_unchanged
assert_rpc_proxy_alive
final_consensus="$temporary/recovery-final-consensus.json"
run_node_json_authority "$final_consensus" scripts/collect-recoverable-safe-recovery.mjs
final_report="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-finalized-report.json"
persist_private_create_once_or_identical "$final_consensus" "$final_report"
assert_private_regular_file "$final_report"
assert_sources_unchanged
final_bundle="$temporary/safe-recovery-finalized-bundle.json"
run_node_json_authority "$final_bundle" scripts/prepare-safe-recovery-evidence-bundle.mjs "$final_report"
final_bundle_installed="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-finalized-bundle.json"
persist_private_create_once_or_identical "$final_bundle" "$final_bundle_installed"

# The create-once helpers authenticate each write, but success must also bind
# both installed completion artifacts and every authoritative input after the
# complete materialization window.
snapshot_private "$final_report" "$temporary/safe-recovery-finalized-report.installed.json"
assert_cmp_unchanged; "$cmp_bin" -s "$final_consensus" \
  "$temporary/safe-recovery-finalized-report.installed.json"
snapshot_private "$final_bundle_installed" "$temporary/safe-recovery-finalized-bundle.installed.json"
assert_cmp_unchanged; "$cmp_bin" -s "$final_bundle" \
  "$temporary/safe-recovery-finalized-bundle.installed.json"
assert_sources_unchanged
assert_rpc_proxy_alive
assert_evidence_parent

final_summary_file="$temporary/safe-recovery-final-summary.json"
run_jq_json_authority "$final_summary_file" \
  '{schema,ethereumChainId,packageHash,baselineSnapshotHash,transitionsByRole,
  recoveryHash,recoveries:[.recoveries[]|{role,safe,transactionHash,blockNumber,
    blockHash,safeTxHash,signers,previousNonce,newNonce}],
  afterSnapshot:{finalizedBlockNumber,finalizedBlockHash,snapshotHash,
    roles:[.roles[]|{role,address,configurationHash,owners,threshold,nonce}]}}' \
  "$final_consensus"
final_summary=$(<"$final_summary_file")
printf '%s\n' "$final_summary"
