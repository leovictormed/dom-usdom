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
# alter credential-bearing Node/Cast/Ledger children. USDOM inputs are exported
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

: "${USDOM_SAFE_PACKAGE:?USDOM_SAFE_PACKAGE is required}"
: "${USDOM_SAFE_BASELINE:?USDOM_SAFE_BASELINE is required}"
: "${USDOM_SAFE_RECOVERY_PLAN:?USDOM_SAFE_RECOVERY_PLAN is required}"
: "${USDOM_SAFE_RECOVERY_TRANSACTIONS:?USDOM_SAFE_RECOVERY_TRANSACTIONS is required}"
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?USDOM_CONTROL_EVIDENCE_DIRECTORY is required}"
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required}"

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
  test "$(realpath "$(command -v cast)")" = "$cast_bin"
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
  test "$(realpath "$(command -v node)")" = "$node_bin"
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
  test "$(realpath "$(command -v jq)")" = "$jq_bin"
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
  test "$(realpath "$(command -v sha256sum)")" = "$sha256_bin"
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
  test "$(realpath "$(command -v cmp)")" = "$cmp_bin"
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
  test "$(realpath "$(command -v timeout)")" = "$timeout_bin"
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
  test "$(realpath "$(command -v setsid)")" = "$setsid_bin"
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
  test "$(realpath "$(command -v flock)")" = "$flock_bin"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$flock_bin")" = "$flock_identity"
  test "$(sha256_file "$flock_bin")" = "$flock_sha256"
}
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
package_source=$(realpath -ms "$USDOM_SAFE_PACKAGE")
baseline_source=$(realpath -ms "$USDOM_SAFE_BASELINE")
plan_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_PLAN")
transactions_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_TRANSACTIONS")
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
# Finalized observations/reports are derived completion artifacts and may be
# regenerated at a newer finalized head. Invalidate them under the evidence
# lock before credentials or RPC; preserve raw transactions, hashes and
# envelopes as immutable anti-replay records.
for derived in governance-finalized-execution.json reserveGuardian-finalized-execution.json \
  checkpointGuardian-finalized-execution.json safe-recovery-finalized-report.json \
  safe-recovery-finalized-bundle.json; do
  assert_node_unchanged
  "$node_bin" "$project/scripts/remove-private-file-durable.mjs" \
    "$evidence_directory/$derived"
done
assert_node_unchanged
temporary=$(mktemp -d -p /dev/shm usdom-safe-recovery-execute.XXXXXXXX)
chmod 0700 "$temporary"
rpc_proxy_pid=''
stop_rpc_proxy() {
  [[ $rpc_proxy_pid =~ ^[0-9]+$ ]] || return 0
  kill -TERM -- "-$rpc_proxy_pid" 2>/dev/null || true
  for _ in {1..40}; do
    kill -0 -- "-$rpc_proxy_pid" 2>/dev/null || break
    sleep 0.05
  done
  kill -KILL -- "-$rpc_proxy_pid" 2>/dev/null || true
  wait "$rpc_proxy_pid" 2>/dev/null || true
  rpc_proxy_pid=''
}
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  stop_rpc_proxy
  assert_node_unchanged &&
    "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary" || status=1
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
rpc_proxy_ready="$temporary/rpc-proxy-ready.json"
rpc_proxy_stdout="$temporary/rpc-proxy.stdout"
rpc_proxy_stderr="$temporary/rpc-proxy.stderr"
check_rpc_proxy_channels() {
  local require_empty=$1
  "$node_bin" -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],65536],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes);if(process.argv[3]==="empty"&&bytes.length!==0)process.exit(1)}' \
    "$rpc_proxy_stdout" "$rpc_proxy_stderr" "$require_empty"
}
assert_setsid_unchanged
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
  sleep 0.05
done
check_rpc_proxy_channels empty
test -f "$rpc_proxy_ready" && test ! -L "$rpc_proxy_ready"
test "$(stat -c '%u:%a:%h' "$rpc_proxy_ready")" = "$(id -u):600:1"
mapfile -t rpc_ready < <("$node_bin" scripts/check-private-rpc-proxy-ready.mjs \
  "$rpc_proxy_ready" "$rpc_proxy_pid")
(( ${#rpc_ready[@]} >= 3 && ${#rpc_ready[@]} <= 6 ))
rpc_proxy_ready_sha=${rpc_ready[0]}
rpc_urls=("${rpc_ready[@]:1}")
primary_rpc=${rpc_urls[0]}
assert_rpc_proxy_alive() {
  kill -0 "$rpc_proxy_pid" 2>/dev/null
  "$node_bin" scripts/check-private-rpc-proxy-ready.mjs "$rpc_proxy_ready" \
    "$rpc_proxy_pid" "$rpc_proxy_ready_sha" >/dev/null
}
rpc() {
  local error_file="$temporary/rpc-error.txt" status message endpoint
  assert_rpc_proxy_alive
  assert_timeout_unchanged
  if "$timeout_bin" --signal=TERM 120s "$cast_bin" "$@" 2>"$error_file"; then
    rm -f -- "$error_file"; return 0
  else
    status=$?; message=$(<"$error_file"); rm -f -- "$error_file"
    for endpoint in "${rpc_urls[@]}"; do message=${message//"$endpoint"/'[redacted RPC URL]'}; done
    printf 'Bounded Safe recovery RPC failed: %s\n' "$message" >&2
    return "$status"
  fi
}
snapshot_private() {
  assert_node_unchanged
  "$node_bin" "$project/scripts/read-private-file-stdout.mjs" "$1" > "$2"
  chmod 0600 "$2"
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
run_node_json_authority() {
  local output=$1 script=$2 error="$output.stderr" status
  shift 2
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --signal=TERM 120s "$node_bin" "$script" "$@" > "$output" 2> "$error"; then
    :
  else
    status=$?
    printf 'Bounded Safe authority helper failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test ! -s "$error"
  chmod 0600 "$output"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$output"
}
run_safe_observer() {
  local output=$1 error=$2 status
  assert_node_unchanged
  assert_timeout_unchanged
  if "$timeout_bin" --signal=TERM 120s "$node_bin" scripts/observe-recoverable-safe-recovery-execution.mjs \
    > "$output" 2> "$error"; then status=0; else status=$?; fi
  "$node_bin" -e 'const fs=require("fs");for(const [file,max] of [[process.argv[1],2097152],[process.argv[2],65536]])if(fs.statSync(file).size>max)process.exit(1)' \
    "$output" "$error"
  if ((status == 0)); then
    test ! -s "$error"
    chmod 0600 "$output"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$output"
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
transactions_snapshot="$temporary/recovery-transactions.json"
snapshot_private "$package_source" "$package_snapshot"
snapshot_private "$baseline_source" "$baseline_snapshot"
snapshot_private "$plan_source" "$plan_snapshot"
snapshot_private "$transactions_source" "$transactions_snapshot"
export USDOM_SAFE_PACKAGE=$package_snapshot
export USDOM_SAFE_BASELINE=$baseline_snapshot
export USDOM_SAFE_RECOVERY_PLAN=$plan_snapshot
export USDOM_SAFE_RECOVERY_TRANSACTIONS=$transactions_snapshot
assert_sources_unchanged() {
  snapshot_private "$package_source" "$temporary/safe-package.current.json"
  snapshot_private "$baseline_source" "$temporary/safe-baseline.current.json"
  snapshot_private "$plan_source" "$temporary/recovery-plan.current.json"
  snapshot_private "$transactions_source" "$temporary/recovery-transactions.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$package_snapshot" "$temporary/safe-package.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$baseline_snapshot" "$temporary/safe-baseline.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$plan_snapshot" "$temporary/recovery-plan.current.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$transactions_snapshot" "$temporary/recovery-transactions.current.json"
}
"$node_bin" scripts/check-recoverable-safe-recovery-plan.mjs >/dev/null
"$node_bin" scripts/check-recoverable-safe-recovery-transactions.mjs >/dev/null
authorized=false

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
  test ! -e "$destination"
  test ! -L "$destination"
  assert_node_unchanged
  "$node_bin" "$project/scripts/install-private-file-new-stdin.mjs" "$destination" < "$source"
  assert_private_regular_file "$destination"
  snapshot_private "$destination" "$installed"
  "$node_bin" -e 'const fs=require("fs");if(!fs.readFileSync(process.argv[1]).equals(fs.readFileSync(process.argv[2])))process.exit(1)' \
    "$source" "$installed"
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
    sleep 15
  done
}

for role in governance reserveGuardian checkpointGuardian; do
  export USDOM_SAFE_RECOVERY_ROLE="$role"
  export USDOM_SAFE_RELAYER_OWNER
  read -r -p "Conecte um owner sobrevivente de $role para transmitir e pressione Enter: " _
  assert_cast_unchanged
  USDOM_SAFE_RELAYER_OWNER=$("$cast_bin" wallet address --ledger)
  test "$("$cast_bin" wallet address --ledger)" = "$USDOM_SAFE_RELAYER_OWNER"
  "$jq_bin" -e --arg role "$role" --arg owner "$USDOM_SAFE_RELAYER_OWNER" '
    .roles[] | select(.role==$role) | .requiredSigners
    | any((ascii_downcase) == ($owner | ascii_downcase))
  ' "$plan_snapshot" >/dev/null
  observed_consensus="$temporary/$role-observed-consensus.json"
  observation_error="$temporary/$role-observation.err"
  raw_file="$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-recovery-raw-transaction.txt"
  hash_file="$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-recovery-submission-hash.txt"
  envelope_file="$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-recovery-envelope.json"
  envelope_snapshot="$temporary/$role-recovery-envelope.snapshot.json"
  raw_snapshot="$temporary/$role-recovery-raw-transaction.snapshot.txt"
  hash_snapshot="$temporary/$role-recovery-submission-hash.snapshot.txt"
  if [[ ! -e "$envelope_file" ]]; then
    envelope_draft="$temporary/$role-recovery-envelope.json"
    run_node_json_authority "$envelope_draft" scripts/prepare-recoverable-safe-recovery-envelope.mjs
    export USDOM_SAFE_RECOVERY_ENVELOPE="$envelope_draft"
    "$node_bin" scripts/check-recoverable-safe-recovery-envelope.mjs >/dev/null
    persist_private_create_once_or_identical "$envelope_draft" "$envelope_file"
  fi
  assert_private_regular_file "$envelope_file"
  snapshot_private "$envelope_file" "$envelope_snapshot"
  export USDOM_SAFE_RECOVERY_ENVELOPE="$envelope_snapshot"
  "$node_bin" scripts/check-recoverable-safe-recovery-envelope.mjs >/dev/null

  set +e
  run_safe_observer "$observed_consensus" "$observation_error"
  observation_status=$?
  set -e
  if ((observation_status == 0)); then
    :
  elif ((observation_status == 3)); then
    target_consensus="$temporary/$role-target-consensus.json"
    run_node_json_authority "$target_consensus" scripts/check-recoverable-safe-recovery-target.mjs

    to=$("$jq_bin" -er --arg role "$role" '.transactions[]|select(.role==$role)|.to' \
      "$USDOM_SAFE_RECOVERY_TRANSACTIONS")
    value=$("$jq_bin" -er --arg role "$role" '.transactions[]|select(.role==$role)|.value' \
      "$USDOM_SAFE_RECOVERY_TRANSACTIONS")
    data=$("$jq_bin" -er --arg role "$role" '.transactions[]|select(.role==$role)|.data' \
      "$USDOM_SAFE_RECOVERY_TRANSACTIONS")
    data_hash=$("$jq_bin" -er --arg role "$role" '.transactions[]|select(.role==$role)|.dataHash' \
      "$USDOM_SAFE_RECOVERY_TRANSACTIONS")
    printf 'Papel=%s Safe=%s Valor=%s CalldataHash=%s EnvelopeHash=%s\n' \
      "$role" "$to" "$value" "$data_hash" "$("$jq_bin" -er '.envelopeHash' "$envelope_snapshot")"

    if [[ "$authorized" != true ]]; then
      read -r -p 'Digite AUTORIZO TRES SWAPOWNER SAFE MAINNET para continuar: ' authorization
      test "$authorization" = 'AUTORIZO TRES SWAPOWNER SAFE MAINNET'
      exec </dev/null
      assert_cast_unchanged
      assert_node_unchanged
      assert_jq_unchanged
      authorized=true
    fi
    assert_sources_unchanged
    assert_private_snapshot_unchanged "$envelope_file" "$envelope_snapshot" \
      "$temporary/$role-recovery-envelope.current.json"
    if [[ ! -e "$raw_file" ]]; then
      assert_rpc_proxy_alive
      run_node_json_authority "$temporary/$role-recovery-envelope.presign.json" \
        scripts/prepare-recoverable-safe-recovery-envelope.mjs
      assert_cmp_unchanged; "$cmp_bin" -s "$envelope_snapshot" "$temporary/$role-recovery-envelope.presign.json"
      "$node_bin" scripts/check-recoverable-safe-recovery-envelope.mjs >/dev/null
      assert_cast_unchanged
      assert_node_unchanged
      assert_jq_unchanged
      test "$("$cast_bin" wallet address --ledger)" = "$USDOM_SAFE_RELAYER_OWNER"
      nonce=$("$jq_bin" -er '.nonce' "$envelope_file")
      gas_limit=$("$jq_bin" -er '.gasLimit' "$envelope_file")
      max_fee_per_gas=$("$jq_bin" -er '.maxFeePerGas' "$envelope_file")
      max_priority_fee_per_gas=$("$jq_bin" -er '.maxPriorityFeePerGas' "$envelope_file")
      raw_command_output="$temporary/$role-raw-command-output.txt"
      rpc mktx "$to" "$data" --value "$value" \
        --nonce "$nonce" --gas-limit "$gas_limit" --gas-price "$max_fee_per_gas" \
        --priority-gas-price "$max_priority_fee_per_gas" --ledger \
        --rpc-url "$primary_rpc" > "$raw_command_output"
      raw_transaction=$(read_canonical_line "$raw_command_output")
      [[ "$raw_transaction" =~ ^0x[0-9a-f]+$ ]]
      raw_draft="$temporary/$role-raw-transaction.txt"
      printf '%s\n' "$raw_transaction" > "$raw_draft"
      chmod 0600 "$raw_draft"
      export USDOM_SAFE_RECOVERY_RAW_TRANSACTION="$raw_draft"
      raw_validation="$temporary/$role-raw-validation.json"
      run_node_json_authority "$raw_validation" scripts/check-recoverable-safe-recovery-raw-transaction.mjs
      transaction_hash=$("$jq_bin" -er '.transactionHash' "$raw_validation")
      persist_private_new "$raw_draft" "$raw_file"
      hash_draft="$temporary/$role-submission-hash.txt"
      printf '%s\n' "$transaction_hash" > "$hash_draft"
      chmod 0600 "$hash_draft"
      persist_private_new "$hash_draft" "$hash_file"
      snapshot_private "$raw_file" "$raw_snapshot"
      snapshot_private "$hash_file" "$hash_snapshot"
      assert_cmp_unchanged; "$cmp_bin" -s "$raw_draft" "$raw_snapshot"
      assert_cmp_unchanged; "$cmp_bin" -s "$hash_draft" "$hash_snapshot"
    else
      assert_private_regular_file "$raw_file"
      snapshot_private "$raw_file" "$raw_snapshot"
      export USDOM_SAFE_RECOVERY_RAW_TRANSACTION="$raw_snapshot"
      raw_validation="$temporary/$role-raw-validation.json"
      run_node_json_authority "$raw_validation" scripts/check-recoverable-safe-recovery-raw-transaction.mjs
      transaction_hash=$("$jq_bin" -er '.transactionHash' "$raw_validation")
      if [[ ! -e "$hash_file" ]]; then
        hash_draft="$temporary/$role-submission-hash.txt"
        printf '%s\n' "$transaction_hash" > "$hash_draft"
        chmod 0600 "$hash_draft"
        persist_private_new "$hash_draft" "$hash_file"
      fi
      assert_private_regular_file "$hash_file"
      snapshot_private "$hash_file" "$hash_snapshot"
      recorded_transaction_hash=$(read_canonical_line "$hash_snapshot")
      test "$recorded_transaction_hash" = "$transaction_hash"
    fi
    [[ "$transaction_hash" =~ ^0x[0-9a-f]{64}$ ]]
    assert_private_regular_file "$raw_file"
    assert_private_regular_file "$hash_file"
    export USDOM_SAFE_RECOVERY_RAW_TRANSACTION="$raw_snapshot"
    raw_validation_recheck="$temporary/$role-raw-validation.recheck.json"
    run_node_json_authority "$raw_validation_recheck" \
      scripts/check-recoverable-safe-recovery-raw-transaction.mjs
    test "$("$jq_bin" -er '.transactionHash' "$raw_validation_recheck")" = "$transaction_hash"
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
    "$jq_bin" -S 'del(.finalizedBlockNumber,.finalizedBlockHash)' "$target_consensus" \
      > "$temporary/$role-target-consensus.state.json"
    "$jq_bin" -S 'del(.finalizedBlockNumber,.finalizedBlockHash)' \
      "$temporary/$role-target-consensus.prepublish.json" \
      > "$temporary/$role-target-consensus.prepublish.state.json"
    assert_cmp_unchanged; "$cmp_bin" -s "$temporary/$role-target-consensus.state.json" \
      "$temporary/$role-target-consensus.prepublish.state.json"
    # The interactive review and Ledger signing interval has a zero-finalized-
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
      "$node_bin" scripts/check-private-strict-json-file.mjs "$seen_file"
      "$jq_bin" -e --arg hash "$transaction_hash" \
        '. == null or ((.hash|ascii_downcase)==($hash|ascii_downcase))' "$seen_file" >/dev/null
      if ! "$jq_bin" -e '. == null' "$seen_file" >/dev/null; then seen_any=true; fi
      ((seen_index+=1))
    done
    if [[ $seen_any == false ]]; then
      assert_cast_unchanged
      assert_node_unchanged
      assert_jq_unchanged
      publish_output="$temporary/$role-publish-output.txt"
      rpc publish "$raw_transaction" --async --rpc-url "$primary_rpc" > "$publish_output"
      published=$(read_canonical_line "$publish_output")
      test "$published" = "$transaction_hash"
    fi

    observe_until_finalized "$observed_consensus" "$observation_error"
  else
    exit "$observation_status"
  fi

  assert_rpc_proxy_alive
  assert_sources_unchanged
  "$node_bin" scripts/check-finalized-safe-recovery-execution.mjs "$observed_consensus" "$role"
  persist_private_create_once_or_identical "$observed_consensus" \
    "$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-finalized-execution.json"
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

assert_jq_unchanged
"$jq_bin" '{schema,ethereumChainId,packageHash,baselineSnapshotHash,transitionsByRole,
  recoveryHash,recoveries:[.recoveries[]|{role,safe,transactionHash,blockNumber,
    blockHash,safeTxHash,signers,previousNonce,newNonce}],
  afterSnapshot:{finalizedBlockNumber,finalizedBlockHash,snapshotHash,
    roles:[.roles[]|{role,address,configurationHash,owners,threshold,nonce}]}}' \
  "$final_consensus"
