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

if (($# != 1)) || [[ ! $1 =~ ^[0-3]$ ]]; then
  printf '%s\n' 'Usage: execute-mainnet-deployment.sh INDEX_0_TO_3' >&2
  exit 64
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  printf '%s\n' 'Mainnet deployment authorization requires an interactive terminal.' >&2
  exit 1
fi
index=$1
: "${USDOM_MAINNET_DEPLOYMENT_PACKAGE:?USDOM_MAINNET_DEPLOYMENT_PACKAGE is required}"
: "${USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION:?USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION is required}"
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
evidence_directory=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY")
test -d "$evidence_directory"
test ! -L "$evidence_directory"
test "$(stat -c '%u' "$evidence_directory")" = "$(id -u)"
test "$(stat -c '%a' "$evidence_directory")" = '700'
exec 9<"$evidence_directory"
assert_flock_unchanged
"$flock_bin" -n 9 || { printf '%s\n' 'Another deployment executor holds the evidence lock' >&2; exit 75; }

# Receipt and assembled evidence are retryable observations. Invalidate only
# the current deployment's derived generation under the evidence lock before
# starting the credential-bearing proxy/RPC. Raw transaction, validation,
# submission hash and finalized fee anchor remain immutable anti-replay data.
for derived in "contract-deployment-$index-receipt.json" \
  "contract-deployment-$index-evidence.json"; do
  assert_node_unchanged
  "$node_bin" "$project/scripts/remove-private-file-durable.mjs" \
    "$evidence_directory/$derived"
done
assert_node_unchanged

temporary=$(mktemp -d -p /dev/shm usdom-mainnet-deployment.XXXXXXXX)
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
assert_private_file() {
  test -f "$1" && test ! -L "$1"
  test "$(stat -c '%u' "$1")" = "$(id -u)"
  test "$(stat -c '%a' "$1")" = '600'
  test "$(stat -c '%h' "$1")" = '1'
}
persist_new() {
  local source=$1 destination=$2 installed="$temporary/${2##*/}.installed"
  test ! -e "$destination" && test ! -L "$destination"
  assert_node_unchanged
  "$node_bin" scripts/install-private-file-new-stdin.mjs "$destination" < "$source"
  assert_private_file "$destination"
  snapshot "$destination" "$installed"
  "$node_bin" -e 'const fs=require("fs");if(!fs.readFileSync(process.argv[1]).equals(fs.readFileSync(process.argv[2])))process.exit(1)' \
    "$source" "$installed"
}
snapshot() {
  assert_node_unchanged
  "$node_bin" scripts/read-private-file-stdout.mjs "$1" > "$2"
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
    printf 'Bounded authority helper failed with status %s\n' "$status" >&2
    return "$status"
  fi
  test ! -s "$error"
  chmod 0600 "$output"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$output"
}
canonical_quantity() {
  "$node_bin" scripts/check-ethereum-quantity.mjs "$@"
}
canonical_decimal() {
  "$node_bin" scripts/check-unsigned-decimal.mjs "$@"
}
project_receipt() {
  chmod 0600 "$1"
  "$node_bin" scripts/project-deployment-receipt.mjs "$1" > "$2"
  chmod 0600 "$2"
}
package_source=$(realpath -ms "$USDOM_MAINNET_DEPLOYMENT_PACKAGE")
assert_private_file "$package_source"
package_snapshot="$temporary/mainnet-deployment-package.json"
snapshot "$package_source" "$package_snapshot"
export USDOM_MAINNET_DEPLOYMENT_PACKAGE=$package_snapshot
export USDOM_PACKAGE_SHA256
USDOM_PACKAGE_SHA256=$(sha256_file "$package_snapshot")
"$node_bin" scripts/check-mainnet-deployment-package.mjs "$package_snapshot" "$USDOM_PACKAGE_SHA256"
release_config_sha256=$("$jq_bin" -er '.releaseConfigSha256' "$package_snapshot")
chain_id=$("$jq_bin" -er '.chainId' "$package_snapshot")
package_observation_hash=$("$jq_bin" -er '.observationHash' "$package_snapshot")
test "$chain_id" = '1'
[[ $release_config_sha256 =~ ^[0-9a-f]{64}$ ]]
rpc_catalog="$project/config/mainnet-preflight-rpc-catalog.json"
test -f "$rpc_catalog" && test ! -L "$rpc_catalog"
test "$(stat -c '%a' "$rpc_catalog")" = '644'
rpc_catalog_sha256=$(sha256_file "$rpc_catalog")
observation_source=$(realpath -ms "$USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION")
assert_private_file "$observation_source"
observation_snapshot="$temporary/mainnet-deployment-identity-observation.json"
snapshot "$observation_source" "$observation_snapshot"
expected_observation_sha=$("$jq_bin" -er '.observationDocumentSha256' "$package_snapshot")
test "$(sha256_file "$observation_snapshot")" = "$expected_observation_sha"
"$node_bin" scripts/check-mainnet-deployment-identity-observation.mjs \
  "$observation_snapshot" "$expected_observation_sha"
export USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION=$observation_snapshot
rpc_urls=()
rpc() {
  local error_file="$temporary/rpc-error.txt" status message endpoint
  assert_rpc_proxy_alive
  assert_timeout_unchanged
  if "$timeout_bin" --signal=TERM 120s "$cast_bin" "$@" 2>"$error_file"; then
    rm -f -- "$error_file"
    return 0
  else
    status=$?
    message=$(<"$error_file")
    rm -f -- "$error_file"
    for endpoint in "${rpc_urls[@]}"; do message=${message//"$endpoint"/'[redacted RPC URL]'}; done
    printf 'Bounded RPC command failed: %s\n' "$message" >&2
    return "$status"
  fi
}
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
assert_private_file "$rpc_proxy_ready"
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

for endpoint in "${rpc_urls[@]}"; do test "$(rpc chain-id --rpc-url "$endpoint")" = '1'; done
transaction_initial="$temporary/transaction.initial.json"
run_node_json_authority "$transaction_initial" scripts/prepare-mainnet-deployment-transaction.mjs "$index"
"$node_bin" scripts/check-mainnet-deployment-ledger-handoff.mjs "$transaction_initial" "$index"
from=$("$jq_bin" -er '.transaction.from' "$transaction_initial")
nonce=$("$jq_bin" -er '.transaction.nonce' "$transaction_initial")
data=$("$jq_bin" -er '.transaction.data' "$transaction_initial")
deployment_name=$("$jq_bin" -er '.transaction.name' "$transaction_initial")
expected=$("$jq_bin" -er '.transaction.expectedContract' "$transaction_initial")
expected_runtime_hash=$("$jq_bin" -er '.transaction.expectedRuntimeCodeHash' "$transaction_initial")
raw_file="$evidence_directory/contract-deployment-$index-raw-transaction.txt"
hash_file="$evidence_directory/contract-deployment-$index-submission-hash.txt"
validation_file="$evidence_directory/contract-deployment-$index-raw-validation.json"
anchor_file="$evidence_directory/contract-deployment-$index-finalized-anchor.json"
receipt_file="$evidence_directory/contract-deployment-$index-receipt.json"
evidence_file="$evidence_directory/contract-deployment-$index-evidence.json"

# A nonce alone only proves that some transaction consumed each earlier slot.
# Bind continuation/retry to the exact runtime at every preceding CREATE address.
assert_prior_deployments_finalized() {
  local endpoint=$1 prior=0 prior_address prior_runtime_hash prior_code prior_data prior_from prior_nonce
  local prior_hash_file prior_receipt_file prior_validation_file prior_raw_file prior_evidence_file prior_fee_anchor_file prior_hash prior_receipt_hash prior_receipt_block prior_receipt_height
  local prior_hash_snapshot prior_receipt_snapshot prior_validation_snapshot prior_raw_snapshot prior_evidence_snapshot prior_fee_anchor_snapshot
  local prior_tx prior_receipt prior_canonical prior_finalized prior_finalized_height prior_anchor prior_anchor_recheck prior_anchor_number prior_anchor_height prior_anchor_hash
  while (( prior < index )); do
    prior_address=$("$jq_bin" -er ".transactions[$prior].expectedContract" "$package_snapshot")
    prior_runtime_hash=$("$jq_bin" -er ".transactions[$prior].expectedRuntimeCodeHash" "$package_snapshot")
    prior_data=$("$jq_bin" -er ".transactions[$prior].data" "$package_snapshot")
    prior_from=$("$jq_bin" -er ".transactions[$prior].from" "$package_snapshot")
    prior_nonce=$("$jq_bin" -er ".transactions[$prior].nonce" "$package_snapshot")
    prior_hash_file="$evidence_directory/contract-deployment-$prior-submission-hash.txt"
    prior_receipt_file="$evidence_directory/contract-deployment-$prior-receipt.json"
    prior_validation_file="$evidence_directory/contract-deployment-$prior-raw-validation.json"
    prior_raw_file="$evidence_directory/contract-deployment-$prior-raw-transaction.txt"
    prior_evidence_file="$evidence_directory/contract-deployment-$prior-evidence.json"
    prior_fee_anchor_file="$evidence_directory/contract-deployment-$prior-finalized-anchor.json"
    assert_private_file "$prior_hash_file"
    assert_private_file "$prior_receipt_file"
    assert_private_file "$prior_validation_file"
    assert_private_file "$prior_raw_file"
    assert_private_file "$prior_evidence_file"
    assert_private_file "$prior_fee_anchor_file"
    prior_hash_snapshot="$temporary/prior-$prior-hash.txt"
    prior_receipt_snapshot="$temporary/prior-$prior-receipt.persisted.json"
    prior_validation_snapshot="$temporary/prior-$prior-validation.json"
    prior_raw_snapshot="$temporary/prior-$prior-raw.txt"
    prior_evidence_snapshot="$temporary/prior-$prior-evidence.json"
    prior_fee_anchor_snapshot="$temporary/prior-$prior-fee-anchor.json"
    snapshot "$prior_hash_file" "$prior_hash_snapshot"
    snapshot "$prior_receipt_file" "$prior_receipt_snapshot"
    snapshot "$prior_validation_file" "$prior_validation_snapshot"
    snapshot "$prior_raw_file" "$prior_raw_snapshot"
    snapshot "$prior_evidence_file" "$prior_evidence_snapshot"
    snapshot "$prior_fee_anchor_file" "$prior_fee_anchor_snapshot"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_receipt_snapshot"
    "$node_bin" scripts/check-deployment-evidence.mjs "$prior_receipt_snapshot" receipt
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_validation_snapshot"
    "$node_bin" scripts/check-deployment-evidence.mjs "$prior_validation_snapshot" raw
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_evidence_snapshot"
    "$node_bin" scripts/check-deployment-evidence.mjs "$prior_evidence_snapshot"
    "$node_bin" scripts/check-deployment-evidence.mjs "$prior_fee_anchor_snapshot" anchor
    "$jq_bin" -e --arg index "$prior" --arg name "$("$jq_bin" -er ".transactions[$prior].name" "$package_snapshot")" \
      --arg package "$USDOM_PACKAGE_SHA256" --arg observation "$expected_observation_sha" \
      --arg observationHash "$package_observation_hash" '
      .index == $index and .name == $name and .packageSha256 == $package and
      .observationDocumentSha256 == $observation and .observationHash == $observationHash' \
      "$prior_fee_anchor_snapshot" >/dev/null
    prior_hash=$("$node_bin" scripts/check-deployment-submission-hash.mjs "$prior_hash_snapshot")
    "$jq_bin" -e --arg hash "$prior_hash" --arg from "$prior_from" --arg nonce "$prior_nonce" \
      --arg expected "$prior_address" --arg name "$("$jq_bin" -er ".transactions[$prior].name" "$package_snapshot")" '
      .transactionHash == $hash and .from == $from and .nonce == $nonce and
      .expectedContract == $expected and .name == $name' "$prior_validation_snapshot" >/dev/null
    "$jq_bin" -e --arg chain "$chain_id" --arg release "$release_config_sha256" \
      --arg package "$USDOM_PACKAGE_SHA256" --arg catalog "$rpc_catalog_sha256" \
      --arg observation "$expected_observation_sha" --arg observationHash "$package_observation_hash" '
      .chainId == $chain and .releaseConfigSha256 == $release and .packageSha256 == $package and
      .rpcCatalogSha256 == $catalog and .observationDocumentSha256 == $observation and
      .observationHash == $observationHash' \
      "$prior_validation_snapshot" >/dev/null
    test "$(sha256_file "$prior_raw_snapshot")" = \
      "$("$jq_bin" -er '.rawSha256' "$prior_validation_snapshot")"
    prior_receipt_hash=$("$jq_bin" -er '.blockHash|ascii_downcase' "$prior_receipt_snapshot")
    prior_receipt_block=$("$jq_bin" -er '.blockNumber' "$prior_receipt_snapshot")
    prior_receipt_height=$(canonical_quantity "$prior_receipt_block")
    prior_anchor_number=$("$jq_bin" -er '.finalizedBlockNumber' "$prior_evidence_snapshot")
    prior_anchor_height=$(canonical_quantity "$prior_anchor_number")
    prior_anchor_hash=$("$jq_bin" -er '.finalizedBlockHash|ascii_downcase' "$prior_evidence_snapshot")
    [[ $prior_anchor_number =~ ^0x[0-9a-f]+$ ]]
    [[ $prior_anchor_hash =~ ^0x[0-9a-f]{64}$ ]]
    "$jq_bin" -e --arg index "$prior" --arg name "$("$jq_bin" -er ".transactions[$prior].name" "$package_snapshot")" \
      --arg chain "$chain_id" --arg release "$release_config_sha256" --arg package "$USDOM_PACKAGE_SHA256" \
      --arg catalog "$rpc_catalog_sha256" --arg observation "$expected_observation_sha" \
      --arg observationHash "$package_observation_hash" --arg tx "$prior_hash" --arg from "$prior_from" \
      --arg nonce "$prior_nonce" --arg contract "$prior_address" --arg runtime "$prior_runtime_hash" \
      --arg initcode "$("$jq_bin" -er ".transactions[$prior].initcodeHash" "$package_snapshot")" \
      --arg raw "$("$jq_bin" -er '.rawSha256' "$prior_validation_snapshot")" \
      --arg block "$prior_receipt_block" --arg blockHash "$prior_receipt_hash" '
      .schema == "usdom-mainnet-deployment-evidence-v1" and .index == $index and .name == $name and
      .chainId == $chain and .releaseConfigSha256 == $release and .packageSha256 == $package and
      .rpcCatalogSha256 == $catalog and .observationDocumentSha256 == $observation and
      .observationHash == $observationHash and .transactionHash == $tx and .from == $from and
      .nonce == $nonce and .expectedContract == $contract and .runtimeCodeHash == $runtime and
      .initcodeHash == $initcode and .rawSha256 == $raw and .receiptBlockNumber == $block and
      .receiptBlockHash == $blockHash and (.finalizedBlockNumber|type) == "string" and
      (.finalizedBlockHash|test("^0x[0-9a-f]{64}$"))' "$prior_evidence_snapshot" >/dev/null
    "$jq_bin" -e --arg hash "$prior_hash" --arg from "$prior_from" --arg expected "$prior_address" '
      (.status == "0x1" or .status == "0x01") and .to == null and
      (.transactionHash|ascii_downcase) == $hash and (.from|ascii_downcase) == ($from|ascii_downcase) and
      (.contractAddress|ascii_downcase) == ($expected|ascii_downcase)' "$prior_receipt_snapshot" >/dev/null
    prior_tx="$temporary/prior-$prior-transaction.json"
    rpc rpc eth_getTransactionByHash "$prior_hash" --rpc-url "$endpoint" > "$prior_tx"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_tx"
    "$jq_bin" -e --arg hash "$prior_hash" --arg from "$prior_from" --arg data "$prior_data" '
      (.hash|ascii_downcase) == $hash and (.from|ascii_downcase) == ($from|ascii_downcase) and
      .to == null and (.input|ascii_downcase) == ($data|ascii_downcase) and
      (.value == "0x0" or .value == "0x00")' "$prior_tx" >/dev/null
    test "$(canonical_quantity "$("$jq_bin" -er '.nonce' "$prior_tx")")" = "$prior_nonce"
    prior_receipt="$temporary/prior-$prior-receipt.json"
    rpc rpc eth_getTransactionReceipt "$prior_hash" --rpc-url "$endpoint" > "$prior_receipt"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_receipt"
    project_receipt "$prior_receipt" "$temporary/prior-$prior-receipt.projected.json"
    assert_cmp_unchanged; "$cmp_bin" -s "$prior_receipt_snapshot" "$temporary/prior-$prior-receipt.projected.json"
    "$jq_bin" -e --arg hash "$prior_hash" --arg from "$prior_from" --arg expected "$prior_address" \
      --arg blockHash "$prior_receipt_hash" --arg blockNumber "$prior_receipt_block" '
      (.status == "0x1" or .status == "0x01") and .to == null and
      (.transactionHash|ascii_downcase) == $hash and (.from|ascii_downcase) == ($from|ascii_downcase) and
      (.contractAddress|ascii_downcase) == ($expected|ascii_downcase) and
      (.blockHash|ascii_downcase) == $blockHash and .blockNumber == $blockNumber' "$prior_receipt" >/dev/null
    prior_canonical="$temporary/prior-$prior-canonical.json"
    rpc block "$prior_receipt_block" --json --rpc-url "$endpoint" > "$prior_canonical"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_canonical"
    test "$("$jq_bin" -er '.hash|ascii_downcase' "$prior_canonical")" = "$prior_receipt_hash"
    prior_finalized="$temporary/prior-$prior-finalized.json"
    rpc block finalized --json --rpc-url "$endpoint" > "$prior_finalized"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_finalized"
    prior_finalized_number=$("$jq_bin" -er '.number' "$prior_finalized")
    prior_finalized_height=$(canonical_quantity "$prior_finalized_number")
    canonical_quantity "$prior_receipt_block" "$prior_finalized_number" >/dev/null
    canonical_quantity "$prior_anchor_number" "$prior_finalized_number" >/dev/null
    prior_anchor="$temporary/prior-$prior-finalized-anchor.json"
    rpc block "$prior_anchor_number" --json --rpc-url "$endpoint" > "$prior_anchor"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_anchor"
    test "$("$jq_bin" -er '.number' "$prior_anchor")" = "$prior_anchor_number"
    test "$("$jq_bin" -er '.hash|ascii_downcase' "$prior_anchor")" = "$prior_anchor_hash"
    prior_code=$(rpc code "$prior_address" --block "$prior_anchor_number" --rpc-url "$endpoint")
    test "$prior_code" != '0x'
    test "$("$cast_bin" keccak "$prior_code")" = "$prior_runtime_hash"
    prior_anchor_recheck="$temporary/prior-$prior-finalized-anchor.recheck.json"
    rpc block "$prior_anchor_number" --json --rpc-url "$endpoint" > "$prior_anchor_recheck"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$prior_anchor_recheck"
    test "$("$jq_bin" -er '.number' "$prior_anchor_recheck")" = "$prior_anchor_number"
    test "$("$jq_bin" -er '.hash|ascii_downcase' "$prior_anchor_recheck")" = "$prior_anchor_hash"
    assert_cmp_unchanged; "$cmp_bin" -s "$prior_anchor" "$prior_anchor_recheck"
    test "$(sha256_file "$rpc_catalog")" = "$rpc_catalog_sha256"
    snapshot "$prior_hash_file" "$temporary/prior-$prior-hash.recheck.txt"
    snapshot "$prior_receipt_file" "$temporary/prior-$prior-receipt.recheck.json"
    snapshot "$prior_validation_file" "$temporary/prior-$prior-validation.recheck.json"
    snapshot "$prior_raw_file" "$temporary/prior-$prior-raw.recheck.txt"
    snapshot "$prior_evidence_file" "$temporary/prior-$prior-evidence.recheck.json"
    snapshot "$prior_fee_anchor_file" "$temporary/prior-$prior-fee-anchor.recheck.json"
    assert_cmp_unchanged; "$cmp_bin" -s "$prior_hash_snapshot" "$temporary/prior-$prior-hash.recheck.txt"
    assert_cmp_unchanged; "$cmp_bin" -s "$prior_receipt_snapshot" "$temporary/prior-$prior-receipt.recheck.json"
    assert_cmp_unchanged; "$cmp_bin" -s "$prior_validation_snapshot" "$temporary/prior-$prior-validation.recheck.json"
    assert_cmp_unchanged; "$cmp_bin" -s "$prior_raw_snapshot" "$temporary/prior-$prior-raw.recheck.txt"
    assert_cmp_unchanged; "$cmp_bin" -s "$prior_evidence_snapshot" "$temporary/prior-$prior-evidence.recheck.json"
    assert_cmp_unchanged; "$cmp_bin" -s "$prior_fee_anchor_snapshot" "$temporary/prior-$prior-fee-anchor.recheck.json"
    prior=$((prior + 1))
  done
}

if [[ ! -e $raw_file ]]; then
  maximum_estimate=0
  maximum_base=0
  minimum_block_gas_limit=0
  balances=()
  finalized_anchor_number=
  finalized_anchor_hash=
  fee_source_index=0
  for endpoint in "${rpc_urls[@]}"; do
    assert_prior_deployments_finalized "$endpoint"
    test "$(rpc nonce "$from" --block finalized --rpc-url "$endpoint")" = "$nonce"
    test "$(rpc nonce "$from" --block pending --rpc-url "$endpoint")" = "$nonce"
    test "$(rpc code "$expected" --block finalized --rpc-url "$endpoint")" = '0x'
    test "$(rpc nonce "$expected" --block finalized --rpc-url "$endpoint")" = 0
    test "$(rpc nonce "$expected" --block pending --rpc-url "$endpoint")" = 0
    estimate=$(canonical_decimal "$(rpc estimate --create "$data" --from "$from" --block finalized --rpc-url "$endpoint")" 16000000)
    "$node_bin" -e 'if(BigInt(process.argv[1])>16000000n)process.exit(1)' "$estimate"
    ((estimate > maximum_estimate)) && maximum_estimate=$estimate
    fee_block="$temporary/fee-block-$fee_source_index.json"
    rpc block finalized --json --rpc-url "$endpoint" > "$fee_block"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$fee_block"
    observed_finalized_number=$("$jq_bin" -er '.number' "$fee_block")
    observed_finalized_hash=$("$jq_bin" -er '.hash|ascii_downcase' "$fee_block")
    canonical_quantity "$observed_finalized_number" >/dev/null
    [[ $observed_finalized_hash =~ ^0x[0-9a-f]{64}$ ]]
    if [[ -z $finalized_anchor_number ]]; then
      finalized_anchor_number=$observed_finalized_number
      finalized_anchor_hash=$observed_finalized_hash
    else
      test "${observed_finalized_number,,}" = "${finalized_anchor_number,,}"
      test "$observed_finalized_hash" = "$finalized_anchor_hash"
    fi
    observed_block_gas_limit=$(canonical_decimal \
      "$(canonical_quantity "$("$jq_bin" -er '.gasLimit' "$fee_block")")" 1000000000)
    ((observed_block_gas_limit > 0))
    ((minimum_block_gas_limit == 0 || observed_block_gas_limit < minimum_block_gas_limit)) && \
      minimum_block_gas_limit=$observed_block_gas_limit
    base=$(canonical_quantity "$("$jq_bin" -er '.baseFeePerGas' "$fee_block")")
    "$node_bin" -e 'const value=BigInt(process.argv[1]);if(value===0n||value>120000000000n)process.exit(1)' "$base"
    ((base > maximum_base)) && maximum_base=$base
    balance=$(canonical_decimal "$(rpc balance "$from" --block finalized --rpc-url "$endpoint")")
    "$node_bin" -e 'const b=BigInt(process.argv[1]);if(b>1000000000000000000n)process.exit(1)' "$balance"
    balances+=("$balance")
    ((fee_source_index += 1))
  done
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  assert_timeout_unchanged
  observed_ledger_deployer=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s \
    "$cast_bin" wallet address --ledger)
  assert_cast_unchanged
  assert_timeout_unchanged
  test "$observed_ledger_deployer" = "$from"
  gas_limit=$("$node_bin" scripts/plan-mainnet-deployment-gas.mjs "$deployment_name" "$data" "$maximum_estimate")
  [[ $gas_limit =~ ^[0-9]+$ ]]
  ((gas_limit > 0 && gas_limit <= 20000000))
  ((gas_limit * 2 <= minimum_block_gas_limit))
  priority_fee=2000000000
  max_fee=$("$node_bin" -e 'let fee=BigInt(process.argv[1]);for(let i=0;i<12;i++)fee=(fee*9n+7n)/8n;fee+=2000000000n;if(fee>100000000000n)process.exit(1);process.stdout.write(String(fee))' "$maximum_base")
  "$node_bin" -e 'if(BigInt(process.argv[1])*BigInt(process.argv[2])>600000000000000000n)process.exit(1)' "$gas_limit" "$max_fee"
  for balance in "${balances[@]}"; do
    "$node_bin" -e 'if(BigInt(process.argv[1])<BigInt(process.argv[2])*BigInt(process.argv[3]))process.exit(1)' \
      "$balance" "$gas_limit" "$max_fee"
  done
  printf 'Índice=%s Deployer=%s Nonce=%s Contrato=%s Gas=%s MaxFee=%s PriorityFee=%s\n' \
    "$index" "$from" "$nonce" "$expected" "$gas_limit" "$max_fee" "$priority_fee"
  assert_rpc_proxy_alive
  run_node_json_authority "$temporary/transaction.presign.json" \
    scripts/prepare-mainnet-deployment-transaction.mjs "$index"
  "$node_bin" scripts/check-mainnet-deployment-ledger-handoff.mjs \
    "$temporary/transaction.presign.json" "$index"
  assert_cmp_unchanged; "$cmp_bin" -s "$transaction_initial" "$temporary/transaction.presign.json"
  read -r -p "Digite AUTORIZO ASSINAR DEPLOY MAINNET INDICE $index para assinar: " \
    signing_authorization
  test "$signing_authorization" = "AUTORIZO ASSINAR DEPLOY MAINNET INDICE $index"
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  presign_maximum_estimate=0
  presign_maximum_base=0
  presign_minimum_block_gas_limit=0
  presign_balances=()
  presign_fee_source_index=0
  for endpoint in "${rpc_urls[@]}"; do
    assert_prior_deployments_finalized "$endpoint"
    test "$(rpc nonce "$from" --block finalized --rpc-url "$endpoint")" = "$nonce"
    test "$(rpc nonce "$from" --block pending --rpc-url "$endpoint")" = "$nonce"
    test "$(rpc code "$expected" --block finalized --rpc-url "$endpoint")" = '0x'
    test "$(rpc nonce "$expected" --block finalized --rpc-url "$endpoint")" = 0
    test "$(rpc nonce "$expected" --block pending --rpc-url "$endpoint")" = 0
    presign_estimate=$(canonical_decimal "$(rpc estimate --create "$data" --from "$from" \
      --block finalized --rpc-url "$endpoint")" 16000000)
    "$node_bin" -e 'if(BigInt(process.argv[1])>16000000n)process.exit(1)' "$presign_estimate"
    ((presign_estimate > presign_maximum_estimate)) && presign_maximum_estimate=$presign_estimate
    presign_fee_block="$temporary/presign-fee-block-$presign_fee_source_index.json"
    rpc block finalized --json --rpc-url "$endpoint" > "$presign_fee_block"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$presign_fee_block"
    test "$("$jq_bin" -er '.number|ascii_downcase' "$presign_fee_block")" = "${finalized_anchor_number,,}"
    test "$("$jq_bin" -er '.hash|ascii_downcase' "$presign_fee_block")" = "$finalized_anchor_hash"
    presign_block_gas_limit=$(canonical_decimal \
      "$(canonical_quantity "$("$jq_bin" -er '.gasLimit' "$presign_fee_block")")" 1000000000)
    ((presign_block_gas_limit > 0))
    ((presign_minimum_block_gas_limit == 0 || presign_block_gas_limit < presign_minimum_block_gas_limit)) && \
      presign_minimum_block_gas_limit=$presign_block_gas_limit
    presign_base=$(canonical_quantity "$("$jq_bin" -er '.baseFeePerGas' "$presign_fee_block")")
    "$node_bin" -e 'const value=BigInt(process.argv[1]);if(value===0n||value>120000000000n)process.exit(1)' "$presign_base"
    ((presign_base > presign_maximum_base)) && presign_maximum_base=$presign_base
    presign_balance=$(canonical_decimal "$(rpc balance "$from" --block finalized --rpc-url "$endpoint")")
    "$node_bin" -e 'const b=BigInt(process.argv[1]);if(b>1000000000000000000n)process.exit(1)' "$presign_balance"
    presign_balances+=("$presign_balance")
    ((presign_fee_source_index += 1))
  done
  presign_gas_limit=$("$node_bin" scripts/plan-mainnet-deployment-gas.mjs "$deployment_name" "$data" "$presign_maximum_estimate")
  [[ $presign_gas_limit =~ ^[0-9]+$ ]]
  presign_max_fee=$("$node_bin" -e 'let fee=BigInt(process.argv[1]);for(let i=0;i<12;i++)fee=(fee*9n+7n)/8n;fee+=2000000000n;if(fee>100000000000n)process.exit(1);process.stdout.write(String(fee))' "$presign_maximum_base")
  "$node_bin" -e 'if(BigInt(process.argv[1])*BigInt(process.argv[2])>600000000000000000n)process.exit(1)' "$presign_gas_limit" "$presign_max_fee"
  test "$presign_gas_limit" = "$gas_limit"
  test "$presign_minimum_block_gas_limit" = "$minimum_block_gas_limit"
  ((presign_gas_limit * 2 <= presign_minimum_block_gas_limit))
  test "$presign_max_fee" = "$max_fee"
  for presign_balance in "${presign_balances[@]}"; do
    "$node_bin" -e 'if(BigInt(process.argv[1])<BigInt(process.argv[2])*BigInt(process.argv[3]))process.exit(1)' \
      "$presign_balance" "$gas_limit" "$max_fee"
  done
  raw_draft="$temporary/raw-transaction.txt"
  assert_cast_unchanged
  raw_command_output="$temporary/raw-command-output.txt"
  rpc mktx --chain 1 --from "$from" --nonce "$nonce" --value 0 \
    --gas-limit "$gas_limit" --gas-price "$max_fee" \
    --priority-gas-price "$priority_fee" --ledger --rpc-url "$primary_rpc" \
    --create "$data" > "$raw_command_output"
  raw=$(read_canonical_line "$raw_command_output")
  [[ $raw =~ ^0x[0-9a-fA-F]+$ ]]
  printf '%s\n' "$raw" > "$raw_draft"
  chmod 0600 "$raw_draft"
  export USDOM_MAINNET_DEPLOYMENT_RAW_TRANSACTION=$raw_draft
  validation_draft="$temporary/raw-validation.json"
  "$node_bin" scripts/check-mainnet-deployment-raw-transaction.mjs "$index" > "$validation_draft"
  chmod 0600 "$validation_draft"
  draft_maximum_cost=$("$jq_bin" -er '.maximumCost' "$validation_draft")
  "$node_bin" scripts/check-mainnet-deployment-sequence-cost.mjs "$index" "$draft_maximum_cost" >/dev/null
  "$jq_bin" -n --arg index "$index" --arg name "$deployment_name" --arg chain "$chain_id" \
    --arg package "$USDOM_PACKAGE_SHA256" --arg observation "$expected_observation_sha" \
    --arg observationHash "$package_observation_hash" --arg number "${finalized_anchor_number,,}" \
    --arg hash "$finalized_anchor_hash" --arg base "$maximum_base" --arg gas "$gas_limit" \
    --arg fee "$max_fee" \
    '{schema:"usdom-mainnet-deployment-fee-anchor-v1",index:$index,name:$name,chainId:$chain,
      packageSha256:$package,observationDocumentSha256:$observation,observationHash:$observationHash,
      finalizedBlockNumber:$number,finalizedBlockHash:$hash,
      maximumBaseFeePerGas:$base,gasLimit:$gas,maxFeePerGas:$fee}' \
    > "$temporary/finalized-anchor.json"
  chmod 0600 "$temporary/finalized-anchor.json"
  "$node_bin" scripts/check-deployment-evidence.mjs "$temporary/finalized-anchor.json" anchor
  persist_new "$temporary/finalized-anchor.json" "$anchor_file"
  persist_new "$raw_draft" "$raw_file"
  persist_new "$validation_draft" "$validation_file"
fi

assert_private_file "$anchor_file"
anchor_snapshot="$temporary/finalized-anchor.snapshot.json"
snapshot "$anchor_file" "$anchor_snapshot"
"$node_bin" scripts/check-deployment-evidence.mjs "$anchor_snapshot" anchor
finalized_anchor_number=$("$jq_bin" -er '.finalizedBlockNumber' "$anchor_snapshot")
finalized_anchor_hash=$("$jq_bin" -er '.finalizedBlockHash' "$anchor_snapshot")
[[ $finalized_anchor_number =~ ^0x[0-9a-f]+$ ]]
[[ $finalized_anchor_hash =~ ^0x[0-9a-f]{64}$ ]]
assert_private_file "$raw_file"
raw_snapshot="$temporary/raw.snapshot.txt"
snapshot "$raw_file" "$raw_snapshot"
export USDOM_MAINNET_DEPLOYMENT_RAW_TRANSACTION=$raw_snapshot
validation_current="$temporary/raw-validation.current.json"
"$node_bin" scripts/check-mainnet-deployment-raw-transaction.mjs "$index" > "$validation_current"
transaction_hash=$("$jq_bin" -er '.transactionHash' "$validation_current")
if [[ ! -e $validation_file ]]; then
  chmod 0600 "$validation_current"
  persist_new "$validation_current" "$validation_file"
fi
if [[ ! -e $hash_file ]]; then
  printf '%s\n' "$transaction_hash" > "$temporary/hash.txt"
  chmod 0600 "$temporary/hash.txt"
  "$node_bin" scripts/check-deployment-submission-hash.mjs "$temporary/hash.txt" >/dev/null
  persist_new "$temporary/hash.txt" "$hash_file"
fi
assert_private_file "$hash_file"
hash_snapshot="$temporary/hash.snapshot.txt"
snapshot "$hash_file" "$hash_snapshot"
test "$("$node_bin" scripts/check-deployment-submission-hash.mjs "$hash_snapshot")" = "$transaction_hash"
assert_private_file "$validation_file"
validation_snapshot="$temporary/validation.snapshot.json"
snapshot "$validation_file" "$validation_snapshot"
assert_cmp_unchanged; "$cmp_bin" -s "$validation_snapshot" "$validation_current"
snapshot "$raw_file" "$temporary/raw.prepublish.txt"
assert_cmp_unchanged; "$cmp_bin" -s "$raw_snapshot" "$temporary/raw.prepublish.txt"

printf 'Índice=%s Deployer=%s Nonce=%s Contrato=%s TxHash=%s\n' \
  "$index" "$from" "$nonce" "$expected" "$transaction_hash"

seen_any=false
seen_index=0
for endpoint in "${rpc_urls[@]}"; do
  seen_file="$temporary/prepublish-seen-$seen_index.json"
  rpc rpc eth_getTransactionByHash "$transaction_hash" --rpc-url "$endpoint" \
    > "$seen_file"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$seen_file"
  "$jq_bin" -e --arg hash "$transaction_hash" \
    '. == null or ((.hash|ascii_downcase) == ($hash|ascii_downcase))' "$seen_file" >/dev/null
  if ! "$jq_bin" -e '. == null' "$seen_file" >/dev/null; then seen_any=true; fi
  ((seen_index+=1))
done
if [[ $seen_any == false ]]; then
  assert_rpc_proxy_alive
  run_node_json_authority "$temporary/transaction.prepublish.json" \
    scripts/prepare-mainnet-deployment-transaction.mjs "$index"
  "$node_bin" scripts/check-mainnet-deployment-ledger-handoff.mjs \
    "$temporary/transaction.prepublish.json" "$index"
  assert_cmp_unchanged; "$cmp_bin" -s "$transaction_initial" "$temporary/transaction.prepublish.json"
  read -r -p "Digite AUTORIZO TRANSMITIR DEPLOY MAINNET INDICE $index para transmitir: " \
    transmission_authorization
  test "$transmission_authorization" = "AUTORIZO TRANSMITIR DEPLOY MAINNET INDICE $index"
  exec </dev/null
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  # The operator prompt is an unbounded pause. Re-establish every mutable
  # publication precondition after authorization so a concurrently consumed
  # nonce or occupied CREATE address cannot be published from a stale view.
  assert_rpc_proxy_alive
  run_node_json_authority "$temporary/transaction.transmit.json" \
    scripts/prepare-mainnet-deployment-transaction.mjs "$index"
  "$node_bin" scripts/check-mainnet-deployment-ledger-handoff.mjs \
    "$temporary/transaction.transmit.json" "$index"
  assert_cmp_unchanged; "$cmp_bin" -s "$transaction_initial" "$temporary/transaction.transmit.json"
  transmit_seen_index=0
  maximum_cost=$(canonical_decimal "$("$jq_bin" -er '.maximumCost' "$validation_snapshot")")
  "$node_bin" scripts/check-mainnet-deployment-sequence-cost.mjs "$index" "$maximum_cost" >/dev/null
  for endpoint in "${rpc_urls[@]}"; do
    assert_prior_deployments_finalized "$endpoint"
    test "$(rpc nonce "$from" --block finalized --rpc-url "$endpoint")" = "$nonce"
    test "$(rpc nonce "$from" --block pending --rpc-url "$endpoint")" = "$nonce"
    test "$(rpc code "$expected" --block finalized --rpc-url "$endpoint")" = '0x'
    test "$(rpc nonce "$expected" --block finalized --rpc-url "$endpoint")" = 0
    test "$(rpc nonce "$expected" --block pending --rpc-url "$endpoint")" = 0
    transmit_estimate=$(canonical_decimal "$(rpc estimate --create "$data" --from "$from" \
      --block finalized --rpc-url "$endpoint")" 16000000)
    "$node_bin" -e 'if(BigInt(process.argv[1])>BigInt(process.argv[2]))process.exit(1)' \
      "$transmit_estimate" "$gas_limit"
    # The signed raw transaction and its immutable fee anchor may survive a
    # crash for longer than one finalized Ethereum epoch. Authenticate that
    # historical anchor on every RPC, then require the moving finalized head
    # to extend it and re-evaluate fees there.
    transmit_anchor_before="$temporary/transmit-anchor-before-$transmit_seen_index.json"
    rpc block "$finalized_anchor_number" --json --rpc-url "$endpoint" > "$transmit_anchor_before"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$transmit_anchor_before"
    test "$("$jq_bin" -er '.number' "$transmit_anchor_before")" = "$finalized_anchor_number"
    test "$("$jq_bin" -er '.hash|ascii_downcase' "$transmit_anchor_before")" = "$finalized_anchor_hash"
    transmit_fee_block="$temporary/transmit-fee-block-$transmit_seen_index.json"
    rpc block finalized --json --rpc-url "$endpoint" > "$transmit_fee_block"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$transmit_fee_block"
    transmit_finalized_number=$("$jq_bin" -er '.number' "$transmit_fee_block")
    canonical_quantity "$finalized_anchor_number" "$transmit_finalized_number" >/dev/null
    transmit_base=$(canonical_quantity "$("$jq_bin" -er '.baseFeePerGas' "$transmit_fee_block")")
    "$node_bin" -e 'if(BigInt(process.argv[1])===0n)process.exit(1)' "$transmit_base"
    "$node_bin" -e 'let fee=BigInt(process.argv[1]);for(let i=0;i<12;i++)fee=(fee*9n+7n)/8n;fee+=2000000000n;if(fee>BigInt(process.argv[2]))process.exit(1)' \
      "$transmit_base" "$max_fee"
    transmit_balance=$(canonical_decimal "$(rpc balance "$from" --block finalized --rpc-url "$endpoint")")
    "$node_bin" -e 'const b=BigInt(process.argv[1]);if(b>1000000000000000000n)process.exit(1)' "$transmit_balance"
    "$node_bin" -e 'if(BigInt(process.argv[1])<BigInt(process.argv[2]))process.exit(1)' \
      "$transmit_balance" "$maximum_cost"
    transmit_seen_file="$temporary/transmit-seen-$transmit_seen_index.json"
    rpc rpc eth_getTransactionByHash "$transaction_hash" --rpc-url "$endpoint" \
      > "$transmit_seen_file"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$transmit_seen_file"
    "$jq_bin" -e '. == null' "$transmit_seen_file" >/dev/null
    transmit_anchor_after="$temporary/transmit-anchor-after-$transmit_seen_index.json"
    rpc block "$finalized_anchor_number" --json --rpc-url "$endpoint" > "$transmit_anchor_after"
    "$node_bin" scripts/check-private-strict-json-file.mjs "$transmit_anchor_after"
    assert_cmp_unchanged; "$cmp_bin" -s "$transmit_anchor_before" "$transmit_anchor_after"
    ((transmit_seen_index+=1))
  done
  snapshot "$raw_file" "$temporary/raw.transmit.txt"
  assert_cmp_unchanged; "$cmp_bin" -s "$raw_snapshot" "$temporary/raw.transmit.txt"
  snapshot "$validation_file" "$temporary/validation.transmit.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$validation_snapshot" "$temporary/validation.transmit.json"
  snapshot "$hash_file" "$temporary/hash.transmit.txt"
  assert_cmp_unchanged; "$cmp_bin" -s "$hash_snapshot" "$temporary/hash.transmit.txt"
  IFS= read -r raw < "$raw_snapshot"
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  publish_output="$temporary/publish-output.txt"
  rpc publish "$raw" --async --rpc-url "$primary_rpc" > "$publish_output"
  published=$(read_canonical_line "$publish_output")
  test "${published,,}" = "${transaction_hash,,}"
fi

receipt_1="$temporary/receipt-0.projected.json"
for source_index in "${!rpc_urls[@]}"; do
  endpoint=${rpc_urls[$source_index]}
  receipt="$temporary/receipt-$source_index.rpc.json"
  rpc receipt "$transaction_hash" --confirmations 2 --json --rpc-url "$endpoint" > "$receipt"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$receipt"
  "$jq_bin" -e --arg hash "$transaction_hash" --arg from "$from" --arg expected "$expected" '
    (.status == "0x1" or .status == "0x01") and .to == null and
    (.transactionHash|ascii_downcase) == ($hash|ascii_downcase) and
    (.from|ascii_downcase) == ($from|ascii_downcase) and
    (.contractAddress|ascii_downcase) == ($expected|ascii_downcase)' "$receipt" >/dev/null
  receipt_number=$("$jq_bin" -er '.blockNumber' "$receipt")
  receipt_height=$(canonical_quantity "$receipt_number")
  receipt_hash=$("$jq_bin" -er '.blockHash|ascii_downcase' "$receipt")
  finalized="$temporary/finalized-$source_index.json"
  rpc block finalized --json --rpc-url "$endpoint" > "$finalized"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$finalized"
  finalized_number=$("$jq_bin" -er '.number' "$finalized")
  finalized_height=$(canonical_quantity "$finalized_number")
  canonical_quantity "$receipt_number" "$finalized_number" >/dev/null
  canonical="$temporary/canonical-$source_index.json"
  rpc block "$receipt_number" --json --rpc-url "$endpoint" > "$canonical"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$canonical"
  canonical_hash=$("$jq_bin" -er '.hash|ascii_downcase' "$canonical")
  test "$canonical_hash" = "$receipt_hash"
  project_receipt "$receipt" "$temporary/receipt-$source_index.projected.json"
  receipt_recheck="$temporary/receipt-$source_index.recheck.json"
  rpc receipt "$transaction_hash" --confirmations 2 --json --rpc-url "$endpoint" > "$receipt_recheck"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$receipt_recheck"
  project_receipt "$receipt_recheck" "$temporary/receipt-$source_index.recheck.projected.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$temporary/receipt-$source_index.projected.json" \
    "$temporary/receipt-$source_index.recheck.projected.json"
  finalized_recheck="$temporary/finalized-$source_index.recheck.json"
  rpc block finalized --json --rpc-url "$endpoint" > "$finalized_recheck"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$finalized_recheck"
  test "$("$jq_bin" -er '.hash|ascii_downcase' "$finalized_recheck")" = \
    "$("$jq_bin" -er '.hash|ascii_downcase' "$finalized")"
  canonical_recheck="$temporary/canonical-$source_index.recheck.json"
  rpc block "$receipt_number" --json --rpc-url "$endpoint" > "$canonical_recheck"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$canonical_recheck"
  canonical_hash_recheck=$("$jq_bin" -er '.hash|ascii_downcase' "$canonical_recheck")
  test "$canonical_hash_recheck" = "$canonical_hash"
  if ((source_index > 0)); then
    assert_cmp_unchanged; "$cmp_bin" -s "$temporary/receipt-0.projected.json" "$temporary/receipt-$source_index.projected.json"
  fi
done

deadline=$((SECONDS + 1800))
while true; do
  code_consensus=''
  code_valid=true
  for endpoint in "${rpc_urls[@]}"; do
    code=$(rpc code "$expected" --block finalized --rpc-url "$endpoint")
    [[ -z $code_consensus ]] && code_consensus=$code
    [[ $code != 0x && $code = "$code_consensus" \
        && $("$cast_bin" keccak "$code") = "$expected_runtime_hash" ]] || code_valid=false
  done
  if [[ $code_valid == true ]]; then break; fi
  test "$SECONDS" -lt "$deadline"
  sleep 12
done
# Re-establish receipt ancestry and code after the potentially long finalization wait.
for source_index in "${!rpc_urls[@]}"; do
  endpoint=${rpc_urls[$source_index]}
  stable_receipt="$temporary/receipt-$source_index.stable.json"
  rpc receipt "$transaction_hash" --confirmations 2 --json --rpc-url "$endpoint" > "$stable_receipt"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$stable_receipt"
  project_receipt "$stable_receipt" "$temporary/receipt-$source_index.stable.projected.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$temporary/receipt-$source_index.projected.json" \
    "$temporary/receipt-$source_index.stable.projected.json"
  stable_number=$("$jq_bin" -er '.blockNumber' "$stable_receipt")
  stable_height=$(canonical_quantity "$stable_number")
  stable_hash=$("$jq_bin" -er '.blockHash|ascii_downcase' "$stable_receipt")
  stable_finalized="$temporary/finalized-$source_index.stable.json"
  rpc block finalized --json --rpc-url "$endpoint" > "$stable_finalized"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$stable_finalized"
  stable_finalized_number=$("$jq_bin" -er '.number' "$stable_finalized")
  stable_finalized_height=$(canonical_quantity "$stable_finalized_number")
  canonical_quantity "$stable_number" "$stable_finalized_number" >/dev/null
  stable_canonical="$temporary/canonical-$source_index.stable.json"
  rpc block "$stable_number" --json --rpc-url "$endpoint" > "$stable_canonical"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$stable_canonical"
  stable_canonical_hash=$("$jq_bin" -er '.hash|ascii_downcase' "$stable_canonical")
  test "$stable_canonical_hash" = "$stable_hash"
  stable_code=$(rpc code "$expected" --block finalized --rpc-url "$endpoint")
  test "$stable_code" = "$code_consensus"
  test "$("$cast_bin" keccak "$stable_code")" = "$expected_runtime_hash"
done
chmod 0600 "$receipt_1"
assert_rpc_proxy_alive
run_node_json_authority "$temporary/transaction.prereceipt.json" \
  scripts/prepare-mainnet-deployment-transaction.mjs "$index"
"$node_bin" scripts/check-mainnet-deployment-ledger-handoff.mjs \
  "$temporary/transaction.prereceipt.json" "$index"
assert_cmp_unchanged; "$cmp_bin" -s "$transaction_initial" "$temporary/transaction.prereceipt.json"
snapshot "$raw_file" "$temporary/raw.prereceipt.txt"
assert_cmp_unchanged; "$cmp_bin" -s "$raw_snapshot" "$temporary/raw.prereceipt.txt"
snapshot "$validation_file" "$temporary/validation.prereceipt.json"
assert_cmp_unchanged; "$cmp_bin" -s "$validation_snapshot" "$temporary/validation.prereceipt.json"
snapshot "$hash_file" "$temporary/hash.prereceipt.txt"
assert_cmp_unchanged; "$cmp_bin" -s "$hash_snapshot" "$temporary/hash.prereceipt.txt"
# Final all-source barrier immediately before create-once receipt/evidence
# persistence. Earlier per-source stability checks cannot rule out a reorg of
# source 0 while later sources are being inspected.
final_barrier_number=
final_barrier_hash=
for source_index in "${!rpc_urls[@]}"; do
  endpoint=${rpc_urls[$source_index]}
  barrier_receipt="$temporary/barrier-receipt-$source_index.json"
  rpc receipt "$transaction_hash" --confirmations 2 --json --rpc-url "$endpoint" > "$barrier_receipt"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$barrier_receipt"
  project_receipt "$barrier_receipt" "$temporary/barrier-receipt-$source_index.projected.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$temporary/receipt-0.projected.json" \
    "$temporary/barrier-receipt-$source_index.projected.json"
  barrier_number=$("$jq_bin" -er '.blockNumber' "$barrier_receipt")
  barrier_height=$(canonical_quantity "$barrier_number")
  barrier_hash=$("$jq_bin" -er '.blockHash|ascii_downcase' "$barrier_receipt")
  barrier_canonical="$temporary/barrier-canonical-$source_index.json"
  rpc block "$barrier_number" --json --rpc-url "$endpoint" > "$barrier_canonical"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$barrier_canonical"
  test "$("$jq_bin" -er '.hash|ascii_downcase' "$barrier_canonical")" = "$barrier_hash"
  barrier_finalized="$temporary/barrier-finalized-$source_index.json"
  rpc block finalized --json --rpc-url "$endpoint" > "$barrier_finalized"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$barrier_finalized"
  barrier_finalized_number=$("$jq_bin" -er '.number' "$barrier_finalized")
  barrier_finalized_height=$(canonical_quantity "$barrier_finalized_number")
  barrier_finalized_hash=$("$jq_bin" -er '.hash|ascii_downcase' "$barrier_finalized")
  canonical_quantity "$barrier_number" "$barrier_finalized_number" >/dev/null
  if [[ -z $final_barrier_number ]]; then
    final_barrier_number=$barrier_finalized_number
    final_barrier_hash=$barrier_finalized_hash
  else
    test "$barrier_finalized_number" = "$final_barrier_number"
    test "$barrier_finalized_hash" = "$final_barrier_hash"
  fi
  barrier_anchor_before="$temporary/barrier-anchor-before-$source_index.json"
  rpc block "$barrier_finalized_number" --json --rpc-url "$endpoint" > "$barrier_anchor_before"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$barrier_anchor_before"
  test "$("$jq_bin" -er '.number' "$barrier_anchor_before")" = "$barrier_finalized_number"
  test "$("$jq_bin" -er '.hash|ascii_downcase' "$barrier_anchor_before")" = "$barrier_finalized_hash"
  barrier_code=$(rpc code "$expected" --block "$barrier_finalized_number" --rpc-url "$endpoint")
  test "$barrier_code" = "$code_consensus"
  test "$("$cast_bin" keccak "$barrier_code")" = "$expected_runtime_hash"
  # The Reserve is deliberately the fourth and final CREATE. Its constructor
  # must leave mainnet paused before any deployment evidence is accepted.
  if [[ $index == 3 ]]; then
    test "$(rpc call "$expected" 'paused()(bool)' --block "$barrier_finalized_number" \
      --rpc-url "$endpoint")" = 'true'
  fi
  barrier_anchor_after="$temporary/barrier-anchor-after-$source_index.json"
  rpc block "$barrier_finalized_number" --json --rpc-url "$endpoint" > "$barrier_anchor_after"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$barrier_anchor_after"
  test "$("$jq_bin" -er '.number' "$barrier_anchor_after")" = "$barrier_finalized_number"
  test "$("$jq_bin" -er '.hash|ascii_downcase' "$barrier_anchor_after")" = "$barrier_finalized_hash"
  assert_cmp_unchanged; "$cmp_bin" -s "$barrier_anchor_before" "$barrier_anchor_after"
done
snapshot "$raw_file" "$temporary/raw.barrier.txt"
assert_cmp_unchanged; "$cmp_bin" -s "$raw_snapshot" "$temporary/raw.barrier.txt"
snapshot "$validation_file" "$temporary/validation.barrier.json"
assert_cmp_unchanged; "$cmp_bin" -s "$validation_snapshot" "$temporary/validation.barrier.json"
snapshot "$hash_file" "$temporary/hash.barrier.txt"
assert_cmp_unchanged; "$cmp_bin" -s "$hash_snapshot" "$temporary/hash.barrier.txt"
test "$(sha256_file "$rpc_catalog")" = "$rpc_catalog_sha256"
# A source checked early in the first pass may change while a later source is
# queried. Recheck both its moving finalized tag and the fixed common anchor
# after all local prerequisites and immediately before persistence.
for source_index in "${!rpc_urls[@]}"; do
  endpoint=${rpc_urls[$source_index]}
  barrier_finalized_recheck="$temporary/barrier-finalized-recheck-$source_index.json"
  rpc block finalized --json --rpc-url "$endpoint" > "$barrier_finalized_recheck"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$barrier_finalized_recheck"
  test "$("$jq_bin" -er '.number' "$barrier_finalized_recheck")" = "$final_barrier_number"
  test "$("$jq_bin" -er '.hash|ascii_downcase' "$barrier_finalized_recheck")" = "$final_barrier_hash"
  barrier_anchor_recheck="$temporary/barrier-anchor-recheck-$source_index.json"
  rpc block "$final_barrier_number" --json --rpc-url "$endpoint" > "$barrier_anchor_recheck"
  "$node_bin" scripts/check-private-strict-json-file.mjs "$barrier_anchor_recheck"
  test "$("$jq_bin" -er '.number' "$barrier_anchor_recheck")" = "$final_barrier_number"
  test "$("$jq_bin" -er '.hash|ascii_downcase' "$barrier_anchor_recheck")" = "$final_barrier_hash"
  assert_cmp_unchanged; "$cmp_bin" -s "$temporary/barrier-anchor-after-$source_index.json" "$barrier_anchor_recheck"
done
if [[ ! -e $receipt_file ]]; then
  persist_new "$receipt_1" "$receipt_file"
else
  assert_private_file "$receipt_file"
  snapshot "$receipt_file" "$temporary/receipt.recorded.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$temporary/receipt.recorded.json" "$receipt_1"
fi
receipt_block_number=$("$jq_bin" -er '.blockNumber' "$receipt_1")
receipt_block_hash=$("$jq_bin" -er '.blockHash|ascii_downcase' "$receipt_1")
evidence_draft="$temporary/deployment-evidence.json"
"$jq_bin" -n --arg index "$index" --arg name "$deployment_name" --arg chain "$chain_id" \
  --arg release "$release_config_sha256" --arg package "$USDOM_PACKAGE_SHA256" \
  --arg catalog "$rpc_catalog_sha256" --arg observation "$expected_observation_sha" \
  --arg observationHash "$package_observation_hash" --arg tx "$transaction_hash" --arg from "$from" \
  --arg nonce "$nonce" --arg contract "$expected" --arg runtime "$expected_runtime_hash" \
  --arg initcode "$("$jq_bin" -er '.transaction.initcodeHash' <<<"$transaction")" \
  --arg raw "$("$jq_bin" -er '.rawSha256' "$validation_snapshot")" \
  --arg block "$receipt_block_number" --arg blockHash "$receipt_block_hash" \
  --arg finalizedBlock "$final_barrier_number" --arg finalizedHash "$final_barrier_hash" \
  '{schema:"usdom-mainnet-deployment-evidence-v1",index:$index,name:$name,chainId:$chain,
    releaseConfigSha256:$release,packageSha256:$package,rpcCatalogSha256:$catalog,
    observationDocumentSha256:$observation,observationHash:$observationHash,
    transactionHash:$tx,from:$from,nonce:$nonce,rawSha256:$raw,initcodeHash:$initcode,
    expectedContract:$contract,runtimeCodeHash:$runtime,
    receiptBlockNumber:$block,receiptBlockHash:$blockHash,
    finalizedBlockNumber:$finalizedBlock,finalizedBlockHash:$finalizedHash}' > "$evidence_draft"
chmod 0600 "$evidence_draft"
"$node_bin" scripts/check-private-strict-json-file.mjs "$evidence_draft"
"$node_bin" scripts/check-deployment-evidence.mjs "$evidence_draft"
if [[ ! -e $evidence_file ]]; then
  persist_new "$evidence_draft" "$evidence_file"
else
  assert_private_file "$evidence_file"
  snapshot "$evidence_file" "$temporary/deployment-evidence.recorded.json"
  assert_cmp_unchanged; "$cmp_bin" -s "$temporary/deployment-evidence.recorded.json" "$evidence_draft"
fi
# Bind success to the authoritative inputs and the exact durable receipt and
# evidence present after the full create-once materialization window.
snapshot "$package_source" "$temporary/mainnet-deployment-package.final.json"
assert_cmp_unchanged; "$cmp_bin" -s "$package_snapshot" "$temporary/mainnet-deployment-package.final.json"
snapshot "$observation_source" "$temporary/mainnet-deployment-identity-observation.final.json"
assert_cmp_unchanged; "$cmp_bin" -s "$observation_snapshot" "$temporary/mainnet-deployment-identity-observation.final.json"
test "$(sha256_file "$rpc_catalog")" = "$rpc_catalog_sha256"
snapshot "$receipt_file" "$temporary/deployment-receipt.installed-final.json"
assert_cmp_unchanged; "$cmp_bin" -s "$receipt_1" "$temporary/deployment-receipt.installed-final.json"
snapshot "$evidence_file" "$temporary/deployment-evidence.installed-final.json"
assert_cmp_unchanged; "$cmp_bin" -s "$evidence_draft" "$temporary/deployment-evidence.installed-final.json"
assert_rpc_proxy_alive
printf 'Deployment %s finalizado em %s fontes: %s\n' \
  "$index" "${#rpc_urls[@]}" "$transaction_hash"
