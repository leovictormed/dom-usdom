#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
for fd_path in /proc/$$/fd/*; do inherited_fd=${fd_path##*/}; [[ $inherited_fd =~ ^[0-9]+$ ]] || exit 1; ((inherited_fd<=2)) && continue; [[ $inherited_fd == 255 ]] && continue; exec {inherited_fd}>&-; done
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE RUST_LOG RUSTFLAGS RUSTC_WRAPPER HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done
export RUST_BACKTRACE=0 RUST_LIB_BACKTRACE=0
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/home/leonardov/.foundry/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C LC_ALL=C TZ=UTC
ulimit -c 0
umask 077
(($#==0)) || { printf '%s\n' 'Usage: npm run --silent execute:safe-control-deployment' >&2; exit 64; }
[[ -t 0 && -t 1 ]] || { printf '%s\n' 'Safe deployment requires an interactive terminal.' >&2; exit 2; }
: "${USDOM_SAFE_PACKAGE:?USDOM_SAFE_PACKAGE is required}"
: "${USDOM_SAFE_HARDWARE_OWNER_IDENTITIES:?USDOM_SAFE_HARDWARE_OWNER_IDENTITIES is required}"
: "${USDOM_SAFE_HARDWARE_CUSTODY_PROOFS:?USDOM_SAFE_HARDWARE_CUSTODY_PROOFS is required}"
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?USDOM_CONTROL_EVIDENCE_DIRECTORY is required}"
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required}"
: "${USDOM_SAFE_BASELINE:?USDOM_SAFE_BASELINE is required}"
for command in cast node jq timeout cmp setsid flock sha256sum stat realpath dirname id mktemp chmod sleep; do command -v "$command" >/dev/null; done
account_home=$(node -e 'const os=require("os");process.stdout.write(os.userInfo().homedir)')
[[ ${HOME:-} == "$account_home" && $account_home == /* && $account_home != / && -d $account_home && ! -L $account_home ]]
[[ $(stat -Lc '%u' "$account_home") == "$(id -u)" ]]
home_mode=$(stat -Lc '%a' "$account_home"); (( (8#$home_mode & 8#022) == 0 ))
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
# shellcheck source=scripts/pinned-shell-tool-functions.sh
source "$project/scripts/pinned-shell-tool-functions.sh"
declare cast_bin node_bin jq_bin timeout_bin cmp_bin setsid_bin flock_bin sleep_bin mktemp_bin chmod_bin
for tool in cast node jq timeout cmp setsid flock sleep mktemp chmod; do pin_runtime_tool "$tool"; done
# Bootstrap needs the pinned Node and Foundry directories. Runtime PATH does
# not: every ceremony tool above now has an authenticated absolute pathname.
export PATH=/usr/bin:/bin
assert_tools(){ for tool in cast node jq timeout cmp setsid flock sleep mktemp chmod; do assert_runtime_tool "$tool"; done; }
run_node(){ assert_runtime_tool node; "$node_bin" "$@"; }
run_jq(){ assert_runtime_tool jq; "$jq_bin" "$@"; }
run_cmp(){ assert_runtime_tool cmp; "$cmp_bin" "$@"; }
run_sleep(){ assert_runtime_tool sleep; "$sleep_bin" "$@"; }
run_mktemp(){ assert_runtime_tool mktemp; "$mktemp_bin" "$@"; }
run_chmod(){ assert_runtime_tool chmod; "$chmod_bin" "$@"; }
control_dir=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY")
test -d "$control_dir"; test ! -L "$control_dir"
test "$(stat -c '%u:%a' "$control_dir")" = "$(id -u):700"
baseline_destination=$(realpath -ms "$USDOM_SAFE_BASELINE")
test "$(dirname "$baseline_destination")" = "$control_dir"
exec 9<"$control_dir"
assert_runtime_tool flock
"$flock_bin" -n 9 || { printf '%s\n' 'Another deployment or recovery executor holds the evidence-directory lock.' >&2; exit 75; }
test "$(realpath -e /proc/$$/fd/9)" = "$control_dir"
control_parent_identity=$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/9)
test "$control_parent_identity" = "$(stat -c '%d:%i:%u:%a' -- "$control_dir")"
assert_control_parent(){
  test "$(realpath -e "$control_dir")" = "$control_dir"
  test "$(realpath -e /proc/$$/fd/9)" = "$control_dir"
  test "$(stat -c '%d:%i:%u:%a' -- "$control_dir")" = "$control_parent_identity"
  test "$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/9)" = "$control_parent_identity"
}
assert_runtime_tool timeout; assert_runtime_tool mktemp
temporary=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
  "$mktemp_bin" -d -p /dev/shm usdom-safe-deploy.XXXXXXXX | /usr/bin/head -c 128)
assert_runtime_tool timeout; assert_runtime_tool mktemp
[[ $temporary =~ ^/dev/shm/usdom-safe-deploy\.[A-Za-z0-9]{8}$ ]]
[[ -d $temporary && ! -L $temporary ]]
test "$(stat -c '%u:%a' -- "$temporary")" = "$(id -u):700"
temporary_identity=$(/usr/bin/stat -c '%u:%d:%i:%a' -- "$temporary")
rpc_proxy_pid=''
safe_broadcast_state=clean
stop_proxy(){ if [[ -n $rpc_proxy_pid ]]; then kill -TERM -- "-$rpc_proxy_pid" 2>/dev/null || true; for _ in {1..100}; do kill -0 -- "-$rpc_proxy_pid" 2>/dev/null || break; run_sleep 0.05; done; kill -KILL -- "-$rpc_proxy_pid" 2>/dev/null || true; wait "$rpc_proxy_pid" 2>/dev/null || true; rpc_proxy_pid=''; fi; }
cleanup(){
  status=${1:-$?}; trap - EXIT HUP INT TERM; stop_proxy
  if [[ $safe_broadcast_state != clean ]] && (( status != 0 )); then
    printf '%s\n' 'Safe transaction outcome requires exact-hash and finalized-nonce revalidation; do not sign or publish a replacement.' >&2
    status=80
  fi
  if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' -- "$temporary" 2>/dev/null) == "$temporary_identity" ]] &&
    assert_runtime_tool node && assert_runtime_tool timeout &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' \
      "$temporary" > /dev/null 2> /dev/null &&
    assert_runtime_tool node && assert_runtime_tool timeout && test ! -e "$temporary"; then
    :
  else
    # Preserve a broadcast/timeout/signal status: cleanup failure must not turn
    # an uncertain on-chain result into an ordinary pre-broadcast rejection.
    (( status != 0 )) || status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
snapshot(){
  local source=$1 output=$2 error="$2.stderr" status
  assert_runtime_tool timeout; assert_runtime_tool node
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s "$node_bin" \
    scripts/read-private-file-stdout.mjs "$source" >"$output" 2>"$error"; then status=0; else status=$?; fi
  run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],2097152],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' "$output" "$error"
  if ((status != 0)); then printf 'Bounded private snapshot failed with status %s\n' "$status" >&2; return "$status"; fi
  test -s "$output"; test ! -s "$error"; run_chmod 0600 "$output"
}
run_node_empty_authority(){
  local label=$1 script=$2 output="$temporary/$1.stdout" error="$temporary/$1.stderr" status
  shift 2
  assert_runtime_tool timeout; assert_runtime_tool node
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$node_bin" \
    "$script" "$@" >"$output" 2>"$error"; then status=0; else status=$?; fi
  run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes)}' "$output" "$error"
  if ((status != 0)); then printf 'Bounded Safe %s authority failed with status %s\n' "$label" "$status" >&2; return "$status"; fi
  test ! -s "$output"; test ! -s "$error"
}
package_source=$(realpath -ms "$USDOM_SAFE_PACKAGE"); identity_source=$(realpath -ms "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"); proof_source=$(realpath -ms "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")
package_snapshot="$temporary/safe-package.json"; identity_snapshot="$temporary/identities.json"; proof_snapshot="$temporary/custody-proofs.json"
snapshot "$package_source" "$package_snapshot"; snapshot "$identity_source" "$identity_snapshot"; snapshot "$proof_source" "$proof_snapshot"
relayer_policy_source="$control_dir/safe-control-deployment-relayer-policy.json"; relayer_keystore_source="$control_dir/safe-control-deployment-relayer-keystore.json"
relayer_policy_snapshot="$temporary/safe-control-deployment-relayer-policy.json"; relayer_keystore_snapshot="$temporary/safe-control-deployment-relayer-keystore.json"
snapshot "$relayer_policy_source" "$relayer_policy_snapshot"; snapshot "$relayer_keystore_source" "$relayer_keystore_snapshot"
export USDOM_SAFE_PACKAGE=$package_snapshot USDOM_SAFE_OWNER_IDENTITIES=$identity_snapshot USDOM_SAFE_HARDWARE_OWNER_IDENTITIES=$identity_snapshot USDOM_SAFE_HARDWARE_CUSTODY_PROOFS=$proof_snapshot
run_node_empty_authority custody scripts/check-safe-owner-hardware-custody-proofs.mjs
assert_package_rebuild(){
  local rebuilt="$temporary/safe-package.rebuilt.json" error="$temporary/safe-package.rebuilt.stderr" status
  assert_runtime_tool timeout; assert_runtime_tool node
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$node_bin" \
    scripts/prepare-recoverable-safe-controls.mjs >"$rebuilt" 2>"$error"; then status=0; else status=$?; fi
  run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],1048576],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' "$rebuilt" "$error"
  if ((status != 0)); then printf 'Bounded Safe package rebuild failed with status %s\n' "$status" >&2; return "$status"; fi
  test ! -s "$error"; run_chmod 0600 "$rebuilt"
  run_node scripts/check-private-strict-json-file.mjs "$rebuilt"
  run_cmp -s "$package_snapshot" "$rebuilt"
}
assert_package_rebuild
deployer=$(run_jq -er '.relayer' "$relayer_policy_snapshot")
[[ $deployer =~ ^0x[0-9A-Fa-f]{40}$ ]]
ready="$temporary/rpc-ready.json"; proxy_out="$temporary/proxy.out"; proxy_err="$temporary/proxy.err"
check_proxy_channels(){ run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes);if(bytes.length!==0)process.exit(1)}' "$proxy_out" "$proxy_err"; }
check_proxy_ready(){
  local output=$1 error="$1.stderr" status
  shift
  assert_runtime_tool timeout; assert_runtime_tool node
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s "$node_bin" \
    scripts/check-private-rpc-proxy-ready.mjs "$ready" "$rpc_proxy_pid" "$@" >"$output" 2>"$error"; then status=0; else status=$?; fi
  run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes)}' "$output" "$error"
  if ((status != 0)); then printf 'Bounded private RPC readiness failed with status %s\n' "$status" >&2; return "$status"; fi
  test ! -s "$error"; run_chmod 0600 "$output"
}
assert_tools
"$setsid_bin" /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin USDOM_PRIVATE_RPC_PROXY_LAUNCHER=1 USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$timeout_bin" --signal=TERM --kill-after=2s 24h "$node_bin" scripts/serve-private-rpc-catalog-proxy.mjs "$ready" >"$proxy_out" 2>"$proxy_err" & rpc_proxy_pid=$!
for _ in {1..200}; do [[ -f $ready ]] && break; kill -0 "$rpc_proxy_pid" 2>/dev/null || { printf '%s\n' 'private RPC proxy failed' >&2; exit 1; }; run_sleep 0.05; done
rpc_ready_observation="$temporary/rpc-ready.observed.txt"
check_proxy_ready "$rpc_ready_observation"
mapfile -t ready_lines < "$rpc_ready_observation"
((${#ready_lines[@]}>=3)); rpc_ready_sha=${ready_lines[0]}; rpc_urls=("${ready_lines[@]:1}")
check_proxy_channels
assert_proxy(){
  kill -0 "$rpc_proxy_pid" 2>/dev/null; check_proxy_channels
  check_proxy_ready "$temporary/rpc-ready.current.txt" "$rpc_ready_sha"
  run_cmp -s "$rpc_ready_observation" "$temporary/rpc-ready.current.txt"
}
rpc(){
  local output="$temporary/rpc-output.txt" error="$temporary/rpc-error.txt" status
  assert_tools; assert_proxy
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$cast_bin" "$@" >"$output" 2>"$error"; then status=0; else status=$?; fi
  run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],2097152],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' "$output" "$error"
  if ((status != 0)); then printf 'Bounded Safe deployment RPC failed with status %s\n' "$status" >&2; return "$status"; fi
  test ! -s "$error"
  run_node scripts/read-private-file-stdout.mjs "$output"
}
strict_json(){ run_node scripts/check-private-strict-json-file.mjs "$1"; }
run_node_json_to_file(){
  local output=$1 script=$2 error="$1.stderr" status
  shift 2
  assert_runtime_tool timeout; assert_runtime_tool node
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$node_bin" \
    "$script" "$@" >"$output" 2>"$error"; then status=0; else status=$?; fi
  run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],1048576],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' "$output" "$error"
  if ((status != 0)); then printf 'Bounded Safe JSON authority failed with status %s\n' "$status" >&2; return "$status"; fi
  test ! -s "$error"; run_chmod 0600 "$output"; strict_json "$output"
}
install_private_create_once(){
  local source=$1 destination=$2 mode=${3:-raw} output="$temporary/install-private.stdout" error="$temporary/install-private.stderr" status verified="$temporary/install-${2##*/}.verified"
  [[ $mode == raw || $mode == json ]]
  assert_control_parent
  assert_runtime_tool timeout; assert_runtime_tool node
  if [[ $mode == json ]]; then
    if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s "$node_bin" \
      scripts/install-private-file-new-stdin.mjs --json "$destination" <"$source" >"$output" 2>"$error"; then status=0; else status=$?; fi
  else
    if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s "$node_bin" \
      scripts/install-private-file-new-stdin.mjs "$destination" <"$source" >"$output" 2>"$error"; then status=0; else status=$?; fi
  fi
  run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes)}' "$output" "$error"
  if ((status != 0)); then printf 'Bounded private installation failed with status %s\n' "$status" >&2; return "$status"; fi
  test ! -s "$output"; test ! -s "$error"
  snapshot "$destination" "$verified"; run_cmp -s "$source" "$verified"
  assert_control_parent
}
observe_safe_target(){
  local role=$1 output=$2 error="$2.stderr" status
  assert_runtime_tool timeout; assert_runtime_tool node
  if "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$node_bin" \
    scripts/check-safe-control-deployment-target.mjs "$role" >"$output" 2>"$error"; then status=0; else status=$?; fi
  run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],1048576],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes)}' "$output" "$error"
  if ((status != 0)); then printf 'Bounded Safe target observation failed with status %s\n' "$status" >&2; return "$status"; fi
  test ! -s "$error"; run_chmod 0600 "$output"; strict_json "$output"
}
assert_inputs(){ snapshot "$package_source" "$temporary/package.current"; snapshot "$identity_source" "$temporary/identity.current"; snapshot "$proof_source" "$temporary/proof.current"; snapshot "$relayer_policy_source" "$temporary/relayer-policy.current"; snapshot "$relayer_keystore_source" "$temporary/relayer-keystore.current"; run_cmp -s "$package_snapshot" "$temporary/package.current"; run_cmp -s "$identity_snapshot" "$temporary/identity.current"; run_cmp -s "$proof_snapshot" "$temporary/proof.current"; run_cmp -s "$relayer_policy_snapshot" "$temporary/relayer-policy.current"; run_cmp -s "$relayer_keystore_snapshot" "$temporary/relayer-keystore.current"; }
assert_inputs
# One deployer pays at most three 1,000,000-gas transactions at 100 gwei.
# Require the whole sequence before the first signature so the pilot cannot
# strand one or two deployed Safes for lack of gas.
for endpoint in "${rpc_urls[@]}"; do
  funding=$(rpc balance "$deployer" --block finalized --rpc-url "$endpoint")
  run_node -e 'const v=process.argv[1];if(!/^(0|[1-9][0-9]*)$/.test(v)||BigInt(v)<300000000000000000n)process.exit(1)' "$funding"
done
for role in governance reserveGuardian checkpointGuardian usdtCustody; do
  raw="$control_dir/safe-deployment-$role-raw.txt"; validation="$control_dir/safe-deployment-$role-validation.json"; journal="$control_dir/safe-deployment-$role-journal.json"; receipt="$control_dir/safe-deployment-$role-receipt.json"; envelope="$control_dir/safe-deployment-$role-relayer-envelope.json"; relayer_input="$control_dir/safe-deployment-$role-relayer-input.json"
  private_transaction_input="$temporary/$role-private-transaction-input.json"
  run_node_json_to_file "$private_transaction_input" scripts/prepare-safe-deployment-private-input.mjs "$role" "$package_snapshot"
  if [[ -e $journal ]]; then
    snapshot "$journal" "$temporary/$role-journal.json"
    run_jq -e --arg role "$role" '(.|keys)==["raw","role","schema","validation"] and .schema=="usdom-safe-deployment-journal/v1" and .role==$role and (.raw|test("^0x[0-9A-Fa-f]+$")) and (.validation|type)=="object"' "$temporary/$role-journal.json" >/dev/null
    run_jq -er '.raw' "$temporary/$role-journal.json" > "$temporary/$role-raw.from-journal.txt"; run_chmod 0600 "$temporary/$role-raw.from-journal.txt"
    run_jq -e '.validation' "$temporary/$role-journal.json" > "$temporary/$role-validation.from-journal.json"; run_chmod 0600 "$temporary/$role-validation.from-journal.json"
    for pair in "$temporary/$role-raw.from-journal.txt:$raw" "$temporary/$role-validation.from-journal.json:$validation"; do source_file=${pair%%:*}; target_file=${pair#*:}; target_name=${target_file##*/}; if [[ -e $target_file ]]; then snapshot "$target_file" "$temporary/existing-$target_name"; run_cmp -s "$source_file" "$temporary/existing-$target_name"; else install_private_create_once "$source_file" "$target_file"; fi; done
  else
    : # The external signer may have installed raw before this executor creates validation/journal.
  fi
  signed_deployment=false
  if [[ -e $raw ]]; then
    test -f "$raw"; test ! -L "$raw"; test -f "$envelope"; test ! -L "$envelope"
    snapshot "$raw" "$temporary/$role-raw.txt"; snapshot "$envelope" "$temporary/$role-envelope.json"
    current_validation="$temporary/$role-validation.current.json"; run_node_json_to_file "$current_validation" scripts/check-safe-control-deployment-relayer-raw.mjs "$role" "$temporary/$role-raw.txt" "$temporary/$role-envelope.json" "$private_transaction_input" "$package_snapshot" "$relayer_policy_snapshot" "$relayer_keystore_snapshot"
    if [[ -e $validation ]]; then snapshot "$validation" "$temporary/$role-validation.json"; run_cmp -s "$temporary/$role-validation.json" "$current_validation"; else install_private_create_once "$current_validation" "$validation" json; snapshot "$validation" "$temporary/$role-validation.json"; fi
    nonce=$(run_jq -er '.nonce' "$temporary/$role-validation.json")
    if [[ ! -e $journal ]]; then journal_candidate="$temporary/$role-journal.candidate.json"; run_jq -n --arg role "$role" --rawfile raw "$temporary/$role-raw.txt" --slurpfile validation "$temporary/$role-validation.json" '{schema:"usdom-safe-deployment-journal/v1",role:$role,raw:($raw|rtrimstr("\n")),validation:$validation[0]}' > "$journal_candidate"; run_chmod 0600 "$journal_candidate"; install_private_create_once "$journal_candidate" "$journal" json; fi
    tx_hash=$(run_jq -er '.transactionHash' "$temporary/$role-validation.json")
    signed_deployment=true
    # A durable signed transaction has no durable proof that publication was
    # never attempted. Until its exact finalized receipt is installed, every
    # failure requires nonce/hash revalidation rather than a blind replay.
    safe_broadcast_state=signed-unresolved
  else
    test ! -e "$validation"; test ! -e "$receipt"
  fi
  target="$temporary/$role-target.json"; observe_safe_target "$role" "$target"
  state=$(run_jq -er '.state' "$target")
  [[ $state == vacant || $state == deployed ]]
  if [[ $state == deployed && $signed_deployment == false ]]; then printf 'Safe %s was already finalized permissionlessly with exact configuration.\n' "$role"; continue; fi
  if [[ $state == deployed ]]; then printf 'Safe %s deployment is finalized; revalidating its durable transaction and receipt.\n' "$role"; fi
  if [[ $state == vacant ]]; then
  test "$state" = vacant
  to=$(run_jq -er '.to' "$private_transaction_input")
  if [[ $signed_deployment == false ]]; then
    test ! -e "$validation"
    nonce=''; estimate=''; base_fee=''
    for index in "${!rpc_urls[@]}"; do
      n=$(rpc nonce "$deployer" --block pending --rpc-url "${rpc_urls[$index]}"); finalized_nonce=$(rpc nonce "$deployer" --block finalized --rpc-url "${rpc_urls[$index]}"); test "$finalized_nonce" = "$n"
      private_estimate=$(run_node scripts/prepare-private-eth-estimate-gas.mjs "$private_transaction_input" "$deployer")
      estimate_response=$(printf '%s\n' "$private_estimate" | rpc rpc eth_estimateGas --raw --rpc-url "${rpc_urls[$index]}")
      e=$(printf '%s' "$estimate_response" | run_node -e 'let s="";process.stdin.setEncoding("utf8");process.stdin.on("data",c=>s+=c);process.stdin.on("end",()=>{const v=JSON.parse(s);if(!/^0x[0-9a-f]+$/i.test(v))process.exit(1);process.stdout.write(BigInt(v).toString())})')
      b=$(rpc block finalized --field baseFeePerGas --rpc-url "${rpc_urls[$index]}")
      run_node -e 'const [n,e,b]=process.argv.slice(1);for(const [v,max] of [[n,(1n<<53n)-1n],[e,1000000n],[b,100000000000n]]){if(!/^(0|[1-9][0-9]*)$/.test(v)||BigInt(v)>max)process.exit(1)}' "$n" "$e" "$b"
      if [[ -z $nonce ]]; then nonce=$n; estimate=$e; base_fee=$b; else test "$n" = "$nonce"; test "$e" = "$estimate"; base_fee=$(run_node -e 'const a=BigInt(process.argv[1]),b=BigInt(process.argv[2]);process.stdout.write(String(a>b?a:b))' "$base_fee" "$b"); fi
    done
    gas_limit=$(run_node -e 'const e=BigInt(process.argv[1]),g=e+e/4n+1n;if(g===0n||g>1000000n)process.exit(1);process.stdout.write(String(g))' "$estimate")
    max_fee=$(run_node -e 'let f=BigInt(process.argv[1]);for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(f>100000000000n)process.exit(1);process.stdout.write(String(f))' "$base_fee")
    assert_inputs; assert_package_rebuild
    presign_target="$temporary/$role-target.presign.json"; observe_safe_target "$role" "$presign_target"
    test "$(run_jq -r '.state' "$presign_target")" = vacant
    for index in "${!rpc_urls[@]}"; do
      test "$(rpc nonce "$deployer" --block finalized --rpc-url "${rpc_urls[$index]}")" = "$nonce"
      test "$(rpc nonce "$deployer" --block pending --rpc-url "${rpc_urls[$index]}")" = "$nonce"
    done
    envelope_candidate="$temporary/$role-relayer-envelope.candidate.json"
    run_node_json_to_file "$envelope_candidate" scripts/prepare-safe-control-deployment-relayer-envelope.mjs "$role" "$private_transaction_input" "$package_snapshot" "$relayer_policy_snapshot" "$relayer_keystore_snapshot" "$nonce" "$gas_limit" "$max_fee" 2000000000
    if [[ -e $envelope ]]; then snapshot "$envelope" "$temporary/$role-envelope.existing.json"; run_cmp -s "$envelope_candidate" "$temporary/$role-envelope.existing.json"; else install_private_create_once "$envelope_candidate" "$envelope" json; fi
    if [[ -e $relayer_input ]]; then snapshot "$relayer_input" "$temporary/$role-input.existing.json"; run_cmp -s "$private_transaction_input" "$temporary/$role-input.existing.json"; else install_private_create_once "$private_transaction_input" "$relayer_input" json; fi
    printf 'Envelope gas-only do relayer instalado em %s. Assine pela fronteira externa e instale a raw privada create-once em %s; nenhum segredo sera aberto por este executor.\n' "$envelope" "$raw" >&2
    exit 78
  fi
  seen=false
  for index in "${!rpc_urls[@]}"; do seen_file="$temporary/$role-seen-$index.json"; rpc rpc eth_getTransactionByHash "$tx_hash" --rpc-url "${rpc_urls[$index]}" > "$seen_file"; strict_json "$seen_file"; run_jq -e --arg hash "$tx_hash" '.==null or ((.hash|ascii_downcase)==($hash|ascii_downcase))' "$seen_file" >/dev/null; run_jq -e '.!=null' "$seen_file" >/dev/null && seen=true || true; done
  if [[ $seen == true ]]; then safe_broadcast_state=observed; fi
  if [[ $seen == false ]]; then
    read -r -p "Digite AUTORIZO TRANSMITIR SAFE $role NONCE $nonce TX $tx_hash: " transmit
    test "$transmit" = "AUTORIZO TRANSMITIR SAFE $role NONCE $nonce TX $tx_hash"
    assert_inputs; assert_package_rebuild
    transmit_target="$temporary/$role-target.pretransmit.json"; observe_safe_target "$role" "$transmit_target"
    test "$(run_jq -r '.state' "$transmit_target")" = vacant
    for endpoint in "${rpc_urls[@]}"; do test "$(rpc nonce "$deployer" --block pending --rpc-url "$endpoint")" = "$nonce"; test "$(rpc nonce "$deployer" --block finalized --rpc-url "$endpoint")" = "$nonce"; done
    assert_control_parent; safe_broadcast_state=publishing
    published=$(run_node scripts/publish-private-raw-transaction.mjs "$temporary/$role-raw.txt" \
      "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$project/config/mainnet-preflight-rpc-catalog.json" 0)
    test "${published,,}" = "${tx_hash,,}"
  fi
  deadline=$((SECONDS+1800)); while :; do target_now="$temporary/$role-target-now.json"; observe_safe_target "$role" "$target_now"; state=$(run_jq -er '.state' "$target_now"); [[ $state == deployed ]] && break; test "$state" = vacant; test "$SECONDS" -lt "$deadline"; run_sleep 12; done
  fi
  assert_inputs
  receipt_existing=''
  if [[ -e $receipt ]]; then
    snapshot "$receipt" "$temporary/$role-receipt.existing.json"
    run_node_json_to_file "$temporary/$role-receipt.rechecked.json" scripts/check-safe-control-deployment-receipt.mjs "$role" "$temporary/$role-receipt.existing.json" "$temporary/$role-validation.json"
    run_cmp -s "$temporary/$role-receipt.existing.json" "$temporary/$role-receipt.rechecked.json"
    receipt_existing="$temporary/$role-receipt.existing.json"
  fi
  receipt_consensus=''
  for index in "${!rpc_urls[@]}"; do
    receipt_raw="$temporary/$role-receipt-$index.raw.json"; receipt_checked="$temporary/$role-receipt-$index.checked.json"
    rpc receipt "$tx_hash" --json --rpc-url "${rpc_urls[$index]}" > "$receipt_raw"; strict_json "$receipt_raw"
    run_node_json_to_file "$receipt_checked" scripts/check-safe-control-deployment-receipt.mjs "$role" "$receipt_raw" "$temporary/$role-validation.json"
    receipt_block=$(run_jq -er '.blockNumber' "$receipt_checked"); receipt_hash=$(run_jq -er '.blockHash' "$receipt_checked")
    canonical_hash=$(rpc block "$receipt_block" --field hash --rpc-url "${rpc_urls[$index]}"); test "${canonical_hash,,}" = "${receipt_hash,,}"
    finalized_number=$(rpc block finalized --field number --rpc-url "${rpc_urls[$index]}")
    run_node_empty_authority finality scripts/check-safe-control-deployment-finality.mjs "$finalized_number" "$receipt_block"
    if [[ -z $receipt_consensus ]]; then receipt_consensus=$receipt_checked; else run_cmp -s "$receipt_consensus" "$receipt_checked"; fi
    [[ -z $receipt_existing ]] || run_cmp -s "$receipt_existing" "$receipt_checked"
  done
  [[ -n $receipt_existing ]] || install_private_create_once "$receipt_consensus" "$receipt" json
  snapshot "$receipt" "$temporary/$role-receipt.installed.json"
  run_cmp -s "$receipt_consensus" "$temporary/$role-receipt.installed.json"
  safe_broadcast_state=clean
done
assert_inputs
assert_package_rebuild
for role in governance reserveGuardian checkpointGuardian usdtCustody; do
  receipt="$control_dir/safe-deployment-$role-receipt.json"
  validation="$control_dir/safe-deployment-$role-validation.json"
  raw="$control_dir/safe-deployment-$role-raw.txt"
  journal="$control_dir/safe-deployment-$role-journal.json"
  envelope="$control_dir/safe-deployment-$role-relayer-envelope.json"
  if [[ -e $journal || -e $raw || -e $receipt || -e $validation ]]; then
    test -e "$journal"; test -e "$raw"; test -e "$receipt"; test -e "$validation"; test -e "$envelope"
    snapshot "$journal" "$temporary/$role-journal.final.json"
    snapshot "$raw" "$temporary/$role-raw.final.txt"
    snapshot "$receipt" "$temporary/$role-receipt.final.json"
    snapshot "$validation" "$temporary/$role-validation.final.json"
    snapshot "$envelope" "$temporary/$role-envelope.final.json"
    run_jq -e --arg role "$role" --rawfile raw "$temporary/$role-raw.final.txt" \
      --slurpfile validation "$temporary/$role-validation.final.json" \
      '.schema=="usdom-safe-deployment-journal/v1" and .role==$role and .raw==($raw|rtrimstr("\n")) and .validation==$validation[0]' \
      "$temporary/$role-journal.final.json" >/dev/null
    run_node_json_to_file "$temporary/$role-private-transaction-input.final.json" scripts/prepare-safe-deployment-private-input.mjs "$role" "$package_snapshot"
    run_node_json_to_file "$temporary/$role-validation.final-rechecked.json" \
      scripts/check-safe-control-deployment-relayer-raw.mjs "$role" "$temporary/$role-raw.final.txt" "$temporary/$role-envelope.final.json" "$temporary/$role-private-transaction-input.final.json" "$package_snapshot" "$relayer_policy_snapshot" "$relayer_keystore_snapshot"
    run_cmp -s "$temporary/$role-validation.final.json" "$temporary/$role-validation.final-rechecked.json"
    run_node_json_to_file "$temporary/$role-receipt.final-rechecked.json" \
      scripts/check-safe-control-deployment-receipt.mjs "$role" \
      "$temporary/$role-receipt.final.json" "$temporary/$role-validation.final.json"
    run_cmp -s "$temporary/$role-receipt.final.json" "$temporary/$role-receipt.final-rechecked.json"
  fi
  final_target="$temporary/$role-target.final.json"; observe_safe_target "$role" "$final_target"
  test "$(run_jq -r '.state' "$final_target")" = deployed
done
assert_inputs
assert_package_rebuild
# Publish the finalized three-Safe snapshot, then an output-last completion
# binding every raw journal and receipt to that exact observed configuration.
baseline_candidate="$temporary/safe-baseline-primary.json"
run_node_json_to_file "$baseline_candidate" scripts/collect-recoverable-safe-controls.mjs
if [[ -e $baseline_destination ]]; then
  snapshot "$baseline_destination" "$temporary/safe-baseline.existing.json"
  run_cmp -s "$baseline_candidate" "$temporary/safe-baseline.existing.json"
else
  install_private_create_once "$baseline_candidate" "$baseline_destination" json
fi
export USDOM_SAFE_BASELINE=$baseline_destination
completion_candidate="$temporary/safe-deployment-finalized-completion.json"
run_node_json_to_file "$completion_candidate" scripts/materialize-safe-control-deployment-completion.mjs
completion_destination="$control_dir/safe-deployment-finalized-completion.json"
if [[ -e $completion_destination ]]; then
  snapshot "$completion_destination" "$temporary/safe-deployment-completion.existing.json"
  run_cmp -s "$completion_candidate" "$temporary/safe-deployment-completion.existing.json"
else
  install_private_create_once "$completion_candidate" "$completion_destination" json
fi
run_node_json_to_file "$temporary/safe-deployment-completion.rechecked.json" \
  scripts/materialize-safe-control-deployment-completion.mjs
run_cmp -s "$completion_candidate" "$temporary/safe-deployment-completion.rechecked.json"
assert_inputs
assert_package_rebuild
assert_control_parent
printf '%s\n' 'All four recoverable Safes are finalized with the exact package configuration.'
