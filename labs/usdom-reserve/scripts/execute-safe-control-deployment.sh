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
for command in cast node jq timeout cmp setsid flock sha256sum stat realpath dirname id mktemp chmod sleep; do command -v "$command" >/dev/null; done
account_home=$(node -e 'const os=require("os");process.stdout.write(os.userInfo().homedir)')
[[ ${HOME:-} == "$account_home" && $account_home == /* && $account_home != / && -d $account_home && ! -L $account_home ]]
[[ $(stat -Lc '%u' "$account_home") == "$(id -u)" ]]
home_mode=$(stat -Lc '%a' "$account_home"); (( (8#$home_mode & 8#022) == 0 ))
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
# shellcheck source=scripts/pinned-shell-tool-functions.sh
source "$project/scripts/pinned-shell-tool-functions.sh"
declare cast_bin node_bin jq_bin timeout_bin cmp_bin setsid_bin flock_bin
for tool in cast node jq timeout cmp setsid flock; do pin_runtime_tool "$tool"; done
assert_tools(){ for tool in cast node jq timeout cmp setsid flock; do assert_runtime_tool "$tool"; done; }
run_node(){ assert_runtime_tool node; "$node_bin" "$@"; }
run_jq(){ assert_runtime_tool jq; "$jq_bin" "$@"; }
run_cmp(){ assert_runtime_tool cmp; "$cmp_bin" "$@"; }
control_dir=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY")
test -d "$control_dir"; test ! -L "$control_dir"
test "$(stat -c '%u:%a' "$control_dir")" = "$(id -u):700"
exec 9<"$control_dir"
assert_runtime_tool flock
"$flock_bin" -n 9 || { printf '%s\n' 'Another deployment or recovery executor holds the evidence-directory lock.' >&2; exit 75; }
temporary=$(mktemp -d -p /dev/shm usdom-safe-deploy.XXXXXXXX); chmod 0700 "$temporary"
rpc_proxy_pid=''
stop_proxy(){ if [[ -n $rpc_proxy_pid ]]; then kill -TERM -- "-$rpc_proxy_pid" 2>/dev/null || true; for _ in {1..100}; do kill -0 -- "-$rpc_proxy_pid" 2>/dev/null || break; sleep 0.05; done; kill -KILL -- "-$rpc_proxy_pid" 2>/dev/null || true; wait "$rpc_proxy_pid" 2>/dev/null || true; rpc_proxy_pid=''; fi; }
cleanup(){ status=${1:-$?}; trap - EXIT HUP INT TERM; stop_proxy; run_node -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary" || status=1; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
snapshot(){ run_node scripts/read-private-file-stdout.mjs "$1" > "$2"; chmod 0600 "$2"; }
package_source=$(realpath -ms "$USDOM_SAFE_PACKAGE"); identity_source=$(realpath -ms "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"); proof_source=$(realpath -ms "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")
package_snapshot="$temporary/safe-package.json"; identity_snapshot="$temporary/identities.json"; proof_snapshot="$temporary/custody-proofs.json"
snapshot "$package_source" "$package_snapshot"; snapshot "$identity_source" "$identity_snapshot"; snapshot "$proof_source" "$proof_snapshot"
export USDOM_SAFE_PACKAGE=$package_snapshot USDOM_SAFE_OWNER_IDENTITIES=$identity_snapshot USDOM_SAFE_HARDWARE_OWNER_IDENTITIES=$identity_snapshot USDOM_SAFE_HARDWARE_CUSTODY_PROOFS=$proof_snapshot
run_node scripts/check-safe-owner-hardware-custody-proofs.mjs >/dev/null
assert_package_rebuild(){ rebuilt="$temporary/safe-package.rebuilt.json"; assert_runtime_tool timeout; assert_runtime_tool node; "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$node_bin" scripts/prepare-recoverable-safe-controls.mjs > "$rebuilt"; run_cmp -s "$package_snapshot" "$rebuilt"; }
assert_package_rebuild
deployer=$(run_jq -er '.ownersByRole.governance[0]' "$identity_snapshot")
[[ $deployer =~ ^0x[0-9A-Fa-f]{40}$ ]]; export USDOM_SAFE_PRIMARY_OWNER=$deployer
ready="$temporary/rpc-ready.json"; proxy_out="$temporary/proxy.out"; proxy_err="$temporary/proxy.err"
check_proxy_channels(){ run_node -e 'const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const file of process.argv.slice(1)){const bytes=fs.readFileSync(file);if(bytes.length>65536)process.exit(1);fatal.decode(bytes);if(bytes.length!==0)process.exit(1)}' "$proxy_out" "$proxy_err"; }
assert_tools
"$setsid_bin" /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin USDOM_PRIVATE_RPC_PROXY_LAUNCHER=1 USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$timeout_bin" --signal=TERM --kill-after=2s 24h "$node_bin" scripts/serve-private-rpc-catalog-proxy.mjs "$ready" >"$proxy_out" 2>"$proxy_err" & rpc_proxy_pid=$!
for _ in {1..200}; do [[ -f $ready ]] && break; kill -0 "$rpc_proxy_pid" 2>/dev/null || { printf '%s\n' 'private RPC proxy failed' >&2; exit 1; }; sleep 0.05; done
mapfile -t ready_lines < <(run_node scripts/check-private-rpc-proxy-ready.mjs "$ready" "$rpc_proxy_pid")
((${#ready_lines[@]}>=3)); rpc_ready_sha=${ready_lines[0]}; rpc_urls=("${ready_lines[@]:1}")
check_proxy_channels
assert_proxy(){ kill -0 "$rpc_proxy_pid" 2>/dev/null; check_proxy_channels; run_node scripts/check-private-rpc-proxy-ready.mjs "$ready" "$rpc_proxy_pid" "$rpc_ready_sha" >/dev/null; }
rpc(){ assert_tools; assert_proxy; "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$cast_bin" "$@"; }
strict_json(){ run_node scripts/check-private-strict-json-file.mjs "$1"; }
assert_inputs(){ snapshot "$package_source" "$temporary/package.current"; snapshot "$identity_source" "$temporary/identity.current"; snapshot "$proof_source" "$temporary/proof.current"; run_cmp -s "$package_snapshot" "$temporary/package.current"; run_cmp -s "$identity_snapshot" "$temporary/identity.current"; run_cmp -s "$proof_snapshot" "$temporary/proof.current"; }
assert_runtime_tool timeout; assert_runtime_tool cast
observed=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet address --ledger); test "$observed" = "$deployer"
read -r -p 'Digite AUTORIZO TRES SAFES 2-DE-3 MAINNET para continuar: ' authorization
test "$authorization" = 'AUTORIZO TRES SAFES 2-DE-3 MAINNET'
assert_inputs
for role in governance reserveGuardian checkpointGuardian; do
  raw="$control_dir/safe-deployment-$role-raw.txt"; validation="$control_dir/safe-deployment-$role-validation.json"; journal="$control_dir/safe-deployment-$role-journal.json"; receipt="$control_dir/safe-deployment-$role-receipt.json"
  if [[ -e $journal ]]; then
    snapshot "$journal" "$temporary/$role-journal.json"
    run_jq -e --arg role "$role" '(.|keys)==["raw","role","schema","validation"] and .schema=="usdom-safe-deployment-journal/v1" and .role==$role and (.raw|test("^0x[0-9A-Fa-f]+$")) and (.validation|type)=="object"' "$temporary/$role-journal.json" >/dev/null
    run_jq -er '.raw' "$temporary/$role-journal.json" > "$temporary/$role-raw.from-journal.txt"; chmod 0600 "$temporary/$role-raw.from-journal.txt"
    run_jq -e '.validation' "$temporary/$role-journal.json" > "$temporary/$role-validation.from-journal.json"; chmod 0600 "$temporary/$role-validation.from-journal.json"
    for pair in "$temporary/$role-raw.from-journal.txt:$raw" "$temporary/$role-validation.from-journal.json:$validation"; do source_file=${pair%%:*}; target_file=${pair#*:}; if [[ -e $target_file ]]; then snapshot "$target_file" "$temporary/existing-$(basename "$target_file")"; run_cmp -s "$source_file" "$temporary/existing-$(basename "$target_file")"; else run_node scripts/install-private-file-new-stdin.mjs "$target_file" < "$source_file"; fi; done
  else
    test ! -e "$raw"; test ! -e "$validation"
  fi
  signed_deployment=false
  if [[ -e $raw ]]; then
    test -f "$raw"; test ! -L "$raw"; test -f "$validation"; test ! -L "$validation"
    snapshot "$raw" "$temporary/$role-raw.txt"; snapshot "$validation" "$temporary/$role-validation.json"
    nonce=$(run_jq -er '.nonce' "$temporary/$role-validation.json")
    export USDOM_SAFE_DEPLOYMENT_RAW="$temporary/$role-raw.txt"
    current_validation="$temporary/$role-validation.current.json"; run_node scripts/check-safe-control-deployment-raw-transaction.mjs "$role" "$nonce" > "$current_validation"
    run_cmp -s "$temporary/$role-validation.json" "$current_validation"
    tx_hash=$(run_jq -er '.transactionHash' "$temporary/$role-validation.json")
    signed_deployment=true
  else
    test ! -e "$validation"; test ! -e "$receipt"
  fi
  target="$temporary/$role-target.json"; run_node scripts/check-safe-control-deployment-target.mjs "$role" > "$target"; strict_json "$target"
  state=$(run_jq -er '.state' "$target")
  [[ $state == vacant || $state == deployed ]]
  if [[ $state == deployed && $signed_deployment == false ]]; then printf 'Safe %s was already finalized permissionlessly with exact configuration.\n' "$role"; continue; fi
  if [[ $state == deployed ]]; then printf 'Safe %s deployment is finalized; revalidating its durable transaction and receipt.\n' "$role"; fi
  if [[ $state == vacant ]]; then
  test "$state" = vacant
  to=$(run_jq -er --arg role "$role" '.controls[]|select(.role==$role)|.to' "$package_snapshot")
  data=$(run_jq -er --arg role "$role" '.controls[]|select(.role==$role)|.data' "$package_snapshot")
  if [[ $signed_deployment == false ]]; then
    test ! -e "$validation"
    nonce=''; estimate=''; base_fee=''
    for index in "${!rpc_urls[@]}"; do
      n=$(rpc nonce "$deployer" --block pending --rpc-url "${rpc_urls[$index]}"); finalized_nonce=$(rpc nonce "$deployer" --block finalized --rpc-url "${rpc_urls[$index]}"); test "$finalized_nonce" = "$n"; e=$(rpc estimate "$to" "$data" --from "$deployer" --value 0 --rpc-url "${rpc_urls[$index]}"); b=$(rpc block finalized --field baseFeePerGas --rpc-url "${rpc_urls[$index]}")
      run_node -e 'const [n,e,b]=process.argv.slice(1);for(const [v,max] of [[n,(1n<<53n)-1n],[e,1000000n],[b,100000000000n]]){if(!/^(0|[1-9][0-9]*)$/.test(v)||BigInt(v)>max)process.exit(1)}' "$n" "$e" "$b"
      if [[ -z $nonce ]]; then nonce=$n; estimate=$e; base_fee=$b; else test "$n" = "$nonce"; test "$e" = "$estimate"; base_fee=$(run_node -e 'const a=BigInt(process.argv[1]),b=BigInt(process.argv[2]);process.stdout.write(String(a>b?a:b))' "$base_fee" "$b"); fi
    done
    gas_limit=$(run_node -e 'const e=BigInt(process.argv[1]),g=e+e/4n+1n;if(g===0n||g>1000000n)process.exit(1);process.stdout.write(String(g))' "$estimate")
    max_fee=$(run_node -e 'let f=BigInt(process.argv[1]);for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(f>100000000000n)process.exit(1);process.stdout.write(String(f))' "$base_fee")
    read -r -p "Digite AUTORIZO ASSINAR SAFE $role NONCE $nonce: " sign; test "$sign" = "AUTORIZO ASSINAR SAFE $role NONCE $nonce"
    assert_inputs; assert_package_rebuild; test "$(run_node scripts/check-safe-control-deployment-target.mjs "$role" | run_jq -r '.state')" = vacant
    raw_candidate="$temporary/$role-raw.candidate"; assert_runtime_tool timeout; assert_runtime_tool cast; "$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" mktx "$to" "$data" --chain 1 --from "$deployer" --nonce "$nonce" --value 0 --gas-limit "$gas_limit" --gas-price "$max_fee" --priority-gas-price 2000000000 --ledger --rpc-url "${rpc_urls[0]}" > "$raw_candidate"; chmod 0600 "$raw_candidate"
    export USDOM_SAFE_DEPLOYMENT_RAW=$raw_candidate; validation_candidate="$temporary/$role-validation.candidate"; run_node scripts/check-safe-control-deployment-raw-transaction.mjs "$role" "$nonce" > "$validation_candidate"; chmod 0600 "$validation_candidate"
    journal_candidate="$temporary/$role-journal.candidate.json"; run_jq -n --arg role "$role" --rawfile raw "$raw_candidate" --slurpfile validation "$validation_candidate" '{schema:"usdom-safe-deployment-journal/v1",role:$role,raw:($raw|rtrimstr("\n")),validation:$validation[0]}' > "$journal_candidate"; chmod 0600 "$journal_candidate"
    run_node scripts/install-private-file-new-stdin.mjs --json "$journal" < "$journal_candidate"
    run_node scripts/install-private-file-new-stdin.mjs "$raw" < "$raw_candidate"; run_node scripts/install-private-file-new-stdin.mjs --json "$validation" < "$validation_candidate"
    snapshot "$raw" "$temporary/$role-raw.txt"; snapshot "$validation" "$temporary/$role-validation.json"; export USDOM_SAFE_DEPLOYMENT_RAW="$temporary/$role-raw.txt"
    tx_hash=$(run_jq -er '.transactionHash' "$temporary/$role-validation.json")
  fi
  seen=false
  for index in "${!rpc_urls[@]}"; do seen_file="$temporary/$role-seen-$index.json"; rpc rpc eth_getTransactionByHash "$tx_hash" --rpc-url "${rpc_urls[$index]}" > "$seen_file"; strict_json "$seen_file"; run_jq -e --arg hash "$tx_hash" '.==null or ((.hash|ascii_downcase)==($hash|ascii_downcase))' "$seen_file" >/dev/null; run_jq -e '.!=null' "$seen_file" >/dev/null && seen=true || true; done
  if [[ $seen == false ]]; then
    read -r -p "Digite AUTORIZO TRANSMITIR SAFE $role NONCE $nonce: " transmit; test "$transmit" = "AUTORIZO TRANSMITIR SAFE $role NONCE $nonce"
    assert_inputs; assert_package_rebuild; test "$(run_node scripts/check-safe-control-deployment-target.mjs "$role" | run_jq -r '.state')" = vacant
    for endpoint in "${rpc_urls[@]}"; do test "$(rpc nonce "$deployer" --block pending --rpc-url "$endpoint")" = "$nonce"; test "$(rpc nonce "$deployer" --block finalized --rpc-url "$endpoint")" = "$nonce"; done
    raw_line=$(<"$temporary/$role-raw.txt"); published=$(rpc publish "$raw_line" --async --rpc-url "${rpc_urls[0]}"); test "${published,,}" = "${tx_hash,,}"
  fi
  deadline=$((SECONDS+1800)); while :; do target_now="$temporary/$role-target-now.json"; run_node scripts/check-safe-control-deployment-target.mjs "$role" > "$target_now"; state=$(run_jq -er '.state' "$target_now"); [[ $state == deployed ]] && break; test "$state" = vacant; test "$SECONDS" -lt "$deadline"; sleep 12; done
  fi
  assert_inputs
  receipt_existing=''
  if [[ -e $receipt ]]; then
    snapshot "$receipt" "$temporary/$role-receipt.existing.json"
    run_node scripts/check-safe-control-deployment-receipt.mjs "$role" "$temporary/$role-receipt.existing.json" "$temporary/$role-validation.json" > "$temporary/$role-receipt.rechecked.json"
    run_cmp -s "$temporary/$role-receipt.existing.json" "$temporary/$role-receipt.rechecked.json"
    receipt_existing="$temporary/$role-receipt.existing.json"
  fi
  receipt_consensus=''
  for index in "${!rpc_urls[@]}"; do
    receipt_raw="$temporary/$role-receipt-$index.raw.json"; receipt_checked="$temporary/$role-receipt-$index.checked.json"
    rpc receipt "$tx_hash" --json --rpc-url "${rpc_urls[$index]}" > "$receipt_raw"; strict_json "$receipt_raw"
    run_node scripts/check-safe-control-deployment-receipt.mjs "$role" "$receipt_raw" "$temporary/$role-validation.json" > "$receipt_checked"
    receipt_block=$(run_jq -er '.blockNumber' "$receipt_checked"); receipt_hash=$(run_jq -er '.blockHash' "$receipt_checked")
    canonical_hash=$(rpc block "$receipt_block" --field hash --rpc-url "${rpc_urls[$index]}"); test "${canonical_hash,,}" = "${receipt_hash,,}"
    finalized_number=$(rpc block finalized --field number --rpc-url "${rpc_urls[$index]}"); (( finalized_number >= receipt_block ))
    if [[ -z $receipt_consensus ]]; then receipt_consensus=$receipt_checked; else run_cmp -s "$receipt_consensus" "$receipt_checked"; fi
    [[ -z $receipt_existing ]] || run_cmp -s "$receipt_existing" "$receipt_checked"
  done
  [[ -n $receipt_existing ]] || run_node scripts/install-private-file-new-stdin.mjs --json "$receipt" < "$receipt_consensus"
done
assert_inputs
assert_package_rebuild
for role in governance reserveGuardian checkpointGuardian; do test "$(run_node scripts/check-safe-control-deployment-target.mjs "$role" | run_jq -r '.state')" = deployed; done
assert_inputs
assert_package_rebuild
printf '%s\n' 'All three recoverable Safes are finalized with the exact package configuration.'
