#!/usr/bin/env bash
set -euo pipefail
# RPC source files can contain reusable provider credentials.  Keep child
# process memory out of tracing, panic backtraces and core artifacts.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
# Do not carry caller-owned evidence, lock or logging descriptors into Ledger
# or validation children. Bash's script descriptor 255 is internal and CLOEXEC.
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
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing RPC operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent sign:recoverable-safe-recovery' >&2
  exit 64
fi

: "${USDOM_SAFE_RECOVERY_PLAN:?USDOM_SAFE_RECOVERY_PLAN is required}"
: "${USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS:?USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS is required}"
: "${USDOM_SAFE_RECOVERY_SIGNATURES:?USDOM_SAFE_RECOVERY_SIGNATURES is required}"
: "${USDOM_SAFE_RECOVERY_TRANSACTIONS:?USDOM_SAFE_RECOVERY_TRANSACTIONS is required}"
: "${USDOM_SAFE_PACKAGE:?USDOM_SAFE_PACKAGE is required}"
: "${USDOM_SAFE_BASELINE:?USDOM_SAFE_BASELINE is required}"
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required}"

for command in cast jq node stat realpath mktemp cmp chmod dirname sha256sum id timeout; do
  command -v "$command" >/dev/null
done
sha256_bin=$(realpath "$(command -v sha256sum)")
test -x "$sha256_bin"; test -f "$sha256_bin"; test ! -L "$sha256_bin"
sha256_owner=$(stat -Lc '%u' "$sha256_bin")
test "$sha256_owner" = 0 || test "$sha256_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$sha256_bin")" = 1
sha256_mode=$(stat -Lc '%a' "$sha256_bin")
(( (8#$sha256_mode & 8#022) == 0 ))
sha256_directory=$(dirname "$sha256_bin")
sha256_directory_owner=$(stat -Lc '%u' "$sha256_directory")
test "$sha256_directory_owner" = 0 || test "$sha256_directory_owner" = "$(id -u)"
sha256_directory_mode=$(stat -Lc '%a' "$sha256_directory")
(( (8#$sha256_directory_mode & 8#022) == 0 ))
sha256_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$sha256_bin")
sha256_file() {
  local digest remainder
  read -r digest remainder < <("$sha256_bin" "$1")
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]]
  printf '%s\n' "$digest"
}
sha256_self=$(sha256_file "$sha256_bin")
assert_sha256_unchanged() {
  test "$(realpath "$(command -v sha256sum)")" = "$sha256_bin"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$sha256_bin")" = "$sha256_identity"
  test "$(sha256_file "$sha256_bin")" = "$sha256_self"
}
cmp_bin=$(realpath "$(command -v cmp)")
test -x "$cmp_bin"; test -f "$cmp_bin"; test ! -L "$cmp_bin"
cmp_owner=$(stat -Lc '%u' "$cmp_bin")
test "$cmp_owner" = 0 || test "$cmp_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$cmp_bin")" = 1
cmp_mode=$(stat -Lc '%a' "$cmp_bin")
(( (8#$cmp_mode & 8#022) == 0 ))
cmp_directory=$(dirname "$cmp_bin")
cmp_directory_owner=$(stat -Lc '%u' "$cmp_directory")
test "$cmp_directory_owner" = 0 || test "$cmp_directory_owner" = "$(id -u)"
cmp_directory_mode=$(stat -Lc '%a' "$cmp_directory")
(( (8#$cmp_directory_mode & 8#022) == 0 ))
cmp_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$cmp_bin")
cmp_sha256=$(sha256_file "$cmp_bin")
assert_cmp_unchanged() {
  assert_sha256_unchanged
  test "$(realpath "$(command -v cmp)")" = "$cmp_bin"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$cmp_bin")" = "$cmp_identity"
  test "$(sha256_file "$cmp_bin")" = "$cmp_sha256"
}
cast_bin=$(realpath "$(command -v cast)")
test -x "$cast_bin"; test -f "$cast_bin"; test ! -L "$cast_bin"
cast_owner=$(stat -Lc '%u' "$cast_bin")
test "$cast_owner" = 0 || test "$cast_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$cast_bin")" = 1
cast_size=$(stat -Lc '%s' "$cast_bin"); (( cast_size > 0 && cast_size <= 512 * 1024 * 1024 ))
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
cast_sha256=$(sha256_file "$cast_bin")
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$cast_bin")" = "$cast_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$cast_directory")" = "$cast_directory_identity"
assert_cast_unchanged() {
  assert_sha256_unchanged
  test "$(realpath "$(command -v cast)")" = "$cast_bin"
  test "$(realpath "$cast_directory")" = "$cast_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$cast_directory")" = "$cast_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$cast_bin")" = "$cast_identity"
  test "$(sha256_file "$cast_bin")" = "$cast_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$cast_bin")" = "$cast_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$cast_directory")" = "$cast_directory_identity"
}
timeout_bin=$(realpath "$(command -v timeout)")
test -x "$timeout_bin"; test -f "$timeout_bin"; test ! -L "$timeout_bin"
timeout_owner=$(stat -Lc '%u' "$timeout_bin")
test "$timeout_owner" = 0 || test "$timeout_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$timeout_bin")" = 1
timeout_size=$(stat -Lc '%s' "$timeout_bin"); (( timeout_size > 0 && timeout_size <= 512 * 1024 * 1024 ))
timeout_mode=$(stat -Lc '%a' "$timeout_bin")
(( (8#$timeout_mode & 8#022) == 0 ))
timeout_directory=$(dirname "$timeout_bin")
test "$(realpath "$timeout_directory")" = "$timeout_directory"
timeout_directory_owner=$(stat -Lc '%u' "$timeout_directory")
test "$timeout_directory_owner" = 0 || test "$timeout_directory_owner" = "$(id -u)"
timeout_directory_mode=$(stat -Lc '%a' "$timeout_directory")
(( (8#$timeout_directory_mode & 8#022) == 0 ))
timeout_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$timeout_directory")
timeout_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$timeout_bin")
timeout_sha256=$(sha256_file "$timeout_bin")
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$timeout_bin")" = "$timeout_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$timeout_directory")" = "$timeout_directory_identity"
assert_timeout_unchanged() {
  assert_sha256_unchanged
  test "$(realpath "$(command -v timeout)")" = "$timeout_bin"
  test "$(realpath "$timeout_directory")" = "$timeout_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$timeout_directory")" = "$timeout_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$timeout_bin")" = "$timeout_identity"
  test "$(sha256_file "$timeout_bin")" = "$timeout_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$timeout_bin")" = "$timeout_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$timeout_directory")" = "$timeout_directory_identity"
}
node_bin=$(realpath "$(command -v node)")
test -x "$node_bin"; test -f "$node_bin"; test ! -L "$node_bin"
node_owner=$(stat -Lc '%u' "$node_bin")
test "$node_owner" = 0 || test "$node_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$node_bin")" = 1
node_size=$(stat -Lc '%s' "$node_bin"); (( node_size > 0 && node_size <= 512 * 1024 * 1024 ))
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
node_sha256=$(sha256_file "$node_bin")
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$node_bin")" = "$node_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
assert_node_unchanged() {
  assert_sha256_unchanged
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
jq_owner=$(stat -Lc '%u' "$jq_bin")
test "$jq_owner" = 0 || test "$jq_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$jq_bin")" = 1
jq_size=$(stat -Lc '%s' "$jq_bin"); (( jq_size > 0 && jq_size <= 512 * 1024 * 1024 ))
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
jq_sha256=$(sha256_file "$jq_bin")
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$jq_bin")" = "$jq_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$jq_directory")" = "$jq_directory_identity"
assert_jq_unchanged() {
  assert_sha256_unchanged
  test "$(realpath "$(command -v jq)")" = "$jq_bin"
  test "$(realpath "$jq_directory")" = "$jq_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$jq_directory")" = "$jq_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$jq_bin")" = "$jq_identity"
  test "$(sha256_file "$jq_bin")" = "$jq_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$jq_bin")" = "$jq_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$jq_directory")" = "$jq_directory_identity"
}
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
plan_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_PLAN")
replacement_proofs_source=$(realpath -ms "$USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS")
package_source=$(realpath -ms "$USDOM_SAFE_PACKAGE")
baseline_source=$(realpath -ms "$USDOM_SAFE_BASELINE")
signatures_output=$(realpath -ms "$USDOM_SAFE_RECOVERY_SIGNATURES")
transactions_output=$(realpath -ms "$USDOM_SAFE_RECOVERY_TRANSACTIONS")
test ! -e "$signatures_output"; test ! -L "$signatures_output"
test ! -e "$transactions_output"; test ! -L "$transactions_output"
output_directory=$(dirname "$signatures_output")
test "$output_directory" = "$(dirname "$transactions_output")"
test -d "$output_directory"
test ! -L "$output_directory"
test "$(stat -c '%u' "$output_directory")" = "$(id -u)"
test "$(stat -c '%a' "$output_directory")" = '700'

temporary=$(mktemp -d -p /dev/shm usdom-safe-recovery-sign.XXXXXXXX)
chmod 0700 "$temporary"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  assert_node_unchanged &&
    "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary" || status=1
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
snapshot_private() {
  "$node_bin" "$project/scripts/read-private-file-stdout.mjs" "$1" > "$2"
  chmod 0600 "$2"
}
plan_snapshot="$temporary/recovery-plan.json"
replacement_proofs_snapshot="$temporary/replacement-proofs.json"
package_snapshot="$temporary/safe-package.json"
baseline_snapshot="$temporary/safe-baseline.json"
snapshot_private "$plan_source" "$plan_snapshot"
snapshot_private "$replacement_proofs_source" "$replacement_proofs_snapshot"
snapshot_private "$package_source" "$package_snapshot"
snapshot_private "$baseline_source" "$baseline_snapshot"
assert_signing_inputs_unchanged() {
  snapshot_private "$plan_source" "$temporary/recovery-plan.current.json"
  snapshot_private "$replacement_proofs_source" "$temporary/replacement-proofs.current.json"
  snapshot_private "$package_source" "$temporary/safe-package.current.json"
  snapshot_private "$baseline_source" "$temporary/safe-baseline.current.json"
  "$cmp_bin" -s "$plan_snapshot" "$temporary/recovery-plan.current.json"
  "$cmp_bin" -s "$replacement_proofs_snapshot" "$temporary/replacement-proofs.current.json"
  "$cmp_bin" -s "$package_snapshot" "$temporary/safe-package.current.json"
  "$cmp_bin" -s "$baseline_snapshot" "$temporary/safe-baseline.current.json"
}
export USDOM_SAFE_RECOVERY_PLAN=$plan_snapshot
export USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS=$replacement_proofs_snapshot
export USDOM_SAFE_PACKAGE=$package_snapshot
export USDOM_SAFE_BASELINE=$baseline_snapshot
test "$("$jq_bin" -r '.schema' "$plan_snapshot")" = 'usdom-safe-recovery-plan/v2'
test "$("$jq_bin" -r '.ethereumChainId' "$plan_snapshot")" = '1'
test "$("$jq_bin" -r '[.roles[].requiredSigners|length] == [2,2,2]' "$plan_snapshot")" = 'true'
test "$("$jq_bin" -r '.roles | length' "$plan_snapshot")" = '3'
"$node_bin" scripts/check-safe-recovery-replacement-proofs.mjs >/dev/null
transitions_snapshot="$temporary/recovery-transitions.json"
"$jq_bin" -e '.transitionsByRole' "$plan_snapshot" > "$transitions_snapshot"
chmod 0600 "$transitions_snapshot"
export USDOM_SAFE_RECOVERY_TRANSITIONS_FILE=$transitions_snapshot

[[ -t 0 && -t 2 ]] || {
  printf '%s\n' 'Safe recovery signing requires an interactive terminal.' >&2
  exit 2
}
read -r -p 'Digite ASSINO RECUPERACAO SAFE SEM TRANSMITIR para continuar: ' authorization
test "$authorization" = 'ASSINO RECUPERACAO SAFE SEM TRANSMITIR'
assert_cast_unchanged
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged

rebuilt_consensus="$temporary/rebuilt-consensus.json"
normalized_plan="$temporary/$(basename "$plan_snapshot").normalized"
"$jq_bin" -S 'del(.finalizedBlockNumber,.finalizedBlockHash,.planningSnapshotHash,.planHash)' \
  "$plan_snapshot" > "$normalized_plan"
reobserve_safe_recovery_network() {
  assert_signing_inputs_unchanged
  "$node_bin" scripts/check-recoverable-safe-recovery-plan.mjs >/dev/null
  "$node_bin" scripts/prepare-recoverable-safe-recovery.mjs > "$rebuilt_consensus"
  normalized_rebuilt="$temporary/$(basename "$rebuilt_consensus").normalized"
  "$jq_bin" -S 'del(.finalizedBlockNumber,.finalizedBlockHash,.planningSnapshotHash,.planHash)' \
    "$rebuilt_consensus" > "$normalized_rebuilt"
  "$cmp_bin" -s "$normalized_plan" "$normalized_rebuilt"
  assert_signing_inputs_unchanged
}
reobserve_safe_recovery_network

signature_draft="$temporary/signatures.json"
transaction_draft="$temporary/transactions.json"
"$jq_bin" -n '{governance:[],reserveGuardian:[],checkpointGuardian:[]}' > "$signature_draft"
chmod 0600 "$signature_draft"

for role in governance reserveGuardian checkpointGuardian; do
  for signer_index in 0 1; do
    expected=$("$jq_bin" -er --arg role "$role" --argjson index "$signer_index" \
      '.roles[]|select(.role==$role)|.requiredSigners[$index]' "$plan_snapshot")
    read -r -p "Conecte somente o dispositivo do signer $expected de $role e pressione Enter: " _
    assert_signing_inputs_unchanged
    assert_cast_unchanged
    assert_node_unchanged
    assert_jq_unchanged
    assert_cmp_unchanged
    assert_timeout_unchanged
    observed=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s \
      "$cast_bin" wallet address --ledger)
    assert_cast_unchanged
    assert_timeout_unchanged
    test "$observed" = "$expected"
    reobserve_safe_recovery_network
    typed_data="$temporary/$role-$signer_index-typed-data.json"
    "$jq_bin" -e --arg role "$role" '.roles[]|select(.role==$role)|.typedData' \
      "$plan_snapshot" > "$typed_data"
    chmod 0600 "$typed_data"
    signature=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s \
      "$cast_bin" wallet sign --data --from-file "$typed_data" --ledger)
    assert_cast_unchanged
    assert_timeout_unchanged
    [[ "$signature" != *$'\r'* && "$signature" != *$'\n'* ]]
    [[ "$signature" =~ ^0x[0-9a-fA-F]{130}$ ]]
    updated="$temporary/signatures-$role-$signer_index.json"
    "$jq_bin" --arg role "$role" --arg signer "$expected" --arg signature "$signature" \
      '.[$role] += [{signer:$signer,signature:$signature}]' "$signature_draft" > "$updated"
    chmod 0600 "$updated"
    signature_draft=$updated
  done
done
exec </dev/null

USDOM_SAFE_RECOVERY_SIGNATURES="$signature_draft" \
  "$node_bin" scripts/assemble-recoverable-safe-recovery.mjs > "$transaction_draft"
chmod 0600 "$transaction_draft"
snapshot_private "$plan_source" "$temporary/recovery-plan.final.json"
snapshot_private "$replacement_proofs_source" "$temporary/replacement-proofs.final.json"
snapshot_private "$package_source" "$temporary/safe-package.final.json"
snapshot_private "$baseline_source" "$temporary/safe-baseline.final.json"
"$cmp_bin" -s "$plan_snapshot" "$temporary/recovery-plan.final.json"
"$cmp_bin" -s "$replacement_proofs_snapshot" "$temporary/replacement-proofs.final.json"
"$cmp_bin" -s "$package_snapshot" "$temporary/safe-package.final.json"
"$cmp_bin" -s "$baseline_snapshot" "$temporary/safe-baseline.final.json"
assert_cast_unchanged
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
assert_signing_inputs_unchanged
"$node_bin" "$project/scripts/install-private-file-new-stdin.mjs" "$signatures_output" < "$signature_draft"
snapshot_private "$signatures_output" "$temporary/signatures.installed.json"
"$cmp_bin" -s "$signature_draft" "$temporary/signatures.installed.json"
assert_signing_inputs_unchanged
assert_cast_unchanged
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
"$node_bin" "$project/scripts/install-private-file-new-stdin.mjs" "$transactions_output" < "$transaction_draft"
snapshot_private "$transactions_output" "$temporary/transactions.installed.json"
"$cmp_bin" -s "$transaction_draft" "$temporary/transactions.installed.json"

"$jq_bin" '{schema,ethereumChainId,planHash,transactionPackageHash,
  transactions:[.transactions[]|{role,to,value,dataHash,safeTxHash,signers}]}' \
  "$transactions_output"
