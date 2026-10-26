#!/usr/bin/env bash
set -euo pipefail

readonly project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
readonly evidence=/home/leonardov/usdom-mainnet-private/control-plane

usage() {
  cat <<'EOF'
usage: scripts/generate-closed-mainnet-phase-command.sh PHASE

PHASE is exactly one of:
  prerequisites
  enroll-safe-owners-secret
  migrate-safe-owners-hardware-secret
  prepare-safe-controls
  execute-safe-controls-deployment-secret
  prepare-safe-recovery-secret
  execute-safe-recovery-secret
  materialize-safe-control-config
  validate-local
  derive-deployment-identity-secret
  prepare-deployment
  execute-pilot-deposit-secret
  execute-pilot-redemption-secret
  checklist
  readiness

The generator prints a complete fail-closed Bash program. It never executes
the program, accesses a network, reads a hardware wallet, signs or broadcasts.
Only phases ending in -secret may create or unlock encrypted key material;
private keys, seeds and passwords must never enter stdout or an environment.
EOF
}

test "$#" -eq 1 || { usage >&2; exit 64; }
phase=$1

common() {
  cat <<EOF
set -euo pipefail
umask 077
export USDOM_PROJECT='$project'
export USDOM_CONTROL_EVIDENCE_DIRECTORY='$evidence'
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/home/leonardov/.foundry/bin:/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd "\$USDOM_PROJECT"
install -d -m 0700 "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"
export ETHEREUM_RPC_URL='https://ethereum-rpc.publicnode.com'
export ETHEREUM_RPC_URL_2='https://rpc.mevblocker.io'
export USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-preflight-rpc-sources.json"
if test ! -e "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"; then
  printf '%s\n' '[{"operatorId":"publicnode","providerId":"publicnode","infrastructureId":"publicnode-declared","url":"https://ethereum-rpc.publicnode.com/","tlsPolicy":"node-default-ca-hostname-expiry-origin-pinned-v1","clockPolicy":"utc-wall-clock-sane-v1","clientPolicy":"ethereum-execution-client-stable-v1"},{"operatorId":"mevblocker","providerId":"mevblocker","infrastructureId":"mevblocker-declared","url":"https://rpc.mevblocker.io/","tlsPolicy":"node-default-ca-hostname-expiry-origin-pinned-v1","clockPolicy":"utc-wall-clock-sane-v1","clientPolicy":"ethereum-execution-client-stable-v1"}]' | node scripts/install-private-file-new-stdin.mjs --json "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"
fi
test "\$(stat -c '%a' "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE")" = 600
export USDOM_SAFE_SOFTWARE_OWNER_IDENTITIES="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-owner-identities-software-v2.json"
export USDOM_SAFE_OWNER_IDENTITIES="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-owner-identities.json"
export USDOM_SAFE_KEYSTORE_DIRECTORY=/home/leonardov/usdom-mainnet-private/safe-keystores
export USDOM_SAFE_KEYSTORE_BACKUP_DIRECTORY=/home/leonardov/usdom-mainnet-backup/safe-keystores
export USDOM_SAFE_PUBLIC_DIRECTORY=/home/leonardov/usdom-mainnet-public
export USDOM_SAFE_PUBLIC_BUNDLE="\$USDOM_SAFE_PUBLIC_DIRECTORY/safe-owner-identities-software-v2.json"
export USDOM_SAFE_HARDWARE_OWNER_IDENTITIES="\$USDOM_SAFE_OWNER_IDENTITIES"
export USDOM_SAFE_HARDWARE_CUSTODY_PROOFS="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-owner-hardware-custody-proofs-v1.json"
export USDOM_SAFE_PACKAGE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-package.json"
export USDOM_SAFE_BASELINE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-baseline-primary.json"
export USDOM_MAINNET_DEPLOYMENT_PACKAGE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-package.json"
export USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-identity-observation.json"
export npm_config_offline=true
export npm_config_audit=false
export npm_config_ignore_scripts=true
export CARGO_NET_OFFLINE=true
export FOUNDRY_OFFLINE=true
EOF
}

case "$phase" in
  prerequisites)
    common
    cat <<'EOF'
node scripts/check-mainnet-toolchain.mjs
test -x /home/leonardov/.svm/0.8.37/solc-0.8.37 || { printf '%s\n' 'missing pre-staged solc 0.8.37; do not let Forge download during a ceremony' >&2; exit 1; }
timeout --version | head -n 1
git status --short
EOF
    ;;
  enroll-safe-owners-secret)
    common
    cat <<'EOF'
readonly cast_bin=/home/leonardov/.foundry/bin/cast
test -x "$cast_bin"; test ! -L "$cast_bin"
node scripts/check-mainnet-toolchain.mjs
install -d -m 0700 "$USDOM_SAFE_KEYSTORE_DIRECTORY" "$USDOM_SAFE_KEYSTORE_BACKUP_DIRECTORY"
install -d -m 0755 "$USDOM_SAFE_PUBLIC_DIRECTORY"
export USDOM_SAFE_OWNER_IDENTITIES="$USDOM_SAFE_SOFTWARE_OWNER_IDENTITIES"
owners_json='{}'
for role in governance reserveGuardian checkpointGuardian; do
  role_owners='[]'
  for slot in primary secondary recovery; do
    name="usdom-$role-$slot"
    keystore="$USDOM_SAFE_KEYSTORE_DIRECTORY/$name"
    backup="$USDOM_SAFE_KEYSTORE_BACKUP_DIRECTORY/$name"
    test ! -L "$keystore"; test ! -L "$backup"
    if test ! -e "$keystore"; then
      test ! -e "$backup"
      printf 'Crie a senha exclusiva de %s no prompt oculto. Nao reutilize senhas.\n' "$name" >&2
      "$cast_bin" wallet new "$USDOM_SAFE_KEYSTORE_DIRECTORY" "$name" --password >/dev/null
    fi
    test -f "$keystore"; test ! -L "$keystore"; chmod 0600 "$keystore"
    test "$(stat -c '%u:%a:%h' "$keystore")" = "$(id -u):600:1"
    owner=$(jq -er 'if (.address|type)=="string" and (.address|test("^(0x)?[0-9A-Fa-f]{40}$")) then (.address|sub("^0x";"")|"0x"+.) else error("invalid keystore address") end' "$keystore")
    [[ $owner =~ ^0x[0-9A-Fa-f]{40}$ ]]
    if test ! -e "$backup"; then
      cp --no-clobber --reflink=never --preserve=mode "$keystore" "$backup"
    fi
    test -f "$backup"; test ! -L "$backup"; chmod 0600 "$backup"
    test "$(stat -c '%u:%a:%h' "$backup")" = "$(id -u):600:1"
    test "$(stat -c '%d:%i' "$keystore")" != "$(stat -c '%d:%i' "$backup")"
    test "$(sha256sum "$keystore" | awk '{print $1}')" = "$(sha256sum "$backup" | awk '{print $1}')"
    role_owners=$(jq -cn --argjson current "$role_owners" --arg owner "$owner" '$current+[$owner]')
  done
  owners_json=$(jq -cn --argjson current "$owners_json" --arg role "$role" \
    --argjson values "$role_owners" '$current+{($role):$values}')
done
candidate=$(mktemp -p "$USDOM_CONTROL_EVIDENCE_DIRECTORY" safe-owner-identities.XXXXXXXX)
trap 'rm -f -- "$candidate"' EXIT
jq -en --argjson owners "$owners_json" '
  ([ $owners[] ]|flatten|map(ascii_downcase)|unique|length)==9
  | if . then {schema:"usdom-safe-owner-identities/v2",ownersByRole:$owners} else error("all nine owners must be globally distinct") end
' > "$candidate"
chmod 0600 "$candidate"
if test -e "$USDOM_SAFE_OWNER_IDENTITIES"; then
  test -f "$USDOM_SAFE_OWNER_IDENTITIES"; test ! -L "$USDOM_SAFE_OWNER_IDENTITIES"
  test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_OWNER_IDENTITIES")" = "$(id -u):600:1"
  cmp -s "$candidate" "$USDOM_SAFE_OWNER_IDENTITIES"
else
  node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_OWNER_IDENTITIES" < "$candidate"
fi
if test -e "$USDOM_SAFE_PUBLIC_BUNDLE"; then
  test -f "$USDOM_SAFE_PUBLIC_BUNDLE"; test ! -L "$USDOM_SAFE_PUBLIC_BUNDLE"
  cmp -s "$candidate" "$USDOM_SAFE_PUBLIC_BUNDLE"
else
  cp --no-clobber --reflink=never "$candidate" "$USDOM_SAFE_PUBLIC_BUNDLE"
fi
chmod 0644 "$USDOM_SAFE_PUBLIC_BUNDLE"
cmp -s "$USDOM_SAFE_OWNER_IDENTITIES" "$USDOM_SAFE_PUBLIC_BUNDLE"
jq -e '.schema=="usdom-safe-owner-identities/v2" and ([.ownersByRole[]|.[]|ascii_downcase]|unique|length)==9' "$USDOM_SAFE_PUBLIC_BUNDLE" >/dev/null
printf '%s\n' 'Public Safe owner bundle:'
cat "$USDOM_SAFE_PUBLIC_BUNDLE"
unset owners_json role_owners owner name keystore backup
EOF
    ;;
  migrate-safe-owners-hardware-secret)
    common
    cat <<'PROGRAM'
readonly cast_bin=/home/leonardov/.foundry/bin/cast
readonly timeout_bin=/usr/bin/timeout
test -x "$cast_bin"; test ! -L "$cast_bin"
test -x "$timeout_bin"; test ! -L "$timeout_bin"
node scripts/check-mainnet-toolchain.mjs
# Recover the only possible interrupted publication state: proofs were installed
# and authenticated first, but the derived public owner identity was not.
if test -e "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES" || test -e "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"; then
  test -f "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"; test ! -L "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"
  test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")" = "$(id -u):600:1"
  recovery_temporary=$(mktemp -d -p /dev/shm usdom-safe-hardware-recovery.XXXXXXXX)
  trap 'rm -rf -- "$recovery_temporary"' EXIT
  chmod 0700 "$recovery_temporary"
  hardware_identity_target=$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES
  if test -e "$hardware_identity_target"; then
    test -f "$hardware_identity_target"; test ! -L "$hardware_identity_target"
    test "$(stat -c '%u:%a:%h' "$hardware_identity_target")" = "$(id -u):600:1"
    identity_candidate=$hardware_identity_target
  else
    identity_candidate="$recovery_temporary/identities.json"
    jq -e '{schema:"usdom-safe-owner-identities/v2",ownersByRole:.ownersByRole}' \
      "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS" > "$identity_candidate"
    chmod 0600 "$identity_candidate"
  fi
  export USDOM_SAFE_OWNER_IDENTITIES=$identity_candidate
  test -f config/mainnet-preflight-rpc-catalog.json || npm run --silent materialize:mainnet-preflight-rpc-catalog
  recovered_package="$recovery_temporary/target-package.json"
  timeout --signal=TERM 120s npm run --silent prepare:recoverable-safe-controls > "$recovered_package"
  chmod 0600 "$recovered_package"
  USDOM_SAFE_PACKAGE="$recovered_package" node scripts/check-safe-owner-hardware-custody-proofs.mjs >/dev/null
  if test ! -e "$hardware_identity_target"; then
    node scripts/install-private-file-new-stdin.mjs --json "$hardware_identity_target" < "$identity_candidate"
  fi
  printf '%s\n' 'Authenticated hardware owner migration was already complete or recovered after an interrupted publication.'
  exit 0
fi
temporary=$(mktemp -d -p /dev/shm usdom-safe-hardware.XXXXXXXX)
trap 'rm -rf -- "$temporary"' EXIT
chmod 0700 "$temporary"
owners_json='{}'
for role in governance reserveGuardian checkpointGuardian; do
  role_owners='[]'
  for slot in primary secondary recovery; do
    read -r -p "Conecte somente o hardware $slot exclusivo de $role e pressione Enter: " _
    owner=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet address --ledger)
    [[ $owner =~ ^0x[0-9A-Fa-f]{40}$ ]]
    test "$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet address --ledger)" = "$owner"
    role_owners=$(jq -cn --argjson current "$role_owners" --arg owner "$owner" '$current+[$owner]')
  done
  owners_json=$(jq -cn --argjson current "$owners_json" --arg role "$role" --argjson values "$role_owners" '$current+{($role):$values}')
done
identities="$temporary/identities.json"
jq -en --argjson owners "$owners_json" '([ $owners[] ]|flatten|map(ascii_downcase)|unique|length)==9 | if . then {schema:"usdom-safe-owner-identities/v2",ownersByRole:$owners} else error("all nine hardware owners must be globally distinct") end' > "$identities"
chmod 0600 "$identities"
export USDOM_SAFE_OWNER_IDENTITIES="$identities"
test "$("$cast_bin" chain-id --rpc-url "$ETHEREUM_RPC_URL")" = 1
test "$("$cast_bin" chain-id --rpc-url "$ETHEREUM_RPC_URL_2")" = 1
test -f config/mainnet-preflight-rpc-catalog.json || npm run --silent materialize:mainnet-preflight-rpc-catalog
target_package="$temporary/target-package.json"
timeout --signal=TERM 120s npm run --silent prepare:recoverable-safe-controls > "$target_package"
package_hash=$(node scripts/hash-safe-control-package.mjs "$target_package")
proofs='[]'
for role in governance reserveGuardian checkpointGuardian; do
  safe=$(jq -er --arg role "$role" '.controls[]|select(.role==$role)|.safe' "$target_package")
  for slot_index in 0 1 2; do
    slot=$(printf '%s\n' primary secondary recovery | sed -n "$((slot_index+1))p")
    owner=$(jq -nr --argjson owners "$owners_json" --arg role "$role" --argjson index "$slot_index" '$owners[$role][$index]')
    typed="$temporary/$role-$slot-typed.json"
    jq -n --arg role "$role" --arg slot "$slot" --arg owner "$owner" --arg safe "$safe" --arg packageHash "$package_hash" '{types:{EIP712Domain:[{name:"name",type:"string"},{name:"version",type:"string"},{name:"chainId",type:"uint256"},{name:"verifyingContract",type:"address"}],SafeOwnerCustodyProof:[{name:"role",type:"string"},{name:"slot",type:"string"},{name:"owner",type:"address"},{name:"packageHash",type:"bytes32"}]},primaryType:"SafeOwnerCustodyProof",domain:{name:"USDOM Safe Owner Custody Proof",version:"1",chainId:1,verifyingContract:$safe},message:{role:$role,slot:$slot,owner:$owner,packageHash:$packageHash}}' > "$typed"
    chmod 0600 "$typed"
    read -r -p "Reconecte somente $slot de $role para a prova offline e pressione Enter: " _
    test "$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet address --ledger)" = "$owner"
    signature=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet sign --data --from-file "$typed" --ledger)
    [[ $signature =~ ^0x[0-9A-Fa-f]{130}$ ]]
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 60s "$cast_bin" wallet verify --address "$owner" --data --from-file "$typed" "$signature" >/dev/null
    proof=$(jq -cn --arg role "$role" --arg slot "$slot" --arg owner "$owner" --arg safe "$safe" --arg signature "$signature" --slurpfile typed "$typed" '{role:$role,slot:$slot,owner:$owner,safe:$safe,typedData:$typed[0],signature:$signature}')
    proofs=$(jq -cn --argjson current "$proofs" --argjson proof "$proof" '$current+[$proof]')
  done
done
proof_bundle="$temporary/proofs.json"
jq -en --arg packageHash "$package_hash" --argjson owners "$owners_json" --argjson proofs "$proofs" '{schema:"usdom-safe-owner-hardware-custody-proofs/v1",ethereumChainId:"1",packageHash:$packageHash,ownersByRole:$owners,proofs:$proofs}' > "$proof_bundle"
chmod 0600 "$proof_bundle"
test "$(jq -r '.proofs|length' "$proof_bundle")" = 9
USDOM_SAFE_PACKAGE="$target_package" USDOM_SAFE_HARDWARE_CUSTODY_PROOFS="$proof_bundle" \
  node scripts/check-safe-owner-hardware-custody-proofs.mjs >/dev/null
# Durable two-step publication: proofs are authenticated first. A crash before
# the identity install is resumed by the recovery branch above without keys.
node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS" < "$proof_bundle"
node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES" < "$identities"
printf '%s\n' 'Nine hardware owner proofs completed; limits remain frozen until Safe deployment/migration finishes.'
cat "$identities"
unset owners_json role_owners owner role slot safe signature proof proofs package_hash
PROGRAM
    ;;
  prepare-safe-controls)
    common
    cat <<'EOF'
test -f "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
test -f "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"
test "$(stat -c '%a' "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES")" = 600
test "$(stat -c '%a' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")" = 600
export USDOM_SAFE_OWNER_IDENTITIES="$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL")" = 1
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL_2")" = 1
test -f config/mainnet-preflight-rpc-catalog.json || npm run --silent materialize:mainnet-preflight-rpc-catalog
candidate=$(mktemp)
trap 'rm -f -- "$candidate"' EXIT
timeout --signal=TERM 120s npm run --silent prepare:recoverable-safe-controls >"$candidate"
test "$(node scripts/hash-safe-control-package.mjs "$candidate")" = \
  "$(jq -er '.packageHash' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")"
USDOM_SAFE_PACKAGE="$candidate" node scripts/check-safe-owner-hardware-custody-proofs.mjs >/dev/null
test "$(jq -r '.schema=="usdom-safe-owner-hardware-custody-proofs/v1" and .ethereumChainId=="1" and (.proofs|length)==9' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")" = true
test "$(jq -cS '.ownersByRole|with_entries(.value |= map(ascii_downcase)|sort)' "$candidate")" = \
  "$(jq -cS '.ownersByRole|with_entries(.value |= map(ascii_downcase)|sort)' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")"
proof_index=0
while test "$proof_index" -lt 9; do
  role_index=$((proof_index/3)); slot_index=$((proof_index%3))
  role=$(printf '%s\n' governance reserveGuardian checkpointGuardian | sed -n "$((role_index+1))p")
  slot=$(printf '%s\n' primary secondary recovery | sed -n "$((slot_index+1))p")
  expected_owner=$(jq -er --arg role "$role" --argjson index "$slot_index" '.ownersByRole[$role][$index]' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")
  expected_safe=$(jq -er --arg role "$role" '.controls[]|select(.role==$role)|.safe' "$candidate")
  jq -e --argjson index "$proof_index" --arg role "$role" --arg slot "$slot" \
    --arg owner "$expected_owner" --arg safe "$expected_safe" --arg packageHash "$(node scripts/hash-safe-control-package.mjs "$candidate")" '
    .proofs[$index] as $p
    | $p.role==$role and $p.slot==$slot
      and (($p.owner|ascii_downcase)==($owner|ascii_downcase))
      and (($p.safe|ascii_downcase)==($safe|ascii_downcase))
      and $p.typedData.primaryType=="SafeOwnerCustodyProof"
      and (($p.typedData|keys)==["domain","message","primaryType","types"])
      and (($p.typedData.types|keys)==["EIP712Domain","SafeOwnerCustodyProof"])
      and ($p.typedData.types.EIP712Domain==[{name:"name",type:"string"},
        {name:"version",type:"string"},{name:"chainId",type:"uint256"},
        {name:"verifyingContract",type:"address"}])
      and ($p.typedData.types.SafeOwnerCustodyProof==[{name:"role",type:"string"},
        {name:"slot",type:"string"},{name:"owner",type:"address"},
        {name:"packageHash",type:"bytes32"}])
      and $p.typedData.domain.name=="USDOM Safe Owner Custody Proof"
      and $p.typedData.domain.version=="1" and $p.typedData.domain.chainId==1
      and (($p.typedData.domain.verifyingContract|ascii_downcase)==($safe|ascii_downcase))
      and $p.typedData.message.role==$role and $p.typedData.message.slot==$slot
      and (($p.typedData.message.owner|ascii_downcase)==($owner|ascii_downcase))
      and $p.typedData.message.packageHash==$packageHash
  ' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS" >/dev/null
  typed="$candidate.typed-$proof_index.json"
  jq -e --argjson index "$proof_index" '.proofs[$index].typedData' \
    "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS" > "$typed"
  owner="$expected_owner"
  signature=$(jq -er --argjson index "$proof_index" '.proofs[$index].signature' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")
  cast wallet verify --address "$owner" --data --from-file "$typed" "$signature" >/dev/null
  proof_index=$((proof_index+1))
done
if test -e "$USDOM_SAFE_PACKAGE"; then
  cmp -s "$candidate" "$USDOM_SAFE_PACKAGE"
else
  node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_PACKAGE" <"$candidate"
fi
jq -e '.schema=="usdom-safe-controls-recoverable/v2" and .ethereumChainId=="1" and .threshold=="2" and (.ownersByRole|[.governance,.reserveGuardian,.checkpointGuardian]|map(length)==[3,3,3]) and (([.ownersByRole[] | .[] | ascii_downcase]|unique|length)==9) and (.controls|length)==3' "$USDOM_SAFE_PACKAGE" >/dev/null
sha256sum "$USDOM_SAFE_PACKAGE"
EOF
    ;;
  execute-safe-controls-deployment-secret)
    common
    cat <<'PROGRAM'
test -f "$USDOM_SAFE_PACKAGE"
test -f "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
test -f "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"
node scripts/check-mainnet-toolchain.mjs
# This executor owns the authorization, Ledger signing, durable raw journal,
# RPC-quorum rechecks, publication and finalized exact-configuration checks.
npm run --silent execute:safe-control-deployment
PROGRAM
    ;;
  prepare-safe-recovery-secret)
    common
    cat <<'PROGRAM'
readonly cast_bin=/home/leonardov/.foundry/bin/cast
readonly timeout_bin=/usr/bin/timeout
test -x "$cast_bin"; test ! -L "$cast_bin"
test -x "$timeout_bin"; test ! -L "$timeout_bin"
node scripts/check-mainnet-toolchain.mjs
test -f "$USDOM_SAFE_PACKAGE"; test -f "$USDOM_SAFE_BASELINE"
test -f "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"; test -f "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"
export USDOM_SAFE_RECOVERY_TRANSITIONS_FILE="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-transitions-v2.json"
export USDOM_SAFE_RECOVERY_PLAN="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-plan-v2.json"
export USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-replacement-proofs-v2.json"
export USDOM_SAFE_RECOVERY_SIGNATURES="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-signatures-v2.json"
export USDOM_SAFE_RECOVERY_TRANSACTIONS="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-transactions-v2.json"
export USDOM_SAFE_RECOVERY_SESSION="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-session-v2.json"
recovery_outputs=("$USDOM_SAFE_RECOVERY_TRANSITIONS_FILE" "$USDOM_SAFE_RECOVERY_PLAN" "$USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS" "$USDOM_SAFE_RECOVERY_SIGNATURES" "$USDOM_SAFE_RECOVERY_TRANSACTIONS")
recovery_state_exists=false
test -e "$USDOM_SAFE_RECOVERY_SESSION" && recovery_state_exists=true
for output in "${recovery_outputs[@]}"; do test -e "$output" && recovery_state_exists=true; done
if "$recovery_state_exists"; then
  test -f "$USDOM_SAFE_RECOVERY_SESSION"; test ! -L "$USDOM_SAFE_RECOVERY_SESSION"
  test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_RECOVERY_SESSION")" = "$(id -u):600:1"
  resume_temporary=$(mktemp -d -p /dev/shm usdom-safe-recovery-resume.XXXXXXXX)
  trap 'rm -rf -- "$resume_temporary"' EXIT
  chmod 0700 "$resume_temporary"
  node scripts/read-private-file-stdout.mjs "$USDOM_SAFE_RECOVERY_SESSION" > "$resume_temporary/session.json"
  jq -e '(.|keys)==["plan","replacementProofs","schema","transitions"] and .schema=="usdom-safe-recovery-session/v2"' "$resume_temporary/session.json" >/dev/null
  jq -e '.transitions' "$resume_temporary/session.json" > "$resume_temporary/transitions.json"
  jq -e '.plan' "$resume_temporary/session.json" > "$resume_temporary/plan.json"
  jq -e '.replacementProofs' "$resume_temporary/session.json" > "$resume_temporary/replacement-proofs.json"
  chmod 0600 "$resume_temporary"/*.json
  install_exact_recovery_input() {
    local source=$1 target=$2
    if test -e "$target"; then
      test -f "$target"; test ! -L "$target"
      test "$(stat -c '%u:%a:%h' "$target")" = "$(id -u):600:1"
      cmp -s "$source" "$target"
    else
      node scripts/install-private-file-new-stdin.mjs --json "$target" < "$source"
    fi
  }
  install_exact_recovery_input "$resume_temporary/transitions.json" "$USDOM_SAFE_RECOVERY_TRANSITIONS_FILE"
  install_exact_recovery_input "$resume_temporary/plan.json" "$USDOM_SAFE_RECOVERY_PLAN"
  install_exact_recovery_input "$resume_temporary/replacement-proofs.json" "$USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS"
  node scripts/check-recoverable-safe-recovery-plan.mjs >/dev/null
  node scripts/check-safe-recovery-replacement-proofs.mjs >/dev/null
  if test -e "$USDOM_SAFE_RECOVERY_TRANSACTIONS"; then
    test -f "$USDOM_SAFE_RECOVERY_SIGNATURES"; test ! -L "$USDOM_SAFE_RECOVERY_SIGNATURES"
    node scripts/check-recoverable-safe-recovery-transactions.mjs >/dev/null
  elif test -e "$USDOM_SAFE_RECOVERY_SIGNATURES"; then
    test -f "$USDOM_SAFE_RECOVERY_SIGNATURES"; test ! -L "$USDOM_SAFE_RECOVERY_SIGNATURES"
    transaction_candidate="$resume_temporary/transactions.json"
    node scripts/assemble-recoverable-safe-recovery.mjs > "$transaction_candidate"
    chmod 0600 "$transaction_candidate"
    node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_RECOVERY_TRANSACTIONS" < "$transaction_candidate"
    node scripts/check-recoverable-safe-recovery-transactions.mjs >/dev/null
  else
    npm run --silent sign:recoverable-safe-recovery
    node scripts/check-recoverable-safe-recovery-transactions.mjs >/dev/null
  fi
  printf '%s\n' 'Authenticated Safe recovery session resumed without discarding durable signatures.'
  exit 0
fi
temporary=$(mktemp -d -p /dev/shm usdom-safe-recovery-plan.XXXXXXXX)
trap 'rm -rf -- "$temporary"' EXIT
chmod 0700 "$temporary"
transitions='{}'; replacements='[]'
for role in governance reserveGuardian checkpointGuardian; do
  lost=$(jq -er --arg role "$role" '.ownersByRole[$role][0]' "$USDOM_SAFE_PACKAGE")
  read -r -p "Conecte o NOVO hardware replacement exclusivo de $role e pressione Enter: " _
  replacement=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet address --ledger)
  [[ $replacement =~ ^0x[0-9A-Fa-f]{40}$ ]]
  test "$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet address --ledger)" = "$replacement"
  test "$(jq -r --arg owner "$replacement" '[.ownersByRole[]|.[]|ascii_downcase] | index($owner|ascii_downcase)==null' "$USDOM_SAFE_PACKAGE")" = true
  test "$(jq -nr --argjson values "$replacements" --arg owner "$replacement" '$values|map(ascii_downcase)|index($owner|ascii_downcase)==null')" = true
  replacements=$(jq -cn --argjson values "$replacements" --arg owner "$replacement" '$values+[$owner]')
  transitions=$(jq -cn --argjson current "$transitions" --arg role "$role" --arg lost "$lost" --arg replacement "$replacement" '$current+{($role):{lostOwner:$lost,replacementOwner:$replacement}}')
done
transition_candidate="$temporary/transitions.json"
jq -en --argjson transitions "$transitions" '$transitions' > "$transition_candidate"
chmod 0600 "$transition_candidate"
plan_candidate="$temporary/plan.json"
export USDOM_SAFE_RECOVERY_TRANSITIONS_FILE="$transition_candidate"
timeout --signal=TERM 120s npm run --silent prepare:recoverable-safe-recovery > "$plan_candidate"
replacement_proofs='[]'
for role in governance reserveGuardian checkpointGuardian; do
  replacement=$(jq -er --arg role "$role" '.transitionsByRole[$role].replacementOwner' "$plan_candidate")
  safe=$(jq -er --arg role "$role" '.roles[]|select(.role==$role)|.safe' "$plan_candidate")
  typed="$temporary/$role-replacement-proof.json"
  jq -n --arg role "$role" --arg owner "$replacement" --arg safe "$safe" \
    --arg planHash "$(jq -er '.planHash' "$plan_candidate")" '{types:{EIP712Domain:[{name:"name",type:"string"},{name:"version",type:"string"},{name:"chainId",type:"uint256"},{name:"verifyingContract",type:"address"}],SafeRecoveryReplacementProof:[{name:"role",type:"string"},{name:"replacementOwner",type:"address"},{name:"planHash",type:"bytes32"}]},primaryType:"SafeRecoveryReplacementProof",domain:{name:"USDOM Safe Recovery Replacement Proof",version:"1",chainId:1,verifyingContract:$safe},message:{role:$role,replacementOwner:$owner,planHash:$planHash}}' > "$typed"
  read -r -p "Reconecte o replacement de $role para provar posse e pressione Enter: " _
  test "$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet address --ledger)" = "$replacement"
  signature=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet sign --data --from-file "$typed" --ledger)
  "$timeout_bin" --foreground --signal=TERM --kill-after=5s 60s "$cast_bin" wallet verify --address "$replacement" --data --from-file "$typed" "$signature" >/dev/null
  proof=$(jq -cn --arg role "$role" --arg owner "$replacement" --arg safe "$safe" \
    --arg signature "$signature" --slurpfile typed "$typed" \
    '{role:$role,replacementOwner:$owner,safe:$safe,typedData:$typed[0],signature:$signature}')
  replacement_proofs=$(jq -cn --argjson values "$replacement_proofs" --argjson proof "$proof" '$values+[$proof]')
done
replacement_proof_candidate="$temporary/replacement-proofs.json"
jq -n --arg planHash "$(jq -er '.planHash' "$plan_candidate")" --argjson proofs "$replacement_proofs" \
  '{schema:"usdom-safe-recovery-replacement-proofs/v2",ethereumChainId:"1",planHash:$planHash,proofs:$proofs}' > "$replacement_proof_candidate"
# Publish only after all three replacement keys prove possession.
session_candidate="$temporary/session.json"
jq -n --slurpfile transitions "$transition_candidate" --slurpfile plan "$plan_candidate" \
  --slurpfile replacementProofs "$replacement_proof_candidate" \
  '{schema:"usdom-safe-recovery-session/v2",transitions:$transitions[0],plan:$plan[0],replacementProofs:$replacementProofs[0]}' > "$session_candidate"
chmod 0600 "$session_candidate"
node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_RECOVERY_SESSION" < "$session_candidate"
export USDOM_SAFE_RECOVERY_TRANSITIONS_FILE="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-transitions-v2.json"
node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_RECOVERY_TRANSITIONS_FILE" < "$transition_candidate"
node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_RECOVERY_PLAN" < "$plan_candidate"
node scripts/install-private-file-new-stdin.mjs --json "$USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS" < "$replacement_proof_candidate"
node scripts/check-safe-recovery-replacement-proofs.mjs >/dev/null
npm run --silent sign:recoverable-safe-recovery
# Signing produces validated calldata only; broadcasting is intentionally absent.
node scripts/check-recoverable-safe-recovery-plan.mjs >/dev/null
node scripts/check-recoverable-safe-recovery-transactions.mjs >/dev/null
jq '{schema,ethereumChainId,planHash,transitionsByRole,roles:[.roles[]|{role,safe,safeTxHash,requiredSigners}]}' "$USDOM_SAFE_RECOVERY_PLAN"
PROGRAM
    ;;
  execute-safe-recovery-secret)
    common
    cat <<'PROGRAM'
test -f "$USDOM_SAFE_PACKAGE"; test -f "$USDOM_SAFE_BASELINE"
export USDOM_SAFE_RECOVERY_PLAN="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-plan-v2.json"
export USDOM_SAFE_RECOVERY_TRANSACTIONS="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-transactions-v2.json"
test -f "$USDOM_SAFE_RECOVERY_PLAN"; test -f "$USDOM_SAFE_RECOVERY_TRANSACTIONS"
node scripts/check-recoverable-safe-recovery-plan.mjs >/dev/null
node scripts/check-recoverable-safe-recovery-transactions.mjs >/dev/null
# The executor has its own explicit mainnet authorization prompt and is the
# only step in this generated phase that signs relayer envelopes or broadcasts.
npm run --silent execute:recoverable-safe-recovery
test -f "$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-finalized-report.json"
test -f "$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-finalized-bundle.json"
PROGRAM
    ;;
  materialize-safe-control-config)
    common
    cat <<'PROGRAM'
test -f "$USDOM_SAFE_PACKAGE"; test -f "$USDOM_SAFE_BASELINE"
export USDOM_SAFE_RECOVERY_REPORT="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-finalized-report.json"
test -f "$USDOM_SAFE_RECOVERY_REPORT"
# This writer validates finalized recovery evidence and creates hash-addressed reports; it does not broadcast.
npm run --silent write:recoverable-safe-release-evidence
npm run --silent materialize:safe-control-release-config
npm run --silent materialize:safe-control-release-metadata
jq '{productionReady,realFundsAuthorized,governance,guardian,checkpointGuardian,governanceOwners,guardianOwners,checkpointGuardianOwners}' config/proof-reserve.unconfigured.json
PROGRAM
    ;;
  validate-local)
    common
    cat <<'EOF'
npm ci --offline --ignore-scripts --audit=false
npm test
forge test -vv
cargo test --locked -p dom-node --features native-usdom-v4-poc native_usdom_config --lib
cargo test --locked -p dom-node --features native-usdom-v4-poc --bin dom-usdom-manifest-check
npm run check:provenance
EOF
    ;;
  derive-deployment-identity-secret)
    common
    cat <<'EOF'
test -s "$USDOM_SAFE_PACKAGE"
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL")" = 1
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL_2")" = 1
npm run --silent materialize:mainnet-deployment-identity
EOF
    ;;
  prepare-deployment)
    common
    cat <<'EOF'
test -s "$USDOM_SAFE_PACKAGE"
test -s "$USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION"
export USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256=$(sha256sum "$USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION" | awk '{print $1}')
candidate=$(mktemp)
trap 'rm -f -- "$candidate"' EXIT
node scripts/prepare-mainnet-deployment.mjs >"$candidate"
if test -e "$USDOM_MAINNET_DEPLOYMENT_PACKAGE"; then
  cmp -s "$candidate" "$USDOM_MAINNET_DEPLOYMENT_PACKAGE"
else
  node scripts/install-private-file-new-stdin.mjs --json "$USDOM_MAINNET_DEPLOYMENT_PACKAGE" <"$candidate"
fi
jq -e '.schema=="usdom-mainnet-deployment-package-v1" and .chainId=="1" and (.transactions|length)==4' "$USDOM_MAINNET_DEPLOYMENT_PACKAGE" >/dev/null
sha256sum "$USDOM_MAINNET_DEPLOYMENT_PACKAGE"
EOF
    ;;
  execute-pilot-deposit-secret)
    common
    cat <<'EOF'
test -s "$USDOM_MAINNET_DEPLOYMENT_PACKAGE"
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
npm run --silent prepare:closed-mainnet-deposit
npm run --silent execute:closed-mainnet-deposit
node scripts/check-closed-mainnet-phase-artifacts.mjs require-deposit-complete >/dev/null
EOF
    ;;
  execute-pilot-redemption-secret)
    common
    cat <<'EOF'
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/closed-mainnet-deposit-execution.json"
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
npm run --silent prepare:closed-mainnet-private-burn
npm run --silent submit:closed-mainnet-private-burn
npm run --silent export:canonical-finalized-burn-source
npm run --silent plan:authenticated-finalized-burn
npm run --silent prove:authenticated-finalized-burn
npm run --silent package:authenticated-finalized-burn-evm-proof
npm run --silent prepare:authenticated-finalized-burn-submission
npm run --silent execute:closed-mainnet-redemption
node scripts/check-closed-mainnet-phase-artifacts.mjs require-pilot-complete >/dev/null
EOF
    ;;
  checklist)
    common
    cat <<'EOF'
node scripts/check-closed-mainnet-phase-artifacts.mjs
EOF
    ;;
  readiness)
    common
    cat <<'EOF'
diagnostic=$(mktemp)
dag=$(mktemp)
trap 'rm -f -- "$diagnostic" "$dag"' EXIT
node scripts/check-closed-mainnet-phase-artifacts.mjs >"$dag"
status=0
node scripts/check-mainnet-readiness.mjs closed-mainnet >"$diagnostic" || status=$?
test "$status" -eq 0 -o "$status" -eq 1
jq -e '.schema and (.ready|type=="boolean") and (.blockerCount|type=="number")' "$diagnostic" >/dev/null
cat "$diagnostic"
EOF
    ;;
  *) usage >&2; exit 64 ;;
esac
