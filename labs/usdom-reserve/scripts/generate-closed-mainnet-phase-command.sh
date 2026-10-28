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
  verify-risc0-trusted-setup
  derive-deployment-identity-secret
  prepare-deployment
  execute-mainnet-deployment-secret
  execute-reserve-resume-secret
  prepare-native-wallet-secret
  authorize-pilot-funds-secret
  execute-pilot-deposit-secret
  submit-pilot-burn-secret
  execute-pilot-redemption-secret
  produce-checkpoint-evidence-secret
  measure-release-capacity
  finalize-native-privacy-ceremony-secret
  open-claims-plan
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
planned=false
case "$phase" in
  prerequisites|enroll-safe-owners-secret|migrate-safe-owners-hardware-secret|prepare-safe-controls|execute-safe-controls-deployment-secret|materialize-safe-control-config|validate-local|verify-risc0-trusted-setup|derive-deployment-identity-secret|prepare-deployment|execute-mainnet-deployment-secret|execute-reserve-resume-secret|measure-release-capacity|prepare-native-wallet-secret|finalize-native-privacy-ceremony-secret|authorize-pilot-funds-secret|execute-pilot-deposit-secret|submit-pilot-burn-secret|produce-checkpoint-evidence-secret|execute-pilot-redemption-secret|prepare-safe-recovery-secret|execute-safe-recovery-secret|readiness)
    planned=true
    ;;
esac

common() {
  cat <<EOF
set +x
unset BASH_XTRACEFD 2>/dev/null || true
set -euo pipefail
set +o history 2>/dev/null || true
umask 077
export LC_ALL=C LANG=C TZ=UTC
IFS=\$' \t\n'
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH NPM_CONFIG_USERCONFIG npm_config_userconfig \
  GIT_CONFIG GIT_CONFIG_COUNT GIT_DIR GIT_WORK_TREE RUSTFLAGS RUSTDOCFLAGS \
  ETH_RPC_URL ETH_KEYSTORE ETH_FROM PYTHONPATH PYTHONHOME PERL5LIB RUBYLIB GEM_HOME BUNDLE_GEMFILE \
  SSH_AUTH_SOCK SSH_AGENT_PID GPG_AGENT_INFO RUST_LOG RUST_BACKTRACE \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy \
  SSLKEYLOGFILE SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS HISTFILE
export HISTFILE=/dev/null
ulimit -c 0 || { printf '%s\n' 'Cannot disable core dumps for a secret-capable phase.' >&2; exit 1; }
for fd_path in /proc/\$\$/fd/*; do
  inherited_fd=\${fd_path##*/}
  [[ \$inherited_fd =~ ^[0-9]+$ ]] || exit 1
  (( inherited_fd <= 2 )) && continue
  [[ \$inherited_fd == 255 ]] && continue
  exec {inherited_fd}>&-
done
unset fd_path inherited_fd
export USDOM_PROJECT='$project'
export USDOM_MAINNET_PRIVATE_ROOT=/home/leonardov/usdom-mainnet-private
export USDOM_CONTROL_EVIDENCE_DIRECTORY='$evidence'
export USDOM_PILOT_PHASE_LOCK_DIRECTORY="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/phase-execution-lock"
export USDOM_CHECKPOINT_REGISTRY_ARTIFACT_PINS="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/checkpoint-registry-artifact-pins.json"
export USDOM_CHECKPOINT_RANDOMX_IMAGE_RATIFICATION="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/checkpoint-randomx-image-ratification.json"
export USDOM_CHECKPOINT_RESTART_WITNESS_REPORT="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/checkpoint-restart-witness-live-exercise.json"
export USDOM_FINALIZED_BURN_RECURSIVE_COMPLETION="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/finalized-burn-recursive-completion.json"
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/home/leonardov/.foundry/bin:/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
hash -r
test "\$(command -v bash)" = /usr/bin/bash
test "\$(command -v node)" = /usr/lib/chatgpt/resources/cua_node/bin/node
test "\$(command -v npm)" = /usr/lib/chatgpt/resources/cua_node/bin/npm
test "\$(command -v jq)" = /usr/bin/jq
test "\$(command -v stat)" = /usr/bin/stat
test "\$(command -v install)" = /usr/bin/install
test "\$(command -v sha256sum)" = /usr/bin/sha256sum
test "\$(command -v git)" = /usr/bin/git
test "\$(command -v forge)" = /home/leonardov/.foundry/bin/forge
test "\$(command -v cargo)" = /home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo
test "\$(command -v python3)" = /usr/bin/python3
cd "\$USDOM_PROJECT"
test -d "\$USDOM_MAINNET_PRIVATE_ROOT"; test ! -L "\$USDOM_MAINNET_PRIVATE_ROOT"
test "\$(realpath -e "\$USDOM_MAINNET_PRIVATE_ROOT")" = "\$USDOM_MAINNET_PRIVATE_ROOT"
exec 7<"\$USDOM_MAINNET_PRIVATE_ROOT"
test "\$(stat -c '%d:%i' "\$USDOM_MAINNET_PRIVATE_ROOT")" = "\$(stat -Lc '%d:%i' /proc/\$\$/fd/7)"
flock -n 7 || { printf '%s\n' 'Phase generation archival or another root operation is active.' >&2; exit 75; }
python3 scripts/ensure-private-directory-path.py "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"
test -d "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"; test ! -L "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"
test "\$(realpath -e "\$USDOM_CONTROL_EVIDENCE_DIRECTORY")" = "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"
test "\$(stat -c '%u:%a' "\$USDOM_CONTROL_EVIDENCE_DIRECTORY")" = "\$(id -u):700"
python3 scripts/ensure-private-directory-path.py "\$USDOM_PILOT_PHASE_LOCK_DIRECTORY"
test -d "\$USDOM_PILOT_PHASE_LOCK_DIRECTORY"; test ! -L "\$USDOM_PILOT_PHASE_LOCK_DIRECTORY"
test "\$(realpath -e "\$USDOM_PILOT_PHASE_LOCK_DIRECTORY")" = "\$USDOM_PILOT_PHASE_LOCK_DIRECTORY"
exec 8<"\$USDOM_PILOT_PHASE_LOCK_DIRECTORY"
test "\$(realpath -e /proc/\$\$/fd/8)" = "\$USDOM_PILOT_PHASE_LOCK_DIRECTORY"
test "\$(stat -Lc '%u:%a' /proc/\$\$/fd/8)" = "\$(id -u):700"
test "\$(stat -c '%d:%i' "\$USDOM_PILOT_PHASE_LOCK_DIRECTORY")" = "\$(stat -Lc '%d:%i' /proc/\$\$/fd/8)"
flock -n 8 || { printf '%s\n' 'Another pilot phase is active.' >&2; exit 75; }
readonly USDOM_PILOT_PHASE_LOCK_DEVICE="\$(stat -Lc '%d' /proc/\$\$/fd/8)"
readonly USDOM_PILOT_PHASE_LOCK_INODE="\$(stat -Lc '%i' /proc/\$\$/fd/8)"
export USDOM_PILOT_PHASE_LOCK_DEVICE USDOM_PILOT_PHASE_LOCK_INODE
export USDOM_PILOT_RPC_SOURCES_FILE=/home/leonardov/.local/state/usdom-onekey-ios-pilot/mainnet-preflight-rpc-sources.json
export USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-preflight-rpc-sources.json"
test -f "\$USDOM_PILOT_RPC_SOURCES_FILE"; test ! -L "\$USDOM_PILOT_RPC_SOURCES_FILE"
test "\$(stat -c '%u:%a:%h' "\$USDOM_PILOT_RPC_SOURCES_FILE")" = "\$(id -u):600:1"
if test ! -e "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"; then
  node scripts/read-private-file-stdout.mjs "\$USDOM_PILOT_RPC_SOURCES_FILE" \
    | node scripts/install-private-file-new-stdin.mjs --json "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"
fi
test -f "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"; test ! -L "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"
test "\$(stat -c '%u:%a:%h' "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE")" = "\$(id -u):600:1"
test "\$(node scripts/read-private-file-stdout.mjs "\$USDOM_PILOT_RPC_SOURCES_FILE" | sha256sum)" = \
  "\$(node scripts/read-private-file-stdout.mjs "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" | sha256sum)"
ETHEREUM_RPC_URL=\$(jq -er '.[0].url' "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE")
ETHEREUM_RPC_URL_2=\$(jq -er '.[1].url' "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE")
export ETHEREUM_RPC_URL ETHEREUM_RPC_URL_2
export USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/checkpoint-runtime-rpc-sources.json"
node scripts/materialize-checkpoint-runtime-rpc-sources.mjs \
  "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "\$USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE"
test -f "\$USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE"; test ! -L "\$USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE"
test "\$(stat -c '%u:%a:%h' "\$USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE")" = "\$(id -u):600:1"
export USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES_FILE="\$USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE"
export USDOM_CHECKPOINT_FINALIZED_RPC_SOURCES_FILE="\$USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE"
export USDOM_SAFE_OWNER_IDENTITIES="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-owner-identities.json"
export USDOM_SAFE_PUBLIC_DIRECTORY=/home/leonardov/usdom-mainnet-public
export USDOM_SAFE_PUBLIC_BUNDLE="\$USDOM_SAFE_PUBLIC_DIRECTORY/safe-owner-identities-v2.json"
export USDOM_PILOT_STATE_DIR=/home/leonardov/.local/state/usdom-onekey-ios-pilot
export USDOM_SAFE_HARDWARE_OWNER_IDENTITIES="\$USDOM_PILOT_STATE_DIR/safe-owner-identities-v2.json"
export USDOM_SAFE_HARDWARE_CUSTODY_PROOFS="\$USDOM_PILOT_STATE_DIR/safe-owner-hardware-custody-proofs-v1.json"
export USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG="\$USDOM_PILOT_STATE_DIR/onekey-ios-walletconnect-client.json"
export USDOM_ONEKEY_IOS_PHYSICAL_EVIDENCE_DIRECTORY="\$USDOM_PILOT_STATE_DIR/onekey-ios-physical-evidence"
export USDOM_SAFE_PACKAGE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-package.json"
export USDOM_SAFE_BASELINE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-baseline-primary.json"
export USDOM_MAINNET_DEPLOYMENT_PACKAGE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-package.json"
export USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-identity-observation.json"
export USDOM_RESERVE_PIN_RATIFICATION_PROPOSAL="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-pin-ratification-proposal.json"
export USDOM_NATIVE_RECEIVING_WALLET_PUBLIC="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/native-receiving-wallet-public.json"
export USDOM_OPERATIONAL_GAS_RUN_CONFIG="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/production-operational-gas-run-config.json"
export USDOM_OPERATIONAL_GAS_RPC_SOURCES="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/production-operational-gas-rpc-sources.json"
export USDOM_OPERATIONAL_GAS_JOB="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/production-operational-gas-job.json"
export USDOM_OPERATIONAL_GAS_EVIDENCE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY/production-operational-gas-evidence.json"
export npm_config_offline=true
export npm_config_audit=false
export npm_config_ignore_scripts=true
export CARGO_NET_OFFLINE=true
export FOUNDRY_OFFLINE=true
EOF
  if "$planned"; then
    cat <<EOF
readonly USDOM_PILOT_PHASE_NAME='$phase'
test "\$(stat -c '%d:%i' "\$USDOM_PILOT_PHASE_LOCK_DIRECTORY")" = "\$USDOM_PILOT_PHASE_LOCK_DEVICE:\$USDOM_PILOT_PHASE_LOCK_INODE"
node scripts/check-closed-mainnet-phase-dependency.mjs begin \
  "\$USDOM_PILOT_PHASE_NAME" "\$0"
phase_body() {
EOF
  fi
}

case "$phase" in
  prerequisites)
    common
    cat <<'EOF'
bash scripts/bootstrap-ubuntu-24.04-dependencies.sh --verify-only
node scripts/check-mainnet-toolchain.mjs
test -x /home/leonardov/.svm/0.8.37/solc-0.8.37 || { printf '%s\n' 'missing pre-staged solc 0.8.37; do not let Forge download during a ceremony' >&2; exit 1; }
timeout --version | head -n 1
git status --short
EOF
    ;;
  enroll-safe-owners-secret)
    common
    cat <<'EOF'
node scripts/check-mainnet-toolchain.mjs
python3 scripts/ensure-private-directory-path.py "$USDOM_SAFE_PUBLIC_DIRECTORY" 0755
test -d "$USDOM_SAFE_PUBLIC_DIRECTORY"; test ! -L "$USDOM_SAFE_PUBLIC_DIRECTORY"
test "$(realpath -e "$USDOM_SAFE_PUBLIC_DIRECTORY")" = "$USDOM_SAFE_PUBLIC_DIRECTORY"
test "$(stat -c '%u:%a' "$USDOM_SAFE_PUBLIC_DIRECTORY")" = "$(id -u):755"
test "$(bash scripts/prepare-onekey-ios-safe-mainnet-pilot.sh --status-onboarding)" = onboarding-complete
test -f "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"; test ! -L "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES")" = "$(id -u):600:1"
jq -e '
  .schema=="usdom-safe-owner-identities/v2"
  and (.ownersByRole|keys|sort)==["checkpointGuardian","governance","reserveGuardian","usdtCustody"]
  and (.ownersByRole.governance|length)==3
  and ([.ownersByRole[]|length]|all(.==3))
  and ([.ownersByRole[]|.[]|ascii_downcase]|unique|length)==3
  and ([.ownersByRole[]|map(ascii_downcase)]|unique|length)==1
' "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES" >/dev/null
for owner_index in 0 1 2; do
  owner_evidence="$USDOM_PILOT_STATE_DIR/owner-$((owner_index+1))-evidence.json"
  test -f "$owner_evidence"; test ! -L "$owner_evidence"
  test "$(stat -c '%u:%a:%h' "$owner_evidence")" = "$(id -u):600:1"
  expected_owner=$(jq -er --argjson index "$owner_index" '.ownersByRole.governance[$index]|ascii_downcase' \
    "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES")
  observed_owner=$(jq -er '.address|ascii_downcase' "$owner_evidence")
  test "$observed_owner" = "$expected_owner"
done
export USDOM_SAFE_OWNER_IDENTITIES="$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
if test -e "$USDOM_SAFE_OWNER_IDENTITIES"; then
  test -f "$USDOM_SAFE_OWNER_IDENTITIES"; test ! -L "$USDOM_SAFE_OWNER_IDENTITIES"
  test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_OWNER_IDENTITIES")" = "$(id -u):600:1"
fi
if test -e "$USDOM_SAFE_PUBLIC_BUNDLE"; then
  test -f "$USDOM_SAFE_PUBLIC_BUNDLE"; test ! -L "$USDOM_SAFE_PUBLIC_BUNDLE"
else
  node scripts/read-private-file-stdout.mjs "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES" \
    | node scripts/install-public-file-create-once-stdin.mjs "$USDOM_SAFE_PUBLIC_BUNDLE"
fi
test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_PUBLIC_BUNDLE")" = "$(id -u):644:1"
private_bundle_sha=$(node scripts/read-private-file-stdout.mjs "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES" | sha256sum | awk '{print $1}')
public_bundle_sha=$(node scripts/read-release-config-file-stdout.mjs "$USDOM_SAFE_PUBLIC_BUNDLE" | sha256sum | awk '{print $1}')
test "$private_bundle_sha" = "$public_bundle_sha"
node scripts/read-release-config-file-stdout.mjs "$USDOM_SAFE_PUBLIC_BUNDLE" \
  | jq -e '.schema=="usdom-safe-owner-identities/v2" and ([.ownersByRole[]|.[]|ascii_downcase]|unique|length)==3 and ([.ownersByRole[]|map(ascii_downcase)]|unique|length)==1' >/dev/null
printf '%s\n' 'Public Safe owner bundle (four separate 2-of-3 Safe roles, backed by three distinct physical owner identities and twelve role/slot custody proofs):'
node scripts/read-release-config-file-stdout.mjs "$USDOM_SAFE_PUBLIC_BUNDLE"
unset owner_index owner_evidence expected_owner observed_owner private_bundle_sha public_bundle_sha
EOF
    ;;
  migrate-safe-owners-hardware-secret)
    common
    cat <<'EOF'
# Owner enrollment is performed by the isolated iPhone WalletConnect EIP-712
# ceremony. This phase only accepts its durable, private, already verified output.
# Account discovery is never inferred from a WalletConnect session.
: "${USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:?WalletConnect config is required}"
: "${USDOM_ONEKEY_IOS_PHYSICAL_EVIDENCE_DIRECTORY:?physical evidence directory is required}"
while test "$(bash scripts/prepare-onekey-ios-safe-mainnet-pilot.sh --status-onboarding)" != onboarding-complete; do
  bash scripts/prepare-onekey-ios-safe-mainnet-pilot.sh --advance-onboarding
done
test -f "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"; test ! -L "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
temporary=$(mktemp -d -p /dev/shm usdom-safe-owner-wc.XXXXXXXX)
test "$(stat -c '%u:%a' "$temporary")" = "$(id -u):700"
temporary_identity=$(stat -c '%u:%d:%i:%a' "$temporary")
cleanup(){ if test "$(stat -c '%u:%d:%i:%a' "$temporary" 2>/dev/null)" = "$temporary_identity"; then rm -rf -- "$temporary"; fi; }
trap cleanup EXIT; trap 'cleanup; exit 129' HUP; trap 'cleanup; exit 130' INT; trap 'cleanup; exit 143' TERM
export USDOM_SAFE_OWNER_IDENTITIES=$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES
temporary_package="$temporary/safe-package.json"
USDOM_SAFE_PACKAGE="$temporary_package" npm run --silent prepare:recoverable-safe-controls >"$temporary_package"
while test "$(USDOM_SAFE_PACKAGE="$temporary_package" bash scripts/prepare-onekey-ios-safe-mainnet-pilot.sh --status-custody)" != custody-proof-bundle-complete; do
  USDOM_SAFE_PACKAGE="$temporary_package" bash scripts/prepare-onekey-ios-safe-mainnet-pilot.sh --advance-custody
done
test -f "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"; test ! -L "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
test -f "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"; test ! -L "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"
test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES")" = "$(id -u):600:1"
test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")" = "$(id -u):600:1"
export USDOM_SAFE_OWNER_IDENTITIES=$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES
# The checker recovers every EIP-712 signature and binds all twelve role/slot
# proofs for the three physical identities reused across the four Safes.
# account evidences to the exact prospective Safe package. It performs no broadcast.
test -f config/mainnet-preflight-rpc-catalog.json || npm run --silent materialize:mainnet-preflight-rpc-catalog
USDOM_SAFE_PACKAGE="$temporary_package" node scripts/check-safe-owner-hardware-custody-proofs.mjs >/dev/null
USDOM_SAFE_PACKAGE="$temporary_package" bash scripts/prepare-onekey-ios-safe-mainnet-pilot.sh --status-custody | grep -Fx 'custody-proof-bundle-complete'
printf '%s\n' 'WalletConnect EIP-712 owner evidence accepted; no transaction or broadcast occurred.'
EOF
    ;;
  prepare-safe-controls)
    common
    cat <<'EOF'
test -f "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
test -f "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"
test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES")" = "$(id -u):600:1"
test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS")" = "$(id -u):600:1"
readonly owner_identity_source=$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES
readonly custody_proofs_source=$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS
temporary=$(mktemp -d -p "$USDOM_CONTROL_EVIDENCE_DIRECTORY" prepare-safe-controls.XXXXXXXX)
test -d "$temporary"; test ! -L "$temporary"
test "$(stat -c '%u:%a' "$temporary")" = "$(id -u):700"
temporary_identity=$(stat -c '%u:%d:%i:%a' "$temporary")
cleanup_temporary(){
  if test "$(stat -c '%u:%d:%i:%a' "$temporary" 2>/dev/null)" = "$temporary_identity"; then
    rm -rf -- "$temporary"
  fi
}
trap cleanup_temporary EXIT
trap 'cleanup_temporary; exit 129' HUP
trap 'cleanup_temporary; exit 130' INT
trap 'cleanup_temporary; exit 143' TERM
identities_snapshot="$temporary/owner-identities.json"
proofs_snapshot="$temporary/custody-proofs.json"
node scripts/read-private-file-stdout.mjs "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES" \
  | node scripts/install-private-file-immutable-stdin.mjs --json "$identities_snapshot"
node scripts/read-private-file-stdout.mjs "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS" \
  | node scripts/install-private-file-immutable-stdin.mjs --json "$proofs_snapshot"
export USDOM_SAFE_OWNER_IDENTITIES="$identities_snapshot"
export USDOM_SAFE_HARDWARE_CUSTODY_PROOFS="$proofs_snapshot"
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL")" = 1
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL_2")" = 1
test -f config/mainnet-preflight-rpc-catalog.json || npm run --silent materialize:mainnet-preflight-rpc-catalog
candidate=$(mktemp -p "$temporary" safe-package.XXXXXXXX)
test -f "$candidate"; test ! -L "$candidate"
test "$(stat -c '%u:%a:%h' "$candidate")" = "$(id -u):600:1"
timeout --signal=TERM 120s npm run --silent prepare:recoverable-safe-controls >"$candidate"
test "$(node scripts/hash-safe-control-package.mjs "$candidate")" = \
  "$(jq -er '.packageHash' "$proofs_snapshot")"
USDOM_SAFE_PACKAGE="$candidate" node scripts/check-safe-owner-hardware-custody-proofs.mjs >/dev/null
test "$(jq -r '.schema=="usdom-safe-owner-hardware-custody-proofs/v1" and .ethereumChainId=="1" and (.proofs|length)==12' "$proofs_snapshot")" = true
candidate_owners=$(jq -ceS '.ownersByRole|with_entries(.value |= (map(ascii_downcase)|sort))' "$candidate")
proof_owners=$(jq -ceS '.ownersByRole|with_entries(.value |= (map(ascii_downcase)|sort))' "$proofs_snapshot")
test "$candidate_owners" = "$proof_owners"
proof_index=0
while test "$proof_index" -lt 12; do
  role_index=$((proof_index/3)); slot_index=$((proof_index%3))
  role=$(printf '%s\n' governance reserveGuardian checkpointGuardian usdtCustody | sed -n "$((role_index+1))p")
  slot=$(printf '%s\n' primary secondary recovery | sed -n "$((slot_index+1))p")
  expected_owner=$(jq -er --arg role "$role" --argjson index "$slot_index" '.ownersByRole[$role][$index]' "$proofs_snapshot")
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
  ' "$proofs_snapshot" >/dev/null
  typed=$(mktemp -p "$temporary" typed-data.XXXXXXXX)
  jq -e --argjson index "$proof_index" '.proofs[$index].typedData' \
    "$proofs_snapshot" > "$typed"
  owner="$expected_owner"
  signature=$(jq -er --argjson index "$proof_index" '.proofs[$index].signature' "$proofs_snapshot")
  cast wallet verify --address "$owner" --data --from-file "$typed" "$signature" >/dev/null
  rm -f -- "$typed"
  proof_index=$((proof_index+1))
done
test "$(node scripts/read-private-file-stdout.mjs "$owner_identity_source" | sha256sum | awk '{print $1}')" = \
  "$(node scripts/read-private-file-stdout.mjs "$identities_snapshot" | sha256sum | awk '{print $1}')"
test "$(node scripts/read-private-file-stdout.mjs "$custody_proofs_source" | sha256sum | awk '{print $1}')" = \
  "$(node scripts/read-private-file-stdout.mjs "$proofs_snapshot" | sha256sum | awk '{print $1}')"
node scripts/read-private-file-stdout.mjs "$candidate" \
  | node scripts/install-private-file-immutable-stdin.mjs --json "$USDOM_SAFE_PACKAGE"
node scripts/read-private-file-stdout.mjs "$USDOM_SAFE_PACKAGE" \
  | jq -e '.schema=="usdom-safe-controls-recoverable/v2" and .ethereumChainId=="1" and .threshold=="2" and (.ownersByRole|[.governance,.reserveGuardian,.checkpointGuardian,.usdtCustody]|map(length)==[3,3,3,3]) and (([.ownersByRole[] | .[] | ascii_downcase]|unique|length)==3) and (.controls|length)==4' >/dev/null
node scripts/read-private-file-stdout.mjs "$USDOM_SAFE_PACKAGE" | sha256sum
unset candidate_owners proof_owners
EOF
    ;;
  execute-safe-controls-deployment-secret)
    common
    cat <<'PROGRAM'
test -f "$USDOM_SAFE_PACKAGE"
test -f "$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"
test -f "$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS"
node scripts/check-mainnet-toolchain.mjs
# This executor owns authorization, external-relayer validation, durable raw journal,
# RPC-quorum rechecks, publication and finalized exact-configuration checks.
node scripts/run-operational-status78-cycle.mjs safe-deployment
test -f "$USDOM_SAFE_BASELINE"
test -f "$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-deployment-finalized-completion.json"
node scripts/materialize-safe-control-deployment-completion.mjs \
  | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-deployment-finalized-completion.json"
PROGRAM
    ;;
  prepare-safe-recovery-secret)
    common
    cat <<'PROGRAM'
: "${USDOM_SAFE_RECOVERY_ROSTER_PLAN:?required}" "${USDOM_SAFE_RECOVERY_ROSTER_PROOFS:?required}"
: "${USDOM_SAFE_RECOVERY_V3_STATE_DIRECTORY:?required}" "${USDOM_ONEKEY_IOS_ONBOARDING_EVIDENCE_DIRECTORY:?required}"
bash scripts/prepare-safe-recovery-roster-v3-step.sh
PROGRAM
    ;;
  execute-safe-recovery-secret)
    common
    cat <<'PROGRAM'
: "${USDOM_SAFE_RECOVERY_ROSTER_PLAN:?required}" "${USDOM_SAFE_RECOVERY_ROSTER_PROOFS:?required}"
: "${USDOM_SAFE_RECOVERY_V3_STATE_DIRECTORY:?required}" "${USDOM_SAFE_RECOVERY_RELAYER_POLICY:?required}"
run_recovery_v3_step() { bash scripts/execute-safe-recovery-roster-v3-step.sh; }
while true; do
  output=$(run_recovery_v3_step)
  printf '%s\n' "$output"
  result=${output##*$'\n'}
  [[ $result == complete ]] && break
done
node scripts/check-safe-recovery-roster-v3-completion.mjs
PROGRAM
    ;;
  materialize-safe-control-config)
    common
    cat <<'PROGRAM'
: "${USDOM_SAFE_RECOVERY_ROSTER_PLAN:?required}" "${USDOM_SAFE_RECOVERY_ROSTER_PROOFS:?required}"
: "${USDOM_SAFE_RECOVERY_V3_STATE_DIRECTORY:?required}"
test -f "$USDOM_SAFE_PACKAGE"; test -f "$USDOM_SAFE_BASELINE"
test -f "$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-deployment-finalized-completion.json"
node scripts/materialize-safe-control-deployment-completion.mjs \
  | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-deployment-finalized-completion.json"
# This v3 writer validates three replacement proofs and twelve finalized steps;
# it creates hash-addressed reports and never broadcasts.
node scripts/check-safe-recovery-roster-v3-completion.mjs >/dev/null
npm run --silent write:recoverable-safe-release-evidence
npm run --silent materialize:safe-control-release-config
npm run --silent materialize:safe-control-release-metadata
jq '{productionReady,realFundsAuthorized,governance,guardian,checkpointGuardian,governanceOwners,guardianOwners,checkpointGuardianOwners}' config/proof-reserve.unconfigured.json
PROGRAM
    ;;
  validate-local)
    common
    cat <<'EOF'
node scripts/check-mainnet-toolchain.mjs
npm run --silent check:closed-mainnet-parameter-policy
npm ci --offline --ignore-scripts --audit=false
npm test
npm run --silent test:solidity
cargo test --locked --offline -j1 -p dom-usdom-state -p dom-usdom-privacy -p dom-usdom-wallet -p dom-usdom-rpc-protocol -p dom-usdom-checkpoint-statement -p dom-usdom-checkpoint-program -p dom-usdom-checkpoint-proof-host -p dom-usdom-economic-block-program -p dom-usdom-economic-proof-host -p dom-usdom-finalized-burn-program -p dom-usdom-finalized-burn-proof-host -p dom-usdom-randomx-portable -p dom-usdom-randomx-proof-host
cargo test --locked --offline -j1 -p dom-node --features native-usdom-v4-poc native_usdom_config --lib
cargo test --locked --offline -j1 -p dom-node --features native-usdom-v4-poc --bin dom-usdom-manifest-check
cargo test --locked --offline -j1 -p dom-usdom-checkpoint-program --features host-reference reference::tests::short_390_v6_target_binding_rejects_span_total_and_closure_drift -- --exact
npm run --silent check:provenance
EOF
    ;;
  verify-risc0-trusted-setup)
    common
    cat <<'EOF'
# Build the fixed toolchain image once when absent. Dependency acquisition is
# lockfile-bound; the image build and every cryptographic verification are offline.
if ! /usr/bin/podman image exists localhost/usdom-snarkjs:0.7.6; then
  npm run --silent build:risc0-snarkjs-image
fi
# The three public ceremony artifacts must already exist in the fixed private layout.
readonly setup_environment=/home/leonardov/usdom-mainnet-private/trusted-setup/verification-environment.json
if test ! -e "$setup_environment"; then
  npm run --silent prepare:risc0-trusted-setup-environment \
    | node scripts/install-private-file-immutable-stdin.mjs --json "$setup_environment"
fi
test -f "$setup_environment"; test ! -L "$setup_environment"
test "$(stat -c '%u:%a:%h' "$setup_environment")" = "$(id -u):600:1"
node scripts/prepare-risc0-trusted-setup-verification-report.mjs --print-podman-plan >/dev/null
npm run --silent execute:risc0-trusted-setup-verification
npm run --silent write:risc0-trusted-setup-verification
node scripts/prepare-risc0-trusted-setup-verification-report.mjs \
  | cmp -s - evidence/trusted-setup/risc0-groth16-ceremony-verification.json
jq -e '.trustedSetup.required==true and .checkpointTrustedSetup.required==true
  and .trustedSetup.transcript==.checkpointTrustedSetup.transcript' \
  config/mainnet-release-evidence.unconfigured.json >/dev/null
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
# Resume the monotonic source/config/runtime pipeline from its last complete
# artifact state. Every resumed boundary rederives source and artifact bindings.
artifact_stage=$(jq -er '
  [.reserveRuntimeCodeHash,.reserveInitcodeHash] as $reserve |
  [.checkpointRegistryRuntimeCodeHash,.checkpointRegistryInitcodeHash] as $registry |
  if (($reserve|all(.==null)) and ($registry|all(.==null))) then "bootstrap"
  elif (($reserve|all(.==null)) and ($registry|all(.!=null))) then "registry"
  elif (($reserve|all(.!=null)) and ($registry|all(.!=null))) then "final"
  else error("partial artifact stage") end' config/proof-reserve.unconfigured.json)
if test "$artifact_stage" = bootstrap; then
  npm run --silent materialize:production-release-core -- registry-pins
  npm run --silent materialize:production-solidity-pins -- checkpointRegistry
  forge build --offline contracts/DOMCheckpointRegistry.sol
  npm run --silent materialize:production-release-core -- reserve-pins
fi
if test "$artifact_stage" != final; then
  node scripts/check-production-release-staged-state.mjs registry
  test -s "$USDOM_RESERVE_PIN_RATIFICATION_PROPOSAL"
  npm run --silent materialize:production-solidity-pins -- reserve \
    "$USDOM_RESERVE_PIN_RATIFICATION_PROPOSAL"
  forge build --offline contracts/USDOMProofReserve.sol
  npm run --silent materialize:production-release-core -- final
fi
node scripts/check-production-release-staged-state.mjs final
node scripts/prepare-production-release-core-materialization.mjs final \
  | cmp -s - config/proof-reserve.unconfigured.json
test -s "$USDOM_SAFE_PACKAGE"
test -s "$USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION"
USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256=$(node scripts/read-private-file-stdout.mjs "$USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION" | sha256sum | awk '{print $1}')
export USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256
candidate=$(mktemp -p /dev/shm usdom-mainnet-deployment-package.XXXXXXXX)
rechecked=$(mktemp -p /dev/shm usdom-mainnet-deployment-rechecked.XXXXXXXX)
release_snapshot=$(mktemp -p /dev/shm usdom-mainnet-release-snapshot.XXXXXXXX)
installed=$(mktemp -p /dev/shm usdom-mainnet-deployment-installed.XXXXXXXX)
candidate_identity=$(stat -c '%u:%d:%i' "$candidate")
rechecked_identity=$(stat -c '%u:%d:%i' "$rechecked")
release_snapshot_identity=$(stat -c '%u:%d:%i' "$release_snapshot")
installed_identity=$(stat -c '%u:%d:%i' "$installed")
cleanup(){
  if test "$(stat -c '%u:%d:%i' "$candidate" 2>/dev/null)" = "$candidate_identity"; then rm -f -- "$candidate"; fi
  if test "$(stat -c '%u:%d:%i' "$rechecked" 2>/dev/null)" = "$rechecked_identity"; then rm -f -- "$rechecked"; fi
  if test "$(stat -c '%u:%d:%i' "$release_snapshot" 2>/dev/null)" = "$release_snapshot_identity"; then rm -f -- "$release_snapshot"; fi
  if test "$(stat -c '%u:%d:%i' "$installed" 2>/dev/null)" = "$installed_identity"; then rm -f -- "$installed"; fi
}
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
node scripts/prepare-mainnet-deployment.mjs >"$candidate"
# Rebuild from every live source immediately before immutable publication.
# Publishing after only one build could poison the create-once destination
# with a stale generation that a later terminal check merely detects.
node scripts/prepare-mainnet-deployment.mjs >"$rechecked"
cmp -s "$candidate" "$rechecked"
node scripts/read-release-config-file-stdout.mjs \
  "$USDOM_PROJECT/config/proof-reserve.unconfigured.json" >"$release_snapshot"
test "$(jq -er '.releaseConfigSha256' "$rechecked")" = \
  "$(sha256sum "$release_snapshot" | awk '{print $1}')"
node scripts/install-private-file-immutable-stdin.mjs --json "$USDOM_MAINNET_DEPLOYMENT_PACKAGE" <"$candidate"
node scripts/read-private-file-stdout.mjs "$USDOM_MAINNET_DEPLOYMENT_PACKAGE" >"$installed"
cmp -s "$candidate" "$installed"
node scripts/read-release-config-file-stdout.mjs \
  "$USDOM_PROJECT/config/proof-reserve.unconfigured.json" | cmp -s "$release_snapshot" -
jq -e '.schema=="usdom-mainnet-deployment-package-v1" and .chainId=="1" and (.transactions|length)==4' "$installed" >/dev/null
sha256sum "$installed"
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
EOF
    ;;
  execute-mainnet-deployment-secret)
    common
    cat <<'EOF'
test -s "$USDOM_MAINNET_DEPLOYMENT_PACKAGE"
test -s "$USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION"
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
# Each indexed executor requires an externally installed gas-only raw and broadcast
# authorization and refuses to skip or reorder an earlier CREATE nonce.
for index in 0 1; do
  node scripts/run-operational-status78-cycle.mjs contract-deployment "$index"
done
# Predeployment observes the two finalized proof adapters before the registry
# and reserve constructors are authorized.
npm run --silent materialize:mainnet-predeployment-attestation
npm run --silent check:mainnet-predeploy
for index in 2 3; do
  node scripts/run-operational-status78-cycle.mjs contract-deployment "$index"
done
completion="$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
candidate=$(mktemp -p /dev/shm usdom-mainnet-deployment-completion.XXXXXXXX)
candidate_identity=$(stat -c '%u:%d:%i' "$candidate")
cleanup(){ if test "$(stat -c '%u:%d:%i' "$candidate" 2>/dev/null)" = "$candidate_identity"; then rm -f -- "$candidate"; fi; }
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
node scripts/materialize-mainnet-deployment-completion.mjs > "$candidate"
chmod 0600 "$candidate"
if test -e "$completion"; then
  node scripts/read-private-file-stdout.mjs "$completion" | cmp -s "$candidate" -
else
  node scripts/install-private-file-new-stdin.mjs --json "$completion" < "$candidate"
fi
node scripts/materialize-mainnet-deployment-completion.mjs | cmp -s "$completion" -
# Postdeployment preflight independently observes runtime/configuration/token and
# Safe authorities only after the four-stage completion is durable.
npm run --silent materialize:mainnet-cold-start-attestation
npm run --silent check:mainnet-cold-start
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
EOF
    ;;
  execute-reserve-resume-secret)
    common
    cat <<'EOF'
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
node scripts/materialize-mainnet-deployment-completion.mjs \
  | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-cold-start-attestation.json"
npm run --silent check:mainnet-cold-start
# The executor performs one 2-of-3 governance Safe schedule ceremony,
# journals signed raw transactions before broadcast, observes two finalized
# RPC sources and enforces the on-chain governanceDelay between calls.
# Its authorization review displays chainId=1, valueWei=0, gasLimit= and
# maximumGasCostWei= before the irreversible schedule transaction.
node scripts/run-operational-status78-cycle.mjs reserve-resume
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-finalized-completion.json"
USDOM_GOVERNANCE_DELAY_SECONDS=$(jq -er '.governanceDelaySeconds' config/proof-reserve.unconfigured.json)
export USDOM_GOVERNANCE_DELAY_SECONDS
node scripts/materialize-reserve-resume-completion.mjs \
  | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-finalized-completion.json"
EOF
    ;;
  prepare-native-wallet-secret)
    common
    cat <<'EOF'
candidate=$(mktemp -p /dev/shm usdom-native-wallet-public.XXXXXXXX)
installed=$(mktemp -p /dev/shm usdom-native-wallet-installed.XXXXXXXX)
candidate_identity=$(stat -c '%u:%d:%i' "$candidate")
installed_identity=$(stat -c '%u:%d:%i' "$installed")
cleanup(){
  if test "$(stat -c '%u:%d:%i' "$candidate" 2>/dev/null)" = "$candidate_identity"; then rm -f -- "$candidate"; fi
  if test "$(stat -c '%u:%d:%i' "$installed" 2>/dev/null)" = "$installed_identity"; then rm -f -- "$installed"; fi
}
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
npm run --silent prepare:native-receiving-wallet > "$candidate"
node scripts/install-private-file-immutable-stdin.mjs "$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC" < "$candidate"
node scripts/read-private-file-stdout.mjs "$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC" > "$installed"
cmp -s "$candidate" "$installed"
jq -e '
  (keys|sort)==(["chainScalar","domDomain","privacyPolicyHash","receivingCommitment","recipientAddress","schema"]|sort)
  and
  .schema == "usdom-native-receiving-wallet-public-v1"
  and (.domDomain | test("^0x[0-9a-f]{64}$"))
  and (.privacyPolicyHash | test("^0x[0-9a-f]{64}$"))
  and (.chainScalar | test("^0x[0-9a-f]{64}$"))
  and (.receivingCommitment | test("^0x[0-9a-f]{64}$"))
  and (.recipientAddress | test("^[0-9a-f]{208}$"))
' "$installed"
EOF
    ;;
  authorize-pilot-funds-secret)
    common
    cat <<'EOF'
readonly authorization_dir="$USDOM_PROJECT/evidence/authorization"
readonly pilot_snapshot="$authorization_dir/pilot-funds-snapshot.json"
readonly pilot_request="$authorization_dir/pilot-funds-authorization-request.json"
readonly safe_bundle="$USDOM_PROJECT/evidence/control-plane/safe-control-release-evidence-bundle.json"
readonly privacy_installation=/home/leonardov/.local/share/dom-usdom/mainnet-privacy/installation.json
checkpoint_report=$(jq -er '.checkpointProofCapacityReport.path' config/mainnet-release-evidence.unconfigured.json)
burn_report=$(jq -er '.realFinalizedEndToEndReport.path' config/mainnet-release-evidence.unconfigured.json)
test -f "$checkpoint_report"; test -f "$burn_report"
test -f "$USDOM_SAFE_BASELINE"; test ! -L "$USDOM_SAFE_BASELINE"
test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_BASELINE")" = "$(id -u):600:1"
funder=$(node scripts/read-private-file-stdout.mjs "$USDOM_SAFE_BASELINE" \
  | jq -er '.roles|map(select(.role=="usdtCustody"))|if length==1 then .[0].address else error("exactly one finalized USDT custody Safe is required") end')
if test -e "$pilot_snapshot"; then
  test -f "$pilot_snapshot" && test ! -L "$pilot_snapshot" && test "$(stat -c '%u:%a:%h' "$pilot_snapshot")" = "$UID:600:1"
  test "$(jq -er '.funder|ascii_downcase' "$pilot_snapshot")" = "${funder,,}"
  salt=$(jq -er .salt "$pilot_snapshot")
else salt=$(node scripts/generate-pilot-deposit-salt.mjs); fi
receiving_commitment=$(jq -er '.receivingCommitment' "$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC")
[[ "$funder" =~ ^0x[0-9a-fA-F]{40}$ && "$salt" =~ ^0x[0-9a-fA-F]{64}$ && "$receiving_commitment" =~ ^0x[0-9a-fA-F]{64}$ ]]
private_tuple=$(mktemp -p /dev/shm usdom-pilot-private-tuple.XXXXXXXX)
private_tuple_identity=$(stat -c '%u:%d:%i' "$private_tuple")
cleanup_private_tuple(){
  if test "$(stat -c '%u:%d:%i' "$private_tuple" 2>/dev/null)" = "$private_tuple_identity"; then rm -f -- "$private_tuple"; fi
}
trap cleanup_private_tuple EXIT
trap 'cleanup_private_tuple; exit 129' HUP
trap 'cleanup_private_tuple; exit 130' INT
trap 'cleanup_private_tuple; exit 143' TERM
printf '{"funder":"%s","salt":"%s","receivingCommitment":"%s"}\n' "$funder" "$salt" "$receiving_commitment" > "$private_tuple"
chmod 0600 "$private_tuple"
release_validation_report=$(jq -er '.releaseValidationReport.path' config/mainnet-release-evidence.unconfigured.json)
test -f "$release_validation_report"
pilot_snapshot_candidate=$(node scripts/prepare-pilot-funds-snapshot.mjs "$USDOM_MAINNET_DEPLOYMENT_PACKAGE" \
  "$safe_bundle" "$privacy_installation" "$checkpoint_report" "$burn_report" "$private_tuple" \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/.phase-generation.json" \
  "$release_validation_report")
if test -e "$pilot_snapshot"; then printf '%s\n' "$pilot_snapshot_candidate" | cmp -s - "$pilot_snapshot"; else printf '%s\n' "$pilot_snapshot_candidate" | node scripts/install-private-file-immutable-stdin.mjs --json "$pilot_snapshot"; fi
if test -e "$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-cancel-finalized.json"; then
  node scripts/run-operational-status78-cycle.mjs pilot-gate-cancel
elif test -e "$authorization_dir/pilot-funds-authorization-state.json" && test -e "$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-finalized.json"; then
  node scripts/run-operational-status78-cycle.mjs pilot-gate-clear
fi
node scripts/rotate-expired-pilot-funds-authorization.mjs
node scripts/prepare-pilot-funds-authorization-request.mjs \
  | node scripts/install-private-file-immutable-stdin.mjs --json "$pilot_request"
npm run --silent sign:pilot-funds-authorization
npm run --silent materialize:pilot-funds-authorization
node scripts/run-operational-status78-cycle.mjs pilot-gate
node scripts/check-pilot-funds-authorization-live.mjs >/dev/null
bash scripts/reject-legacy-eoa-mainnet-deposit.sh
EOF
    ;;
  execute-pilot-deposit-secret)
    common
    cat <<'EOF'
node scripts/run-operational-status78-cycle.mjs pilot-gate
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-finalized.json"
node scripts/check-pilot-funds-authorization-live.mjs >/dev/null
test -s "$USDOM_MAINNET_DEPLOYMENT_PACKAGE"
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
node scripts/materialize-mainnet-deployment-completion.mjs \
  | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-finalized-completion.json"
USDOM_GOVERNANCE_DELAY_SECONDS=$(jq -er '.governanceDelaySeconds' config/proof-reserve.unconfigured.json)
export USDOM_GOVERNANCE_DELAY_SECONDS
node scripts/materialize-reserve-resume-completion.mjs \
  | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-finalized-completion.json"
test -s "$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC"
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
: "${USDOM_SAFE_FINALIZED_BASELINE:?required}" "${USDOM_RELEASE_CONFIG_PRIVATE:?required}" "${USDOM_SAFE_DEPOSIT_AUTHORITY:?required}"
readonly pilot_state=${USDOM_PILOT_STATE_DIR:-$HOME/.local/state/usdom-onekey-ios-pilot}
readonly relayer_state=${USDOM_RELAYER_STATE_DIR:-$HOME/.local/share/dom-usdom/mainnet-relayers}
readonly custody_public="$USDOM_SAFE_DEPOSIT_AUTHORITY.public.json"
node scripts/materialize-onekey-ios-safe-usdt-custody-authority.mjs \
  "$USDOM_SAFE_FINALIZED_BASELINE" \
  "$pilot_state/safe-owner-hardware-custody-proofs-v1.json" \
  "$pilot_state/safe-owner-identities-v2.json" \
  "$USDOM_RELEASE_CONFIG_PRIVATE" \
  "$USDOM_PROJECT/evidence/authorization/pilot-funds-snapshot.json" \
  "$pilot_state/mainnet-preflight-rpc-sources.json" \
  "$relayer_state/deployment/relayer-public-identity.json" \
  "$relayer_state/safe-deployment/relayer-public-identity.json" \
  "$relayer_state/recovery/relayer-public-identity.json" \
  "$relayer_state/reserve-resume/relayer-public-identity.json" \
  "$relayer_state/pilot-gate/relayer-public-identity.json" \
  "$USDOM_SAFE_DEPOSIT_AUTHORITY" "$custody_public"
test "$(stat -c '%u:%a:%h' "$USDOM_SAFE_DEPOSIT_AUTHORITY")" = "$UID:600:1"
test "$(stat -c '%u:%a:%h' "$custody_public")" = "$UID:644:1"
npm run --silent prepare:closed-mainnet-deposit
node scripts/run-operational-status78-cycle.mjs deposit
node scripts/check-closed-mainnet-phase-artifacts.mjs require-deposit-complete >/dev/null
# The loopback DOM Mainnet node must already be running through
# `npm run --silent run:closed-mainnet-node` in its dedicated operator terminal.
npm run --silent collect:finalized-deposit-source
npm run --silent build:finalized-deposit-witness
npm run --silent initialize:closed-mainnet-genesis
npm run --silent provision:closed-mainnet-tpm-keystore
npm run --silent register:finalized-deposit-wallet
npm run --silent submit:finalized-deposit-issuance
npm run --silent mine:closed-mainnet-issuance-block
npm run --silent observe:finalized-deposit-wallet
npm run --silent check:native-finalized-deposit-vector
node scripts/check-closed-mainnet-phase-artifacts.mjs require-deposit-complete >/dev/null
EOF
    ;;
  submit-pilot-burn-secret)
    common
    cat <<'EOF'
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/closed-mainnet-deposit-execution.json"
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
npm run --silent check:native-finalized-deposit-vector >/dev/null
npm run --silent prepare:closed-mainnet-private-burn
npm run --silent submit:closed-mainnet-private-burn
npm run --silent mine:closed-mainnet-burn-block
node scripts/materialize-closed-mainnet-burn-checkpoint-input.mjs
EOF
    ;;
  execute-pilot-redemption-secret)
    common
    cat <<'EOF'
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/closed-mainnet-deposit-execution.json"
test -s "$HOME/.local/share/dom-usdom/mainnet-wallet/private-burn-block-production-v1.json"
test -s evidence/finalized-burn-source/finalized-burn-source-index.json
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
npm run --silent check:native-finalized-deposit-vector >/dev/null
npm run --silent plan:authenticated-finalized-burn
npm run --silent prove:authenticated-finalized-burn
npm run --silent package:authenticated-finalized-burn-evm-proof
npm run --silent prepare:authenticated-finalized-burn-submission
npm run --silent materialize:finalized-burn-recursive-completion
node scripts/check-finalized-burn-evidence-phase-coverage.mjs
node scripts/run-operational-status78-cycle.mjs redemption
node scripts/check-closed-mainnet-phase-artifacts.mjs require-pilot-complete >/dev/null
EOF
    ;;
  produce-checkpoint-evidence-secret)
    common
    cat <<'EOF'
USDOM_CLOSED_MAINNET_BUILD_ONLY=YES npm run --silent run:closed-mainnet-node
node scripts/manage-closed-mainnet-node.mjs prepare
node scripts/manage-closed-mainnet-node.mjs start
trap 'node scripts/manage-closed-mainnet-node.mjs stop' EXIT
trap 'node scripts/manage-closed-mainnet-node.mjs stop; exit 129' HUP
trap 'node scripts/manage-closed-mainnet-node.mjs stop; exit 130' INT
trap 'node scripts/manage-closed-mainnet-node.mjs stop; exit 143' TERM
node scripts/manage-closed-mainnet-node.mjs readiness
node scripts/manage-closed-mainnet-node.mjs restart
node scripts/manage-closed-mainnet-node.mjs readiness
node scripts/manage-closed-mainnet-node.mjs verify-restart
readonly USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH=${USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH-}
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
test -s "$HOME/.local/share/dom-usdom/mainnet-wallet/private-burn-block-production-v1.json"
node scripts/materialize-closed-mainnet-burn-checkpoint-input.mjs >/dev/null
node scripts/materialize-mainnet-deployment-completion.mjs \
  | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
# These authenticated writers/provers are resumable and retain claims false
# until their receipts, observations and release evidence all validate.
npm run --silent materialize:checkpoint-registry-artifact-pins
npm run --silent check:checkpoint-registry-artifact-pins
npm run --silent export:canonical-checkpoint-source-set
npm run --silent plan:authenticated-randomx-receipt-set
npm run --silent prove:authenticated-randomx-receipt-set
npm run --silent materialize:checkpoint-randomx-image-ratification
npm run --silent plan:authenticated-economic-receipt-set
npm run --silent prove:authenticated-economic-receipt-set
npm run --silent plan:authenticated-checkpoint-segment-set
npm run --silent prove:authenticated-checkpoint-segment-set
npm run --silent plan:authenticated-checkpoint-outer
npm run --silent prove:authenticated-checkpoint-outer
npm run --silent package:authenticated-checkpoint-outer-evm-proof
npm run --silent prepare:authenticated-checkpoint-submission
npm run --silent observe:authenticated-checkpoint
USDOM_RUN_CHECKPOINT_RESTART_WITNESS=YES npm run --silent exercise:checkpoint-restart-witness
npm run --silent check:checkpoint-restart-witness
test -s config/checkpoint-bootstrap-ratification-rpc-catalog.json \
  || npm run --silent materialize:checkpoint-bootstrap-rpc-catalog
test -s evidence/checkpoint-bootstrap/ratification-signing-request.json \
  || npm run --silent write:checkpoint-bootstrap-ratification-request
test -s evidence/checkpoint-bootstrap/ratification-signature.hex \
  || npm run --silent sign:checkpoint-bootstrap-ratification
npm run --silent collect:checkpoint-bootstrap-ratification
npm run --silent write:checkpoint-bootstrap-ratification-report
test -s config/checkpoint-finalized-event-rpc-catalog.json \
  || npm run --silent materialize:checkpoint-finalized-event-rpc-catalog
if ! test -s evidence/checkpoint-finalized-event/transaction-reference.json; then
  test -n "${USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH:-}" \
    || { printf '%s\n' 'USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH is required after the real checkpoint submission.' >&2; exit 64; }
  npm run --silent write:checkpoint-finalized-transaction-reference
fi
test -s evidence/checkpoint-finalized-event/transaction-reference.sha256
npm run --silent collect:checkpoint-finalized-event
npm run --silent write:checkpoint-finalized-event-report
test -s evidence/checkpoint-witness-source/checkpoint-witness-source.complete.json \
  || npm run --silent collect:authenticated-checkpoint-witness-source
test -s evidence/finalized-burn-source/checkpoint-witness.bin \
  || npm run --silent materialize:authenticated-checkpoint-witness
node scripts/check-checkpoint-evidence-phase-coverage.mjs
node scripts/check-closed-mainnet-phase-artifacts.mjs >/dev/null
npm run --silent export:canonical-finalized-burn-source
EOF
    ;;
  measure-release-capacity)
    common
    cat <<'EOF'
USDOM_RUN_LONG_RELEASE_TEST=YES npm run --silent execute:release-validation-jobs -- pre-ceremony
npm run --silent check:checkpoint-capacity-e2e
npm run --silent materialize:checkpoint-capacity-release-evidence
npm run --silent check:checkpoint-capacity-release-evidence
finalized_burn_capacity_output=$(mktemp -p /dev/shm usdom-finalized-burn-capacity.XXXXXXXX)
finalized_burn_capacity_output_identity=$(stat -c '%u:%d:%i:%a:%h' "$finalized_burn_capacity_output")
cleanup_capacity_output(){
  if test "$(stat -c '%u:%d:%i:%a:%h' "$finalized_burn_capacity_output" 2>/dev/null)" = "$finalized_burn_capacity_output_identity"; then
    rm -f -- "$finalized_burn_capacity_output"
  fi
}
trap cleanup_capacity_output EXIT
trap 'cleanup_capacity_output; exit 129' HUP
trap 'cleanup_capacity_output; exit 130' INT
trap 'cleanup_capacity_output; exit 143' TERM
npm run --silent check:finalized-burn-capacity-e2e > "$finalized_burn_capacity_output"
node scripts/read-private-file-stdout.mjs "$finalized_burn_capacity_output"
USDOM_FINALIZED_BURN_PROOF_RUN_ID=$(jq -er \
  '.runId | select(type=="string" and test("^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$"))' \
  "$finalized_burn_capacity_output")
export USDOM_FINALIZED_BURN_PROOF_RUN_ID
cleanup_capacity_output
trap - EXIT HUP INT TERM
USDOM_FINALIZED_BURN_PROOF_RUN_ID="$USDOM_FINALIZED_BURN_PROOF_RUN_ID" \
  npm run --silent check:finalized-burn-capacity-evidence
USDOM_FINALIZED_BURN_PROOF_RUN_ID="$USDOM_FINALIZED_BURN_PROOF_RUN_ID" \
  npm run --silent materialize:finalized-burn-capacity-release-evidence
node scripts/check-local-operational-gas.mjs docs/LOCAL-OPERATIONAL-GAS-MEASUREMENT-2026-10-26.json
if test ! -s "$USDOM_OPERATIONAL_GAS_RUN_CONFIG" -o ! -s "$USDOM_OPERATIONAL_GAS_RPC_SOURCES"; then
  bash scripts/prepare-production-operational-gas-inputs.sh
fi
node scripts/prepare-production-operational-gas-job-v2.mjs \
  config/proof-reserve.unconfigured.json docs/LOCAL-OPERATIONAL-GAS-MEASUREMENT-2026-10-26.json \
  "$USDOM_OPERATIONAL_GAS_RUN_CONFIG" "$USDOM_OPERATIONAL_GAS_JOB"
node scripts/collect-production-operational-gas-evidence.mjs \
  "$USDOM_OPERATIONAL_GAS_JOB" "$USDOM_OPERATIONAL_GAS_RPC_SOURCES" "$USDOM_OPERATIONAL_GAS_EVIDENCE"
node scripts/check-production-operational-gas-evidence.mjs \
  "$USDOM_OPERATIONAL_GAS_JOB" "$USDOM_OPERATIONAL_GAS_EVIDENCE"
npm run --silent check:provenance
EOF
    ;;
  finalize-native-privacy-ceremony-secret)
    common
    cat <<'EOF'
# Contributions and erasure attestations come from isolated participant
# machines. This phase assembles the fixed three-party transcript, verifies all
# transitions, and installs the exact release-bound VK create-once.
readonly ceremony=/home/leonardov/usdom-mainnet-private/native-privacy-ceremony
readonly phase2_records="$ceremony/phase2-records"
readonly finalization_signatures="$ceremony/finalization-signatures"
readonly artifacts="$ceremony/artifacts"
readonly header="$ceremony/header.json"
readonly circuit="$ceremony/spend-circuit.r1cs"
readonly final_pk="$ceremony/final-proving-key.bin"
readonly vk="$ceremony/spend-verifying-key.bin"
readonly draft="$ceremony/transcript-draft.json"
readonly transcript="$ceremony/transcript.json"
readonly runtime_manifest="$USDOM_PROJECT/evidence/native-runtime-manifest.json"
readonly verifier="$USDOM_PROJECT/target/release/dom-usdom-groth16-ceremony"
readonly installation=/home/leonardov/.local/share/dom-usdom/mainnet-privacy
for directory in "$ceremony" "$phase2_records" "$finalization_signatures" "$artifacts"; do
  test -d "$directory"; test ! -L "$directory"
  test "$(realpath -e "$directory")" = "$directory"
  test "$(stat -c '%u:%a' "$directory")" = "$(id -u):700"
done
for file in "$header" "$circuit" "$final_pk" "$vk"; do
  test -f "$file"; test ! -L "$file"; test "$(stat -c '%h' "$file")" = 1
  test "$(stat -c '%u:%a' "$file")" = "$(id -u):600"
done
test -f "$runtime_manifest"; test ! -L "$runtime_manifest"
test "$(stat -c '%u:%a:%h' "$runtime_manifest")" = "$(id -u):644:1"
test -x "$verifier"; test -f "$verifier"; test ! -L "$verifier"
test "$(stat -c '%h' "$verifier")" = 1
for ordinal in 001 002 003; do
  for file in "$phase2_records/phase2-record-$ordinal.json" \
    "$finalization_signatures/finalization-$ordinal.json"; do
    test -f "$file"; test ! -L "$file"
    test "$(stat -c '%u:%a:%h' "$file")" = "$(id -u):600:1"
  done
done
node scripts/assemble-native-privacy-ceremony.mjs draft \
  "$header" "$phase2_records" 3 "$draft"
node scripts/assemble-native-privacy-ceremony.mjs finalize "$draft" "$finalization_signatures" "$circuit" "$final_pk" "$vk" "$transcript"
npm run --silent check:native-privacy-ceremony -- "$transcript" "$circuit" "$final_pk" "$vk" "$artifacts" "$verifier"
npm run --silent install:native-privacy-verifying-key -- "$transcript" "$circuit" "$final_pk" "$vk" "$runtime_manifest" "$installation" "$artifacts" "$verifier"
# Completion-last validation repeats the full artifact verifier and proves that
# all three installed source documents and the resulting receipt are exact.
npm run --silent check:native-privacy-ceremony -- "$transcript" "$circuit" "$final_pk" "$vk" "$artifacts" "$verifier" | jq -S 'del(.schema)' | cmp -s - <(jq -S 'del(.schema,.nativeRuntimeManifestSha256,.ceremonyTranscriptSha256)' "$installation/installation.json")
cmp -s "$transcript" "$installation/ceremony-transcript.json"
cmp -s "$vk" "$installation/spend-verifying-key.bin"
cmp -s "$runtime_manifest" "$installation/native-usdom-v2.json"
USDOM_RUN_LONG_RELEASE_TEST=YES npm run --silent execute:release-validation-jobs -- post-ceremony
EOF
    ;;
  open-claims-plan)
    common
    cat <<'EOF'
node scripts/write-open-claims-execution-plan.mjs
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
test -s "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
node scripts/materialize-mainnet-deployment-completion.mjs \
  | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-finalized-completion.json"
temporary=$(mktemp -d -p /dev/shm usdom-readiness.XXXXXXXX)
test "$(stat -c '%u:%a' "$temporary")" = "$(id -u):700"
temporary_identity=$(stat -c '%u:%d:%i:%a' "$temporary")
cleanup(){ if test "$(stat -c '%u:%d:%i:%a' "$temporary" 2>/dev/null)" = "$temporary_identity"; then rm -rf -- "$temporary"; fi; }
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
diagnostic="$temporary/readiness.json"
dag="$temporary/dag.json"
node scripts/check-closed-mainnet-phase-artifacts.mjs >"$dag"
node scripts/materialize-operational-claims-ledger.mjs >/dev/null
status=0
node scripts/check-mainnet-readiness.mjs closed-mainnet >"$diagnostic" || status=$?
test "$status" -eq 0 -o "$status" -eq 1
jq -e '.schema and (.ready|type=="boolean") and (.blockerCount|type=="number")' "$diagnostic" >/dev/null
cat "$diagnostic"
EOF
    ;;
  *) usage >&2; exit 64 ;;
esac

if "$planned"; then
  cat <<'EOF'
}
phase_body
test "$(stat -c '%d:%i' "$USDOM_PILOT_PHASE_LOCK_DIRECTORY")" = "$USDOM_PILOT_PHASE_LOCK_DEVICE:$USDOM_PILOT_PHASE_LOCK_INODE"
node scripts/check-closed-mainnet-phase-dependency.mjs complete \
  "$USDOM_PILOT_PHASE_NAME" "$0"
test "$(stat -c '%d:%i' "$USDOM_PILOT_PHASE_LOCK_DIRECTORY")" = "$USDOM_PILOT_PHASE_LOCK_DEVICE:$USDOM_PILOT_PHASE_LOCK_INODE"
EOF
fi
