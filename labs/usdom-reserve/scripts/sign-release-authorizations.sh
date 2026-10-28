#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for release signing.' >&2
  exit 1
fi
# Do not carry caller-owned evidence, lock or logging descriptors into OneKey
# or validation children. Bash's script descriptor 255 is internal and CLOEXEC.
for fd_path in /proc/$$/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ "$inherited_fd" =~ ^[0-9]+$ ]] || exit 1
  ((inherited_fd > 2)) || continue
  [[ "$inherited_fd" == 255 ]] && continue
  exec {inherited_fd}>&-
done
# Do not let the operator's ambient toolchain, loader, proxy or debug settings
# alter credential-bearing Node/OneKey children. USDOM inputs are exported
# explicitly below; HOME is retained for hardware-wallet integration.
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
  RUST_LOG RUSTFLAGS RUSTC_WRAPPER \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done
umask 077
export LC_ALL=C

if (($# != 1)) || [[ "$1" != native && "$1" != release && "$1" != pilot ]]; then
  printf '%s\n' 'Internal usage: sign-release-authorizations.sh native|release|pilot' >&2
  exit 64
fi
mode=$1
for command in jq stat realpath mktemp id node cmp chmod sha256sum timeout; do command -v "$command" >/dev/null; done
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
authorization_root="$project/evidence/authorization"
walletconnect_config="$authorization_root/onekey-walletconnect-client.json"
walletconnect_handoff="$authorization_root/onekey-walletconnect-release-authorizations"
native_root="$project/evidence/native-attestations"
release_request="$authorization_root/release-authorization-request.json"
pilot_request="$authorization_root/pilot-funds-authorization-request.json"
pilot_snapshot="$authorization_root/pilot-funds-snapshot.json"
native_request="$native_root/native-release-attestation-requests.json"
safe_bundle="$project/evidence/control-plane/safe-control-release-evidence-bundle.json"
release_config="$project/config/proof-reserve.unconfigured.json"
release_evidence="$project/config/mainnet-release-evidence.unconfigured.json"
for directory in "$authorization_root" "$native_root" "$(dirname "$safe_bundle")" "$walletconnect_handoff"; do
  test -d "$directory"; test ! -L "$directory"
  test "$(stat -c '%u:%a' "$directory")" = "$(id -u):700"
done
temporary=$(mktemp -d -p /dev/shm usdom-release-authorization.XXXXXXXX)
chmod 0700 "$temporary"
temporary_identity=$(stat -c '%u:%d:%i:%a' "$temporary")
signing_state=clean
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ $(stat -c '%u:%d:%i:%a' "$temporary" 2>/dev/null) == "$temporary_identity" ]] &&
    assert_node_unchanged && assert_timeout_unchanged &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' \
      "$temporary" > /dev/null 2> /dev/null &&
    assert_node_unchanged && assert_timeout_unchanged && test ! -e "$temporary"; then
    :
  else
    status=1
  fi
  if ((status != 0)) && [[ "$signing_state" != clean ]]; then status=80; fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
run_bounded_node() {
  assert_node_unchanged; assert_timeout_unchanged
  "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$node_bin" "$@"
  assert_node_unchanged
}
run_bounded_walletconnect() {
  assert_node_unchanged; assert_timeout_unchanged
  "$timeout_bin" --foreground --signal=TERM --kill-after=15s 330s "$node_bin" "$@"
  assert_node_unchanged
}
snapshot_private() {
  run_bounded_node "$project/scripts/read-private-file-stdout.mjs" "$1" > "$2"
  chmod 0600 "$2"
}
snapshot_public() {
  run_bounded_node "$project/scripts/read-release-config-file-stdout.mjs" "$1" > "$2"
  chmod 0600 "$2"
}
safe_bundle_snapshot="$temporary/safe-control-release-evidence-bundle.json"
snapshot_private "$safe_bundle" "$safe_bundle_snapshot"
release_config_snapshot="$temporary/proof-reserve.json"
release_evidence_snapshot="$temporary/mainnet-release-evidence.json"
snapshot_public "$release_config" "$release_config_snapshot"
snapshot_public "$release_evidence" "$release_evidence_snapshot"
walletconnect_config_snapshot="$temporary/onekey-walletconnect-client.json"
snapshot_private "$walletconnect_config" "$walletconnect_config_snapshot"
test "$("$jq_bin" -r '.roleReports.governance.threshold' "$safe_bundle_snapshot")" = 2
# Safe requires the concatenated EOA signatures in strictly increasing owner
# address order. A swapOwner recovery preserves the replaced list position, so
# the observed ownersAfter array is not itself a signature-order guarantee.
mapfile -t owners < <("$jq_bin" -er \
  '.roleReports.governance.ownersAfter | map(ascii_downcase) | sort | .[]' \
  "$safe_bundle_snapshot")
test "${#owners[@]}" = 3
for index in 0 1 2; do [[ "${owners[$index]}" =~ ^0x[0-9a-f]{40}$ ]]; done
test "${owners[0]}" '<' "${owners[1]}"
test "${owners[1]}" '<' "${owners[2]}"
declare -a walletconnect_physical=()
declare -a walletconnect_physical_snapshot=()
for index in 0 1; do
  walletconnect_physical[$index]="$authorization_root/onekey-governance-owner-$((index + 1))-physical-account.json"
  walletconnect_physical_snapshot[$index]="$temporary/onekey-governance-owner-$((index + 1))-physical-account.json"
  snapshot_private "${walletconnect_physical[$index]}" "${walletconnect_physical_snapshot[$index]}"
  observed=$("$jq_bin" -er '.address|ascii_downcase' "${walletconnect_physical_snapshot[$index]}")
  test "$observed" = "${owners[$index],,}"
done
declare -A digests=()
declare -A outputs=()
if [[ "$mode" = native ]]; then
  request_source=$native_request
  request_snapshot="$temporary/native-release-attestation-requests.json"
  snapshot_private "$request_source" "$request_snapshot"
  test "$("$jq_bin" -r '.schema' "$request_snapshot")" = usdom-native-release-attestation-requests/v3
  test "$("$jq_bin" -r '.finalizedAnchor.governance' "$request_snapshot")" = \
    "$("$jq_bin" -r '.roleReports.governance.address' "$safe_bundle_snapshot")"
  digests[native-privacy-trusted-setup]=$("$jq_bin" -er '.requests.nativePrivacyTrustedSetup.digest' "$request_snapshot")
  digests[native-scheduled-runtime-activation]=$("$jq_bin" -er '.requests.nativeScheduledRuntimeActivation.digest' "$request_snapshot")
  digests[native-wallet-custody]=$("$jq_bin" -er '.requests.nativeWalletCustody.digest' "$request_snapshot")
  digests[native-wallet-recovery]=$("$jq_bin" -er '.requests.nativeWalletRecovery.digest' "$request_snapshot")
  run_bounded_node "$project/scripts/check-native-release-attestation-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
    "$release_evidence_snapshot" >/dev/null
  outputs[native-privacy-trusted-setup]="$native_root/native-privacy-trusted-setup-signature.hex"
  outputs[native-scheduled-runtime-activation]="$native_root/native-scheduled-runtime-activation-signature.hex"
  outputs[native-wallet-custody]="$native_root/native-wallet-custody-signature.hex"
  outputs[native-wallet-recovery]="$native_root/native-wallet-recovery-signature.hex"
  phrase='ASSINO ATESTACOES NATIVAS USDOM SEM TRANSMITIR'
  digest_context="native-privacy-trusted-setup:${digests[native-privacy-trusted-setup]},native-scheduled-runtime-activation:${digests[native-scheduled-runtime-activation]},native-wallet-custody:${digests[native-wallet-custody]},native-wallet-recovery:${digests[native-wallet-recovery]}"
elif [[ "$mode" = release ]]; then
  request_source=$release_request
  request_snapshot="$temporary/release-authorization-request.json"
  snapshot_private "$request_source" "$request_snapshot"
  test "$("$jq_bin" -r '.schema' "$request_snapshot")" = usdom-release-authorization-request/v2
  test "$("$jq_bin" -r '.finalizedAnchor.governance' "$request_snapshot")" = \
    "$("$jq_bin" -r '.roleReports.governance.address' "$safe_bundle_snapshot")"
  digests[release]=$("$jq_bin" -er '.digest' "$request_snapshot")
  outputs[release]="$authorization_root/release-authorization-signature.hex"
  run_bounded_node "$project/scripts/check-release-authorization-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
    "$release_evidence_snapshot" >/dev/null
  phrase='AUTORIZO RELEASE USDOM COM FUNDOS REAIS'
  digest_context="release:${digests[release]}"
else
  request_source=$pilot_request
  request_snapshot="$temporary/pilot-funds-authorization-request.json"
  snapshot_private "$request_source" "$request_snapshot"
  pilot_snapshot_copy="$temporary/pilot-funds-snapshot.json"
  snapshot_private "$pilot_snapshot" "$pilot_snapshot_copy"
  test "$("$jq_bin" -r '.schema' "$request_snapshot")" = usdom-pilot-funds-authorization-request/v1
  test "$("$jq_bin" -r '.finalizedAnchor.governance' "$request_snapshot")" = \
    "$("$jq_bin" -r '.roleReports.governance.address' "$safe_bundle_snapshot")"
  digests[pilot]=$("$jq_bin" -er '.digest' "$request_snapshot")
  outputs[pilot]="$authorization_root/pilot-funds-authorization-signature.hex"
  run_bounded_node "$project/scripts/check-pilot-funds-authorization-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" "$pilot_snapshot_copy" >/dev/null
  phrase='AUTORIZO O DEPOSITO PILOTO USDOM EXATO SEM TRANSMITIR'
  digest_context="pilot:${digests[pilot]}"
fi
for name in "${!digests[@]}"; do
  case "$name" in
    native-privacy-trusted-setup) selector='.requests.nativePrivacyTrustedSetup.typedData' ;;
    native-scheduled-runtime-activation) selector='.requests.nativeScheduledRuntimeActivation.typedData' ;;
    native-wallet-custody) selector='.requests.nativeWalletCustody.typedData' ;;
    native-wallet-recovery) selector='.requests.nativeWalletRecovery.typedData' ;;
    release|pilot) selector='.typedData' ;;
    *) exit 1 ;;
  esac
  "$jq_bin" -c "$selector" "$request_snapshot" > "$temporary/$name.typed-data.json"
  chmod 0600 "$temporary/$name.typed-data.json"
  "$jq_bin" -c -n --arg digest "${digests[$name]}" --slurpfile typedData \
    "$temporary/$name.typed-data.json" \
    '{schema:"usdom-onekey-eip712-signing/v1",digest:$digest,typedData:$typedData[0]}' \
    > "$temporary/$name.envelope.json"
  chmod 0600 "$temporary/$name.envelope.json"
done
assert_release_signing_inputs_unchanged() {
  snapshot_private "$safe_bundle" "$temporary/safe-control-release-evidence-bundle.current.json"
  snapshot_private "$request_source" "$temporary/signing-request.current.json"
  snapshot_public "$release_config" "$temporary/proof-reserve.current.json"
  snapshot_public "$release_evidence" "$temporary/mainnet-release-evidence.current.json"
  "$cmp_bin" -s "$safe_bundle_snapshot" "$temporary/safe-control-release-evidence-bundle.current.json"
  "$cmp_bin" -s "$request_snapshot" "$temporary/signing-request.current.json"
  "$cmp_bin" -s "$release_config_snapshot" "$temporary/proof-reserve.current.json"
  "$cmp_bin" -s "$release_evidence_snapshot" "$temporary/mainnet-release-evidence.current.json"
  snapshot_private "$walletconnect_config" "$temporary/onekey-walletconnect-client.current.json"
  "$cmp_bin" -s "$walletconnect_config_snapshot" "$temporary/onekey-walletconnect-client.current.json"
  for signer_index in 0 1; do
    snapshot_private "${walletconnect_physical[$signer_index]}" "$temporary/onekey-governance-owner-$((signer_index + 1))-physical-account.current.json"
    "$cmp_bin" -s "${walletconnect_physical_snapshot[$signer_index]}" "$temporary/onekey-governance-owner-$((signer_index + 1))-physical-account.current.json"
  done
  if [[ "$mode" = pilot ]]; then
    snapshot_private "$pilot_snapshot" "$temporary/pilot-funds-snapshot.current.json"
    "$cmp_bin" -s "$pilot_snapshot_copy" "$temporary/pilot-funds-snapshot.current.json"
  fi
}
for name in "${!digests[@]}"; do
  [[ "${digests[$name]}" =~ ^0x[0-9a-fA-F]{64}$ ]]
  test ! -e "${outputs[$name]}"; test ! -L "${outputs[$name]}"
done
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Release authorization signing requires an interactive terminal.' >&2
  exit 2
fi
request_sha256=$(sha256_file "$request_snapshot")
safe_bundle_sha256=$(sha256_file "$safe_bundle_snapshot")
release_config_sha256=$(sha256_file "$release_config_snapshot")
release_evidence_sha256=$(sha256_file "$release_evidence_snapshot")
pilot_snapshot_sha256=none
if [[ "$mode" = pilot ]]; then pilot_snapshot_sha256=$(sha256_file "$pilot_snapshot_copy"); fi
authorization_preimage="usdom-release-offline-sign-v1|action=signReleaseAuthorization|phase=offline-sign-only|mode=$mode|chainId=1|digests=$digest_context|requestSha256=$request_sha256|safeBundleSha256=$safe_bundle_sha256|releaseConfigSha256=$release_config_sha256|releaseEvidenceSha256=$release_evidence_sha256|pilotSnapshotSha256=$pilot_snapshot_sha256"
printf '%s' "$authorization_preimage" > "$temporary/offline-sign-authorization.txt"
chmod 0600 "$temporary/offline-sign-authorization.txt"
authorization_hash=$(sha256_file "$temporary/offline-sign-authorization.txt")
printf 'RELEASE OFFLINE SIGN REVIEW action=signReleaseAuthorization phase=offline-sign-only mode=%s chainId=1 digests=%s requestSha256=%s safeBundleSha256=%s releaseConfigSha256=%s releaseEvidenceSha256=%s pilotSnapshotSha256=%s authorizationHash=%s\n' \
  "$mode" "$digest_context" "$request_sha256" "$safe_bundle_sha256" "$release_config_sha256" \
  "$release_evidence_sha256" "$pilot_snapshot_sha256" "$authorization_hash" >&2
read -r -p "Digite $phrase AUTH $authorization_hash: " authorization
test "$authorization" = "$phrase AUTH $authorization_hash"
assert_release_signing_inputs_unchanged
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
for index in 0 1; do
  expected="${owners[$index]}"
  printf 'Confirme no iPhone OneKey a conta de hardware %s; a sessao WalletConnect sera unica.\n' "$expected" >&2
  assert_release_signing_inputs_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  assert_timeout_unchanged
  observed=$("$jq_bin" -er '.address|ascii_downcase' "${walletconnect_physical_snapshot[$index]}")
  test "$observed" = "${expected,,}"
  for name in "${!digests[@]}"; do
    assert_release_signing_inputs_unchanged
    run_bounded_node "$project/scripts/check-release-signing-network.mjs"       "$request_snapshot" "$release_config_snapshot" >/dev/null
    assert_release_signing_inputs_unchanged
    assert_node_unchanged
    assert_jq_unchanged
    assert_cmp_unchanged
    assert_timeout_unchanged
    wc_request="$walletconnect_handoff/$mode-$name-owner-$((index + 1))-request.json"
    wc_response="$walletconnect_handoff/$mode-$name-owner-$((index + 1))-response.json"
    if test ! -e "$wc_request"; then
      run_bounded_node "$project/scripts/prepare-onekey-ios-walletconnect-request.mjs" \
        "$walletconnect_config_snapshot" "$temporary/$name.envelope.json" \
        "${walletconnect_physical_snapshot[$index]}" "$expected" "$wc_request"
    fi
    run_bounded_node "$project/scripts/check-onekey-ios-walletconnect-request.mjs" \
      "$walletconnect_config_snapshot" "$temporary/$name.envelope.json" \
      "${walletconnect_physical_snapshot[$index]}" "$expected" "$wc_request"
    if test ! -e "$wc_response"; then
      run_bounded_walletconnect "$project/scripts/sign-onekey-ios-walletconnect-typed-data.mjs" \
        "$walletconnect_config_snapshot" "$wc_request" \
        "${walletconnect_physical_snapshot[$index]}" "$wc_response"
    fi
    signing_state=signed-unresolved
    run_bounded_node "$project/scripts/extract-onekey-ios-walletconnect-signature.mjs" \
      "$wc_request" "$wc_response" > "$temporary/$name-$index.hex"
    chmod 0600 "$temporary/$name-$index.hex"
  done
  printf 'A sessao WalletConnect do signer %s foi excluida antes da proxima identidade.\n' "$expected" >&2
done
exec </dev/null
snapshot_private "$safe_bundle" "$temporary/safe-control-release-evidence-bundle.final.json"
"$cmp_bin" -s "$safe_bundle_snapshot" "$temporary/safe-control-release-evidence-bundle.final.json"
snapshot_private "$request_source" "$temporary/signing-request.final.json"
"$cmp_bin" -s "$request_snapshot" "$temporary/signing-request.final.json"
snapshot_public "$release_config" "$temporary/proof-reserve.final.json"
snapshot_public "$release_evidence" "$temporary/mainnet-release-evidence.final.json"
"$cmp_bin" -s "$release_config_snapshot" "$temporary/proof-reserve.final.json"
"$cmp_bin" -s "$release_evidence_snapshot" "$temporary/mainnet-release-evidence.final.json"
if [[ "$mode" = release ]]; then
  run_bounded_node "$project/scripts/check-release-authorization-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
    "$release_evidence_snapshot" >/dev/null
elif [[ "$mode" = native ]]; then
  run_bounded_node "$project/scripts/check-native-release-attestation-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
    "$release_evidence_snapshot" >/dev/null
else
  snapshot_private "$pilot_snapshot" "$temporary/pilot-funds-snapshot.final.json"
  "$cmp_bin" -s "$pilot_snapshot_copy" "$temporary/pilot-funds-snapshot.final.json"
  run_bounded_node "$project/scripts/check-pilot-funds-authorization-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" "$pilot_snapshot_copy" >/dev/null
fi
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
for name in "${!digests[@]}"; do
  run_bounded_node "$project/scripts/assemble-onekey-safe-signatures.mjs" \
    "$temporary/$name.envelope.json" "${owners[0]}" "$temporary/$name-0.hex" \
    "${owners[1]}" "$temporary/$name-1.hex" "$temporary/$name.hex"
  [[ $(<"$temporary/$name.hex") =~ ^0x[0-9a-fA-F]{260}$ ]]
  assert_release_signing_inputs_unchanged
    assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  run_bounded_node "$project/scripts/install-private-file-new-stdin.mjs" "${outputs[$name]}" \
    < "$temporary/$name.hex"
  snapshot_private "${outputs[$name]}" "$temporary/$name.installed.hex"
  "$cmp_bin" -s "$temporary/$name.hex" "$temporary/$name.installed.hex"
done
signing_state=clean
printf '%s\n' 'Two-owner Safe EIP-1271 signature bundles created locally; nothing was transmitted.'
