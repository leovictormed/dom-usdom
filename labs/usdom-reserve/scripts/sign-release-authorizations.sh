#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for release signing.' >&2
  exit 1
fi
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
umask 077
export LC_ALL=C

if (($# != 1)) || [[ "$1" != native && "$1" != release ]]; then
  printf '%s\n' 'Internal usage: sign-release-authorizations.sh native|release' >&2
  exit 64
fi
mode=$1
for command in cast jq stat realpath mktemp id node cmp chmod sha256sum timeout; do command -v "$command" >/dev/null; done
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
authorization_root="$project/evidence/authorization"
native_root="$project/evidence/native-attestations"
release_request="$authorization_root/release-authorization-request.json"
native_request="$native_root/native-release-attestation-requests.json"
safe_bundle="$project/evidence/control-plane/safe-control-release-evidence-bundle.json"
release_config="$project/config/proof-reserve.unconfigured.json"
release_evidence="$project/config/mainnet-release-evidence.unconfigured.json"
for directory in "$authorization_root" "$native_root" "$(dirname "$safe_bundle")"; do
  test -d "$directory"; test ! -L "$directory"
  test "$(stat -c '%u:%a' "$directory")" = "$(id -u):700"
done
temporary=$(mktemp -d -p /dev/shm usdom-release-authorization.XXXXXXXX)
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
snapshot_public() {
  "$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$1" > "$2"
  chmod 0600 "$2"
}
safe_bundle_snapshot="$temporary/safe-control-release-evidence-bundle.json"
snapshot_private "$safe_bundle" "$safe_bundle_snapshot"
release_config_snapshot="$temporary/proof-reserve.json"
release_evidence_snapshot="$temporary/mainnet-release-evidence.json"
snapshot_public "$release_config" "$release_config_snapshot"
snapshot_public "$release_evidence" "$release_evidence_snapshot"
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
declare -A digests=()
declare -A outputs=()
if [[ "$mode" = native ]]; then
  request_source=$native_request
  request_snapshot="$temporary/native-release-attestation-requests.json"
  snapshot_private "$request_source" "$request_snapshot"
  test "$("$jq_bin" -r '.schema' "$request_snapshot")" = usdom-native-release-attestation-requests/v2
  test "$("$jq_bin" -r '.finalizedAnchor.governance' "$request_snapshot")" = \
    "$("$jq_bin" -r '.roleReports.governance.address' "$safe_bundle_snapshot")"
  digests[native-privacy-trusted-setup]=$("$jq_bin" -er '.requests.nativePrivacyTrustedSetup.digest' "$request_snapshot")
  digests[native-scheduled-runtime-activation]=$("$jq_bin" -er '.requests.nativeScheduledRuntimeActivation.digest' "$request_snapshot")
  digests[native-wallet-custody]=$("$jq_bin" -er '.requests.nativeWalletCustody.digest' "$request_snapshot")
  digests[native-wallet-recovery]=$("$jq_bin" -er '.requests.nativeWalletRecovery.digest' "$request_snapshot")
  "$node_bin" "$project/scripts/check-native-release-attestation-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
    "$release_evidence_snapshot" >/dev/null
  outputs[native-privacy-trusted-setup]="$native_root/native-privacy-trusted-setup-signature.hex"
  outputs[native-scheduled-runtime-activation]="$native_root/native-scheduled-runtime-activation-signature.hex"
  outputs[native-wallet-custody]="$native_root/native-wallet-custody-signature.hex"
  outputs[native-wallet-recovery]="$native_root/native-wallet-recovery-signature.hex"
  phrase='ASSINO ATESTACOES NATIVAS USDOM SEM TRANSMITIR'
else
  request_source=$release_request
  request_snapshot="$temporary/release-authorization-request.json"
  snapshot_private "$request_source" "$request_snapshot"
  test "$("$jq_bin" -r '.schema' "$request_snapshot")" = usdom-release-authorization-request/v2
  test "$("$jq_bin" -r '.finalizedAnchor.governance' "$request_snapshot")" = \
    "$("$jq_bin" -r '.roleReports.governance.address' "$safe_bundle_snapshot")"
  digests[release]=$("$jq_bin" -er '.digest' "$request_snapshot")
  outputs[release]="$authorization_root/release-authorization-signature.hex"
  "$node_bin" "$project/scripts/check-release-authorization-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
    "$release_evidence_snapshot" >/dev/null
  phrase='AUTORIZO RELEASE USDOM COM FUNDOS REAIS'
fi
assert_release_signing_inputs_unchanged() {
  snapshot_private "$safe_bundle" "$temporary/safe-control-release-evidence-bundle.current.json"
  snapshot_private "$request_source" "$temporary/signing-request.current.json"
  snapshot_public "$release_config" "$temporary/proof-reserve.current.json"
  snapshot_public "$release_evidence" "$temporary/mainnet-release-evidence.current.json"
  "$cmp_bin" -s "$safe_bundle_snapshot" "$temporary/safe-control-release-evidence-bundle.current.json"
  "$cmp_bin" -s "$request_snapshot" "$temporary/signing-request.current.json"
  "$cmp_bin" -s "$release_config_snapshot" "$temporary/proof-reserve.current.json"
  "$cmp_bin" -s "$release_evidence_snapshot" "$temporary/mainnet-release-evidence.current.json"
}
for name in "${!digests[@]}"; do
  [[ "${digests[$name]}" =~ ^0x[0-9a-fA-F]{64}$ ]]
  test ! -e "${outputs[$name]}"; test ! -L "${outputs[$name]}"
done
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'Release authorization signing requires an interactive terminal.' >&2
  exit 2
fi
read -r -p "Digite $phrase para continuar: " authorization
test "$authorization" = "$phrase"
assert_cast_unchanged
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
for index in 0 1; do
  expected="${owners[$index]}"
  read -r -p "Conecte somente o Ledger do signer $expected e pressione Enter: " _
  assert_release_signing_inputs_unchanged
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  assert_timeout_unchanged
  observed=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s \
    "$cast_bin" wallet address --ledger)
  assert_cast_unchanged
  assert_timeout_unchanged
  test "${observed,,}" = "${expected,,}"
  for name in "${!digests[@]}"; do
    assert_release_signing_inputs_unchanged
    "$node_bin" "$project/scripts/check-release-signing-network.mjs" \
      "$request_snapshot" "$release_config_snapshot" >/dev/null
    assert_release_signing_inputs_unchanged
    assert_cast_unchanged
    assert_node_unchanged
    assert_jq_unchanged
    assert_cmp_unchanged
    assert_timeout_unchanged
    signature=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s \
      "$cast_bin" wallet sign --no-hash "${digests[$name]}" --ledger)
    [[ "$signature" != *$'\r'* && "$signature" != *$'\n'* ]]
    [[ "$signature" =~ ^0x[0-9a-fA-F]{130}$ ]]
    assert_cast_unchanged
    assert_node_unchanged
    assert_jq_unchanged
    assert_cmp_unchanged
    assert_timeout_unchanged
    "$cast_bin" wallet verify --address "$expected" --no-hash "${digests[$name]}" "$signature" >/dev/null
    printf '%s' "$signature" > "$temporary/$name-$index.hex"
  done
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
  "$node_bin" "$project/scripts/check-release-authorization-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
    "$release_evidence_snapshot" >/dev/null
else
  "$node_bin" "$project/scripts/check-native-release-attestation-signing-request.mjs" \
    "$request_snapshot" "$safe_bundle_snapshot" "$release_config_snapshot" \
    "$release_evidence_snapshot" >/dev/null
fi
assert_cast_unchanged
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
for name in "${!digests[@]}"; do
  first=$(<"$temporary/$name-0.hex"); second=$(<"$temporary/$name-1.hex")
  printf '0x%s%s\n' "${first:2}" "${second:2}" > "$temporary/$name.hex"
  chmod 0600 "$temporary/$name.hex"
  [[ $(<"$temporary/$name.hex") =~ ^0x[0-9a-fA-F]{260}$ ]]
  assert_release_signing_inputs_unchanged
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  "$node_bin" "$project/scripts/install-private-file-new-stdin.mjs" "${outputs[$name]}" \
    < "$temporary/$name.hex"
  snapshot_private "${outputs[$name]}" "$temporary/$name.installed.hex"
  "$cmp_bin" -s "$temporary/$name.hex" "$temporary/$name.installed.hex"
done
printf '%s\n' 'Two-owner Safe EIP-1271 signature bundles created locally; nothing was transmitted.'
