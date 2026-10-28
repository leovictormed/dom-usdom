#!/usr/bin/env bash
set -euo pipefail
# The signing-network check reads credential-bearing RPC source files. Keep
# inherited tracing, panic backtraces and core artifacts out of this ceremony.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
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
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for checkpoint signing.' >&2
  exit 1
fi
umask 077
if (($# != 0)); then printf '%s\n' 'Usage: bash scripts/sign-checkpoint-bootstrap-ratification.sh' >&2; exit 64; fi
: "${USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:?required}"
for command in node jq timeout realpath stat id mktemp chmod sha256sum cmp dirname; do command -v "$command" >/dev/null; done
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
ROOT=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$ROOT"
BASE="$ROOT/evidence/checkpoint-bootstrap"
REQUEST="$BASE/ratification-signing-request.json"
REQUEST_SHA="$BASE/ratification-signing-request.sha256"
SIGNATURE="$BASE/ratification-signature.hex"
SIGNATURE_SHA="$BASE/ratification-signature.sha256"
SAFE_BUNDLE="$ROOT/evidence/control-plane/safe-control-release-evidence-bundle.json"
RELEASE_CONFIG="$ROOT/config/proof-reserve.unconfigured.json"
for input in "$REQUEST" "$REQUEST_SHA" "$SAFE_BUNDLE"; do
  [[ -f "$input" && ! -L "$input" && "$(stat -c '%u:%a' "$input")" == "$(id -u):600" ]] || exit 1
done
[[ ! -e "$SIGNATURE" && ! -L "$SIGNATURE" ]] || exit 1
if [[ -e "$SIGNATURE_SHA" || -L "$SIGNATURE_SHA" ]]; then
  [[ -f "$SIGNATURE_SHA" && ! -L "$SIGNATURE_SHA"
    && "$(stat -c '%u:%a' "$SIGNATURE_SHA")" == "$(id -u):600" ]] || exit 1
fi
TEMPORARY=$(mktemp -d -p /dev/shm usdom-checkpoint-ratification-sign.XXXXXXXX)
chmod 0700 "$TEMPORARY"
TEMPORARY_IDENTITY=$(stat -c '%u:%d:%i:%a' "$TEMPORARY")
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ $(stat -c '%u:%d:%i:%a' "$TEMPORARY" 2>/dev/null) == "$TEMPORARY_IDENTITY" ]] &&
    assert_node_unchanged && assert_timeout_unchanged &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' \
      "$TEMPORARY" > /dev/null 2> /dev/null &&
    assert_node_unchanged && assert_timeout_unchanged && test ! -e "$TEMPORARY"; then
    :
  else
    status=1
  fi
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
  "$timeout_bin" --foreground --signal=TERM --kill-after=10s 330s "$node_bin" "$@"
  assert_node_unchanged; assert_timeout_unchanged
}
snapshot() { run_bounded_node "$ROOT/scripts/read-private-file-stdout.mjs" "$1" > "$2"; chmod 0600 "$2"; }
snapshot "$REQUEST" "$TEMPORARY/request.json"
snapshot "$REQUEST_SHA" "$TEMPORARY/request.sha256"
snapshot "$SAFE_BUNDLE" "$TEMPORARY/safe-bundle.json"
run_bounded_node "$ROOT/scripts/read-release-config-file-stdout.mjs" "$RELEASE_CONFIG" > "$TEMPORARY/release-config.json"
chmod 0600 "$TEMPORARY/release-config.json"
exec 8<"$TEMPORARY/request.sha256"
IFS= read -r EXPECTED_REQUEST_SHA <&8
if IFS= read -r _ <&8; then exit 1; fi
exec 8<&-
[[ "$EXPECTED_REQUEST_SHA" =~ ^[0-9a-f]{64}$ ]]
test "$(sha256_file "$TEMPORARY/request.json")" = "$EXPECTED_REQUEST_SHA"
test "$("$jq_bin" -r '.schema' "$TEMPORARY/request.json")" = 'usdom-checkpoint-bootstrap-ratification-signing-request-v1'
run_bounded_node "$ROOT/scripts/check-checkpoint-bootstrap-ratification-request.mjs" "$TEMPORARY/request.json" >/dev/null
DIGEST=$("$jq_bin" -er '.ratificationDigest' "$TEMPORARY/request.json")
[[ "$DIGEST" =~ ^0x[0-9a-f]{64}$ ]]
"$jq_bin" -c '{schema:"usdom-onekey-eip712-signing/v1",digest:.ratificationDigest,typedData}' \
  "$TEMPORARY/request.json" > "$TEMPORARY/typed-envelope.json"
chmod 0600 "$TEMPORARY/typed-envelope.json"
mapfile -t OWNERS < <("$jq_bin" -er '.roleReports.governance.ownersAfter | sort_by(ascii_downcase)[]' \
  "$TEMPORARY/safe-bundle.json")
test "${#OWNERS[@]}" = 3
test "${OWNERS[0],,}" != "${OWNERS[1],,}"
test "${OWNERS[1],,}" != "${OWNERS[2],,}"
test "$("$jq_bin" -r '.roleReports.governance.threshold' "$TEMPORARY/safe-bundle.json")" = 2
test "$("$jq_bin" -r '.roleReports.governance.address|ascii_downcase' "$TEMPORARY/safe-bundle.json")" = \
  "$("$jq_bin" -r '.governance|ascii_downcase' "$TEMPORARY/request.json")"
"$jq_bin" -e --slurpfile release "$TEMPORARY/release-config.json" \
  '.roleReports.governance.ownersAfter == $release[0].governanceOwners' \
  "$TEMPORARY/safe-bundle.json" >/dev/null
assert_inputs() {
  snapshot "$REQUEST" "$TEMPORARY/request.current"; "$cmp_bin" -s "$TEMPORARY/request.json" "$TEMPORARY/request.current"
  snapshot "$REQUEST_SHA" "$TEMPORARY/request-sha.current"; "$cmp_bin" -s "$TEMPORARY/request.sha256" "$TEMPORARY/request-sha.current"
  snapshot "$SAFE_BUNDLE" "$TEMPORARY/bundle.current"; "$cmp_bin" -s "$TEMPORARY/safe-bundle.json" "$TEMPORARY/bundle.current"
  run_bounded_node "$ROOT/scripts/read-release-config-file-stdout.mjs" "$RELEASE_CONFIG" \
    > "$TEMPORARY/release-config.current.json"
  "$cmp_bin" -s "$TEMPORARY/release-config.json" "$TEMPORARY/release-config.current.json"
}
[[ -t 0 && -t 2 ]] || { printf '%s\n' 'Ratification signing requires an interactive terminal.' >&2; exit 2; }
SAFE_BUNDLE_SHA256=$(sha256_file "$TEMPORARY/safe-bundle.json")
RELEASE_CONFIG_SHA256=$(sha256_file "$TEMPORARY/release-config.json")
OWNER_SET=$(printf '%s,%s,%s' "${OWNERS[0],,}" "${OWNERS[1],,}" "${OWNERS[2],,}")
AUTHORIZATION_PREIMAGE="usdom-checkpoint-bootstrap-ratification-offline-sign-v1|action=signCheckpointBootstrapRatification|phase=offline-sign-only|chainId=1|ratificationDigest=${DIGEST,,}|requestSha256=$EXPECTED_REQUEST_SHA|safeBundleSha256=$SAFE_BUNDLE_SHA256|releaseConfigSha256=$RELEASE_CONFIG_SHA256|governanceOwners=$OWNER_SET|threshold=2"
printf '%s' "$AUTHORIZATION_PREIMAGE" > "$TEMPORARY/authorization-preimage.txt"
chmod 0600 "$TEMPORARY/authorization-preimage.txt"
AUTHORIZATION_HASH=$(sha256_file "$TEMPORARY/authorization-preimage.txt")
printf 'CHECKPOINT BOOTSTRAP RATIFICATION OFFLINE SIGN REVIEW action=signCheckpointBootstrapRatification phase=offline-sign-only chainId=1 ratificationDigest=%s requestSha256=%s safeBundleSha256=%s releaseConfigSha256=%s governanceOwners=%s threshold=2 authorizationHash=%s\n' \
  "$DIGEST" "$EXPECTED_REQUEST_SHA" "$SAFE_BUNDLE_SHA256" "$RELEASE_CONFIG_SHA256" "$OWNER_SET" "$AUTHORIZATION_HASH" >&2
read -r -p "Digite ASSINO CHECKPOINT BOOTSTRAP USDOM SEM TRANSMITIR AUTH $AUTHORIZATION_HASH: " AUTHORIZATION
test "$AUTHORIZATION" = "ASSINO CHECKPOINT BOOTSTRAP USDOM SEM TRANSMITIR AUTH $AUTHORIZATION_HASH"
assert_inputs
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
for INDEX in 0 1; do
  EXPECTED=${OWNERS[$INDEX]}
  printf 'Conecte somente a OneKey Classic 1S do signer %s por Bluetooth; a assinatura iniciará agora.\n' "$EXPECTED" >&2
  assert_inputs
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  PHYSICAL="$ROOT/evidence/authorization/onekey-governance-owner-$((INDEX + 1))-physical-account.json"
  snapshot "$PHYSICAL" "$TEMPORARY/$INDEX.physical-account.json"
  OBSERVED=$("$jq_bin" -er '.address' "$TEMPORARY/$INDEX.physical-account.json")
  test "${EXPECTED,,}" = "${OBSERVED,,}"
  run_bounded_node "$ROOT/scripts/check-release-signing-network.mjs" \
    "$TEMPORARY/request.json" "$TEMPORARY/release-config.json" >/dev/null
  run_bounded_node "$ROOT/scripts/check-checkpoint-bootstrap-ratification-request.mjs" \
    "$TEMPORARY/request.json" >/dev/null
  assert_inputs
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  WC_REQUEST="$BASE/ratification-owner-$((INDEX + 1))-walletconnect-request.json"
  WC_RESPONSE="$BASE/ratification-owner-$((INDEX + 1))-walletconnect-response.json"
  if [[ ! -e "$WC_REQUEST" ]]; then
    run_bounded_node "$ROOT/scripts/prepare-onekey-ios-walletconnect-request.mjs" \
      "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$TEMPORARY/typed-envelope.json" \
      "$TEMPORARY/$INDEX.physical-account.json" "$EXPECTED" "$WC_REQUEST"
  fi
  run_bounded_node "$ROOT/scripts/check-onekey-ios-walletconnect-request.mjs" \
    "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$TEMPORARY/typed-envelope.json" \
    "$TEMPORARY/$INDEX.physical-account.json" "$EXPECTED" "$WC_REQUEST"
  if [[ ! -e "$WC_RESPONSE" ]]; then
    if run_bounded_walletconnect "$ROOT/scripts/sign-onekey-ios-walletconnect-typed-data.mjs" \
      "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$WC_REQUEST" \
      "$TEMPORARY/$INDEX.physical-account.json" "$WC_RESPONSE"; then :; else
      STATUS=$?; (( STATUS == 80 )) && exit 80; exit "$STATUS"
    fi
  fi
  run_bounded_node "$ROOT/scripts/extract-onekey-ios-walletconnect-signature.mjs" \
    "$WC_REQUEST" "$WC_RESPONSE" > "$TEMPORARY/$INDEX.hex"
  chmod 0600 "$TEMPORARY/$INDEX.hex"
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  printf 'Desconecte o dispositivo do signer %s antes de conectar a proxima identidade.\n' "$EXPECTED" >&2
done
exec </dev/null
run_bounded_node "$ROOT/scripts/assemble-checkpoint-bootstrap-ratification-signatures.mjs" \
  "$TEMPORARY/request.json" "${OWNERS[0]}" "$TEMPORARY/0.hex" \
  "${OWNERS[1]}" "$TEMPORARY/1.hex" "$TEMPORARY/signature.hex"
[[ $(<"$TEMPORARY/signature.hex") =~ ^0x[0-9a-fA-F]{260}$ ]]
sha256_file "$TEMPORARY/signature.hex" > "$TEMPORARY/signature.sha256"
chmod 0600 "$TEMPORARY/signature.sha256"
assert_inputs
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
if [[ -e "$SIGNATURE_SHA" ]]; then
  snapshot "$SIGNATURE_SHA" "$TEMPORARY/signature-sha.preexisting.txt"
  "$cmp_bin" -s "$TEMPORARY/signature.sha256" "$TEMPORARY/signature-sha.preexisting.txt" || {
    printf '%s\n' 'Existing ratification-signature hash differs from rebuilt signature.' >&2
    exit 1
  }
else
  run_bounded_node "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$SIGNATURE_SHA" < "$TEMPORARY/signature.sha256"
fi
snapshot "$SIGNATURE_SHA" "$TEMPORARY/signature-sha.installed.txt"
"$cmp_bin" -s "$TEMPORARY/signature.sha256" "$TEMPORARY/signature-sha.installed.txt"
assert_inputs
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
run_bounded_node "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$SIGNATURE" < "$TEMPORARY/signature.hex"
snapshot "$SIGNATURE" "$TEMPORARY/signature.installed.hex"
"$cmp_bin" -s "$TEMPORARY/signature.hex" "$TEMPORARY/signature.installed.hex"
printf '%s\n' 'Two-owner checkpoint ratification signature created locally; nothing was transmitted.'
