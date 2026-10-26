#!/usr/bin/env bash
set -euo pipefail
# The signing-network check reads credential-bearing RPC source files. Keep
# inherited tracing, panic backtraces and core artifacts out of this ceremony.
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
  printf '%s\n' 'Cannot disable core dumps for checkpoint signing.' >&2
  exit 1
fi
umask 077
if (($# != 0)); then printf '%s\n' 'Usage: bash scripts/sign-checkpoint-bootstrap-ratification.sh' >&2; exit 64; fi
for command in node jq cast realpath stat id mktemp chmod sha256sum cmp dirname; do command -v "$command" >/dev/null; done
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
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  assert_node_unchanged &&
    "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$TEMPORARY" || status=1
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
snapshot() { "$node_bin" "$ROOT/scripts/read-private-file-stdout.mjs" "$1" > "$2"; chmod 0600 "$2"; }
snapshot "$REQUEST" "$TEMPORARY/request.json"
snapshot "$REQUEST_SHA" "$TEMPORARY/request.sha256"
snapshot "$SAFE_BUNDLE" "$TEMPORARY/safe-bundle.json"
"$node_bin" "$ROOT/scripts/read-release-config-file-stdout.mjs" "$RELEASE_CONFIG" > "$TEMPORARY/release-config.json"
chmod 0600 "$TEMPORARY/release-config.json"
exec 8<"$TEMPORARY/request.sha256"
IFS= read -r EXPECTED_REQUEST_SHA <&8
if IFS= read -r _ <&8; then exit 1; fi
exec 8<&-
[[ "$EXPECTED_REQUEST_SHA" =~ ^[0-9a-f]{64}$ ]]
test "$(sha256_file "$TEMPORARY/request.json")" = "$EXPECTED_REQUEST_SHA"
test "$("$jq_bin" -r '.schema' "$TEMPORARY/request.json")" = 'usdom-checkpoint-bootstrap-ratification-signing-request-v1'
"$node_bin" "$ROOT/scripts/check-checkpoint-bootstrap-ratification-request.mjs" "$TEMPORARY/request.json" >/dev/null
DIGEST=$("$jq_bin" -er '.ratificationDigest' "$TEMPORARY/request.json")
[[ "$DIGEST" =~ ^0x[0-9a-f]{64}$ ]]
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
  "$node_bin" "$ROOT/scripts/read-release-config-file-stdout.mjs" "$RELEASE_CONFIG" \
    > "$TEMPORARY/release-config.current.json"
  "$cmp_bin" -s "$TEMPORARY/release-config.json" "$TEMPORARY/release-config.current.json"
}
[[ -t 0 && -t 2 ]] || { printf '%s\n' 'Ratification signing requires an interactive terminal.' >&2; exit 2; }
printf 'Ratification digest: %s\n' "$DIGEST"
read -r -p 'Digite ASSINO CHECKPOINT BOOTSTRAP USDOM SEM TRANSMITIR para continuar: ' AUTHORIZATION
test "$AUTHORIZATION" = 'ASSINO CHECKPOINT BOOTSTRAP USDOM SEM TRANSMITIR'
assert_cast_unchanged
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
for INDEX in 0 1; do
  EXPECTED=${OWNERS[$INDEX]}
  read -r -p "Conecte somente o Ledger do signer $EXPECTED e pressione Enter: " _
  assert_inputs
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  OBSERVED=$("$cast_bin" wallet address --ledger)
  [[ "$OBSERVED" != *$'\r'* && "$OBSERVED" != *$'\n'* ]]
  [[ "$OBSERVED" =~ ^0x[0-9a-fA-F]{40}$ ]]
  test "${EXPECTED,,}" = "${OBSERVED,,}"
  "$node_bin" "$ROOT/scripts/check-release-signing-network.mjs" \
    "$TEMPORARY/request.json" "$TEMPORARY/release-config.json" >/dev/null
  "$node_bin" "$ROOT/scripts/check-checkpoint-bootstrap-ratification-request.mjs" \
    "$TEMPORARY/request.json" >/dev/null
  assert_inputs
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  PART=$("$cast_bin" wallet sign --no-hash "$DIGEST" --ledger)
  [[ "$PART" != *$'\r'* && "$PART" != *$'\n'* ]]
  [[ "$PART" =~ ^0x[0-9a-fA-F]{130}$ ]]
  assert_cast_unchanged
  assert_node_unchanged
  assert_jq_unchanged
  assert_cmp_unchanged
  "$cast_bin" wallet verify --address "$EXPECTED" --no-hash "$DIGEST" "$PART" >/dev/null
  printf '%s' "$PART" > "$TEMPORARY/$INDEX.hex"
done
exec </dev/null
FIRST=$(<"$TEMPORARY/0.hex")
SECOND=$(<"$TEMPORARY/1.hex")
printf '0x%s%s\n' "${FIRST:2}" "${SECOND:2}" > "$TEMPORARY/signature.hex"
chmod 0600 "$TEMPORARY/signature.hex"
[[ $(<"$TEMPORARY/signature.hex") =~ ^0x[0-9a-fA-F]{260}$ ]]
sha256_file "$TEMPORARY/signature.hex" > "$TEMPORARY/signature.sha256"
chmod 0600 "$TEMPORARY/signature.sha256"
assert_inputs
assert_cast_unchanged
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
  "$node_bin" "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$SIGNATURE_SHA" < "$TEMPORARY/signature.sha256"
fi
snapshot "$SIGNATURE_SHA" "$TEMPORARY/signature-sha.installed.txt"
"$cmp_bin" -s "$TEMPORARY/signature.sha256" "$TEMPORARY/signature-sha.installed.txt"
assert_inputs
assert_cast_unchanged
assert_node_unchanged
assert_jq_unchanged
assert_cmp_unchanged
"$node_bin" "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$SIGNATURE" < "$TEMPORARY/signature.hex"
snapshot "$SIGNATURE" "$TEMPORARY/signature.installed.hex"
"$cmp_bin" -s "$TEMPORARY/signature.hex" "$TEMPORARY/signature.installed.hex"
printf '%s\n' 'Two-owner checkpoint ratification signature created locally; nothing was transmitted.'
