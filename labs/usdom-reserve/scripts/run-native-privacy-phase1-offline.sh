#!/usr/bin/env bash
set -euo pipefail
umask 077

die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $# -ge 4 ]] || die 'usage: init BIN BIN_SHA256 DIR DEGREE | contribute BIN BIN_SHA256 DIR ORDINAL RELEASE CIRCUIT IDENTITY PREVIOUS_RECORD | verify-specialize BIN BIN_SHA256 DIR COUNT PK0 | phase2-contribute BIN BIN_SHA256 DIR ORDINAL RELEASE CIRCUIT IDENTITY PREVIOUS_RECORD'
BIN=$2; BIN_SHA256=$3; DIRECTORY=$4
[[ "$BIN" = /* && -f "$BIN" && ! -L "$BIN" && -x "$BIN" ]] || die 'unsafe verifier binary'
[[ "$(/usr/bin/sha256sum -- "$BIN" | /usr/bin/cut -d' ' -f1)" == "$BIN_SHA256" ]] || die 'verifier binary pin mismatch'
[[ "$DIRECTORY" = /* ]] || die 'artifact directory must be absolute'
if [[ ! -e "$DIRECTORY" ]]; then /usr/bin/mkdir -m 700 -- "$DIRECTORY"; fi
[[ -d "$DIRECTORY" && ! -L "$DIRECTORY" && "$(/usr/bin/stat -c %u -- "$DIRECTORY")" == "$EUID" && "$(/usr/bin/stat -c %a -- "$DIRECTORY")" == 700 ]] || die 'unsafe artifact directory'

publish(){
  local tmp=$1 final=$2
  /usr/bin/chmod 600 -- "$tmp"
  /usr/bin/sync -f -- "$tmp"
  if ! /usr/bin/ln -- "$tmp" "$final" 2>/dev/null; then
    [[ -f "$final" && ! -L "$final" && "$(/usr/bin/stat -c %u:%a:%h -- "$final")" == "$EUID:600:1" ]] || die "create-once publication refused: $final"
    [[ "$(/usr/bin/sha256sum -- "$tmp" | /usr/bin/cut -d' ' -f1)" == "$(/usr/bin/sha256sum -- "$final" | /usr/bin/cut -d' ' -f1)" ]] || die "published artifact differs: $final"
  fi
  /usr/bin/rm -- "$tmp"
  /usr/bin/sync -f -- "$DIRECTORY"
}
temporary(){ /usr/bin/mktemp --tmpdir="$DIRECTORY" '.phase1.partial.XXXXXXXX'; }

case "$1" in
  init)
    [[ $# -eq 5 && "$5" =~ ^[0-9]+$ ]] || die 'invalid init arguments'
    tmp=$(temporary); trap '/usr/bin/rm -f -- "$tmp"' EXIT
    "$BIN" phase1-init "$5" >"$tmp"
    "$BIN" phase1-verify-initial "$tmp"
    publish "$tmp" "$DIRECTORY/phase1-accumulator-000.bin"
    ;;
  contribute)
    [[ $# -eq 9 && "$5" =~ ^[1-9][0-9]*$ ]] || die 'invalid contribution arguments'
    for value in "$6" "$7" "$8" "$9"; do [[ "$value" =~ ^[0-9a-f]{64}$ ]] || die 'invalid contribution binding'; done
    ordinal=$(printf '%03d' "$5"); previous=$(printf '%03d' "$((10#$5-1))")
    before="$DIRECTORY/phase1-accumulator-$previous.bin"; artifact="$DIRECTORY/phase1-contribution-$ordinal.bin"; after="$DIRECTORY/phase1-accumulator-$ordinal.bin"
    [[ -f "$before" && ! -L "$before" ]] || die 'previous accumulator missing'
    artifact_tmp=$(temporary); accumulator_tmp=$(temporary); trap '/usr/bin/rm -f -- "$artifact_tmp" "$accumulator_tmp"' EXIT
    # All entropy is drawn by the pinned Rust binary from OsRng and never
    # appears in arguments, environment, stdout, transcript or shell history.
    "$BIN" phase1-contribute "$before" "$6" "$7" "$8" "$5" "$9" >"$artifact_tmp"
    "$BIN" phase1-extract "$artifact_tmp" >"$accumulator_tmp"
    "$BIN" phase1-verify "$before" "$artifact_tmp" "$6" "$7" "$8" "$5" "$9"
    publish "$artifact_tmp" "$artifact"; publish "$accumulator_tmp" "$after"
    ;;
  verify-specialize)
    [[ $# -eq 6 && "$5" =~ ^[1-9][0-9]*$ ]] || die 'invalid verification arguments'
    final=$(printf '%03d' "$5"); tmp=$(temporary); trap '/usr/bin/rm -f -- "$tmp"' EXIT
    "$BIN" phase1-specialize "$DIRECTORY/phase1-accumulator-$final.bin" >"$tmp"
    [[ "$(/usr/bin/sha256sum -- "$tmp" | /usr/bin/cut -d' ' -f1)" == "$6" ]] || die 'specialized PK0 hash mismatch'
    publish "$tmp" "$DIRECTORY/pk-000.bin"
    ;;
  phase2-contribute)
    [[ $# -eq 9 && "$5" =~ ^[1-9][0-9]*$ ]] || die 'invalid Phase2 contribution arguments'
    for value in "$6" "$7" "$8" "$9"; do [[ "$value" =~ ^[0-9a-f]{64}$ ]] || die 'invalid Phase2 binding'; done
    ordinal=$(printf '%03d' "$5"); previous=$(printf '%03d' "$((10#$5-1))")
    before="$DIRECTORY/pk-$previous.bin"; artifact="$DIRECTORY/phase2-contribution-$ordinal.bin"; after="$DIRECTORY/pk-$ordinal.bin"
    [[ -f "$before" && ! -L "$before" ]] || die 'previous Phase2 key missing'
    artifact_tmp=$(temporary); key_tmp=$(temporary); trap '/usr/bin/rm -f -- "$artifact_tmp" "$key_tmp"' EXIT
    "$BIN" phase2-contribute "$before" "$6" "$7" "$8" "$5" "$9" >"$artifact_tmp"
    "$BIN" phase2-extract "$artifact_tmp" >"$key_tmp"
    "$BIN" phase2-verify "$before" "$artifact_tmp" "$6" "$7" "$8" "$5" "$9"
    publish "$artifact_tmp" "$artifact"; publish "$key_tmp" "$after"
    ;;
  *) die 'unknown operation' ;;
esac
