#!/usr/bin/env bash
# Source-only helper: decode a snapshotted ProgramBinary and bind its ImageID
# before invoking any proof host.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  printf '%s\n' 'require-risc0-program-binary.sh must be sourced' >&2
  exit 2
fi
verify_risc0_program_binary() {
  if (($# != 4)); then
    printf '%s\n' 'verify_risc0_program_binary requires CARGO REPOSITORY PROGRAM EXPECTED_IMAGE_ID' >&2
    return 2
  fi
  local cargo_path=$1 repository=$2 program=$3 expected_image_id=$4
  [[ -x $cargo_path && -f $cargo_path && ! -L $cargo_path ]] || return 1
  [[ -f $program && ! -L $program ]] || return 1
  [[ $expected_image_id =~ ^[0-9a-f]{64}$ ]] || return 1
  "$cargo_path" run --quiet --locked --manifest-path "$repository/Cargo.toml" \
    -p dom-risc0-program-packager -- --verify "$program" "$expected_image_id" >/dev/null
}
