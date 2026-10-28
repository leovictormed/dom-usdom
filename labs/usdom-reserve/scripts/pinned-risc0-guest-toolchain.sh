#!/usr/bin/env bash
# Source-only helper. Authenticate and expose the exact RISC Zero guest Cargo
# and rustc executables instead of trusting mutable rustup dispatch state.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  printf '%s\n' 'pinned-risc0-guest-toolchain.sh must be sourced' >&2
  exit 2
fi

readonly USDOM_RISC0_GUEST_CARGO_SHA256=0276b3bcaeb32ebc534382197b0ce1ee73d07e836b0da5ae992ff08079f2d4d2
readonly USDOM_RISC0_GUEST_RUSTC_SHA256=288ee1994dd8ec08184686e7a52b779c9b075498ffe73003884fefe60389c351
# rustc's canonical RISC Zero target specification selects the external
# `rust-lld` shipped by this exact v1.97.0 toolchain. Keep it in the same
# authenticated closure as Cargo and rustc.
readonly USDOM_RISC0_GUEST_RUST_LLD_SHA256=b6eb2515fa8b6731ffe8be03fbe38de87f0dca59aa7b15a4195d6c0235698fb3
readonly USDOM_HOST_CARGO_SHA256=ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24
readonly USDOM_HOST_RUSTC_SHA256=3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2
readonly USDOM_SHA256SUM=/usr/bin/sha256sum USDOM_OPENSSL=/usr/bin/openssl
readonly USDOM_CMP=/usr/bin/cmp USDOM_GREP=/usr/bin/grep USDOM_MKTEMP=/usr/bin/mktemp
readonly USDOM_ENV=/usr/bin/env USDOM_INSTALL=/usr/bin/install
readonly USDOM_STAT=/usr/bin/stat USDOM_REALPATH=/usr/bin/realpath USDOM_ID=/usr/bin/id USDOM_XXD=/usr/bin/xxd
readonly USDOM_DOCKER=/usr/bin/docker
readonly USDOM_HOST_LINKER=/usr/bin/x86_64-linux-gnu-gcc-13
readonly USDOM_HOST_LIBC=/usr/lib/x86_64-linux-gnu/libc.so.6 USDOM_HOST_LOADER=/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
readonly USDOM_R0VM=/home/leonardov/usdom-security-audit-20261015/risc0-home-stage196/extensions/v3.0.6-cargo-risczero-x86_64-unknown-linux-gnu/r0vm
readonly USDOM_CARGO_RISZERO=/home/leonardov/usdom-security-audit-20261015/risc0-home-stage196/extensions/v3.0.6-cargo-risczero-x86_64-unknown-linux-gnu/cargo-risczero
readonly USDOM_SHA256SUM_SHA256=4d2db56c867e5324e0084c9e897f6360d37517de77ac96f2bd31494223d69a60
readonly USDOM_OPENSSL_SHA256=b4f547c0f16272d1cc7f870330a6f2c243710c335e7a99c734ff7a0c6fdb2503
readonly USDOM_CMP_SHA256=b4589abb5222ad6aa4ef63ac31006766f99d1b82cdee30316349f3ad37b80189
readonly USDOM_GREP_SHA256=20a35a4c18f2fe9e6305c1cbf866b9c0fcc3f957132ae66028c99ec353bb0a80
readonly USDOM_MKTEMP_SHA256=7e4b5260cd8eebb68c28c66dd279394aee9139ff6e3b7023d21c875821bc3110
readonly USDOM_ENV_SHA256=886e5fa8be716b03eeda48856e0f04493f2969fc148fb7812594ffac647fa050
readonly USDOM_INSTALL_SHA256=14e9088c53f771fea828d81866a22c7817177504d1f993a1f5ed2f70373ebe17
readonly USDOM_STAT_SHA256=166809d4415b69e598e9ad20539e85223394cb7db38903b0b0a9104a13434739
readonly USDOM_REALPATH_SHA256=3e57a30f3d83065ac5a5feaf47b5c0fe94bac4207b9d9ce148caac7359b68a89
readonly USDOM_ID_SHA256=0e967a87e22a60b330c6dbdc7affe1dda41f342f14d20877725f0486d8777df2
readonly USDOM_XXD_SHA256=b18a89abfa47b36fc3f3516e6672cbf2c8e10c7b19c9787a96b9254c6f76a457
readonly USDOM_DOCKER_SHA256=7ed12b00293d64742419a6601ae97960a367a0ce97c88b06e3278cc0a409557b
readonly USDOM_HOST_LINKER_SHA256=1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26
readonly USDOM_HOST_LIBC_SHA256=3a15d66867d83762c7f2f1e37359cb8f6c5743edb369c65285cb0b1c4f7498bf
readonly USDOM_HOST_LOADER_SHA256=c20a2dc8917c755f02b94049356320fe1f62ac7d9f8994731f807d9df39302da
readonly USDOM_R0VM_SHA256=751b9b188d341e8bec5e02060086b7b1dc3f7289e90f726c38589bb6735dd6d7
readonly USDOM_CARGO_RISZERO_SHA256=f4215df6cb521a922cb3539a33fae286f73d6814b40619dadd10733102213bfc

usdom_sha256() { local output; output=$($USDOM_SHA256SUM "$1") || return; printf '%s\n' "${output%% *}"; }
authenticate_risc0_build_launcher_parent() {
  local parent_executable="/proc/$PPID/exe" info
  [[ -r $parent_executable ]] || return 1
  info=$($USDOM_STAT -Lc '%u:%a:%h' "$parent_executable") || return 1
  [[ $info == "$($USDOM_ID -u):700:1" ]] || return 1
  [[ ${USDOM_BUILD_LAUNCHER_SHA256:-} =~ ^[0-9a-f]{64}$ ]]
  [[ $(usdom_sha256 "$parent_executable") == "$USDOM_BUILD_LAUNCHER_SHA256" ]]
}
pin_build_utilities() {
  local openssl_digest utility expected info
  openssl_digest=$($USDOM_OPENSSL dgst -sha256 "$USDOM_SHA256SUM"); [[ ${openssl_digest##*= } == "$USDOM_SHA256SUM_SHA256" ]]
  [[ $(usdom_sha256 "$USDOM_OPENSSL") == "$USDOM_OPENSSL_SHA256" ]]
  set -- "$USDOM_ENV" "$USDOM_ENV_SHA256" "$USDOM_INSTALL" "$USDOM_INSTALL_SHA256" "$USDOM_HOST_LINKER" "$USDOM_HOST_LINKER_SHA256" "$USDOM_HOST_LIBC" "$USDOM_HOST_LIBC_SHA256" "$USDOM_HOST_LOADER" "$USDOM_HOST_LOADER_SHA256" "$@"
  while (($#)); do utility=$1; expected=$2; shift 2
    [[ $utility == /* && -f $utility && ! -L $utility && -x $utility ]]
    info=$($USDOM_STAT -Lc '%u:%a:%h' "$utility"); [[ $info == 0:*:1 || $info == "$($USDOM_ID -u)":*:1 ]]
    [[ $(usdom_sha256 "$utility") == "$expected" ]]
  done
}
reject_ambient_build_environment() {
  local name
  while IFS='=' read -r name _; do
    case $name in CARGO_*|RUST*|CC|CFLAGS|CPPFLAGS|CXX|CXXFLAGS|AR|ARFLAGS|LD|LDFLAGS|LINKER) return 1;; esac
  done < <(/usr/bin/env)
}
prepare_isolated_cargo_home() {
  (($# == 1)); local root=$1
  /usr/bin/install -d -m 0700 "$root/home" "$root/cargo-home"
  export HOME="$root/home" CARGO_HOME="$root/cargo-home" RUSTUP_HOME=/home/leonardov/.rustup
  export CARGO_TERM_COLOR=never CARGO_NET_GIT_FETCH_WITH_CLI=false
}
freeze_authenticated_tool() {
  (($# == 3)); local -n destination=$1; local source=$2 expected=$3 descriptor
  exec {descriptor}<"$source"
  [[ $(usdom_sha256 "/proc/$$/fd/$descriptor") == "$expected" ]]
  destination="/proc/$$/fd/$descriptor"
  USDOM_FROZEN_TOOL_FDS+=("$descriptor")
}
declare -a USDOM_FROZEN_TOOL_FDS=()

pin_risc0_guest_toolchain() {
  (($# == 2)) || return 2
  local rustup_path=$1 expected_rustup_sha=$2 executable owner mode
  [[ -x $rustup_path && -f $rustup_path && ! -L $rustup_path ]] || return 1
  [[ $(usdom_sha256 "$rustup_path") == "$expected_rustup_sha" ]] || return 1
  RISC0_GUEST_CARGO=$($USDOM_REALPATH "$("$rustup_path" which --toolchain risc0 cargo)")
  RISC0_GUEST_RUSTC=$($USDOM_REALPATH "$("$rustup_path" which --toolchain risc0 rustc)")
  local guest_sysroot
  guest_sysroot=$("$RISC0_GUEST_RUSTC" --print sysroot)
  RISC0_GUEST_RUST_LLD=$($USDOM_REALPATH "$guest_sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld")
  for executable in "$RISC0_GUEST_CARGO" "$RISC0_GUEST_RUSTC" "$RISC0_GUEST_RUST_LLD"; do
    [[ $executable == /* && $($USDOM_REALPATH "$executable") == "$executable" ]]
    [[ -x $executable && -f $executable && ! -L $executable ]]
    [[ $($USDOM_STAT -Lc '%h' "$executable") == 1 ]]
    owner=$($USDOM_STAT -Lc '%u' "$executable"); [[ $owner == 0 || $owner == "$($USDOM_ID -u)" ]]
    mode=$($USDOM_STAT -Lc '%a' "$executable"); (( (8#$mode & 8#022) == 0 ))
  done
  [[ $(usdom_sha256 "$RISC0_GUEST_CARGO") == "$USDOM_RISC0_GUEST_CARGO_SHA256" ]]
  [[ $(usdom_sha256 "$RISC0_GUEST_RUSTC") == "$USDOM_RISC0_GUEST_RUSTC_SHA256" ]]
  [[ $(usdom_sha256 "$RISC0_GUEST_RUST_LLD") == "$USDOM_RISC0_GUEST_RUST_LLD_SHA256" ]]
  freeze_authenticated_tool RISC0_GUEST_CARGO "$RISC0_GUEST_CARGO" "$USDOM_RISC0_GUEST_CARGO_SHA256"
  freeze_authenticated_tool RISC0_GUEST_RUSTC "$RISC0_GUEST_RUSTC" "$USDOM_RISC0_GUEST_RUSTC_SHA256"
  freeze_authenticated_tool RISC0_GUEST_RUST_LLD "$RISC0_GUEST_RUST_LLD" "$USDOM_RISC0_GUEST_RUST_LLD_SHA256"
  readonly RISC0_GUEST_CARGO RISC0_GUEST_RUSTC RISC0_GUEST_RUST_LLD
}

assert_risc0_guest_toolchain_unchanged() {
  [[ -n ${RISC0_GUEST_CARGO:-} && -n ${RISC0_GUEST_RUSTC:-} && -n ${RISC0_GUEST_RUST_LLD:-} ]]
  [[ $(usdom_sha256 "$RISC0_GUEST_CARGO") == "$USDOM_RISC0_GUEST_CARGO_SHA256" ]]
  [[ $(usdom_sha256 "$RISC0_GUEST_RUSTC") == "$USDOM_RISC0_GUEST_RUSTC_SHA256" ]]
  [[ $(usdom_sha256 "$RISC0_GUEST_RUST_LLD") == "$USDOM_RISC0_GUEST_RUST_LLD_SHA256" ]]
}

pin_host_rust_toolchain() {
  (($# == 2)) || return 2
  local rustup_path=$1 expected_rustup_sha=$2 executable owner mode
  [[ -x $rustup_path && -f $rustup_path && ! -L $rustup_path ]] || return 1
  [[ $(usdom_sha256 "$rustup_path") == "$expected_rustup_sha" ]] || return 1
  HOST_CARGO=$($USDOM_REALPATH "$("$rustup_path" which --toolchain 1.98.0-x86_64-unknown-linux-gnu cargo)")
  HOST_RUSTC=$($USDOM_REALPATH "$("$rustup_path" which --toolchain 1.98.0-x86_64-unknown-linux-gnu rustc)")
  for executable in "$HOST_CARGO" "$HOST_RUSTC"; do
    [[ $executable == /* && -x $executable && -f $executable && ! -L $executable ]]
    [[ $($USDOM_STAT -Lc '%h' "$executable") == 1 ]]
    owner=$($USDOM_STAT -Lc '%u' "$executable"); [[ $owner == 0 || $owner == "$($USDOM_ID -u)" ]]
    mode=$($USDOM_STAT -Lc '%a' "$executable"); (( (8#$mode & 8#022) == 0 ))
  done
  [[ $(usdom_sha256 "$HOST_CARGO") == "$USDOM_HOST_CARGO_SHA256" ]]
  [[ $(usdom_sha256 "$HOST_RUSTC") == "$USDOM_HOST_RUSTC_SHA256" ]]
  freeze_authenticated_tool HOST_CARGO "$HOST_CARGO" "$USDOM_HOST_CARGO_SHA256"
  freeze_authenticated_tool HOST_RUSTC "$HOST_RUSTC" "$USDOM_HOST_RUSTC_SHA256"
  readonly HOST_CARGO HOST_RUSTC
}

assert_host_rust_toolchain_unchanged() {
  [[ -n ${HOST_CARGO:-} && -n ${HOST_RUSTC:-} ]]
  [[ $(usdom_sha256 "$HOST_CARGO") == "$USDOM_HOST_CARGO_SHA256" ]]
  [[ $(usdom_sha256 "$HOST_RUSTC") == "$USDOM_HOST_RUSTC_SHA256" ]]
}
