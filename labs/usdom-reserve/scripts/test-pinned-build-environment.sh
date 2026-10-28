#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "${BASH_SOURCE[0]%/*}/../../.." && pwd -P)"
source "$repo/labs/usdom-reserve/scripts/pinned-risc0-guest-toolchain.sh"
pin_build_utilities "$USDOM_CMP" "$USDOM_CMP_SHA256" "$USDOM_GREP" "$USDOM_GREP_SHA256" "$USDOM_MKTEMP" "$USDOM_MKTEMP_SHA256" "$USDOM_STAT" "$USDOM_STAT_SHA256" "$USDOM_REALPATH" "$USDOM_REALPATH_SHA256" "$USDOM_ID" "$USDOM_ID_SHA256"
root="$($USDOM_MKTEMP -d /tmp/usdom-build-env-test.XXXXXX)"
trap '/usr/bin/rm -rf -- "$root"' EXIT
/usr/bin/install -d -m 0700 "$root/shim"
printf '#!/bin/sh\nprintf "00  %%s\\n" "$1"\n' >"$root/shim/sha256sum"
printf '#!/bin/sh\nexit 0\n' >"$root/shim/cmp"
printf '#!/bin/sh\nprintf reached >"%s"\nexit 1\n' "$root/cc-reached" >"$root/shim/cc"
/usr/bin/chmod 0700 "$root/shim/sha256sum" "$root/shim/cmp" "$root/shim/cc"
PATH="$root/shim:$PATH"
[[ $(usdom_sha256 "$USDOM_CMP") == "$USDOM_CMP_SHA256" ]]
"$USDOM_HOST_LINKER" --version >/dev/null; [[ ! -e $root/cc-reached ]]
if CARGO_HOME="$root/attacker" reject_ambient_build_environment; then exit 1; fi
if RUSTC_WRAPPER="$root/shim/cmp" reject_ambient_build_environment; then exit 1; fi
prepare_isolated_cargo_home "$root/isolated"
[[ $HOME == "$root/isolated/home" && $CARGO_HOME == "$root/isolated/cargo-home" ]]
[[ $($USDOM_STAT -Lc '%a' "$HOME") == 700 && $($USDOM_STAT -Lc '%a' "$CARGO_HOME") == 700 ]]
cat >"$root/bash-env" <<'EOF'
export ESCAPED_BUILD_ENV=1
EOF
cat >"$root/clean-script" <<'EOF'
#!/usr/bin/env -S -i USDOM_PINNED_BUILD_ENV=1 PATH=/usr/bin:/bin LC_ALL=C /usr/bin/bash --noprofile --norc
[[ -z ${BASH_ENV:-} && -z ${LD_PRELOAD:-} && -z ${ESCAPED_BUILD_ENV:-} ]]
EOF
/usr/bin/chmod 0700 "$root/clean-script"
BASH_ENV="$root/bash-env" LD_PRELOAD=/does/not/exist "$root/clean-script"
printf '#!/bin/sh\nprintf old\n' >"$root/tool"; /usr/bin/chmod 0700 "$root/tool"
tool_digest=$(usdom_sha256 "$root/tool"); freeze_authenticated_tool FROZEN_TEST_TOOL "$root/tool" "$tool_digest"
printf '#!/bin/sh\nprintf replacement\n' >"$root/replacement"; /usr/bin/chmod 0700 "$root/replacement"; /usr/bin/mv "$root/replacement" "$root/tool"
[[ $("$FROZEN_TEST_TOOL") == old ]]
printf '%s\n' 'PASS: PATH shims and ambient Cargo/Rust configuration cannot enter pinned builds'
