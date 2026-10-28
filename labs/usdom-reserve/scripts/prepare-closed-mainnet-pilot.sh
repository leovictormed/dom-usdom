#!/usr/bin/env bash
set +x
unset BASH_XTRACEFD 2>/dev/null || true
set -euo pipefail
set +o history 2>/dev/null || true
umask 077
export LC_ALL=C LANG=C TZ=UTC
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/home/leonardov/.foundry/bin:/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME PERL5LIB RUBYLIB \
  GIT_CONFIG GIT_CONFIG_COUNT GIT_DIR GIT_WORK_TREE RUSTFLAGS RUSTDOCFLAGS \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy \
  SSLKEYLOGFILE SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS HISTFILE \
  USDOM_TEST_PLAN_INSTALL_FAULT
export HISTFILE=/dev/null
ulimit -c 0 || { printf '%s\n' 'Cannot disable core dumps for pilot preparation.' >&2; exit 1; }
for inherited_function in $(compgen -A function); do unset -f "$inherited_function"; done
unset inherited_function
for fd_path in /proc/"$$"/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ $inherited_fd =~ ^[0-9]+$ ]] || exit 1
  (( inherited_fd <= 2 )) && continue
  [[ $inherited_fd == 255 ]] && continue
  exec {inherited_fd}>&-
done
unset fd_path inherited_fd
readonly root=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
readonly plan_directory=/home/leonardov/usdom-mainnet-public
usage(){ cat <<'EOF'
Usage:
  bash scripts/prepare-closed-mainnet-pilot.sh --verify-only
  bash scripts/prepare-closed-mainnet-pilot.sh --generate-plan

--verify-only checks Ubuntu packages, executable hashes, the release toolchain,
all 23 operator phases and all 57 current claim routes. It never installs, downloads,
signs or uses a network.
--generate-plan performs the same checks and publishes an immutable,
content-addressed public JSON plan. It never executes a generated phase.
EOF
}
test "$#" -eq 1 || { usage >&2; exit 64; }
case $1 in --help|-h) usage; exit 0;; --verify-only|--generate-plan) mode=$1;; *) usage >&2; exit 64;; esac
cd "$root"
if ! bash scripts/bootstrap-ubuntu-24.04-dependencies.sh --verify-only; then
  printf '%s\n' 'NEXT: sudo -- /usr/bin/bash --noprofile --norc /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve/scripts/bootstrap-ubuntu-24.04-dependencies.sh --install' >&2
  exit 1
fi
if ! node scripts/check-mainnet-toolchain.mjs; then
  printf '%s\n' 'NEXT: /usr/bin/bash --noprofile --norc /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve/scripts/bootstrap-solc-0.8.37.sh' >&2
  printf '%s\n' 'NEXT: /usr/bin/bash --noprofile --norc /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve/scripts/prepare-closed-mainnet-pilot.sh --verify-only' >&2
  exit 1
fi
node scripts/check-open-claims-execution-plan.mjs
if [[ $mode == --verify-only ]]; then
  printf '%s\n' 'PASS: pilot prerequisites, 23/23 operator phases and 57/57 claim routes verified'
  printf '%s\n' 'NEXT: /usr/bin/bash --noprofile --norc /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve/scripts/prepare-closed-mainnet-pilot.sh --generate-plan'
  exit 0
fi
python3 scripts/ensure-private-directory-path.py "$plan_directory" 0755
test -d "$plan_directory"; test ! -L "$plan_directory"
test "$(realpath -e "$plan_directory")" = "$plan_directory"
test "$(stat -c '%u:%a' "$plan_directory")" = "$(id -u):755"
exec 9<"$plan_directory"
test "$(realpath -e /proc/$$/fd/9)" = "$plan_directory"
test "$(stat -Lc '%u:%a' /proc/$$/fd/9)" = "$(id -u):755"
test "$(stat -c '%d:%i' "$plan_directory")" = "$(stat -Lc '%d:%i' /proc/$$/fd/9)"
flock -n 9 || { printf '%s\n' 'Another pilot plan materialization is active.' >&2; exit 75; }
plan_directory_device=$(stat -Lc '%d' /proc/$$/fd/9)
plan_directory_inode=$(stat -Lc '%i' /proc/$$/fd/9)
readonly plan_directory_device plan_directory_inode
candidate=$(mktemp -p /dev/shm usdom-open-claims-plan.XXXXXXXX)
candidate_identity=$(stat -c '%u:%d:%i' "$candidate")
cleanup(){ if test "$(stat -c '%u:%d:%i' "$candidate" 2>/dev/null)" = "$candidate_identity"; then rm -f -- "$candidate"; fi; }
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
node scripts/write-open-claims-execution-plan.mjs >"$candidate"
chmod 0644 "$candidate"
test "$(realpath -e /proc/$$/fd/9)" = "$plan_directory"
test "$(stat -c '%d:%i' "$plan_directory")" = "$plan_directory_device:$plan_directory_inode"
plan=$(/usr/bin/python3 scripts/install-content-addressed-public-plan.py "$candidate" "$plan_directory" \
  "$plan_directory_device" "$plan_directory_inode")
test "$(realpath -e /proc/$$/fd/9)" = "$plan_directory"
test "$(stat -c '%d:%i' "$plan_directory")" = "$plan_directory_device:$plan_directory_inode"
printf 'PLAN: %s\n' "$plan"
printf 'NEXT: jq -r '\''.phaseOrder[]'\'' %s\n' "$plan"
printf 'NEXT: jq -r '\''.entries[] | [.claim,.phase,.generateCommand,.validateCommand,.executeCommand] | @tsv'\'' %s\n' "$plan"
