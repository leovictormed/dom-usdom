#!/usr/bin/env bash
set +x
unset BASH_XTRACEFD 2>/dev/null || true
set -euo pipefail
set +o history 2>/dev/null || true
umask 077
export LC_ALL=C LANG=C TZ=UTC
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME
export PATH=/usr/bin:/bin
ulimit -c 0 || exit 1
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
readonly private_root=/home/leonardov/usdom-mainnet-private
readonly directory=/home/leonardov/usdom-mainnet-private/operator-phases
test "$#" -eq 1 || exit 64
phase=$1
[[ $phase =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || exit 64
cd "$root"
/usr/bin/python3 scripts/ensure-private-directory-path.py "$private_root"
test -d "$private_root"; test ! -L "$private_root"
test "$(/usr/bin/realpath -e "$private_root")" = "$private_root"
exec 10<"$private_root"
test "$(/usr/bin/realpath -e /proc/$$/fd/10)" = "$private_root"
test "$(/usr/bin/stat -Lc '%u:%a' /proc/$$/fd/10)" = "$(/usr/bin/id -u):700"
test "$(/usr/bin/stat -c '%d:%i' "$private_root")" = "$(/usr/bin/stat -Lc '%d:%i' /proc/$$/fd/10)"
/usr/bin/flock -n 10 || exit 75
/usr/bin/python3 scripts/ensure-private-directory-path.py "$directory"
test -d "$directory"; test ! -L "$directory"
test "$(/usr/bin/realpath -e "$directory")" = "$directory"
exec 9<"$directory"
test "$(/usr/bin/realpath -e /proc/$$/fd/9)" = "$directory"
test "$(/usr/bin/stat -Lc '%u:%a' /proc/$$/fd/9)" = "$(/usr/bin/id -u):700"
test "$(/usr/bin/stat -c '%d:%i' "$directory")" = "$(/usr/bin/stat -Lc '%d:%i' /proc/$$/fd/9)"
/usr/bin/flock -n 9 || exit 75
temporary=$(/usr/bin/mktemp -d -p /dev/shm usdom-phase-materializer.XXXXXXXX)
test "$(/usr/bin/stat -c '%u:%a' "$temporary")" = "$(/usr/bin/id -u):700"
temporary_identity=$(/usr/bin/stat -c '%u:%d:%i:%a' "$temporary")
cleanup(){ if test "$(/usr/bin/stat -c '%u:%d:%i:%a' "$temporary" 2>/dev/null)" = "$temporary_identity"; then /usr/bin/rm -rf -- "$temporary"; fi; }
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
candidate="$temporary/$phase.sh"
/usr/bin/bash --noprofile --norc scripts/generate-closed-mainnet-phase-command.sh "$phase" >"$candidate"
test -f "$candidate"; test ! -L "$candidate"
test "$(/usr/bin/stat -c '%u:%a:%h' "$candidate")" = "$(/usr/bin/id -u):600:1"
/usr/bin/bash --noprofile --norc -n "$candidate"
candidate_identity=$(/usr/bin/stat -c '%u:%d:%i:%a:%h:%s' "$candidate")
candidate_sha256=$(/usr/bin/sha256sum "$candidate"); candidate_sha256=${candidate_sha256%% *}
/usr/lib/chatgpt/resources/cua_node/bin/node scripts/check-closed-mainnet-phase-dependency.mjs \
  materialize "$phase" "$candidate"
test "$(/usr/bin/stat -c '%u:%d:%i:%a:%h:%s' "$candidate")" = "$candidate_identity"
test "$(/usr/bin/sha256sum "$candidate")" = "$candidate_sha256  $candidate"
test "$(/usr/bin/realpath -e /proc/$$/fd/10)" = "$private_root"
test "$(/usr/bin/stat -c '%d:%i' "$private_root")" = "$(/usr/bin/stat -Lc '%d:%i' /proc/$$/fd/10)"
test "$(/usr/bin/realpath -e /proc/$$/fd/9)" = "$directory"
test "$(/usr/bin/stat -c '%d:%i' "$directory")" = "$(/usr/bin/stat -Lc '%d:%i' /proc/$$/fd/9)"
target="$directory/$phase.sh"
/usr/lib/chatgpt/resources/cua_node/bin/node scripts/install-private-file-immutable-stdin.mjs "$target" <"$candidate"
test "$(/usr/bin/realpath -e /proc/$$/fd/10)" = "$private_root"
test "$(/usr/bin/stat -c '%d:%i' "$private_root")" = "$(/usr/bin/stat -Lc '%d:%i' /proc/$$/fd/10)"
test "$(/usr/bin/realpath -e /proc/$$/fd/9)" = "$directory"
test "$(/usr/bin/stat -c '%d:%i' "$directory")" = "$(/usr/bin/stat -Lc '%d:%i' /proc/$$/fd/9)"
printf '%s\n' "$target"
