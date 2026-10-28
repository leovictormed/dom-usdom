#!/usr/bin/env bash
set +x
unset BASH_XTRACEFD 2>/dev/null || true
set -euo pipefail
umask 077
export LC_ALL=C LANG=C TZ=UTC PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME
ulimit -c 0 || exit 1
for inherited_function in $(compgen -A function); do unset -f "$inherited_function"; done
for fd_path in /proc/"$$"/fd/*; do inherited_fd=${fd_path##*/}; [[ $inherited_fd =~ ^[0-9]+$ ]] || exit 1; (( inherited_fd <= 2 )) && continue; [[ $inherited_fd == 255 ]] && continue; exec {inherited_fd}>&-; done
readonly root=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
readonly private=/home/leonardov/usdom-mainnet-private
test "$#" -eq 0 || exit 64
cd "$root"
test -d "$private"; test ! -L "$private"; test "$(/usr/bin/realpath -e "$private")" = "$private"; test "$(/usr/bin/stat -c '%u:%a' "$private")" = "$(/usr/bin/id -u):700"
exec 9<"$private"
test "$(/usr/bin/realpath -e /proc/$$/fd/9)" = "$private"
test "$(/usr/bin/stat -c '%d:%i' "$private")" = "$(/usr/bin/stat -Lc '%d:%i' /proc/$$/fd/9)"
/usr/bin/flock -n 9 || exit 75
/usr/lib/chatgpt/resources/cua_node/bin/node scripts/archive-closed-mainnet-phase-generation.mjs
test "$(/usr/bin/realpath -e /proc/$$/fd/9)" = "$private"
test "$(/usr/bin/stat -c '%d:%i' "$private")" = "$(/usr/bin/stat -Lc '%d:%i' /proc/$$/fd/9)"
