#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
if ! ulimit -c 0; then echo 'Cannot disable core dumps for pilot authorization.' >&2; exit 1; fi
if (($#)); then echo 'Usage: sign-pilot-funds-authorization.sh' >&2; exit 64; fi
unset BASH_ENV ENV CDPATH
for fd_path in /proc/$$/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ "$inherited_fd" =~ ^[0-9]+$ ]] || exit 1
  ((inherited_fd > 2)) || continue
  [[ "$inherited_fd" == 255 ]] && continue
  exec {inherited_fd}>&-
done
exec /usr/bin/bash --noprofile --norc scripts/sign-release-authorizations.sh pilot
