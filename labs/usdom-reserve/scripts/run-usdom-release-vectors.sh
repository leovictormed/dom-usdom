#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${USDOM_RUN_LONG_RELEASE_TEST-}" != "YES" ]]; then
  echo 'refusing: set USDOM_RUN_LONG_RELEASE_TEST=YES for mandatory USDOM release vectors' >&2
  exit 64
fi

"$here/run-randomx-cache-release-vector.sh"
"$here/run-checkpoint-390-release-vector.sh"
