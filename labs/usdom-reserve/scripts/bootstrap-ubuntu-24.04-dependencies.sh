#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C LANG=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
test "$#" -eq 1; mode=$1; [[ $mode == --verify-only || $mode == --install ]]
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
lock="$root/config/ubuntu-24.04-bootstrap-lock.json"
test -f "$lock" && test ! -L "$lock"
test "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = ubuntu:24.04
mapfile -t specs < <(jq -er '.packages|to_entries|sort_by(.key)[]|"\(.key)=\(.value)"' "$lock")
if [[ $mode == --install ]]; then
  test "$(id -u)" -eq 0 || { printf '%s\n' 'Run this exact command explicitly as root; there is no internal privilege escalation.' >&2; exit 77; }
  apt-get update
  apt-get install --no-install-recommends --yes "${specs[@]}"
fi
for spec in "${specs[@]}"; do test "$(dpkg-query -W -f='${Version}' "${spec%%=*}")" = "${spec#*=}"; done
while IFS=$'\t' read -r executable expected; do
  test -f "$executable" && test ! -L "$executable"
  test "$(sha256sum "$executable" | awk '{print $1}')" = "$expected"
done < <(jq -er '.executables|to_entries|sort_by(.key)[]|[.key,.value]|@tsv' "$lock")
printf '%s\n' 'PASS: Ubuntu 24.04 bootstrap dependencies verified; run check-mainnet-toolchain next'
