#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
readonly project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
readonly manifest="$project/config/solc-0.8.37-official-manifest.json"
readonly directory=/home/leonardov/.svm/0.8.37
readonly target="$directory/solc-0.8.37"
cd "$project"

test "$(id -u)" -eq "$(stat -c '%u' /home/leonardov)"
test -f "$manifest" && test ! -L "$manifest"
origin=$(jq -er '.origin' "$manifest")
expected=$(jq -er '.sha256' "$manifest")
version=$(jq -er '.version' "$manifest")
test "$origin" = 'https://github.com/argotorg/solidity/releases/download/v0.8.37/solc-static-linux'
[[ $expected =~ ^[0-9a-f]{64}$ ]]
test "$version" = '0.8.37+commit.f401782d.Linux.g++'

install -d -m 0700 "$directory"
test "$(realpath -e "$directory")" = "$directory"
test "$(stat -c '%u:%a' "$directory")" = "$(id -u):700"
if test -e "$target" || test -L "$target"; then
  test -f "$target" && test ! -L "$target" && test "$(stat -c '%u:%a:%h' "$target")" = "$(id -u):700:1"
  test "$(sha256sum "$target" | awk '{print $1}')" = "$expected"
else
  candidate=$(mktemp "$directory/.solc-0.8.37.XXXXXXXX")
  trap 'rm -f -- "$candidate"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout 15 --max-time 300 --max-filesize 67108864 \
    --retry 3 --retry-all-errors \
    --output "$candidate" "$origin"
  test "$(sha256sum "$candidate" | awk '{print $1}')" = "$expected"
  chmod 0700 "$candidate"
  test "$("$candidate" --version | tail -n 1)" = "Version: $version"
  ln "$candidate" "$target"
  rm -f -- "$candidate"
  trap - EXIT
  sync -f "$target"
fi
node scripts/materialize-solc-toolchain-lock.mjs
node scripts/check-mainnet-toolchain.mjs
