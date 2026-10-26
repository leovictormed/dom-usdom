#!/usr/bin/env bash
set -euo pipefail
# These short-lived operators read the local RPC bearer token. Refuse inherited
# tracing and crash artifacts before Node captures the token into process memory.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a token-bearing operation.' >&2
  exit 1
fi
umask 077

if (($# != 1)); then
  printf '%s\n' 'Internal usage: run-secret-node-entrypoint.sh ENTRYPOINT' >&2
  exit 64
fi
case $1 in
  submit-finalized-deposit-issuance.mjs|initialize-closed-mainnet-genesis.mjs|mine-closed-mainnet-issuance-block.mjs)
    entrypoint=$1
    ;;
  *)
    printf '%s\n' 'Unsupported token-bearing Node entrypoint.' >&2
    exit 64
    ;;
esac
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
for command in node env realpath stat dirname sha256sum cut id; do command -v "$command" >/dev/null; done
NODE_BIN=$(realpath "$(command -v node)")
test -x "$NODE_BIN"; test -f "$NODE_BIN"; test ! -L "$NODE_BIN"
node_owner=$(stat -Lc '%u' "$NODE_BIN"); test "$node_owner" = 0 || test "$node_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$NODE_BIN")" = 1
node_size=$(stat -Lc '%s' "$NODE_BIN"); (( node_size > 0 && node_size <= 512 * 1024 * 1024 ))
node_mode=$(stat -Lc '%a' "$NODE_BIN"); (( (8#$node_mode & 8#022) == 0 ))
node_directory=$(dirname "$NODE_BIN")
test "$(realpath "$node_directory")" = "$node_directory"
node_directory_owner=$(stat -Lc '%u' "$node_directory"); test "$node_directory_owner" = 0 || test "$node_directory_owner" = "$(id -u)"
node_directory_mode=$(stat -Lc '%a' "$node_directory"); (( (8#$node_directory_mode & 8#022) == 0 ))
node_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$node_directory")
node_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")
node_sha256=$(sha256sum "$NODE_BIN" | cut -d ' ' -f 1)
ENV_BIN=$(realpath "$(command -v env)")
test -x "$ENV_BIN"; test -f "$ENV_BIN"; test ! -L "$ENV_BIN"
env_owner=$(stat -Lc '%u' "$ENV_BIN"); test "$env_owner" = 0 || test "$env_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$ENV_BIN")" = 1
env_size=$(stat -Lc '%s' "$ENV_BIN"); (( env_size > 0 && env_size <= 512 * 1024 * 1024 ))
env_mode=$(stat -Lc '%a' "$ENV_BIN"); (( (8#$env_mode & 8#022) == 0 ))
env_directory=$(dirname "$ENV_BIN"); test "$(realpath "$env_directory")" = "$env_directory"
env_directory_owner=$(stat -Lc '%u' "$env_directory"); test "$env_directory_owner" = 0 || test "$env_directory_owner" = "$(id -u)"
env_directory_mode=$(stat -Lc '%a' "$env_directory"); (( (8#$env_directory_mode & 8#022) == 0 ))
env_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$env_directory")
env_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$ENV_BIN")
env_sha256=$(sha256sum "$ENV_BIN" | cut -d ' ' -f 1)
test "$(realpath "$(command -v env)")" = "$ENV_BIN"
test "$(stat -Lc '%d:%i:%u:%a' "$env_directory")" = "$env_directory_identity"
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$ENV_BIN")" = "$env_identity"
test "$(sha256sum "$ENV_BIN" | cut -d ' ' -f 1)" = "$env_sha256"
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$ENV_BIN")" = "$env_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$env_directory")" = "$env_directory_identity"
test "$(realpath "$(command -v node)")" = "$NODE_BIN"
test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")" = "$node_identity"
test "$(sha256sum "$NODE_BIN" | cut -d ' ' -f 1)" = "$node_sha256"
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")" = "$node_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
exec "$ENV_BIN" -i HOME="$HOME" USDOM_SECRET_NODE_LAUNCHER=1 \
  "$NODE_BIN" "scripts/$entrypoint"
