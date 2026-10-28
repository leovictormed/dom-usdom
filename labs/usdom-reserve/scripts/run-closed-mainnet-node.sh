#!/usr/bin/env bash
set -euo pipefail
# These entrypoints handle reusable wallet/RPC/TPM credentials.  Refuse shell
# tracing inherited from `bash -x`, suppress Rust panic backtraces, and prevent
# children from writing memory-bearing core dumps.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent run:closed-mainnet-node' >&2
  exit 2
fi
BUILD_ONLY=${USDOM_CLOSED_MAINNET_BUILD_ONLY:-NO}
SUPERVISED=${USDOM_CLOSED_MAINNET_SUPERVISED:-NO}
[[ "$BUILD_ONLY" == NO || "$BUILD_ONLY" == YES ]] || exit 64
[[ "$SUPERVISED" == NO || "$SUPERVISED" == YES ]] || exit 64
[[ "$BUILD_ONLY" != YES || "$SUPERVISED" != YES ]] || exit 64

LAB_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPOSITORY_ROOT=$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout cargo; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
pin_runtime_tool cargo
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
RUNTIME_ROOT="$LAB_ROOT/evidence/native-runtime"
if [[ -n "${USDOM_CHECKPOINT_RESTART_RUNTIME_ROOT:-}" ]]; then
  if [[ "${USDOM_RUN_CHECKPOINT_RESTART_WITNESS:-}" != YES \
      || ! "$USDOM_CHECKPOINT_RESTART_RUNTIME_ROOT" =~ ^/[^[:space:]]+$ \
      || -L "$USDOM_CHECKPOINT_RESTART_RUNTIME_ROOT" \
      || ! -d "$USDOM_CHECKPOINT_RESTART_RUNTIME_ROOT" ]]; then
    printf '%s\n' 'Unsafe checkpoint restart runtime snapshot.' >&2
    exit 1
  fi
  RUNTIME_ROOT=$(CDPATH='' cd -- "$USDOM_CHECKPOINT_RESTART_RUNTIME_ROOT" && pwd -P)
fi
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"
NODE_ROOT="$HOME/.local/share/dom-usdom/mainnet-node"
DATA_ROOT="$NODE_ROOT/data"
TOKEN_FILE="$NODE_ROOT/rpc.token"

for required in "$MANIFEST" "$MANIFEST_PIN"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Missing direct regular file: %s\n' "$required" >&2
    exit 1
  fi
done
IFS= read -r manifest_sha256 < "$MANIFEST_PIN"
if [[ ! "$manifest_sha256" =~ ^[0-9a-f]{64}$ ]] \
  || [[ $(wc -l < "$MANIFEST_PIN") -ne 1 ]] \
  || [[ $(sha256sum -- "$MANIFEST" | cut -d ' ' -f 1) != "$manifest_sha256" ]]; then
  printf '%s\n' 'Native runtime manifest does not match its exact SHA-256 pin.' >&2
  exit 1
fi

mkdir -p -- "$NODE_ROOT" "$DATA_ROOT"
chmod 700 -- "$NODE_ROOT" "$DATA_ROOT"
run_pinned_timeout --signal=TERM --kill-after=2s 30s \
  python3 - "$NODE_ROOT" "$DATA_ROOT" <<'PY'
import os
import re
import secrets
import stat
import sys

node_root, data_root = map(os.path.abspath, sys.argv[1:])
uid = os.getuid()
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def reject(message):
    raise SystemExit(message)

def validate_directory(path, expected_mode):
    try:
        named = os.lstat(path)
    except OSError as error:
        reject(f"Unsafe closed-mainnet directory: {path}: {error}")
    if (not stat.S_ISDIR(named.st_mode) or stat.S_IMODE(named.st_mode) != expected_mode
            or named.st_uid != uid or os.path.realpath(path) != path):
        reject(f"Unsafe closed-mainnet directory: {path}")
    try:
        descriptor = os.open(path, directory_flags)
    except OSError as error:
        reject(f"Unsafe closed-mainnet directory: {path}: {error}")
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        os.close(descriptor)
        reject(f"Closed-mainnet directory changed while opening: {path}")
    return descriptor, opened

root_fd, root_identity = validate_directory(node_root, 0o700)
try:
    try:
        data_fd = os.open("data", directory_flags, dir_fd=root_fd)
    except OSError as error:
        reject(f"Unsafe closed-mainnet data directory: {error}")
    try:
        data_opened = os.fstat(data_fd)
        data_named = os.lstat(data_root)
        if (not stat.S_ISDIR(data_opened.st_mode)
                or stat.S_IMODE(data_opened.st_mode) != 0o700
                or data_opened.st_uid != uid
                or (data_opened.st_dev, data_opened.st_ino) != (data_named.st_dev, data_named.st_ino)
                or os.path.realpath(data_root) != data_root):
            reject("Unsafe closed-mainnet data directory")
    finally:
        os.close(data_fd)

    token_name = "rpc.token"
    try:
        token_named = os.stat(token_name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        token_named = None
    except OSError as error:
        reject(f"Unsafe DOM RPC token: {error}")

    if token_named is None:
        token_flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            token_fd = os.open(token_name, token_flags, 0o600, dir_fd=root_fd)
        except OSError as error:
            reject(f"Cannot create DOM RPC token safely: {error}")
        try:
            payload = (secrets.token_hex(32) + "\n").encode("ascii")
            offset = 0
            while offset < len(payload):
                written = os.write(token_fd, payload[offset:])
                if written <= 0:
                    reject("Short write while creating DOM RPC token")
                offset += written
            os.fsync(token_fd)
        finally:
            os.close(token_fd)
        os.fsync(root_fd)

    try:
        token_fd = os.open(token_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
    except OSError as error:
        reject(f"Unsafe DOM RPC token: {error}")
    try:
        token_opened = os.fstat(token_fd)
        token_named = os.stat(token_name, dir_fd=root_fd, follow_symlinks=False)
        if (not stat.S_ISREG(token_opened.st_mode)
                or stat.S_IMODE(token_opened.st_mode) != 0o600
                or token_opened.st_uid != uid or token_opened.st_nlink != 1
                or (token_opened.st_dev, token_opened.st_ino) != (token_named.st_dev, token_named.st_ino)):
            reject("DOM RPC token must be a direct owner-only single-link file")
        payload = bytearray()
        while len(payload) <= 65:
            chunk = os.read(token_fd, 66 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != 65 or re.fullmatch(rb"[0-9a-f]{64}\n", payload) is None:
            reject("DOM RPC token must contain exactly 32-byte lowercase hex")
        if os.read(token_fd, 1):
            reject("DOM RPC token exceeds its canonical length")
    finally:
        os.close(token_fd)

    root_named = os.lstat(node_root)
    if ((root_named.st_dev, root_named.st_ino) != (root_identity.st_dev, root_identity.st_ino)
            or os.path.realpath(node_root) != node_root):
        reject("Closed-mainnet directory changed while preparing its token")
finally:
    os.close(root_fd)
PY

exec 8<"$NODE_ROOT"
flock -n 8 || {
  printf '%s\n' 'Another node or offline exporter holds the mainnet data lock.' >&2
  exit 75
}

cd "$REPOSITORY_ROOT"
CARGO_HOME_FIXED="$HOME/.cargo"
config_search="$REPOSITORY_ROOT"
while :; do
  if [[ -e "$config_search/.cargo/config" || -L "$config_search/.cargo/config" \
      || -e "$config_search/.cargo/config.toml" || -L "$config_search/.cargo/config.toml" ]]; then
    printf '%s\n' 'Cargo configuration overrides are forbidden for the production node build.' >&2
    exit 1
  fi
  [[ "$config_search" == / ]] && break
  config_search=${config_search%/*}; [[ -n "$config_search" ]] || config_search=/
done
NODE_BINARY="$REPOSITORY_ROOT/target/release/dom-node"
if [[ "$SUPERVISED" == YES ]]; then
  expected=${USDOM_CLOSED_MAINNET_EXPECTED_BINARY_SHA256:-}
  [[ "$expected" =~ ^[0-9a-f]{64}$ && -f "$NODE_BINARY" && ! -L "$NODE_BINARY" ]] || exit 1
  [[ $(sha256sum -- "$NODE_BINARY" | cut -d ' ' -f 1) == "$expected" ]] || exit 1
else
  assert_runtime_tool cargo
  run_pinned_timeout --signal=TERM --kill-after=30s 3600s \
    env -i HOME="$HOME" USER="${USER:-}" LOGNAME="${LOGNAME:-}" \
    PATH=/usr/bin:/bin LANG=C LC_ALL=C CARGO_HOME="$CARGO_HOME_FIXED" \
    CARGO_TARGET_DIR="$REPOSITORY_ROOT/target" CARGO_INCREMENTAL=0 \
    RUST_BACKTRACE=0 RUST_LIB_BACKTRACE=0 \
    "$cargo_bin" build --quiet --release --frozen --no-default-features -p dom-node \
    --features native-usdom-v4-poc --bin dom-node
fi
[[ "$BUILD_ONLY" == YES ]] && exit 0

export DOM_LOG=info
export DOM_NETWORK=mainnet
export DOM_DATA_DIR="$DATA_ROOT"
export DOM_P2P_LISTEN_ADDR=127.0.0.1:33369
export DOM_MIN_OUTBOUND=0
export DOM_MAX_INBOUND=0
export DOM_DISABLE_DNS_SEEDS=true
export DOM_MINE=false
export DOM_CLOSED_MAINNET_TEST=true
export DOM_RPC_LISTEN_ADDR=default
export DOM_RPC_BEARER_TOKEN_FILE="$TOKEN_FILE"
export DOM_USDOM_V4_MANIFEST_FILE="$MANIFEST"
export DOM_USDOM_V4_MANIFEST_SHA256="$manifest_sha256"
exec "$NODE_BINARY"
