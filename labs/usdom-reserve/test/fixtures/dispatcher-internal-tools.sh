#!/usr/bin/bash
set -euo pipefail
node --version
npm --version
python3 --version
forge --version | head -n 1
cast --version | head -n 1
rustc --version
cargo --version
solc --version | tail -n 1
jq --version
