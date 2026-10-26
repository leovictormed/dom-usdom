import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source=await readFile(new URL(
  '../../scripts/run-closed-mainnet-node.sh',import.meta.url),'utf8');

test('production Cargo child receives a fixed allowlisted environment',()=>{
  assert.match(source,/env -i HOME="\$HOME" USER="\$\{USER:-\}" LOGNAME="\$\{LOGNAME:-\}"/);
  assert.match(source,/PATH=\/usr\/bin:\/bin LANG=C LC_ALL=C CARGO_HOME="\$CARGO_HOME_FIXED"/);
  assert.match(source,/CARGO_TARGET_DIR="\$REPOSITORY_ROOT\/target" CARGO_INCREMENTAL=0/);
  assert.match(source,/RUST_BACKTRACE=0 RUST_LIB_BACKTRACE=0/);
  for(const ambient of ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER',
    'RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET','RUSTUP_TOOLCHAIN','CC','CFLAGS','LDFLAGS']) {
    assert.doesNotMatch(source,new RegExp(`env -i[^\\n]*${ambient}=`),ambient);
  }
});

test('Cargo executable and hierarchical configuration are fail-closed',()=>{
  assert.match(source,/pin_runtime_tool cargo/);
  assert.match(source,/assert_runtime_tool cargo/);
  assert.match(source,/"\$cargo_bin" build --quiet --release --frozen/);
  assert.match(source,/\.cargo\/config" \|\| -L .*\.cargo\/config"/);
  assert.match(source,/\.cargo\/config\.toml" \|\| -L .*\.cargo\/config\.toml"/);
  assert.match(source,/while :; do[\s\S]*\[\[ "\$config_search" == \/ \]\] && break/);
});
