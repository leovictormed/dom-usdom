import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const helper='scripts/pinned-risc0-guest-toolchain.sh';
const builders=['checkpoint-segment','checkpoint-outer','economic-block','economic-chunk',
  'complete-randomx','randomx-aggregate'];

test('all six guest builders invoke byte-pinned guest and host toolchains directly',()=>{
  for(const name of builders) {
    const source=readFileSync(path.join(root,`scripts/build-${name}-risc0-guest.sh`),'utf8');
    assert.match(source,/source "\$repo\/labs\/usdom-reserve\/scripts\/pinned-risc0-guest-toolchain\.sh"/);
    assert.match(source,/pin_risc0_guest_toolchain "\$rustup_path" "\$expected_rustup_sha"/);
    assert.match(source,/rustup_path=\/home\/leonardov\/\.cargo\/bin\/rustup/);
    assert.match(source,/pin_host_rust_toolchain "\$rustup_path" "\$expected_rustup_sha"/);
    assert.match(source,/RUSTC="\$RISC0_GUEST_RUSTC" "\$RISC0_GUEST_CARGO" build --release --locked/);
    assert.match(source,/linker='"\$RISC0_GUEST_RUST_LLD"/);
    assert.match(source,/RUSTC="\$HOST_RUSTC" "\$HOST_CARGO" run --quiet --locked/);
    assert.doesNotMatch(source,/"\$cargo_path" \+risc0 build/);
    assert.doesNotMatch(source,/command -v (?:cargo|rustup)/);
    assert.doesNotMatch(source,/cargo_path/);
    assert.ok(source.indexOf('assert_risc0_guest_toolchain_unchanged')
      < source.indexOf('user_elf="$CARGO_TARGET_DIR/'));
    assert.ok(source.lastIndexOf('assert_host_rust_toolchain_unchanged')
      < source.indexOf('test "$actual_id" = "$expected_id"'));
  }
});

test('installed guest and host compiler pairs match the immutable byte pins',()=>{
  const script=`set -euo pipefail
source ${JSON.stringify(path.join(root,helper))}
pin_risc0_guest_toolchain /home/leonardov/.cargo/bin/rustup 4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
pin_host_rust_toolchain /home/leonardov/.cargo/bin/rustup 4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
assert_risc0_guest_toolchain_unchanged
assert_host_rust_toolchain_unchanged
printf '%s\n%s\n%s\n%s\n%s\n' "$RISC0_GUEST_CARGO" "$RISC0_GUEST_RUSTC" "$RISC0_GUEST_RUST_LLD" "$HOST_CARGO" "$HOST_RUSTC"
`;
  const result=spawnSync('/usr/bin/bash',['-c',script],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stdout,
    '/home/leonardov/.risc0/toolchains/v1.97.0-rust-x86_64-unknown-linux-gnu/bin/cargo\n'+
    '/home/leonardov/.risc0/toolchains/v1.97.0-rust-x86_64-unknown-linux-gnu/bin/rustc\n'+
    '/home/leonardov/.risc0/toolchains/v1.97.0-rust-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld\n'+
    '/home/leonardov/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo\n'+
    '/home/leonardov/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc\n');
});
