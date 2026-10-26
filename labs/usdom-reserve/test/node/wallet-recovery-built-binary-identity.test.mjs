import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const script=name=>readFileSync(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
const scriptPath=name=>fileURLToPath(new URL(`../../scripts/${name}`,import.meta.url));

test('receiving wallet authenticates the built executable before credentials and execution',()=>{
  const name='prepare-native-receiving-wallet.sh',source=script(name);
  assert.equal(spawnSync('bash',['-n',scriptPath(name)],
    {encoding:'utf8'}).status,0);
  for(const marker of [
    'test -f "$WALLET_RECOVERY_BIN"; test -x "$WALLET_RECOVERY_BIN"; test ! -L "$WALLET_RECOVERY_BIN"',
    "wallet_recovery_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h'",
    'wallet_recovery_sha256=$(sha256sum -- "$WALLET_RECOVERY_BIN"',
    'wallet_recovery_directory_identity=$(stat -Lc',
    'assert_wallet_recovery_binary_unchanged',
  ]) assert.match(source,new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  const pin=source.indexOf('wallet_recovery_identity=$(stat');
  const prompt=source.indexOf("read -r -s -p 'Digite a senha");
  const recheck=source.lastIndexOf('assert_wallet_recovery_binary_unchanged');
  const execute=source.indexOf('run_pinned_timeout --signal=TERM --kill-after=5s 300s "${COMMAND[@]}"');
  assert.ok(pin>0&&pin<prompt&&recheck>prompt&&recheck<execute);
});

test('checkpoint recovery authenticates both built executables before secrets and each use',()=>{
  const name='drill-closed-mainnet-wallet-recovery.sh',source=script(name);
  assert.equal(spawnSync('bash',['-n',scriptPath(name)],
    {encoding:'utf8'}).status,0);
  assert.match(source,/test -f "\$built_binary"; test -x "\$built_binary"; test ! -L "\$built_binary"/);
  assert.match(source,/keystore_binary_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h'/);
  assert.match(source,/recovery_binary_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h'/);
  assert.match(source,/built_binary_directory_identity=\$\(stat -Lc '%d:%i:%u:%a'/);
  for(const binary of ['keystore','recovery']) {
    const recheck=source.indexOf(`"$${binary}_binary")" = "$${binary}_binary_identity"`);
    const executable=binary==='keystore'?'target/release/dom-usdom-wallet-tpm-keystore':'target/release/dom-usdom-recover-wallet-at-checkpoint';
    const execute=source.lastIndexOf(executable);
    assert.ok(recheck>0&&recheck<execute,binary);
  }
});
