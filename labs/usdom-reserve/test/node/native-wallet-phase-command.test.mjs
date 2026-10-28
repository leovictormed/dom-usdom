import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');

test('native wallet phase publishes and validates only the exact public identity',()=>{
  const result=spawnSync('/usr/bin/bash',[
    path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'prepare-native-wallet-secret',
  ],{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,0,result.stderr);
  const source=result.stdout;
  assert.match(source,/prepare:native-receiving-wallet > "\$candidate"/);
  assert.match(source,/install-private-file-immutable-stdin\.mjs "\$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC"/);
  assert.match(source,/read-private-file-stdout\.mjs "\$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC" > "\$installed"/);
  assert.match(source,/cmp -s "\$candidate" "\$installed"/);
  for(const field of ['chainScalar','domDomain','privacyPolicyHash','receivingCommitment','recipientAddress','schema']) {
    assert.ok(source.includes(`"${field}"`),field);
  }
  assert.doesNotMatch(source,/backupPath|recovery\.usdom|cat .*recovery|wallet sign|broadcast/);
});
