import assert from 'node:assert/strict';
import {access,readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');
const script=name=>readFile(path.join(root,'scripts',name),'utf8');

test('checkpoint consensus collection bounds local preparation and RPC collection',async()=>{
  const source=await script('collect-ethereum-checkpoint-consensus.sh');
  assert.match(source,/timeout --signal=TERM --kill-after=2s 30s[\s\\]+python3 /);
  assert.match(source,/timeout --signal=TERM --kill-after=5s 300s[\s\\]+node /);
  for(const [signal,status] of [['HUP','129'],['INT','130'],['TERM','143']]) {
    assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`));
  }
  assert.doesNotMatch(source,/(?:^|\s)&\s*(?:#.*)?$/m);
});

test('finalized deposit and closed-mainnet preparation bound every remote or Ledger child',async()=>{
  const [collector,deposit]=await Promise.all([
    script('collect-finalized-deposit-source.sh'),script('prepare-closed-mainnet-deposit.sh'),
  ]);
  assert.match(collector,/timeout --signal=TERM --kill-after=5s 300s[\s\\]+node scripts\/collect-finalized-deposit-source\.mjs/);
  assert.equal((deposit.match(/timeout --signal=TERM --kill-after=5s 300s cast wallet address --ledger/g)??[]).length,2);
  assert.match(deposit,/exec timeout --signal=TERM --kill-after=2s 120s[\s\\]+node scripts\/prepare-closed-mainnet-deposit\.mjs/);
  assert.doesNotMatch(`${collector}\n${deposit}`,/(?:^|\s)&\s*(?:#.*)?$/m);
});

test('obsolete shell deployment preparer is absent',async()=>{
  await assert.rejects(access(path.join(root,'scripts','prepare-mainnet-deployment.sh')),
    error=>error?.code==='ENOENT');
  for(const name of ['prepare-mainnet-deployment.mjs','prepare-mainnet-deployment-transaction.mjs']) {
    await access(path.join(root,'scripts',name));
  }
});
