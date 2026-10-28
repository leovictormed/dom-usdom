import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(new URL('../..',import.meta.url).pathname);
const checker=path.join(root,'scripts/check-safe-control-deployment-finality.mjs');
const run=(finalized,receipt)=>spawnSync(process.execPath,[checker,finalized,receipt],{
  cwd:root,encoding:'utf8'});

test('Safe deployment finality compares decimal finalized height to Ethereum quantity',()=>{
  assert.equal(run('16','0x10').status,0);
  assert.equal(run('17','0x10').status,0);
  for(const [finalized,receipt] of [
    ['15','0x10'],['0x10','0x10'],['016','0x10'],['16','16'],['16','0x010'],
    ['18446744073709551616','0x10'],['18446744073709551615','0x10000000000000000'],
    ['9'.repeat(100000),'0x10'],
  ]) assert.notEqual(run(finalized,receipt).status,0,`${finalized.slice(0,24)} ${receipt}`);
});
