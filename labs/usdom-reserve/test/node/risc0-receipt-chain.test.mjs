import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const checker=new URL('../../scripts/check-risc0-receipt-chain.py',import.meta.url);

test('all seven receipt chains bind version, ImageID, journal and Ethereum roots',()=>{
 const result=spawnSync('/usr/bin/python3',[checker.pathname,'--self-test'],{
  encoding:'utf8',env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},timeout:10_000,
 });
 assert.equal(result.status,0,result.stderr);
 assert.match(result.stdout,/PASS: 7\/7 RISC Zero/);
});

test('the checker inventory cannot silently omit a program or Ethereum root',async()=>{
 const source=await readFile(checker,'utf8');
 assert.equal([...source.matchAll(/^ '([a-z_]+)':'[0-9a-f]{64}',$/gm)].length,7);
 assert.match(source,/for key,image in \(\('checkpoint_adapter',IMAGES\['checkpoint_outer'\]\),\('burn_adapter',IMAGES\['finalized_burn'\]\)\)/);
 assert.match(source,/mutation removing receipt\.verify was accepted/);
 assert.match(source,/sha256\(abi\.encodePacked\(statementHash\)\)/);
});
