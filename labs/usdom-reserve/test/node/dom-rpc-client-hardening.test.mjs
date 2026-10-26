import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const names=['initialize-closed-mainnet-genesis.mjs','mine-closed-mainnet-issuance-block.mjs',
  'submit-finalized-deposit-issuance.mjs'];

test('all DOM operator RPC clients are loopback, bounded and structurally parsed',()=>{
  for(const name of names){
    const file=fileURLToPath(new URL(`../../scripts/${name}`,import.meta.url));
    assert.equal(spawnSync(process.execPath,['--check',file]).status,0,name);
    const source=readFileSync(file,'utf8');
    assert.match(source,/hostname:'127\.0\.0\.1',port:33372/,name);
    assert.match(source,/authorization:`Bearer \$\{token\}`/,name);
    assert.match(source,/DOM RPC response exceeds 64 KiB/,name);
    assert.match(source,/maxNodes:10_000/,name);
    assert.match(source,/req\.on\('timeout'/,name);
  }
});

test('issuance mutation double-reads DOM identity before and after admission',()=>{
  const source=readFileSync(new URL('../../scripts/submit-finalized-deposit-issuance.mjs',
    import.meta.url),'utf8');
  assert.match(source,/const beforeRecheck=validateDomMainnetIdentity/);
  assert.match(source,/DOM chain identity changed before issuance submission/);
  assert.match(source,/const afterRecheck=validateDomMainnetIdentity/);
  assert.match(source,/DOM chain identity changed after issuance submission/);
});
