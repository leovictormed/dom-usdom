import assert from 'node:assert/strict';
import {chmodSync,mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {getAddress} from 'ethers';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');
const helper=path.join(root,'scripts/prepare-safe-deployment-private-input.mjs');
const run=file=>spawnSync(process.execPath,[helper,'governance',file],{cwd:root,encoding:'utf8'});

test('private transaction boundary canonicalizes address/data and rejects zero target',()=>{
  const directory=mkdtempSync(path.join(tmpdir(),'usdom-private-canonical-'));
  try{
    const file=path.join(directory,'package.json');
    const write=(to,data)=>{writeFileSync(file,`${JSON.stringify({controls:[{role:'governance',to,data}]})}\n`,{mode:0o600});chmodSync(file,0o600);};
    const target='0x00000000000000000000000000000000000000AA';
    write(target,'0xAABBCCDD');
    const accepted=run(file);assert.equal(accepted.status,0,accepted.stderr);
    assert.deepEqual(JSON.parse(accepted.stdout),{
      to:getAddress(target),data:'0xaabbccdd',
      dataHash:'0x40eed0325a12c6c6af8db2ea05450bfe21d6343b6fe955bff65045b67d9d5fe6',selector:'0xaabbccdd',
    });
    write('0x0000000000000000000000000000000000000000','0xAABBCCDD');
    assert.notEqual(run(file).status,0);
    write('0x00000000000000000000000000000000000000aA','0xAABBCCDD');
    assert.notEqual(run(file).status,0);
    write(target,'0xABC');
    assert.notEqual(run(file).status,0);
  }finally{rmSync(directory,{recursive:true,force:true});}
});
