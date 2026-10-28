import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

const root=new URL('../..',import.meta.url);
const script=new URL('../../scripts/install-release-config-stdin.mjs',import.meta.url);
const template=JSON.parse(await readFile(new URL(
  '../../config/mainnet-release-evidence.unconfigured.json',import.meta.url),'utf8'));

const invoke=(target,value)=>spawnSync(process.execPath,[script.pathname,target],{
  cwd:root,encoding:'utf8',input:JSON.stringify(value,null,2)+'\n',
});

test('shared release-evidence installer enforces global document invariants',async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-release-evidence-install-'));
  try {
    let target=path.join(directory,'mainnet-release-evidence.unconfigured.json');
    let result=invoke(target,template);
    assert.equal(result.status,0,result.stderr);

    await rm(target);
    const zero={...structuredClone(template),operationsReviewReport:{
      path:'evidence/operations.json',sha256:'0'.repeat(64),
    }};
    result=invoke(target,zero);
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/malformed document/);

    const duplicate={...structuredClone(template),
      operationsReviewReport:{path:'evidence/operations.json',sha256:'a'.repeat(64)},
      securityValidationReport:{path:'evidence/security.json',sha256:'a'.repeat(64)},
    };
    result=invoke(target,duplicate);
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/duplicate document content/);
  } finally {
    await rm(directory,{recursive:true,force:true});
  }
});
