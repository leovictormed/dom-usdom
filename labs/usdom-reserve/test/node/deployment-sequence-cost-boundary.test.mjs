import test from 'node:test';
import assert from 'node:assert/strict';
import {chmod,mkdtemp,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST}
  from '../../sdk/mainnet-deployment-execution.mjs';

const script=fileURLToPath(new URL('../../scripts/check-mainnet-deployment-sequence-cost.mjs',import.meta.url));
const run=(directory,index,cost)=>spawnSync(process.execPath,[script,index,cost],{
  encoding:'utf8',env:{...process.env,USDOM_CONTROL_EVIDENCE_DIRECTORY:directory},
});
const hash=n=>'0x'+n.toString(16).padStart(64,'0');
const rawEvidence=()=>({schema:'usdom-mainnet-deployment-raw-validation-v1',index:'0',
  name:'finalizedBurnVerifier',from:'0x00000000000000000000000000000000000000AA',nonce:'8',
  expectedContract:'0x00000000000000000000000000000000000000bb',transactionHash:hash(6),
  gasLimit:'100000',maxFeePerGas:'10000000000',maxPriorityFeePerGas:'2000000000',
  maximumCost:'1000000000000000',chainId:'1',releaseConfigSha256:'11'.repeat(32),
  packageSha256:'22'.repeat(32),rpcCatalogSha256:'33'.repeat(32),
  observationDocumentSha256:'44'.repeat(32),observationHash:hash(5),rawSha256:'55'.repeat(32)});

test('deployment sequence cost bounds current and persisted values before BigInt',async t=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-sequence-cost-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  assert.equal(run(directory,'0','100').stdout,'100\n');
  for(const cost of ['9'.repeat(100_000),(MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST+1n).toString(),'01','-1']) {
    const result=run(directory,'0',cost);
    assert.equal(result.status,1);
    assert.equal(result.stderr.includes(cost),false);
  }
  const evidence=path.join(directory,'contract-deployment-0-raw-validation.json');
  await writeFile(evidence,JSON.stringify({schema:'usdom-mainnet-deployment-raw-validation-v1',
    index:'0',maximumCost:'100'}),{mode:0o600});
  await chmod(evidence,0o600);
  assert.equal(run(directory,'1','100').status,1);
  await writeFile(evidence,JSON.stringify(rawEvidence()),{mode:0o600});
  await chmod(evidence,0o600);
  assert.equal(run(directory,'1','100').stdout,'1000000000000100\n');
  const ambiguous=rawEvidence(); ambiguous.extra=true;
  await writeFile(evidence,JSON.stringify(ambiguous),{mode:0o600});
  assert.equal(run(directory,'1','100').status,1);
  for(const maximumCost of ['9'.repeat(100_000),
    (MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST+1n).toString()]) {
    await writeFile(evidence,JSON.stringify({schema:'usdom-mainnet-deployment-raw-validation-v1',
      index:'0',maximumCost}),{mode:0o600});
    await chmod(evidence,0o600);
    const result=run(directory,'1','100');
    assert.equal(result.status,1);
    assert.equal(result.stderr.includes(maximumCost),false);
  }
});
