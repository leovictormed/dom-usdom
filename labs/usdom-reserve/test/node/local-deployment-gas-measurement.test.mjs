import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile} from 'node:fs/promises';
import path from 'node:path';

const run=promisify(execFile);
const root=path.resolve(import.meta.dirname,'../..');
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';

test('fresh local CREATE gas evidence reproduces exactly with pinned Anvil',async()=>{
  const evidence=await readFile(path.join(root,'docs/LOCAL-DEPLOYMENT-GAS-MEASUREMENT-2026-10-26.json'),'utf8');
  const {stdout,stderr}=await run(node,['scripts/measure-local-deployment-gas.mjs'],{
    cwd:root,timeout:180_000,maxBuffer:4*1024*1024,
  });
  assert.equal(stderr,''); assert.equal(stdout,evidence);
  const report=JSON.parse(evidence);
  assert.equal(report.schema,'usdom-local-deployment-gas-measurement/v1');
  assert.equal(report.runs,2); assert.equal(report.network,'anvil-local-chain-31337');
  assert.equal(report.anvil.sha256,'00f97668e1ae0fcca118fd7d2d1b6d25c0496447a523ca6bc2dfd10958c99604');
  assert.deepEqual(Object.keys(report.contracts),[
    'finalizedBurnVerifier','checkpointVerifier','checkpointRegistry','reserve',
  ]);
  for(const value of Object.values(report.contracts)) {
    assert(BigInt(value.gasUsed)>0n);
    assert.equal(BigInt(value.auditedCreateGasCeiling)-BigInt(value.gasUsed),
      BigInt(value.measuredMargin));
    assert(BigInt(value.plannedGasLimit)>BigInt(value.gasUsed));
  }
  assert.equal(report.contracts.reserve.runtimeBytes,20100);
  const measured=Object.values(report.contracts).reduce((sum,value)=>sum+BigInt(value.gasUsed),0n);
  const planned=Object.values(report.contracts).reduce((sum,value)=>sum+BigInt(value.plannedGasLimit),0n);
  assert.equal(measured,BigInt(report.aggregate.measuredGas));
  assert.equal(planned,BigInt(report.aggregate.plannedGasLimit));
  assert.equal(BigInt(report.aggregate.sequenceGasLimit)-planned,BigInt(report.aggregate.policyMargin));
  assert(planned<=BigInt(report.aggregate.sequenceGasLimit));
});
