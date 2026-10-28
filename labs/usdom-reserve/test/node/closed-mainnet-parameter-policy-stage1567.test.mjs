import test from 'node:test';
import assert from 'node:assert/strict';
import {linkSync,mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import os from 'node:os';import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {readAndValidateClosedMainnetParameterPolicy,validateClosedMainnetParameterPolicy} from '../../sdk/closed-mainnet-parameter-policy.mjs';

const policy=JSON.parse(readFileSync(new URL('../../config/closed-mainnet-pilot-parameter-policy.json',import.meta.url)));
test('canonical closed-mainnet policy is exact and internally consistent',()=>assert.equal(validateClosedMainnetParameterPolicy(policy),true));
test('parameter policy reader refuses symlink and hardlink aliases',()=>{const root=mkdtempSync(path.join(os.tmpdir(),'usdom-policy-reader-')),direct=path.join(root,'policy.json');try{writeFileSync(direct,JSON.stringify(policy));for(const kind of ['symlink','hardlink']){const alias=path.join(root,`${kind}.json`);if(kind==='symlink')symlinkSync(direct,alias);else linkSync(direct,alias);assert.throws(()=>readAndValidateClosedMainnetParameterPolicy(alias));rmSync(alias)}}finally{rmSync(root,{recursive:true,force:true})}});
test('every reviewed category fails closed on drift',()=>{
  for(const category of Object.keys(policy).filter(key=>key!=='schema')) {
    const changed=structuredClone(policy); const key=Object.keys(changed[category])[0];
    changed[category][key]=typeof changed[category][key]==='boolean'?!changed[category][key]:`${changed[category][key]}0`;
    assert.throws(()=>validateClosedMainnetParameterPolicy(changed),/differs/);
  }
});
test('source/config checker binds Solidity and checkpoint policy',()=>{
  const run=spawnSync(process.execPath,['scripts/check-closed-mainnet-parameter-policy.mjs'],{cwd:new URL('../..',import.meta.url),encoding:'utf8'});
  assert.equal(run.status,0,run.stderr); assert.equal(JSON.parse(run.stdout).status,'PASS');
});
test('release review rejects examples and accepts only exact limited values',async()=>{
  const release={productionReady:false,realFundsAuthorized:false,ethereumChainId:'1',token:policy.ethereum.token,
    withdrawalDelaySeconds:policy.reserve.withdrawalDelaySeconds,governanceDelaySeconds:policy.reserve.governanceDelaySeconds,
    maxOutstandingBaseUnits:policy.reserve.maxOutstandingBaseUnits,
    outflowCapacityBaseUnitsPerDay:policy.reserve.outflowCapacityBaseUnitsPerRefillPeriod,
    nativeRelaySafetyMarginSeconds:policy.nativeFinality.relaySafetyMarginSeconds,
    nativeMaxEthereumAnchorAgeSeconds:policy.nativeFinality.maximumEthereumAnchorAgeSeconds,
    nativeMaxDomClockLeadSeconds:policy.nativeFinality.maximumDomClockLeadSeconds};
  const path=`/tmp/usdom-policy-${process.pid}.json`;
  const {writeFileSync,unlinkSync}=await import('node:fs');
  try {
    writeFileSync(path,JSON.stringify(release));
    let run=spawnSync(process.execPath,['scripts/check-closed-mainnet-parameter-policy.mjs','--release-config',path],{cwd:new URL('../..',import.meta.url),encoding:'utf8'});
    assert.equal(run.status,0,run.stderr); assert.equal(JSON.parse(run.stdout).releaseConfigReviewed,true);
    release.maxOutstandingBaseUnits='100000000000'; writeFileSync(path,JSON.stringify(release));
    run=spawnSync(process.execPath,['scripts/check-closed-mainnet-parameter-policy.mjs','--release-config',path],{cwd:new URL('../..',import.meta.url),encoding:'utf8'});
    assert.notEqual(run.status,0);
  } finally { unlinkSync(path); }
});
