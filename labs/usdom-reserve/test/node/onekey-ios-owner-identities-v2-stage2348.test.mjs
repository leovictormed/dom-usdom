import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,readFile,stat,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {Wallet} from 'ethers';
import {buildIosOnboardingEvidence} from '../../sdk/onekey-ios-onboarding.mjs';
import {buildOneKeyIosOwnerIdentitiesV2,materializeOneKeyIosOwnerIdentitiesV2} from '../../sdk/onekey-ios-owner-identities-v2.mjs';
import {canonicalOwnersByRole} from '../../sdk/safe-control-deployment.mjs';

const physical=address=>({schema:'usdom-onekey-classic1s-human-confirmation-v1',source:'human-observed-device-screen',model:'classic1s',addressShownOnDevice:true,address,operatorConfirmed:true,mock:false});
const evidence=(address,n)=>buildIosOnboardingEvidence({projectId:'ab'.repeat(16),session:{schema:'usdom-onekey-ios-wc-onboarding-session-v1',chain:'eip155:1',account:`eip155:1:${address}`,methods:['eth_signTypedData_v4'],events:[],sessionDeleted:true},physical:physical(address),roles:[`owner-${n}`]});

test('three onboarding evidences derive one explicit single-operator 2-of-3 identity set shared by four separated Safe roles',()=>{
  const values=[1,2,3].map(n=>evidence(Wallet.createRandom().address,n));
  const identities=buildOneKeyIosOwnerIdentitiesV2(values);
  assert.equal(identities.threshold,2);
  assert.equal(identities.singleOperatorResidualRisk,true);
  assert.equal(identities.custodySignaturesStatus,'awaiting-safe-package-for-12-custody-signatures');
  assert.deepEqual(identities.ownersByRole.governance,identities.ownersByRole.reserveGuardian);
  assert.notEqual(identities.ownersByRole.governance,identities.ownersByRole.reserveGuardian);
  assert.doesNotThrow(()=>canonicalOwnersByRole(identities.ownersByRole));
});

test('duplicate address, role substitution, synthetic approval and partial cross-role reuse fail closed',()=>{
  const values=[1,2,3].map(n=>evidence(Wallet.createRandom().address,n));
  const duplicate=structuredClone(values); duplicate[2]=evidence(values[0].address,3);
  assert.throws(()=>buildOneKeyIosOwnerIdentitiesV2(duplicate));
  const wrong=structuredClone(values); wrong[1].roles[0].role='owner-9';
  assert.throws(()=>buildOneKeyIosOwnerIdentitiesV2(wrong));
  const synthetic=structuredClone(values); synthetic[0].hardwareSigningApproved=true;
  assert.throws(()=>buildOneKeyIosOwnerIdentitiesV2(synthetic));
  const bad=structuredClone(buildOneKeyIosOwnerIdentitiesV2(values).ownersByRole);
  bad.checkpointGuardian[2]=Wallet.createRandom().address;
  assert.throws(()=>canonicalOwnersByRole(bad));
});

test('materializer hashes exact private bytes, installs 0600 create-once and refuses replacement',async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-owner-identities-v2-'));
  const evidencePaths=[];
  for(let index=0;index<3;index++){
    const target=path.join(directory,`owner-${index+1}.json`);
    await writeFile(target,`${JSON.stringify(evidence(Wallet.createRandom().address,index+1),null,2)}\n`,{mode:0o600,flag:'wx'});
    evidencePaths.push(target);
  }
  const outputPath=path.join(directory,'identities.json');
  const identities=await materializeOneKeyIosOwnerIdentitiesV2({evidencePaths,outputPath});
  assert.equal((await stat(outputPath)).mode&0o777,0o600);
  for(let index=0;index<3;index++){
    const bytes=await readFile(evidencePaths[index]);
    assert.equal(identities.evidenceSha256ByOwner[`owner-${index+1}`],createHash('sha256').update(bytes).digest('hex'));
  }
  await assert.rejects(materializeOneKeyIosOwnerIdentitiesV2({evidencePaths,outputPath}));
});
