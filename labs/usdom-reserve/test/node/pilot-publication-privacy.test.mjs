import test from 'node:test';
import assert from 'node:assert/strict';
import {auditPilotPublicArtifact,auditPilotPublicArtifactSet} from '../../sdk/pilot-publication-privacy.mjs';
import {mkdtempSync,writeFileSync,symlinkSync,linkSync,rmSync,readFileSync} from 'node:fs';import {spawnSync} from 'node:child_process';import os from 'node:os';import path from 'node:path';

test('public pilot artifacts may expose one phase or opaque commitments, never cross-link phases',()=>{
  assert.deepEqual(auditPilotPublicArtifact({schema:'public-deposit/v1',depositId:'0x'+'11'.repeat(32),amount:'1000000'}),
    {containsDepositIdentity:true,containsRedemptionIdentity:false});
  assert.deepEqual(auditPilotPublicArtifact({schema:'public-redemption/v1',burnId:'0x'+'22'.repeat(32),amount:'1000000'}),
    {containsDepositIdentity:false,containsRedemptionIdentity:true});
  assert.deepEqual(auditPilotPublicArtifact({schema:'public-conservation/v1',depositPhaseCommitment:'aa'.repeat(32),
    redemptionPhaseCommitment:'bb'.repeat(32),amount:'1000000'}),
    {containsDepositIdentity:false,containsRedemptionIdentity:false});
  assert.throws(()=>auditPilotPublicArtifact({depositId:'0x'+'11'.repeat(32),burnId:'0x'+'22'.repeat(32)}),/links deposit/);
});

test('public pilot artifacts reject private witnesses, secrets, memo plaintext and raw transactions',()=>{
  for(const value of [{witness:'secret'},{private_witness:'secret'},{rho:'secret'},
    {secretNullifier:'secret'},{memo_plaintext:'secret'},{rawTransaction:'0x02'+'ab'.repeat(100)},
    {innocent:'0x02'+'ab'.repeat(100)}]) assert.throws(()=>auditPilotPublicArtifact(value));
});

test('nested generic identities cannot evade phase classification',()=>{
  assert.throws(()=>auditPilotPublicArtifact({deposit:{id:'0x'+'11'.repeat(32)},
    redemption:{id:'0x'+'22'.repeat(32)}}),/links deposit/);
  assert.throws(()=>auditPilotPublicArtifact({issuance:{transaction_hash:'0x'+'11'.repeat(32)},
    payout:{address:'0x'+'22'.repeat(20)}}),/links deposit/);
});

test('artifact-set audit rejects filename and cross-file correlation',()=>{
  assert.throws(()=>auditPilotPublicArtifactSet([{label:'deposit-burn-report.json',value:{ok:true}}]),
    /filename links/);
  assert.throws(()=>auditPilotPublicArtifactSet([
    {label:'deposit.json',value:{depositId:'0x'+'44'.repeat(32)}},
    {label:'redemption.json',value:{burnId:'0x'+'44'.repeat(32)}},
  ]),/reuses an identity/);
  assert.deepEqual(auditPilotPublicArtifactSet([
    {label:'deposit.json',value:{depositId:'0x'+'44'.repeat(32)}},
    {label:'redemption.json',value:{burnId:'0x'+'55'.repeat(32)}},
  ]),{artifactCount:2});
});

test('public phase checklist exposes conservation result without either phase identity',async()=>{
  const source=await import('node:fs').then(fs=>fs.readFileSync(
    new URL('../../scripts/check-closed-mainnet-phase-artifacts.mjs',import.meta.url),'utf8'));
  assert.match(source,/artifact:'financialConservation',status:'verified'/);
  assert.doesNotMatch(source,/detail:conservation/);
});
test('publication checker rejects symlink and hardlink inputs and holds the whole set',()=>{const root=mkdtempSync(path.join(os.tmpdir(),'usdom-publication-privacy-')),direct=path.join(root,'direct.json'),script=new URL('../../scripts/check-pilot-publication-privacy.mjs',import.meta.url).pathname;try{writeFileSync(direct,JSON.stringify({schema:'deposit/v1',depositPhaseCommitment:'11'.repeat(32)}));for(const kind of ['symlink','hardlink']){const alias=path.join(root,`${kind}.json`);if(kind==='symlink')symlinkSync(direct,alias);else linkSync(direct,alias);const result=spawnSync(process.execPath,[script,alias],{encoding:'utf8'});assert.notEqual(result.status,0,kind);rmSync(alias)}const source=readFileSync(script,'utf8');assert.match(source,/const captures=\[\]/);assert.match(source,/artifact set changed during audit/);assert.match(source,/auditPilotPublicArtifactSet\(entries\)/)}finally{rmSync(root,{recursive:true,force:true})}});
