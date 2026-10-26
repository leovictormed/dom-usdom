import test from 'node:test';
import assert from 'node:assert/strict';
import {auditPilotPublicArtifact} from '../../sdk/pilot-publication-privacy.mjs';

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

test('public phase checklist exposes conservation result without either phase identity',async()=>{
  const source=await import('node:fs').then(fs=>fs.readFileSync(
    new URL('../../scripts/check-closed-mainnet-phase-artifacts.mjs',import.meta.url),'utf8'));
  assert.match(source,/artifact:'financialConservation',status:'verified'/);
  assert.doesNotMatch(source,/detail:conservation/);
});
