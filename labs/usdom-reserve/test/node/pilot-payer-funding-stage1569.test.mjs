import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PILOT_PAYER_WORST_CASE_WEI,requiredPilotPayerFunding} from '../../sdk/pilot-gas-funding.mjs';
import {classifyPilotNonce} from '../../sdk/pilot-nonce-recovery.mjs';

const address=n=>`0x${n.toString(16).padStart(40,'0')}`;
test('worst-case funding is exact per phase and sums reused payer addresses',()=>{
  assert.deepEqual(PILOT_PAYER_WORST_CASE_WEI,{
    safeDeployer:'300000000000000000',contractDeployer:'1000000000000000000',
    depositFunder:'150000000000000000',redemptionRelayer:'200000000000000000',
    safeRecoveryRelayerAllRoles:'750000000000000000'});
  const distinct=requiredPilotPayerFunding({safeDeployer:address(1),contractDeployer:address(2),
    depositFunder:address(3),redemptionRelayer:address(4),safeRecoveryRelayerAllRoles:address(5)});
  assert.equal(distinct.length,5);
  const shared=requiredPilotPayerFunding({safeDeployer:address(1),contractDeployer:address(1),
    depositFunder:address(1),redemptionRelayer:address(1),safeRecoveryRelayerAllRoles:address(1)});
  assert.deepEqual(shared,[{address:address(1),maximumCostWei:'2400000000000000000'}]);
});

test('nonce policy permits exact rebroadcast/recovery and rejects replacement or cancellation hashes',()=>{
  const original='0x'+'11'.repeat(32),replacement='0x'+'22'.repeat(32);
  assert.equal(classifyPilotNonce('7','7','8','7','8',original,original,original),'recover-receipt');
  assert.throws(()=>classifyPilotNonce('7','7','8','7','8',original,replacement,replacement),/exact known/);
  assert.throws(()=>classifyPilotNonce('7','7','8','7','8',original,original,replacement),/exact known/);
});

test('executors serialize nonce owners and fund full bounded sequences',()=>{
  const safe=readFileSync(new URL('../../scripts/execute-safe-control-deployment.sh',import.meta.url),'utf8');
  const deploy=readFileSync(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
  for(const source of [safe,deploy]) assert.match(source,/flock/);
  assert.match(safe,/BigInt\(v\)<300000000000000000n/);
  assert.match(safe,/--block finalized/);
  assert.match(deploy,/MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST|check-mainnet-deployment-sequence-cost/);
});
