import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const reserve=readFileSync(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url),'utf8');
const registry=readFileSync(new URL('../../contracts/DOMCheckpointRegistry.sol',import.meta.url),'utf8');

test('reserve constructor enforces disjoint infrastructure and control roles',()=>{
  for(const binding of [
    'config.guardian == config.governance',
    'config.governance == address(config.token)',
    'config.guardian == address(config.token)',
    'config.governance == address(config.verifier)',
    'config.guardian == address(config.verifier)',
    'config.governance == address(config.checkpointRegistry)',
    'config.guardian == address(config.checkpointRegistry)',
  ]) assert.ok(reserve.includes(binding),binding);
});

test('ordinary recovery requires governance and revalidates the whole control plane',()=>{
  assert.match(reserve,/function scheduleResume\(\) external onlyGovernance[\s\S]*_requireControlPlaneUnchanged\(\)/);
  assert.match(reserve,/function executeResume\(\) external[\s\S]*_requireControlPlaneUnchanged\(\)[\s\S]*_requireVerifierUnchanged\(\)[\s\S]*_requireTokenUsable/);
  assert.match(reserve,/function _safePolicyIntact[\s\S]*CONTROL_PLANE_THRESHOLD[\s\S]*_safeOwnersIntact[\s\S]*_safeModulesEmpty[\s\S]*_safeGuardEmpty[\s\S]*_safeFallbackHandlerIntact/);
});

test('checkpoint emergency halt is guardian-only while graceful closure is proof-state authorized',()=>{
  assert.match(registry,/function haltPermanently\(\) external[\s\S]*msg\.sender != guardian[\s\S]*_requireGuardianUnchanged\(\)[\s\S]*halted = true/);
  assert.match(registry,/function finalizeGracefulShutdown\(\) external[\s\S]*latestIssuanceClosed[\s\S]*latestTotalBurned != latestTotalIssued[\s\S]*_requireGuardianUnchanged\(\)[\s\S]*_requireVerifierUnchanged\(\)/);
});
