import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL('../../scripts/generate-local-proof-reserve-fixture.mjs',import.meta.url),'utf8');
const reserveArtifact=JSON.parse(await readFile(new URL(
  '../../out/USDOMProofReserve.sol/USDOMProofReserve.json',import.meta.url),'utf8'));
const registryArtifact=JSON.parse(await readFile(new URL(
  '../../out/Mocks.sol/MockGracefulShutdownRegistry.json',import.meta.url),'utf8'));

test('local proof-reserve fixture deploys and binds the mandatory checkpoint registry',()=>{
  assert.match(source,/"Mocks\.sol\/MockGracefulShutdownRegistry\.json",\s*\[domain, activation\]/);
  assert.match(source,/await token\.getAddress\(\),\s*await verifier\.getAddress\(\),\s*await checkpointRegistry\.getAddress\(\),\s*domain,\s*activation,/);
  const reserveConstructor=reserveArtifact.abi.find(entry=>entry.type==='constructor');
  assert.deepEqual(reserveConstructor.inputs[0].components.map(component=>component.name),[
    'token','verifier','checkpointRegistry','domDomain','activationScheduleCommitment','governance','guardian',
    'withdrawalDelay','governanceDelay','maxOutstanding','outflowCapacity','pilotRestricted',
  ]);
  const registryConstructor=registryArtifact.abi.find(entry=>entry.type==='constructor');
  assert.deepEqual(registryConstructor.inputs.map(input=>input.type),['bytes32','bytes32']);
});
