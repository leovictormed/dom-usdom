import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {Interface,id} from 'ethers';

const root=new URL('../../',import.meta.url);
const artifact=JSON.parse(readFileSync(new URL('out/USDOMProofReserve.sol/USDOMProofReserve.json',root),'utf8'));
const iface=new Interface(artifact.abi);
const signature=fragment=>fragment.format('sighash');
const selector=fragment=>id(signature(fragment)).slice(0,10);

function unique(values,label) {
 const seen=new Map();
 for(const [identity,name] of values) {
  assert(!seen.has(identity),`${label} collision ${identity}: ${seen.get(identity)} / ${name}`);
  seen.set(identity,name);
 }
}

test('final functions, events and custom errors have collision-free identities',()=>{
 const functions=iface.fragments.filter(v=>v.type==='function');
 const errors=iface.fragments.filter(v=>v.type==='error');
 const events=iface.fragments.filter(v=>v.type==='event');
 unique(functions.map(v=>[selector(v),signature(v)]),'function selector');
 unique(errors.map(v=>[selector(v),signature(v)]),'custom-error selector');
 unique([...functions,...errors].map(v=>[selector(v),`${v.type}:${signature(v)}`]),'function/error selector');
 unique(events.map(v=>[v.topicHash,signature(v)]),'event topic');
 assert(events.every(v=>!v.anonymous),'anonymous event');
 assert.throws(()=>unique([[selector(functions[0]),signature(functions[0])],[selector(functions[0]),'mutated()']],
  'function selector'),/collision/);
});

test('pilot storage is packed once without overlap or layout drift',()=>{
 const expected=[
  ['authorizedPilotDeposit','20',0,'t_bytes32'],['authorizedPilotSnapshot','21',0,'t_bytes32'],
  ['authorizedPilotValidUntil','22',0,'t_uint64'],['pilotAuthorizationGeneration','22',8,'t_uint64'],
  ['pilotDepositConsumed','22',16,'t_bool'],['permissionlessDeposits','22',17,'t_bool'],
  ['permissionlessDepositsReadyAt','22',18,'t_uint64'],
 ];
 const records=artifact.storageLayout.storage.filter(v=>expected.some(([name])=>name===v.label));
 assert.deepEqual(records.map(v=>[v.label,v.slot,Number(v.offset),v.type]),expected);
 const widths={t_bytes32:32,t_uint64:8,t_bool:1},occupied=new Set();
 for(const value of records) for(let byte=value.offset;byte<value.offset+widths[value.type];byte++) {
  const identity=`${value.slot}:${byte}`;assert(!occupied.has(identity),`storage overlap ${identity}`);occupied.add(identity);
 }
});

test('every production consumer uses the final pilot ABI and no removed selector',()=>{
 const consumers=['sdk/pilot-deposit-gate.mjs','sdk/pilot-deposit-gate-cancel.mjs','sdk/risc0-incident-response.mjs',
  'scripts/check-pilot-deposit-gate-clear-raw.mjs','scripts/execute-expired-pilot-gate-clear.sh',
  'scripts/execute-pilot-deposit-gate.sh'];
 const joined=consumers.map(path=>readFileSync(new URL(path,root),'utf8')).join('\n');
 for(const current of [
  'authorizePilotDeposit(bytes32 snapshotCommitment,address funder,uint64 amount,bytes32 salt,bytes32 receivingCommitment,uint64 validUntil,uint64 expectedGeneration)',
  'cancelPilotDepositAuthorization(bytes32 expectedSnapshotCommitment,uint64 expectedGeneration)',
  'clearExpiredPilotDepositAuthorization(bytes32 expectedSnapshotCommitment,uint64 expectedGeneration)',
  'pauseQueueEpoch(uint64 expectedQueueEpoch,uint64 expectedPilotAuthorizationGeneration)',
 ]) assert(joined.includes(current),`missing final consumer ${current}`);
 for(const stale of [
  /authorizePilotDeposit\(bytes32 snapshotCommitment,address funder,uint64 amount,bytes32 salt,bytes32 receivingCommitment,uint64 validUntil\)(?!,)/u,
  /cancelPilotDepositAuthorization\(bytes32 expectedSnapshotCommitment\)(?!,)/u,
  /clearExpiredPilotDepositAuthorization\(bytes32 expectedSnapshotCommitment\)(?!,)/u,
  /pauseQueueEpoch\(uint64 expectedQueueEpoch\)(?!,)/u,
 ]) {
  assert(!stale.test(joined),`stale pilot ABI consumer ${stale}`);
  assert(stale.test(`${joined}\nauthorizePilotDeposit(bytes32 snapshotCommitment,address funder,uint64 amount,bytes32 salt,bytes32 receivingCommitment,uint64 validUntil)\ncancelPilotDepositAuthorization(bytes32 expectedSnapshotCommitment)\nclearExpiredPilotDepositAuthorization(bytes32 expectedSnapshotCommitment)\npauseQueueEpoch(uint64 expectedQueueEpoch)`));
 }
});
