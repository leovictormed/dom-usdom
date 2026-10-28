import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {runStatus78Cycle} from '../../sdk/status78-cycle.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const source=name=>readFile(path.join(root,name),'utf8');

test('cancel and expired-clear use the fixed pilot-gate relayer artifacts',async()=>{
 const runner=await source('scripts/run-operational-status78-cycle.mjs');
 const signer=await source('scripts/sign-operational-gas-relayer.sh');
 const generator=await source('scripts/generate-closed-mainnet-phase-command.sh');
 for(const [profile,flow,stem,command] of [
  ['pilot-gate-cancel','pilot-gate:cancel','pilot-deposit-gate-cancel','execute:pilot-deposit-gate-cancel'],
  ['pilot-gate-clear','pilot-gate:clear','pilot-deposit-gate-clear','execute:expired-pilot-gate-clear'],
 ]){
  const profileSlice=runner.slice(runner.indexOf(`case '${profile}'`),runner.indexOf('break;',runner.indexOf(`case '${profile}'`))+6);
  assert.match(profileSlice,new RegExp(command.replaceAll(':','\\:')));
  for(const suffix of ['relayer-envelope.json','transaction.json','raw.txt','finalized.json']) assert.match(profileSlice,new RegExp(`${stem}-${suffix}`));
  assert.match(profileSlice,new RegExp(`candidate\\('${flow.replace(':','\\:')}'`));
  assert.match(generator,new RegExp(`run-operational-status78-cycle\\.mjs ${profile}`));
  const signerSlice=signer.slice(signer.indexOf(`${flow})`),signer.indexOf(';;',signer.indexOf(`${flow})`))+2);
  assert.match(signerSlice,/relayer_role=pilot-gate/);
  assert.match(signerSlice,new RegExp(`${stem}-relayer-envelope\\.json`));
  assert.match(signerSlice,new RegExp(`${stem}-raw\\.txt`));
  assert.doesNotMatch(signerSlice,/onekey|walletconnect|ledger|hardware/i);
 }
});

test('uncertain status 80 and existing raw never trigger signing or retransmission',async()=>{
 const events=[];
 assert.equal(await runStatus78Cycle({
  runExecutor:async()=>{events.push('executor');return 80},
  resolveSigner:async()=>{events.push('resolve');return 'pilot-gate:cancel'},
  runSigner:async()=>{events.push('sign');return 0},
 }),80);
 assert.deepEqual(events,['executor']);
 const runner=await source('scripts/run-operational-status78-cycle.mjs');
 assert.match(runner,/regular\(c\.envelope\)&&regular\(c\.input\)&&absent\(c\.raw\)&&absent\(c\.done\)/);
});

test('executors journal publication uncertainty and prove terminal chain state',async()=>{
 for(const [file,state] of [
  ['scripts/execute-pilot-deposit-gate-cancel.sh','pilot_cancel_broadcast_state'],
  ['scripts/execute-expired-pilot-gate-clear.sh','pilot_clear_broadcast_state'],
 ]){
  const script=await source(file);
  assert.match(script,new RegExp(`${state}=signed-unresolved`));
  assert.match(script,new RegExp(`${state}=publishing[\\s\\S]*publish-private-raw-transaction\\.mjs`));
  assert.match(script,/restart to recover without rebroadcast/);
  assert.match(script,/authorizedPilotDeposit\(\)\(bytes32\)[\s\S]*authorizedPilotSnapshot\(\)\(bytes32\)[\s\S]*authorizedPilotValidUntil\(\)\(uint64\)[\s\S]*pilotAuthorizationGeneration\(\)\(uint64\)/);
  assert.match(script,/0x\$\(printf '0%\.0s' \{1\.\.64\}\)/);
  assert.match(script,/canonical-uint256\.mjs add1 "\$generation"/);
  assert.match(script,/finalizedBlockHash/);
 }
});

test('open-claims DAG exposes the same cancel and clear recovery routes',async()=>{
 const dag=await source('scripts/write-open-claims-execution-plan.mjs');
 const route=dag.slice(dag.indexOf("key.startsWith('production_onekey_ios_relayer_')"),dag.indexOf("key.startsWith('production_onekey_')"));
 for(const profile of ['pilot-gate','pilot-gate-cancel','pilot-gate-clear']) assert.match(route,new RegExp(`run-operational-status78-cycle\\.mjs ${profile}`));
});
