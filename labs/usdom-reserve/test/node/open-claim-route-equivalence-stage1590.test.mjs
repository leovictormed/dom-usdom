import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {assertOpenClaimRouteEquivalence} from '../../sdk/open-claim-route-equivalence.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const generated=spawnSync(node,['scripts/write-open-claims-execution-plan.mjs'],{cwd:root,encoding:'utf8'});
assert.equal(generated.status,0,generated.stderr);
const plan=JSON.parse(generated.stdout);
const packageScripts=JSON.parse(readFileSync(path.join(root,'package.json'),'utf8')).scripts;
const phases=new Map(plan.phaseOrder.map(phase=>{
  const result=spawnSync('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh',phase],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
  });
  assert.equal(result.status,0,result.stderr);
  return [phase,result.stdout];
}));
const readSource=relative=>readFileSync(path.join(root,relative),'utf8');

test('all 57 claims have implementation-backed semantic evidence contracts',()=>{
  const result=assertOpenClaimRouteEquivalence({plan,phaseSources:phases,packageScripts,readSource});
  assert.equal(result.claimCount,57);
  assert.ok(result.semanticContractCount>=25);
});

test('equivalence fails closed when a label is present only in a comment',()=>{
  const row=plan.entries.find(value=>value.claim==='production_checkpoint_randomx_complete_guest_positive_receipt_executed');
  const command=row.independentValidatorCommands[0];
  const changed=new Map(phases);
  changed.set(row.phase,phases.get(row.phase).replace(command,`# ${command}`));
  assert.throws(()=>assertOpenClaimRouteEquivalence({plan,phaseSources:changed,packageScripts,readSource}),
    /not an active invocation/);
});

test('equivalence rejects a self-described semantic contract drift',()=>{
  const changed=structuredClone(plan);
  changed.entries[0].semanticEvidence.id='misleading-command-label-v1';
  assert.throws(()=>assertOpenClaimRouteEquivalence({plan:changed,phaseSources:phases,packageScripts,readSource}),
    /semantic evidence contract drift/);
});

test('equivalence resolves full npm and direct-node commands to one audited script',()=>{
  const npmRow=plan.entries.find(value=>value.evidenceProducerCommands.some(command=>command.startsWith('npm run --silent ')));
  const alias=npmRow.evidenceProducerCommands[0].slice('npm run --silent '.length).split(/\s/,1)[0];
  assert.throws(()=>assertOpenClaimRouteEquivalence({plan,phaseSources:phases,
    packageScripts:{...packageScripts,[alias]:`${packageScripts[alias]} && node scripts/foreign.mjs`},readSource}),
  /not one direct audited script/);
  const changed=structuredClone(plan);
  changed.entries[0].evidenceProducerCommands=['node scripts/absent-audited-target.mjs'];
  const changedPhases=new Map(phases);
  changedPhases.set(changed.entries[0].phase,`${phases.get(changed.entries[0].phase)}\nnode scripts/absent-audited-target.mjs\n`);
  assert.throws(()=>assertOpenClaimRouteEquivalence({plan:changed,phaseSources:changedPhases,
    packageScripts,readSource}),/ENOENT/);
});

test('corrected routes identify actual configuration and RandomX consumers',()=>{
  const byClaim=new Map(plan.entries.map(row=>[row.claim,row]));
  for(const claim of ['native_scheduled_public_runtime_configured','production_reserve_config_hash_configured']) {
    assert.deepEqual(byClaim.get(claim).evidenceProducerCommands,[
      'npm run --silent materialize:production-release-core -- registry-pins',
      'npm run --silent materialize:production-release-core -- reserve-pins',
      'npm run --silent materialize:production-release-core -- final',
    ]);
    assert.deepEqual(byClaim.get(claim).independentValidatorCommands,
      ['node scripts/prepare-production-release-core-materialization.mjs final | cmp -s - config/proof-reserve.unconfigured.json']);
  }
  assert.deepEqual(byClaim.get('production_checkpoint_randomx_complete_guest_positive_receipt_executed')
    .independentValidatorCommands,['npm run --silent plan:authenticated-checkpoint-segment-set']);
  assert.deepEqual(byClaim.get('production_verified_checkpoint_restart_witness_live_exercised')
    .independentValidatorCommands,
    ['npm run --silent check:checkpoint-restart-witness']);
  const vk=byClaim.get('native_privacy_production_verifying_key_installed');
  assert.equal(vk.independentValidatorCommands.length,4);
  assert.match(vk.independentValidatorCommands[0],/installation\.json/);
  assert.match(vk.independentValidatorCommands[0],/^npm run --silent check:native-privacy-ceremony -- /);
});

test('bootstrap ratification phase creates every immutable prerequisite before collection',()=>{
  const phase=phases.get('produce-checkpoint-evidence-secret');
  const commands=[
    'materialize:checkpoint-bootstrap-rpc-catalog',
    'write:checkpoint-bootstrap-ratification-request',
    'sign:checkpoint-bootstrap-ratification',
    'collect:checkpoint-bootstrap-ratification',
    'write:checkpoint-bootstrap-ratification-report',
  ];
  const offsets=commands.map(command=>phase.indexOf(command));
  assert(offsets.every(offset=>offset>=0));
  assert.deepEqual(offsets,[...offsets].sort((left,right)=>left-right));
  for(const artifact of [
    'config/checkpoint-bootstrap-ratification-rpc-catalog.json',
    'evidence/checkpoint-bootstrap/ratification-signing-request.json',
    'evidence/checkpoint-bootstrap/ratification-signature.hex',
  ]) assert.match(phase,new RegExp(`test -s ${artifact.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}`));
});

test('finalized-event route materializes prerequisites and requires a real transaction hash',()=>{
  const phase=phases.get('produce-checkpoint-evidence-secret');
  const commands=[
    'materialize:checkpoint-finalized-event-rpc-catalog',
    'USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH is required after the real checkpoint submission.',
    'write:checkpoint-finalized-transaction-reference',
    'collect:checkpoint-finalized-event',
    'write:checkpoint-finalized-event-report',
  ];
  const offsets=commands.map(command=>phase.indexOf(command));
  assert(offsets.every(offset=>offset>=0));
  assert.deepEqual(offsets,[...offsets].sort((left,right)=>left-right));
  assert.match(phase,/test -s config\/checkpoint-finalized-event-rpc-catalog\.json/);
  assert.match(phase,/test -n "\$\{USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH:-\}"/);
  assert.match(phase,/test -s evidence\/checkpoint-finalized-event\/transaction-reference\.json/);
  assert.match(phase,/test -s evidence\/checkpoint-finalized-event\/transaction-reference\.sha256/);
});

test('finalized-burn capacity validator consumes the run selected by its producer',()=>{
  const phase=phases.get('measure-release-capacity');
  const producer='npm run --silent check:finalized-burn-capacity-e2e > "$finalized_burn_capacity_output"';
  const selection='USDOM_FINALIZED_BURN_PROOF_RUN_ID=$(jq -er';
  const validator='USDOM_FINALIZED_BURN_PROOF_RUN_ID="$USDOM_FINALIZED_BURN_PROOF_RUN_ID"';
  const offsets=[producer,selection,validator].map(command=>phase.indexOf(command));
  assert(offsets.every(offset=>offset>=0));
  assert.deepEqual(offsets,[...offsets].sort((left,right)=>left-right));
  assert.match(phase,/\.runId \| select\(type=="string" and test\("\^\[0-9\]\{8\}T/);
  for(const claim of [
    'production_finalized_burn_proving_capacity_measured',
    'production_finalized_burn_evm_verification_gas_measured',
  ]) assert.deepEqual(plan.entries.find(row=>row.claim===claim).independentValidatorCommands,[
    'USDOM_FINALIZED_BURN_PROOF_RUN_ID="$USDOM_FINALIZED_BURN_PROOF_RUN_ID" npm run --silent check:finalized-burn-capacity-evidence',
  ]);
});
