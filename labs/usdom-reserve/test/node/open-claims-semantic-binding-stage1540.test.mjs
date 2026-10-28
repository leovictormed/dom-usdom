import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {checkpointEvidenceClaimCoverage} from '../../sdk/checkpoint-evidence-phase-coverage.mjs';
import {finalizedBurnEvidenceClaimCoverage} from '../../sdk/finalized-burn-evidence-phase-coverage.mjs';

const root=new URL('../..',import.meta.url);
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
function plan() { const result=spawnSync(node,['scripts/write-open-claims-execution-plan.mjs'],{cwd:root,encoding:'utf8'}); assert.equal(result.status,0,result.stderr); return JSON.parse(result.stdout); }
const executable=command=>/^[a-z0-9][a-z0-9._-]*\.mjs(?:\s|$)/.test(command)
  ?`node scripts/${command}`:/^[a-z0-9][a-z0-9:_-]*$/.test(command)&&command.includes(':')
    ?`npm run --silent ${command}`:command;

test('each proof claim is bound to its own real producer and later independent validator',()=>{
  const value=plan(),byClaim=new Map(value.entries.map(row=>[row.claim,row]));
  for(const expected of [...checkpointEvidenceClaimCoverage,...finalizedBurnEvidenceClaimCoverage]) {
    const row=byClaim.get(expected.claim); assert(row,expected.claim);
    assert.deepEqual(row.evidenceProducerCommands,[executable(expected.producer)],expected.claim);
    assert.deepEqual(row.independentValidatorCommands,[executable(expected.validator)],expected.claim);
  }
  for(const row of value.entries.filter(item=>item.implementationStatus==='external-operation')) {
    const phase=spawnSync('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh',row.phase],{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}}).stdout.replace(/[ \t]*\\\n\s*/g,' ');
    const producer=Math.max(...row.evidenceProducerCommands.map(command=>phase.indexOf(command)));
    const validator=Math.min(...row.independentValidatorCommands.map(command=>phase.indexOf(command)));
    assert(producer>=0&&validator>producer,`${row.claim}: validator must follow producer`);
  }
});

test('privacy ceremony boundaries route external inputs through assembly, validation and installation',()=>{
  const missing=plan().entries.filter(row=>row.implementationStatus!=='external-operation');
  assert.deepEqual(missing,[]);
  const byClaim=new Map(plan().entries.map(row=>[row.claim,row]));
  assert.equal(byClaim.get('native_privacy_trusted_setup_ceremony_completed').phase,
    'finalize-native-privacy-ceremony-secret');
  const vk=byClaim.get('native_privacy_production_verifying_key_installed');
  assert.equal(vk.evidenceProducerCommands.length,1);
  assert.match(vk.evidenceProducerCommands[0],
    /^npm run --silent install:native-privacy-verifying-key -- "\$transcript"/);
  assert.match(vk.independentValidatorCommands[0],
    /^npm run --silent check:native-privacy-ceremony -- .*\| cmp -s - /);
});
