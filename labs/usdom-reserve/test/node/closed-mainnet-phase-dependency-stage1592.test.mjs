import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {
  buildClosedMainnetPhaseCompletion,closedMainnetPhaseGenerationIdentity,
  closedMainnetPhaseSha256,validateClosedMainnetExecutionPlan,
  validateClosedMainnetPhaseCompletion,validateClosedMainnetPhaseGenerationIdentity,
} from '../../sdk/closed-mainnet-phase-dependency.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const run=(command,args)=>spawnSync(command,args,{cwd:root,encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024});
const generated=run(process.execPath,['scripts/write-open-claims-execution-plan.mjs']);
assert.equal(generated.status,0,generated.stderr.toString());
assert.equal(generated.stderr.length,0);
const planBytes=generated.stdout;
const plan=validateClosedMainnetExecutionPlan(JSON.parse(planBytes));
const planSha256=closedMainnetPhaseSha256(planBytes);
const identity=closedMainnetPhaseGenerationIdentity({planBytes,plan,
  evidenceDirectoryStat:{dev:2049n,ino:817263n},
  executionLockStat:{dev:2049n,ino:817300n},
  planPath:`/home/leonardov/usdom-mainnet-public/open-claims-execution-plan-v1-${planSha256}.json`,
});
const scripts=plan.phaseOrder.map(phase=>{
  const result=run('/usr/bin/bash',['--noprofile','--norc','scripts/generate-closed-mainnet-phase-command.sh',phase]);
  assert.equal(result.status,0,result.stderr.toString());
  assert.equal(result.stderr.length,0);
  return result.stdout;
});

test('all planned phases form one exact, canonical all-predecessor chain',()=>{
  const predecessorBytes=[];
  plan.phaseArtifacts.forEach((artifact,index)=>{
    assert.deepEqual(artifact.prerequisitePhases,plan.phaseOrder.slice(0,index));
    const value=buildClosedMainnetPhaseCompletion({identity,artifact,
      scriptBytes:scripts[index],predecessorBytes});
    assert.equal(value.predecessorCompletionSha256.length,index);
    const completionBytes=Buffer.from(`${JSON.stringify(value)}\n`);
    validateClosedMainnetPhaseCompletion(value,{identity,artifact,
      bytes:{scriptBytes:scripts[index],completionBytes},predecessorBytes});
    predecessorBytes.push(completionBytes);
  });
});

test('old plans, regenerated script drift and foreign evidence generations fail closed',()=>{
  const artifact=plan.phaseArtifacts[0];
  const value=buildClosedMainnetPhaseCompletion({identity,artifact,
    scriptBytes:scripts[0],predecessorBytes:[]});
  const completionBytes=Buffer.from(`${JSON.stringify(value)}\n`);
  const oldIdentity={...identity,planSha256:'0'.repeat(64)};
  assert.throws(()=>validateClosedMainnetPhaseGenerationIdentity(oldIdentity,identity),/stale, foreign or malformed/);
  const foreignIdentity={...identity,evidenceDirectoryInode:'817264'};
  assert.throws(()=>validateClosedMainnetPhaseGenerationIdentity(foreignIdentity,identity),/stale, foreign or malformed/);
  const replacedLock={...identity,executionLockInode:'817301'};
  assert.throws(()=>validateClosedMainnetPhaseGenerationIdentity(replacedLock,identity),/stale, foreign or malformed/);
  assert.throws(()=>validateClosedMainnetPhaseCompletion(value,{identity,artifact,
    bytes:{scriptBytes:Buffer.concat([scripts[0],Buffer.from('# drift\n')]),completionBytes},predecessorBytes:[]}),
  /phase completion inputs are invalid/);
});

test('generation identity rejects a plan object detached from the hashed plan bytes',()=>{
  const detached=structuredClone(plan);
  detached.phaseArtifacts[0].generatedScriptSha256='f'.repeat(64);
  assert.throws(()=>closedMainnetPhaseGenerationIdentity({planBytes,plan:detached,
    evidenceDirectoryStat:{dev:2049n,ino:817263n},
    executionLockStat:{dev:2049n,ino:817300n},
    planPath:`/home/leonardov/usdom-mainnet-public/open-claims-execution-plan-v1-${planSha256}.json`,
  }),/plan bytes differ from parsed authority/);
});

test('missing, reordered or altered predecessor declarations and receipts are rejected',()=>{
  const changed=structuredClone(plan);
  changed.phaseArtifacts[2].prerequisitePhases.pop();
  assert.throws(()=>validateClosedMainnetExecutionPlan(changed),/artifact is invalid/);
  const first=buildClosedMainnetPhaseCompletion({identity,artifact:plan.phaseArtifacts[0],
    scriptBytes:scripts[0],predecessorBytes:[]});
  const firstBytes=Buffer.from(`${JSON.stringify(first)}\n`);
  assert.throws(()=>buildClosedMainnetPhaseCompletion({identity,artifact:plan.phaseArtifacts[1],
    scriptBytes:scripts[1],predecessorBytes:[]}),/inputs are invalid/);
  const second=buildClosedMainnetPhaseCompletion({identity,artifact:plan.phaseArtifacts[1],
    scriptBytes:scripts[1],predecessorBytes:[firstBytes]});
  const secondBytes=Buffer.from(`${JSON.stringify(second)}\n`);
  assert.throws(()=>validateClosedMainnetPhaseCompletion(second,{identity,artifact:plan.phaseArtifacts[1],
    bytes:{scriptBytes:scripts[1],completionBytes:secondBytes},
    predecessorBytes:[Buffer.from(`${JSON.stringify({...first,ordinal:99})}\n`)]}),/stale, foreign or noncanonical/);
  const third=buildClosedMainnetPhaseCompletion({identity,artifact:plan.phaseArtifacts[2],
    scriptBytes:scripts[2],predecessorBytes:[firstBytes,secondBytes]});
  const thirdBytes=Buffer.from(`${JSON.stringify(third)}\n`);
  assert.throws(()=>validateClosedMainnetPhaseCompletion(third,{identity,artifact:plan.phaseArtifacts[2],
    bytes:{scriptBytes:scripts[2],completionBytes:thirdBytes},
    predecessorBytes:[secondBytes,firstBytes]}),/stale, foreign or noncanonical/);
});

test('every planned script authorizes before its body and commits completion last',()=>{
  scripts.forEach((source,index)=>{
    const text=source.toString();
    const begin=text.indexOf('check-closed-mainnet-phase-dependency.mjs begin');
    const body=text.indexOf('phase_body() {');
    const execute=text.lastIndexOf('\nphase_body\n');
    const complete=text.lastIndexOf('check-closed-mainnet-phase-dependency.mjs complete');
    assert.ok(begin>=0&&body>begin&&execute>body&&complete>execute,plan.phaseOrder[index]);
  });
  const materializer=readFileSync(path.join(root,'scripts/materialize-closed-mainnet-phase-script.sh'),'utf8');
  assert.match(materializer,/check-closed-mainnet-phase-dependency\.mjs \\\n+  materialize "\$phase" "\$candidate"/);
});
