#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {
  buildClosedMainnetPhaseCompletion,closedMainnetPhaseGenerationIdentity,
  closedMainnetPhaseSha256,validateClosedMainnetExecutionPlan,
  validateClosedMainnetPhaseCompletion,validateClosedMainnetPhaseGenerationIdentity,
} from '../sdk/closed-mainnet-phase-dependency.mjs';

const root=path.resolve(import.meta.dirname,'..');
const publicDirectory='/home/leonardov/usdom-mainnet-public';
const evidenceDirectory='/home/leonardov/usdom-mainnet-private/control-plane';
const completionDirectory=path.join(evidenceDirectory,'.phase-completions');
const identityPath=path.join(evidenceDirectory,'.phase-generation.json');
const [action,phase,scriptPath]=process.argv.slice(2);
if(!['materialize','begin','complete'].includes(action)||!phase||!scriptPath||process.argv.length!==5) {
  throw new Error('usage: check-closed-mainnet-phase-dependency.mjs materialize|begin|complete PHASE SCRIPT');
}
const generated=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
  cwd:root,encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
});
if(generated.status!==0||generated.stderr.length!==0||generated.stdout.length<2) {
  throw new Error('cannot reproduce current closed-mainnet execution plan');
}
const planBytes=generated.stdout;
const planSha256=closedMainnetPhaseSha256(planBytes);
const planPath=path.join(publicDirectory,`open-claims-execution-plan-v1-${planSha256}.json`);
const installedPlan=await readDirectFile(planPath,{minimum:2,maximum:16*1024*1024,
  exactMode:0o644,label:'published current execution plan'});
if(!installedPlan.equals(planBytes)) throw new Error('published execution plan differs from current sources');
const plan=validateClosedMainnetExecutionPlan(parseStrictJsonBytes(planBytes,{label:'execution plan',maxBytes:16*1024*1024,maxDepth:64}));
const index=plan.phaseOrder.indexOf(phase);
if(index<0) throw new Error('phase is not in the current execution plan');
const artifact=plan.phaseArtifacts[index];
const scriptBytes=await readDirectFile(path.resolve(scriptPath),{minimum:1,maximum:16*1024*1024,
  exactMode:0o600,label:'materialized phase script'});
if(closedMainnetPhaseSha256(scriptBytes)!==artifact.generatedScriptSha256
    ||scriptBytes.length!==artifact.generatedScriptBytes) throw new Error('phase script differs from its current plan artifact');
if(action==='materialize') process.exit(0);
const evidenceStat=fs.lstatSync(evidenceDirectory,{bigint:true});
const executionLockPath=path.join(evidenceDirectory,'phase-execution-lock');
const executionLockStat=fs.lstatSync(executionLockPath,{bigint:true});
if(!evidenceStat.isDirectory()||evidenceStat.uid!==BigInt(process.getuid())
    ||(evidenceStat.mode&0o777n)!==0o700n||fs.realpathSync(evidenceDirectory)!==evidenceDirectory) {
  throw new Error('phase evidence directory identity is invalid');
}
if(!executionLockStat.isDirectory()||executionLockStat.uid!==BigInt(process.getuid())
    ||(executionLockStat.mode&0o777n)!==0o700n||fs.realpathSync(executionLockPath)!==executionLockPath
    ||process.env.USDOM_PILOT_PHASE_LOCK_DEVICE!==String(executionLockStat.dev)
    ||process.env.USDOM_PILOT_PHASE_LOCK_INODE!==String(executionLockStat.ino)) {
  throw new Error('phase execution lock identity is invalid or changed');
}
const expectedIdentity=closedMainnetPhaseGenerationIdentity({planBytes,plan,evidenceDirectoryStat:evidenceStat,executionLockStat,planPath});
let identity;
try {
  const bytes=await readDirectFile(identityPath,{minimum:2,maximum:64*1024,exactMode:0o600,label:'phase generation identity'});
  identity=validateClosedMainnetPhaseGenerationIdentity(parseStrictJsonBytes(bytes,{label:'phase generation identity'}),expectedIdentity);
} catch(error) {
  if(error?.code!=='ENOENT'||index!==0) throw error;
}
if(!identity) {
  try { fs.mkdirSync(completionDirectory,{mode:0o700}); }
  catch(error) { if(error?.code!=='EEXIST') throw error; }
  const metadata=fs.lstatSync(completionDirectory,{bigint:true});
  if(!metadata.isDirectory()||metadata.uid!==BigInt(process.getuid())
      ||(metadata.mode&0o777n)!==0o700n||metadata.nlink<2n
      ||fs.realpathSync(completionDirectory)!==completionDirectory) {
    throw new Error('phase completion directory is unsafe');
  }
  await writePrivateFileDurableNewOrEqual(identityPath,
    Buffer.from(`${JSON.stringify(expectedIdentity)}\n`),{maximum:64*1024});
  identity=expectedIdentity;
}
const generatePhaseBytes=phaseName=>{
  const current=spawnSync('/usr/bin/bash',['--noprofile','--norc',
    'scripts/generate-closed-mainnet-phase-command.sh',phaseName],{
    cwd:root,encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
  });
  if(current.status!==0||current.stderr.length!==0||current.stdout.length<1) {
    throw new Error(`cannot regenerate predecessor phase: ${phaseName}`);
  }
  return current.stdout;
};
const predecessorBytes=[];
for(let ordinal=1;ordinal<=index;ordinal++) {
  const predecessorArtifact=plan.phaseArtifacts[ordinal-1];
  const target=path.join(completionDirectory,`${String(ordinal).padStart(2,'0')}-${predecessorArtifact.phase}.json`);
  const completionBytes=await readDirectFile(target,{minimum:2,maximum:1024*1024,exactMode:0o600,
    label:`phase ${ordinal} completion`});
  const value=parseStrictJsonBytes(completionBytes,{label:`phase ${ordinal} completion`});
  validateClosedMainnetPhaseCompletion(value,{identity,artifact:predecessorArtifact,
    bytes:{scriptBytes:generatePhaseBytes(predecessorArtifact.phase),completionBytes},predecessorBytes});
  predecessorBytes.push(completionBytes);
}
const ownPath=path.join(completionDirectory,`${String(index+1).padStart(2,'0')}-${phase}.json`);
if(action==='begin') {
  if(fs.existsSync(ownPath)||fs.lstatSync(ownPath,{throwIfNoEntry:false})?.isSymbolicLink()) {
    throw new Error('phase is already completed and cannot be replayed');
  }
  process.stdout.write(`${JSON.stringify({status:'authorized',phase,ordinal:index+1,planSha256})}\n`);
  process.exit(0);
}
const completion=buildClosedMainnetPhaseCompletion({identity,artifact,scriptBytes,predecessorBytes});
await writePrivateFileDurableNewOrEqual(ownPath,Buffer.from(`${JSON.stringify(completion)}\n`),{maximum:1024*1024});
process.stdout.write(`${JSON.stringify({status:'completed',phase,ordinal:index+1,planSha256})}\n`);
