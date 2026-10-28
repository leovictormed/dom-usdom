#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {closedMainnetPhaseGenerationIdentity,closedMainnetPhaseSha256,
  validateClosedMainnetExecutionPlan,validateClosedMainnetPhaseGenerationIdentity}
  from '../sdk/closed-mainnet-phase-dependency.mjs';
import {buildOperationalClaimsLedger,operationalClaimsReleaseBinding}
  from '../sdk/operational-claims-ledger.mjs';

const root=path.resolve(import.meta.dirname,'..');
const control='/home/leonardov/usdom-mainnet-private/control-plane';
const completionDirectory=path.join(control,'.phase-completions');
const identityPath=path.join(control,'.phase-generation.json');
const output=path.join(control,'operational-claims-ledger.json');
const generated=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
  cwd:root,encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
});
if(generated.status!==0||generated.stderr.length!==0||generated.stdout.length<2) {
  throw new Error('cannot reproduce current claims plan');
}
const planBytes=generated.stdout;
const plan=validateClosedMainnetExecutionPlan(parseStrictJsonBytes(planBytes,{label:'claims plan',
  maxBytes:16*1024*1024,maxDepth:64}));
const planPath=path.join('/home/leonardov/usdom-mainnet-public',
  `open-claims-execution-plan-v1-${closedMainnetPhaseSha256(planBytes)}.json`);
const installedPlanBytes=await readDirectFile(planPath,{minimum:2,maximum:16*1024*1024,
  exactMode:0o644,label:'published claims plan'});
if(!installedPlanBytes.equals(planBytes)) throw new Error('published claims plan differs from current sources');
const controlStat=fs.lstatSync(control,{bigint:true});
const executionLockStat=fs.lstatSync(path.join(control,'phase-execution-lock'),{bigint:true});
if(!controlStat.isDirectory()||controlStat.uid!==BigInt(process.getuid())
    ||(controlStat.mode&0o777n)!==0o700n||fs.realpathSync(control)!==control) {
  throw new Error('operational claims evidence directory is unsafe');
}
const phaseGenerationBytes=await readDirectFile(identityPath,{minimum:2,maximum:64*1024,
  exactMode:0o600,label:'phase generation identity'});
const phaseGenerationIdentity=parseStrictJsonBytes(phaseGenerationBytes,{
  label:'phase generation identity',maxBytes:64*1024,maxDepth:8});
validateClosedMainnetPhaseGenerationIdentity(phaseGenerationIdentity,
  closedMainnetPhaseGenerationIdentity({planBytes,plan,evidenceDirectoryStat:controlStat,executionLockStat,planPath}));
const [requirementsBytes,releaseConfigBytes,releaseEvidenceBytes]=await Promise.all([
  readDirectProjectFile(root,'config/production-requirements.json',{exactMode:0o644}),
  readDirectProjectFile(root,'config/proof-reserve.unconfigured.json',{exactMode:0o644}),
  readDirectProjectFile(root,'config/mainnet-release-evidence.unconfigured.json',{exactMode:0o644}),
]);
const phaseArtifactAudit=spawnSync(process.execPath,
  ['scripts/check-closed-mainnet-phase-artifacts.mjs','require-pilot-complete'],{
  cwd:root,encoding:null,env:process.env,maxBuffer:16*1024*1024,
});
if(phaseArtifactAudit.status!==0||phaseArtifactAudit.stderr.length!==0
    ||phaseArtifactAudit.stdout.length<2) {
  throw new Error('terminal phase artifacts do not independently validate');
}
parseStrictJsonBytes(phaseArtifactAudit.stdout,{label:'terminal phase artifact audit',
  maxBytes:16*1024*1024,maxDepth:64});
const binding=operationalClaimsReleaseBinding({planBytes,plan,requirementsBytes,
  releaseConfigBytes,releaseEvidenceBytes,phaseGenerationBytes,phaseGenerationIdentity,
  phaseArtifactAuditBytes:phaseArtifactAudit.stdout});
const phaseCompletionBytes=new Map();
for(const artifact of plan.phaseArtifacts.slice(0,-1)) {
  const name=`${String(artifact.ordinal).padStart(2,'0')}-${artifact.phase}.json`;
  phaseCompletionBytes.set(artifact.phase,await readDirectFile(path.join(completionDirectory,name),{
    minimum:2,maximum:1024*1024,exactMode:0o600,label:`${artifact.phase} completion`}));
}
const before=[requirementsBytes,releaseConfigBytes,releaseEvidenceBytes];
const ledger=buildOperationalClaimsLedger({binding,plan,phaseCompletionBytes});
await writePrivateFileDurableNewOrEqual(output,Buffer.from(`${JSON.stringify(ledger)}\n`),{
  maximum:4*1024*1024});
const after=await Promise.all([
  readDirectProjectFile(root,'config/production-requirements.json',{exactMode:0o644}),
  readDirectProjectFile(root,'config/proof-reserve.unconfigured.json',{exactMode:0o644}),
  readDirectProjectFile(root,'config/mainnet-release-evidence.unconfigured.json',{exactMode:0o644}),
]);
if(after.some((bytes,index)=>!bytes.equals(before[index]))) {
  throw new Error('release authority changed while materializing operational claims ledger');
}
const currentGeneration=await readDirectFile(identityPath,{minimum:2,maximum:64*1024,
  exactMode:0o600,label:'phase generation identity recheck'});
if(!currentGeneration.equals(phaseGenerationBytes)) {
  throw new Error('phase generation changed while materializing operational claims ledger');
}
for(const artifact of plan.phaseArtifacts.slice(0,-1)) {
  const name=`${String(artifact.ordinal).padStart(2,'0')}-${artifact.phase}.json`;
  const current=await readDirectFile(path.join(completionDirectory,name),{
    minimum:2,maximum:1024*1024,exactMode:0o600,label:`${artifact.phase} completion recheck`});
  if(!current.equals(phaseCompletionBytes.get(artifact.phase))) {
    throw new Error(`phase completion changed while materializing ledger: ${artifact.phase}`);
  }
}
const regenerated=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
  cwd:root,encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
});
if(regenerated.status!==0||regenerated.stderr.length!==0||!regenerated.stdout.equals(planBytes)) {
  throw new Error('claims plan changed while materializing operational claims ledger');
}
const reaudit=spawnSync(process.execPath,
  ['scripts/check-closed-mainnet-phase-artifacts.mjs','require-pilot-complete'],{
  cwd:root,encoding:null,env:process.env,maxBuffer:16*1024*1024,
});
if(reaudit.status!==0||reaudit.stderr.length!==0
    ||!reaudit.stdout.equals(phaseArtifactAudit.stdout)) {
  throw new Error('terminal phase artifacts changed while materializing operational claims ledger');
}
const metadata=fs.lstatSync(output,{bigint:true});
if(!metadata.isFile()||metadata.isSymbolicLink()||metadata.uid!==BigInt(process.getuid())
    ||(metadata.mode&0o777n)!==0o600n||metadata.nlink!==1n) throw new Error('installed ledger is unsafe');
process.stdout.write(`${JSON.stringify({ok:true,claimCount:ledger.claimCount,
  headSha256:ledger.headSha256,releaseConfigSha256:ledger.releaseConfigSha256})}\n`);
