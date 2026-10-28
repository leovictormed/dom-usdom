#!/usr/bin/env node
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,lstat} from 'node:fs/promises';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {buildSafeControlReleaseEvidenceV3} from '../sdk/safe-control-release-evidence-v3.mjs';

const MAXIMUM=4*1024*1024;
function requiredAbsolute(name) {
  const value=process.env[name];
  if(typeof value!=='string'||!path.isAbsolute(value)) throw new Error(`${name} required`);
  return path.resolve(value);
}
async function capture(file,label) {
  const bytes=await readDirectFile(file,{minimum:2,maximum:MAXIMUM,exactMode:0o600,label});
  return {
    path:file,label,bytes,
    value:parseStrictJsonBytes(bytes,{label,maxBytes:MAXIMUM,maxDepth:64}),
  };
}
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');

const packageFile=await capture(requiredAbsolute('USDOM_SAFE_PACKAGE'),'Safe package');
const baseline=await capture(requiredAbsolute('USDOM_SAFE_BASELINE'),'Safe baseline');
const plan=await capture(requiredAbsolute('USDOM_SAFE_RECOVERY_ROSTER_PLAN'),'recovery v3 plan');
const proofs=await capture(requiredAbsolute('USDOM_SAFE_RECOVERY_ROSTER_PROOFS'),'recovery v3 proofs');
const stateDirectory=requiredAbsolute('USDOM_SAFE_RECOVERY_V3_STATE_DIRECTORY');
const completions=[];
for(let ordinal=0;ordinal<12;ordinal++) {
  completions.push(await capture(
    path.join(stateDirectory,`recovery-v3-step-${ordinal}-completion.json`),
    `recovery v3 completion ${ordinal}`,
  ));
}
const inputs=[packageFile,baseline,plan,proofs,...completions];
const bundle=buildSafeControlReleaseEvidenceV3({
  packageDocument:packageFile.value,baselineSnapshot:baseline.value,plan:plan.value,
  proofs:proofs.value,completions:completions.map(value=>value.value),
});
const projectRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const outputDirectory=path.join(projectRoot,'evidence/control-plane');
const documents={
  bundle,governance:bundle.roleReports.governance,guardian:bundle.roleReports.guardian,
  checkpointGuardian:bundle.roleReports.checkpointGuardian,
  usdtCustody:bundle.roleReports.usdtCustody,separation:bundle.separationReport,
  recovery:bundle.recoveryDrillReport,
};
const names={
  bundle:'safe-control-release-evidence-bundle.json',governance:'governance-configuration.json',
  guardian:'guardian-configuration.json',
  checkpointGuardian:'checkpoint-guardian-configuration.json',
  usdtCustody:'usdt-custody-configuration.json',
  separation:'control-plane-separation.json',recovery:'control-plane-recovery-drill.json',
};
await mkdir(outputDirectory,{recursive:true,mode:0o700});
const outputStat=await lstat(outputDirectory);
if(!outputStat.isDirectory()||outputStat.isSymbolicLink()||(outputStat.mode&0o777)!==0o700
    ||outputStat.uid!==process.getuid()) throw new Error('unsafe control-plane evidence directory');

const serialized={};
for(const [key,value] of Object.entries(documents)) {
  serialized[key]=Buffer.from(`${JSON.stringify(value,null,2)}\n`);
  await writePrivateFileDurableNewOrEqual(
    path.join(outputDirectory,names[key]),serialized[key],{maximum:MAXIMUM},
  );
}
for(const input of inputs) {
  const current=await readDirectFile(input.path,{
    minimum:input.bytes.length,maximum:input.bytes.length,exactMode:0o600,label:input.label,
  });
  if(!current.equals(input.bytes)) throw new Error(`${input.label} changed during materialization`);
}
const reference=key=>({
  path:`evidence/control-plane/${names[key]}`,sha256:sha256(serialized[key]),
});
const fragment={
  schema:'usdom-safe-control-release-fragment/v3',bundleHash:bundle.bundleHash,
  controlPlaneEvidenceBundle:reference('bundle'),
  controlPlane:Object.fromEntries(
    ['governance','guardian','checkpointGuardian','usdtCustody'].map(key=>[key,{
      address:documents[key].address,runtimeCodeHash:documents[key].runtimeCodeHash,
      configurationHash:documents[key].configurationHash,configurationReport:reference(key),
    }]),
  ),
  controlPlaneSeparationReport:reference('separation'),
  controlPlaneRecoveryDrillReport:reference('recovery'),
};
await writePrivateFileDurableNewOrEqual(
  path.join(outputDirectory,'release-evidence-fragment.json'),
  Buffer.from(`${JSON.stringify(fragment,null,2)}\n`),{maximum:MAXIMUM},
);
process.stdout.write(`${JSON.stringify(fragment)}\n`);
