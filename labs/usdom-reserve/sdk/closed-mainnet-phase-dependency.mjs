import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const hex=/^[0-9a-f]{64}$/;
const phaseName=/^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());

export function validateClosedMainnetExecutionPlan(plan) {
  const top=['schema','claimCount','phaseOrder','phaseArtifacts','entries'];
  if(!exact(plan,top)||plan.schema!=='usdom-open-claims-execution-plan/v1'
      ||!Number.isSafeInteger(plan.claimCount)||plan.claimCount<1||plan.claimCount>256
      ||!Array.isArray(plan.entries)||plan.entries.length!==plan.claimCount
      ||!Array.isArray(plan.phaseOrder)||plan.phaseOrder.length<21
      ||plan.phaseOrder.length>32||new Set(plan.phaseOrder).size!==plan.phaseOrder.length
      ||plan.phaseOrder.some(value=>!phaseName.test(value))
      ||!Array.isArray(plan.phaseArtifacts)||plan.phaseArtifacts.length!==plan.phaseOrder.length) {
    throw new Error('closed-mainnet execution plan schema or phase order is invalid');
  }
  plan.phaseArtifacts.forEach((artifact,index)=>{
    const keys=['phase','ordinal','prerequisitePhases','generatedScriptSha256','generatedScriptBytes'];
    if(!exact(artifact,keys)||artifact.phase!==plan.phaseOrder[index]||artifact.ordinal!==index+1
        ||!Array.isArray(artifact.prerequisitePhases)
        ||JSON.stringify(artifact.prerequisitePhases)!==JSON.stringify(plan.phaseOrder.slice(0,index))
        ||!hex.test(artifact.generatedScriptSha256)||!Number.isSafeInteger(artifact.generatedScriptBytes)
        ||artifact.generatedScriptBytes<1||artifact.generatedScriptBytes>16*1024*1024) {
      throw new Error(`closed-mainnet phase artifact is invalid at ordinal ${index+1}`);
    }
  });
  return plan;
}

export function closedMainnetPhaseGenerationIdentity({planBytes,plan,evidenceDirectoryStat,executionLockStat,planPath}) {
  if(!Buffer.isBuffer(planBytes)
      ||JSON.stringify(parseStrictJsonBytes(planBytes,{label:'closed-mainnet execution plan',
        maxBytes:16*1024*1024,maxDepth:64}))!==JSON.stringify(plan)) {
    throw new Error('plan bytes differ from parsed authority');
  }
  validateClosedMainnetExecutionPlan(plan);
  const validIdentityNumber=value=>(typeof value==='bigint'&&value>0n)
    ||(Number.isSafeInteger(value)&&value>0);
  if(!hex.test(hash(planBytes))
      ||typeof planPath!=='string'||!planPath.endsWith(`${hash(planBytes)}.json`)
      ||!evidenceDirectoryStat||!validIdentityNumber(evidenceDirectoryStat.dev)
      ||!validIdentityNumber(evidenceDirectoryStat.ino)||!executionLockStat
      ||!validIdentityNumber(executionLockStat.dev)||!validIdentityNumber(executionLockStat.ino)) throw new Error('phase generation identity input is invalid');
  return Object.freeze({schema:'usdom-closed-mainnet-phase-generation/v1',
    planSha256:hash(planBytes),planPath,phaseCount:plan.phaseOrder.length,
    phaseCatalogSha256:hash(Buffer.from(`${JSON.stringify(plan.phaseArtifacts)}\n`)),
    evidenceDirectoryDevice:String(evidenceDirectoryStat.dev),
    evidenceDirectoryInode:String(evidenceDirectoryStat.ino),
    executionLockDevice:String(executionLockStat.dev),executionLockInode:String(executionLockStat.ino)});
}

export function validateClosedMainnetPhaseGenerationIdentity(value,expected) {
  const keys=['schema','planSha256','planPath','phaseCount','phaseCatalogSha256',
    'evidenceDirectoryDevice','evidenceDirectoryInode','executionLockDevice','executionLockInode'];
  if(!exact(value,keys)||value.schema!=='usdom-closed-mainnet-phase-generation/v1'
      ||!Number.isSafeInteger(value.phaseCount)||value.phaseCount<21||value.phaseCount>32
      ||!hex.test(value.planSha256)||!hex.test(value.phaseCatalogSha256)
      ||!/^[1-9][0-9]*$/.test(value.evidenceDirectoryDevice)
      ||!/^[1-9][0-9]*$/.test(value.evidenceDirectoryInode)
      ||!/^[1-9][0-9]*$/.test(value.executionLockDevice)
      ||!/^[1-9][0-9]*$/.test(value.executionLockInode)
      ||JSON.stringify(value)!==JSON.stringify(expected)) {
    throw new Error('phase generation identity is stale, foreign or malformed');
  }
  return value;
}

export function buildClosedMainnetPhaseCompletion({identity,artifact,scriptBytes,predecessorBytes}) {
  if(!Buffer.isBuffer(scriptBytes)||hash(scriptBytes)!==artifact?.generatedScriptSha256
      ||scriptBytes.length!==artifact.generatedScriptBytes||!Array.isArray(predecessorBytes)
      ||predecessorBytes.length!==artifact.ordinal-1) throw new Error('phase completion inputs are invalid');
  const predecessorCompletionSha256=predecessorBytes.map(bytes=>hash(bytes));
  return Object.freeze({schema:'usdom-closed-mainnet-phase-completion/v1',
    planSha256:identity.planSha256,phaseCatalogSha256:identity.phaseCatalogSha256,
    evidenceDirectoryDevice:identity.evidenceDirectoryDevice,
    evidenceDirectoryInode:identity.evidenceDirectoryInode,
    phase:artifact.phase,ordinal:artifact.ordinal,
    phaseScriptSha256:artifact.generatedScriptSha256,
    predecessorCompletionSha256});
}

export function validateClosedMainnetPhaseCompletion(value,{identity,artifact,bytes,predecessorBytes}) {
  const keys=['schema','planSha256','phaseCatalogSha256','evidenceDirectoryDevice',
    'evidenceDirectoryInode','phase','ordinal','phaseScriptSha256','predecessorCompletionSha256'];
  const expected=buildClosedMainnetPhaseCompletion({identity,artifact,
    scriptBytes:bytes.scriptBytes,predecessorBytes});
  if(!exact(value,keys)||value.schema!=='usdom-closed-mainnet-phase-completion/v1'
      ||JSON.stringify(value)!==JSON.stringify(expected)
      ||!Buffer.isBuffer(bytes.completionBytes)
      ||!bytes.completionBytes.equals(Buffer.from(`${JSON.stringify(value)}\n`))) {
    throw new Error(`phase completion is stale, foreign or noncanonical: ${artifact.phase}`);
  }
  return value;
}

export const closedMainnetPhaseSha256=hash;
