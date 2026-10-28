import {createHash} from 'node:crypto';
import {validateClosedMainnetExecutionPlan} from './closed-mainnet-phase-dependency.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

const hex=/^[0-9a-f]{64}$/;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());

function fail(message) { throw new Error(message); }

export function operationalClaimsReleaseBinding({planBytes,plan,requirementsBytes,
  releaseConfigBytes,releaseEvidenceBytes,phaseGenerationBytes,phaseGenerationIdentity,
  phaseArtifactAuditBytes}={}) {
  for(const [label,value] of Object.entries({planBytes,requirementsBytes,releaseConfigBytes,
    releaseEvidenceBytes,phaseGenerationBytes,phaseArtifactAuditBytes})) if(!Buffer.isBuffer(value)||value.length<2) fail(`${label} is invalid`);
  const parsedPlan=parseStrictJsonBytes(planBytes,{label:'open claims execution plan',maxDepth:32});
  if(JSON.stringify(parsedPlan)!==JSON.stringify(plan)) fail('plan bytes differ from parsed authority');
  validateClosedMainnetExecutionPlan(plan);
  const planSha256=sha(planBytes);
  const phaseCatalogSha256=sha(Buffer.from(`${JSON.stringify(plan.phaseArtifacts)}\n`));
  if(!phaseGenerationIdentity||phaseGenerationIdentity.planSha256!==planSha256
      ||phaseGenerationIdentity.phaseCatalogSha256!==phaseCatalogSha256
      ||!bytesCanonicalJson(phaseGenerationBytes,phaseGenerationIdentity)) {
    fail('phase generation identity is not canonical or does not bind the plan');
  }
  validatePhaseArtifactAudit(phaseArtifactAuditBytes);
  return Object.freeze({planSha256,phaseCatalogSha256,
    phaseGenerationSha256:sha(phaseGenerationBytes),
    phaseArtifactAuditSha256:sha(phaseArtifactAuditBytes),
    evidenceDirectoryDevice:phaseGenerationIdentity.evidenceDirectoryDevice,
    evidenceDirectoryInode:phaseGenerationIdentity.evidenceDirectoryInode,
    productionRequirementsSha256:sha(requirementsBytes),
    releaseConfigSha256:sha(releaseConfigBytes),releaseEvidenceSha256:sha(releaseEvidenceBytes)});
}

function bytesCanonicalJson(bytes,value) {
  return bytes.equals(Buffer.from(`${JSON.stringify(value)}\n`));
}

function validatePhaseArtifactAudit(bytes) {
  let value;
  try { value=parseStrictJsonBytes(bytes,{label:'terminal phase artifact audit',maxDepth:64}); }
  catch { fail('terminal phase artifact audit is malformed'); }
  if(!exact(value,['schema','artifacts'])
      ||value.schema!=='usdom-closed-mainnet-phase-checklist/v1'||!Array.isArray(value.artifacts)
      ||!bytes.equals(Buffer.from(`${JSON.stringify(value,null,2)}\n`))) {
    fail('terminal phase artifact audit schema is invalid');
  }
  const byName=new Map();
  for(const artifact of value.artifacts) {
    if(!artifact||typeof artifact!=='object'||Array.isArray(artifact)
        ||typeof artifact.artifact!=='string'||typeof artifact.status!=='string'
        ||byName.has(artifact.artifact)||artifact.status==='missing') {
      fail('terminal phase artifact audit is incomplete or ambiguous');
    }
    byName.set(artifact.artifact,artifact.status);
  }
  const required=new Map([
    ['owners','verified'],['safePackage','bound-to-owners-awaiting-baseline'],['baseline','verified'],
    ['identity','verified'],['deployment','verified'],
    ['predeploymentAttestation','deferred-to-readiness'],['coldStartAttestation','deferred-to-readiness'],
    ['depositPackage','verified'],['depositExecution','verified'],
    ['redemptionPackage','verified'],['redemptionExecution','verified'],
    ['financialConservation','verified'],['pilot','reconciled'],
  ]);
  for(const [name,status] of required) if(byName.get(name)!==status) {
    fail(`terminal phase artifact audit lacks ${name}=${status}`);
  }
  return value;
}

export function buildOperationalClaimsLedger({binding,plan,phaseCompletionBytes}={}) {
  validateClosedMainnetExecutionPlan(plan);
  const bindingKeys=['planSha256','phaseCatalogSha256','phaseGenerationSha256','phaseArtifactAuditSha256',
    'evidenceDirectoryDevice','evidenceDirectoryInode','productionRequirementsSha256',
    'releaseConfigSha256','releaseEvidenceSha256'];
  if(!exact(binding,bindingKeys)
      ||['planSha256','phaseCatalogSha256','phaseGenerationSha256','phaseArtifactAuditSha256','productionRequirementsSha256',
        'releaseConfigSha256','releaseEvidenceSha256'].some(key=>!hex.test(binding[key]))
      ||!/^([1-9][0-9]*)$/.test(binding.evidenceDirectoryDevice)
      ||!/^([1-9][0-9]*)$/.test(binding.evidenceDirectoryInode)
      ||!(phaseCompletionBytes instanceof Map)) fail('operational claims release binding is invalid');
  const completionKeys=['schema','planSha256','phaseCatalogSha256','evidenceDirectoryDevice',
    'evidenceDirectoryInode','phase','ordinal','phaseScriptSha256','predecessorCompletionSha256'];
  if(plan.phaseArtifacts.at(-1)?.phase!=='readiness'
      ||plan.entries.some(route=>route.phase==='readiness')) {
    fail('readiness must be the terminal claim-free ledger materialization phase');
  }
  const completedArtifacts=plan.phaseArtifacts.slice(0,-1);
  if(phaseCompletionBytes.size!==completedArtifacts.length) {
    fail('operational claims phase completion catalog is incomplete');
  }
  const orderedCompletionBytes=[];
  let evidenceDirectoryDevice=null,evidenceDirectoryInode=null;
  for(const artifact of completedArtifacts) {
    const bytes=phaseCompletionBytes.get(artifact.phase);
    if(!Buffer.isBuffer(bytes)||bytes.length<2) fail(`phase completion is absent: ${artifact.phase}`);
    let completion;
    try { completion=parseStrictJsonBytes(bytes,{label:`phase completion ${artifact.phase}`,maxDepth:32}); }
    catch { fail(`phase completion is malformed: ${artifact.phase}`); }
    const expectedPredecessors=orderedCompletionBytes.map(sha);
    if(!exact(completion,completionKeys)
        ||completion.schema!=='usdom-closed-mainnet-phase-completion/v1'
        ||completion.planSha256!==binding.planSha256
        ||completion.phaseCatalogSha256!==binding.phaseCatalogSha256
        ||completion.phase!==artifact.phase||completion.ordinal!==artifact.ordinal
        ||completion.phaseScriptSha256!==artifact.generatedScriptSha256
        ||JSON.stringify(completion.predecessorCompletionSha256)!==JSON.stringify(expectedPredecessors)
        ||!bytes.equals(Buffer.from(`${JSON.stringify(completion)}\n`))) {
      fail(`phase completion is foreign or noncanonical: ${artifact.phase}`);
    }
    if(evidenceDirectoryDevice===null) {
      evidenceDirectoryDevice=completion.evidenceDirectoryDevice;
      evidenceDirectoryInode=completion.evidenceDirectoryInode;
    } else if(completion.evidenceDirectoryDevice!==evidenceDirectoryDevice
        ||completion.evidenceDirectoryInode!==evidenceDirectoryInode) {
      fail(`phase completion evidence generation changed: ${artifact.phase}`);
    }
    if(completion.evidenceDirectoryDevice!==binding.evidenceDirectoryDevice
        ||completion.evidenceDirectoryInode!==binding.evidenceDirectoryInode) {
      fail(`phase completion belongs to another evidence generation: ${artifact.phase}`);
    }
    orderedCompletionBytes.push(bytes);
  }
  let previousEntrySha256='0'.repeat(64);
  const entries=plan.entries.map((route,index)=>{
    const completionBytes=phaseCompletionBytes.get(route.phase);
    const completion=parseStrictJsonBytes(completionBytes,{label:`phase completion ${route.phase}`,maxDepth:32});
    if(completion.phase!==route.phase||completion.ordinal!==route.phaseOrdinal) {
      fail(`phase completion is foreign for operational claim: ${route.claim}`);
    }
    const entry={ordinal:index+1,claim:route.claim,category:route.category,phase:route.phase,
      phaseOrdinal:route.phaseOrdinal,phaseCompletionSha256:sha(completionBytes),
      previousEntrySha256};
    previousEntrySha256=sha(Buffer.from(`${JSON.stringify(entry)}\n`));
    return Object.freeze(entry);
  });
  return Object.freeze({schema:'usdom-operational-claims-ledger/v1',...binding,
    claimCount:entries.length,entries:Object.freeze(entries),headSha256:previousEntrySha256});
}

export function validateOperationalClaimsLedger(ledger,{binding,plan,phaseCompletionBytes}={}) {
  const keys=['schema','planSha256','phaseCatalogSha256','phaseGenerationSha256','phaseArtifactAuditSha256',
    'evidenceDirectoryDevice','evidenceDirectoryInode','productionRequirementsSha256',
    'releaseConfigSha256','releaseEvidenceSha256','claimCount','entries','headSha256'];
  if(!exact(ledger,keys)||ledger.schema!=='usdom-operational-claims-ledger/v1') {
    fail('operational claims ledger schema is invalid');
  }
  const expected=buildOperationalClaimsLedger({binding,plan,phaseCompletionBytes});
  if(JSON.stringify(ledger)!==JSON.stringify(expected)) {
    fail('operational claims ledger is stale, truncated, reordered or foreign');
  }
  return ledger;
}

export function applyOperationalClaimsLedger(requirements,ledger) {
  if(!requirements||typeof requirements!=='object'||Array.isArray(requirements)) {
    fail('production requirements are invalid');
  }
  const overlaid={...requirements};
  for(const entry of ledger.entries) {
    if(requirements[entry.claim]!==false) {
      fail(`operational claim is not an immutable false policy slot: ${entry.claim}`);
    }
    overlaid[entry.claim]=true;
  }
  return Object.freeze(overlaid);
}
