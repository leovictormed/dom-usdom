import {createHash} from 'node:crypto';

export const MAINNET_FORK_REHEARSAL_OBSERVATIONS_SCHEMA=
  'usdom-mainnet-fork-rehearsal-observations-v1';
export const MAINNET_FORK_REHEARSAL_REPORT_SCHEMA='usdom-mainnet-fork-rehearsal-report-v1';
const hash=/^0x[0-9a-f]{64}$/;
const sha=/^[0-9a-f]{64}$/;
const commit=/^[0-9a-f]{40}$/;
const identifier=/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const pathPattern=/^evidence\/fork-rehearsal\/raw\/[a-z0-9][a-z0-9._-]{0,127}$/;
const decisions=Object.freeze(new Map([
  ['ethereum-reorganization','reject-conflicting-ethereum-finality'],
  ['dom-reorganization','reject-dom-reorg-below-checkpoint-floor'],
  ['ethereum-unavailability','halt-ethereum-dependent-issuance-and-redemption'],
  ['dom-unavailability','halt-checkpoint-advancement-and-redemption'],
  ['censorship','preserve-permissionless-retry-without-bypass'],
  ['recovery','resume-only-after-release-bound-recovery-drill'],
]));
const topFields=['schema','releaseId','sourceCommit','sourceTag','ethereumChainId','reserveConfigHash',
  'checkpointRegistryConfigHash','activationScheduleCommitment','generationId','forkBlockNumber',
  'forkBlockHash','rpcSourceIds','rpcEndpointHashes','startedAtUnix','finishedAtUnix','scenarios'];
const scenarioFields=['id','faultObserved','decisionObserved','unsafeTransitionCount','fundLossBaseUnits',
  'recoveryObserved','startedAtUnix','finishedAtUnix','preStateCommitment','faultStateCommitment',
  'postRecoveryStateCommitment','faultEvidence','recoveryEvidence'];
const reportFields=['schema','status','releaseId','sourceCommit','sourceTag','ethereumChainId',
  'reserveConfigHash','checkpointRegistryConfigHash','activationScheduleCommitment','generationId',
  'forkBlockNumber','forkBlockHash','rpcSourceIds','rpcEndpointHashes','startedAtUnix',
  'finishedAtUnix','observationsSha256','scenarioCount','scenarios','successCondition','failureCondition'];
const faultEvidenceFields=['schema','scenarioId','releaseId','sourceCommit','commandId',
  'assertionExitCode','observedDecision','preStateCommitment','faultStateCommitment',
  'unsafeTransitionCount','fundLossBaseUnits','generationId','forkBlockNumber','forkBlockHash','capturedAtUnix'];
const recoveryEvidenceFields=['schema','scenarioId','releaseId','sourceCommit','commandId',
  'assertionExitCode','recoveryObserved','postRecoveryStateCommitment','generationId',
  'forkBlockNumber','forkBlockHash','capturedAtUnix'];

function fail(message) { throw new Error(message); }
function exact(value,fields,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||Object.keys(value).length!==fields.length||fields.some(field=>!(field in value))) {
    fail(`${label} must use the exact supported schema`);
  }
}
function decimal(value,bits,label) {
  const maxDigits={8:3,64:20,128:39,256:78}[bits];
  if(maxDigits===undefined||typeof value!=='string'||value.length>maxDigits
      ||!/^(0|[1-9][0-9]*)$/.test(value)) fail(`${label} must be canonical decimal`);
  const parsed=BigInt(value);
  if(parsed>=(1n<<BigInt(bits))) fail(`${label} exceeds uint${bits}`);
  return parsed;
}
function bytes32(value,label) {
  if(!hash.test(value??'')||BigInt(value)===0n) fail(`${label} must be nonzero lowercase bytes32`);
  return value;
}
function document(value,label) {
  exact(value,['path','sha256'],label);
  if(typeof value.path!=='string'||!pathPattern.test(value.path)||!sha.test(value.sha256??'')) {
    fail(`${label} must be a canonical raw rehearsal document`);
  }
  return value;
}
function stable(value) {
  if(Array.isArray(value)) return value.map(stable);
  if(value&&typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,stable(value[key])]),
  );
  return value;
}
function digest(value) {
  return createHash('sha256').update(`${JSON.stringify(stable(value))}\n`).digest('hex');
}
function validateExecutionIdentity(value) {
  if(!sha.test(value.generationId??'')) fail('fork rehearsal generationId is invalid');
  if(decimal(value.forkBlockNumber,64,'forkBlockNumber')===0n) fail('fork block number must be nonzero');
  bytes32(value.forkBlockHash,'forkBlockHash');
  const ids=['drpc','publicnode'];
  const endpointHashes=['c5b9f7564a09b1b2bbdff2c7145d474bbc2ccd025460d9c5b097a39474b7980c',
    '7b71d04b616d2ce47598465ad04d63da212a14b1317f965044bf325b749a6746'];
  if(JSON.stringify(value.rpcSourceIds)!==JSON.stringify(ids)
      ||JSON.stringify(value.rpcEndpointHashes)!==JSON.stringify(endpointHashes)) {
    fail('fork rehearsal RPC source identity is invalid');
  }
}
export function serializeForkRehearsalEvidenceDocument(value) {
  return Buffer.from(`${JSON.stringify(stable(value))}\n`);
}
export function forkRehearsalEvidenceDocumentSha256(value) {
  return createHash('sha256').update(serializeForkRehearsalEvidenceDocument(value)).digest('hex');
}
function validateEvidenceDocument({kind,entry,scenario,observations,scenarioStarted,scenarioFinished}) {
  if(!entry||typeof entry!=='object'||Array.isArray(entry)||Object.keys(entry).length!==2
      ||!sha.test(entry.sha256??'')) fail(`${scenario.id} ${kind} evidence index is invalid`);
  const value=entry.document;
  if(forkRehearsalEvidenceDocumentSha256(value)!==entry.sha256) {
    fail(`${scenario.id} ${kind} evidence bytes do not match its content hash`);
  }
  if(kind==='fault') {
    exact(value,faultEvidenceFields,`${scenario.id} fault evidence document`);
    if(value.schema!=='usdom-mainnet-fork-fault-evidence-v1'
        ||value.commandId!==`${scenario.id}-fault-assertion`||value.assertionExitCode!=='0'
        ||value.observedDecision!==scenario.decisionObserved
        ||value.preStateCommitment!==scenario.preStateCommitment
        ||value.faultStateCommitment!==scenario.faultStateCommitment
        ||value.unsafeTransitionCount!=='0'||value.fundLossBaseUnits!=='0') {
      fail(`${scenario.id} fault evidence does not prove the required decision`);
    }
  } else {
    exact(value,recoveryEvidenceFields,`${scenario.id} recovery evidence document`);
    if(value.schema!=='usdom-mainnet-fork-recovery-evidence-v1'
        ||value.commandId!==`${scenario.id}-recovery-assertion`||value.assertionExitCode!=='0'
        ||value.recoveryObserved!==true
        ||value.postRecoveryStateCommitment!==scenario.postRecoveryStateCommitment) {
      fail(`${scenario.id} recovery evidence does not prove restoration`);
    }
  }
  if(value.scenarioId!==scenario.id||value.releaseId!==observations.releaseId
      ||value.sourceCommit!==observations.sourceCommit||value.generationId!==observations.generationId
      ||value.forkBlockNumber!==observations.forkBlockNumber
      ||value.forkBlockHash!==observations.forkBlockHash) fail(`${scenario.id} ${kind} evidence release/generation binding differs`);
  const captured=decimal(value.capturedAtUnix,64,`${scenario.id} ${kind} capturedAtUnix`);
  if(captured<scenarioStarted||captured>scenarioFinished) fail(`${scenario.id} ${kind} evidence time is invalid`);
  return captured;
}

export function buildMainnetForkRehearsalReport({observations,releaseEvidence,releaseConfig,
  evidenceFiles}={}) {
  exact(observations,topFields,'fork rehearsal observations');
  if(observations.schema!==MAINNET_FORK_REHEARSAL_OBSERVATIONS_SCHEMA) fail('unsupported observations schema');
  if(!identifier.test(observations.releaseId??'')||!identifier.test(observations.sourceTag??'')
      ||!releaseEvidence||releaseEvidence.schema!==1||observations.releaseId!==releaseEvidence.releaseId
      ||observations.sourceCommit!==releaseEvidence.sourceCommit
      ||observations.sourceTag!==releaseEvidence.sourceTag||!commit.test(observations.sourceCommit??'')) {
    fail('observations are not bound to the exact release provenance');
  }
  if(!releaseConfig||releaseConfig.ethereumChainId!=='1') fail('Ethereum mainnet release config is required');
  for(const field of ['reserveConfigHash','checkpointRegistryConfigHash','activationScheduleCommitment']) {
    if(bytes32(observations[field],field)!==releaseConfig[field]) fail(`${field} differs from release config`);
  }
  if(observations.ethereumChainId!==releaseConfig.ethereumChainId) fail('ethereumChainId differs from release config');
  validateExecutionIdentity(observations);
  const started=decimal(observations.startedAtUnix,64,'startedAtUnix');
  const finished=decimal(observations.finishedAtUnix,64,'finishedAtUnix');
  if(started===0n||finished<started||finished-started>7n*86400n) fail('rehearsal time window is invalid');
  if(!Array.isArray(observations.scenarios)||observations.scenarios.length!==decisions.size) {
    fail('all six fork rehearsal scenarios are required');
  }
  if(!evidenceFiles||typeof evidenceFiles!=='object'||Array.isArray(evidenceFiles)) {
    fail('raw rehearsal evidence index is required');
  }
  const paths=new Set(),hashes=new Set();
  const scenarios=observations.scenarios.map((scenario,index)=>{
    exact(scenario,scenarioFields,`scenario ${index+1}`);
    const expected=[...decisions.keys()][index];
    if(scenario.id!==expected) fail('rehearsal scenarios must use the fixed canonical order');
    if(scenario.faultObserved!==true||scenario.recoveryObserved!==true
        ||scenario.decisionObserved!==decisions.get(expected)
        ||scenario.unsafeTransitionCount!=='0'||scenario.fundLossBaseUnits!=='0') {
      fail(`${scenario.id} did not demonstrate its required fail-closed outcome`);
    }
    const scenarioStarted=decimal(scenario.startedAtUnix,64,`${scenario.id} startedAtUnix`);
    const scenarioFinished=decimal(scenario.finishedAtUnix,64,`${scenario.id} finishedAtUnix`);
    if(scenarioStarted<started||scenarioFinished<scenarioStarted||scenarioFinished>finished) {
      fail(`${scenario.id} time window is outside the rehearsal`);
    }
    const pre=bytes32(scenario.preStateCommitment,`${scenario.id} preStateCommitment`);
    const during=bytes32(scenario.faultStateCommitment,`${scenario.id} faultStateCommitment`);
    const recovered=bytes32(scenario.postRecoveryStateCommitment,
      `${scenario.id} postRecoveryStateCommitment`);
    if(pre!==during) fail(`${scenario.id} changed protected state while the fault was active`);
    if(recovered!==pre) fail(`${scenario.id} did not restore the exact protected pre-fault state`);
    const capturedAt={};
    for(const [kind,reference] of [['fault',document(scenario.faultEvidence,
      `${scenario.id} faultEvidence`)],['recovery',document(scenario.recoveryEvidence,
      `${scenario.id} recoveryEvidence`)]]) {
      if(paths.has(reference.path)||hashes.has(reference.sha256)) fail('raw rehearsal evidence must be independent');
      paths.add(reference.path); hashes.add(reference.sha256);
      const entry=evidenceFiles[reference.path];
      if(entry?.sha256!==reference.sha256) {
        fail(`${scenario.id} ${kind} evidence content hash mismatch`);
      }
      capturedAt[kind]=validateEvidenceDocument({kind,entry,scenario,observations,
        scenarioStarted,scenarioFinished});
    }
    if(capturedAt.recovery<capturedAt.fault) {
      fail(`${scenario.id} recovery evidence predates fault evidence`);
    }
    return structuredClone(scenario);
  });
  if(Object.keys(evidenceFiles).length!==paths.size
      ||Object.keys(evidenceFiles).some(path=>!paths.has(path))) fail('raw rehearsal evidence index has extra files');
  return Object.freeze({schema:MAINNET_FORK_REHEARSAL_REPORT_SCHEMA,status:'passed',
    releaseId:observations.releaseId,sourceCommit:observations.sourceCommit,
    sourceTag:observations.sourceTag,ethereumChainId:observations.ethereumChainId,
    reserveConfigHash:observations.reserveConfigHash,
    checkpointRegistryConfigHash:observations.checkpointRegistryConfigHash,
    activationScheduleCommitment:observations.activationScheduleCommitment,
    generationId:observations.generationId,forkBlockNumber:observations.forkBlockNumber,
    forkBlockHash:observations.forkBlockHash,rpcSourceIds:[...observations.rpcSourceIds],
    rpcEndpointHashes:[...observations.rpcEndpointHashes],
    startedAtUnix:observations.startedAtUnix,finishedAtUnix:observations.finishedAtUnix,
    observationsSha256:digest(observations),scenarioCount:scenarios.length.toString(),scenarios,
    successCondition:'all-six-faults-observed; exact fail-closed decision; zero unsafe transitions; zero fund loss; protected state unchanged during fault; exact pre-fault state restored; recovery evidence at or after fault evidence',
    failureCondition:'any missing, stale, release-mismatched, hash-mismatched, state-changing, loss-bearing, bypassed, causally inverted, incompletely restored, unrecovered, or unexpected scenario fails the report',
  });
}

export function serializeMainnetForkRehearsalReport(report) {
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}

export function validateMainnetForkRehearsalReport({report,releaseEvidence,releaseConfig,
  evidenceFiles}={}) {
  exact(report,reportFields,'mainnet fork rehearsal report');
  if(report.schema!==MAINNET_FORK_REHEARSAL_REPORT_SCHEMA||report.status!=='passed'
      ||report.scenarioCount!=='6'||!sha.test(report.observationsSha256??'')) {
    fail('mainnet fork rehearsal report status or schema is invalid');
  }
  const observations={schema:MAINNET_FORK_REHEARSAL_OBSERVATIONS_SCHEMA,
    releaseId:report.releaseId,sourceCommit:report.sourceCommit,sourceTag:report.sourceTag,
    ethereumChainId:report.ethereumChainId,reserveConfigHash:report.reserveConfigHash,
    checkpointRegistryConfigHash:report.checkpointRegistryConfigHash,
    activationScheduleCommitment:report.activationScheduleCommitment,
    generationId:report.generationId,forkBlockNumber:report.forkBlockNumber,
    forkBlockHash:report.forkBlockHash,rpcSourceIds:structuredClone(report.rpcSourceIds),
    rpcEndpointHashes:structuredClone(report.rpcEndpointHashes),
    startedAtUnix:report.startedAtUnix,finishedAtUnix:report.finishedAtUnix,
    scenarios:structuredClone(report.scenarios)};
  const expected=buildMainnetForkRehearsalReport({observations,releaseEvidence,releaseConfig,evidenceFiles});
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(expected))) {
    fail('mainnet fork rehearsal report is not the canonical release-bound report');
  }
  return true;
}
