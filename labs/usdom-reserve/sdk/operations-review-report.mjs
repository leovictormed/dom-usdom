import {getAddress} from 'ethers';

const sha256=/^[0-9a-f]{64}$/;
const bytes32=/^0x[0-9a-fA-F]{64}$/;
const commit=/^[0-9a-f]{40}$/;
const tag=/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/;
const evidenceNames=Object.freeze([
  'securityValidationReport','riscZeroHealthSourceCatalog','realFinalizedEndToEndReport',
  'checkpointProofCapacityReport','controlPlaneEvidenceBundle','controlPlaneSeparationReport',
  'controlPlaneRecoveryDrillReport','mainnetPredeploymentAttestationReport',
  'nativeScheduledRuntimeActivationAttestationReport',
]);
export const OPERATIONS_REVIEW_EVIDENCE_NAMES=evidenceNames;
const assertionNames=Object.freeze([
  'automaticFundMovementAbsent','checkpointCapacityValidated','controlPlaneRecoveryValidated',
  'deploymentRequiresSeparateSigningAndPublicationAuthorization',
  'finalizedBurnCapacityValidated','nativeRuntimeActivationReviewed',
  'predeploymentSnapshotValidated','releaseValidationPassed','verifierHealthSourcesPinned',
]);

export const OPERATIONS_REVIEW_REPORT_SCHEMA='usdom-operations-review-report/v1';

function fail(message) { throw new Error(message); }
function exact(value,keys) {
  return value&&typeof value==='object'&&!Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
}
function stable(value) {
  if(Array.isArray(value)) return value.map(stable);
  if(value&&typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,stable(value[key])]),
  );
  return value;
}
function document(value,name) {
  if(!exact(value,['path','sha256'])||typeof value.path!=='string'||value.path.length===0
      ||value.path.startsWith('/')||value.path.includes('\\')||value.path.split('/').includes('..')
      ||!sha256.test(value.sha256??'')) fail(`${name} is not exact hash-addressed evidence`);
  return {...value};
}
function hash(value,name) {
  if(!bytes32.test(value??'')||BigInt(value)===0n) fail(`${name} must be nonzero bytes32`);
  return value.toLowerCase();
}
function address(value,name) {
  try {
    const parsed=getAddress(value);
    if(BigInt(parsed)===0n) fail(`${name} must be nonzero`);
    return parsed;
  } catch { fail(`${name} must be a nonzero address`); }
}

export function buildOperationsReviewReport({releaseEvidence,releaseConfig,runbookSha256}={}) {
  if(!releaseEvidence||releaseEvidence.schema!==1||typeof releaseEvidence.releaseId!=='string'
      ||releaseEvidence.releaseId.length===0||!commit.test(releaseEvidence.sourceCommit??'')
      ||!tag.test(releaseEvidence.sourceTag??'')) fail('release provenance is incomplete');
  if(!releaseConfig||releaseConfig.ethereumChainId!=='1') fail('Ethereum mainnet release is required');
  if(!sha256.test(runbookSha256??'')) fail('operator runbook SHA-256 is invalid');
  const operationalEvidence=Object.fromEntries(evidenceNames.map(name=>[
    name,document(releaseEvidence[name],name),
  ]));
  const paths=Object.values(operationalEvidence).map(value=>value.path);
  const hashes=Object.values(operationalEvidence).map(value=>value.sha256);
  if(new Set(paths).size!==paths.length||new Set(hashes).size!==hashes.length) {
    fail('operations review evidence must use distinct paths and content hashes');
  }
  return {schema:OPERATIONS_REVIEW_REPORT_SCHEMA,status:'reviewed',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',
    reserve:address(releaseConfig.reserve,'reserve'),
    checkpointRegistry:address(releaseConfig.checkpointRegistry,'checkpointRegistry'),
    governance:address(releaseConfig.governance,'governance'),
    guardian:address(releaseConfig.guardian,'guardian'),
    checkpointGuardian:address(releaseConfig.checkpointGuardian,'checkpointGuardian'),
    reserveConfigHash:hash(releaseConfig.reserveConfigHash,'reserveConfigHash'),
    checkpointRegistryConfigHash:hash(releaseConfig.checkpointRegistryConfigHash,
      'checkpointRegistryConfigHash'),runbookSha256,operationalEvidence,
    reviewAssertions:Object.fromEntries(assertionNames.map(name=>[name,true])),
    limitation:'This review binds tested procedures and immutable evidence. Every signature, publication, deployment and movement of funds still requires its separately authorized release step.'};
}

export function validateOperationsReviewReport(report,context={}) {
  const keys=['checkpointGuardian','checkpointRegistry','checkpointRegistryConfigHash','ethereumChainId',
    'governance','guardian','limitation','operationalEvidence','releaseId','reserve','reserveConfigHash',
    'reviewAssertions','runbookSha256','schema','sourceCommit','sourceTag','status'];
  if(!exact(report,keys)||!exact(report.reviewAssertions,assertionNames)
      ||Object.values(report.reviewAssertions??{}).some(value=>value!==true)
      ||!exact(report.operationalEvidence,evidenceNames)) fail('operations review report schema is invalid');
  const rebuilt=buildOperationsReviewReport(context);
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(rebuilt))) {
    fail('operations review report differs from its canonical release binding');
  }
  return rebuilt;
}

export function serializeOperationsReviewReport(report) {
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}
