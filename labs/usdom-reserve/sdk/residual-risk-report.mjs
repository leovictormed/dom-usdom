import {createHash} from 'node:crypto';
import {getAddress} from 'ethers';

const bytes32=/^0x[0-9a-fA-F]{64}$/;
const commit=/^[0-9a-f]{40}$/;
const sha256=/^[0-9a-f]{64}$/;
const releaseTag=/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/;
const uint64=/^(0|[1-9][0-9]{0,19})$/;
const reportKeys=['activationScheduleCommitment','checkpointRegistryConfigHash','draftSha256',
  'ethereumChainId','evidenceEnvelopeSha256','governance','governanceDelaySeconds','maxOutstandingBaseUnits',
  'outflowCapacityBaseUnitsPerDay','realFundsAuthorized','releaseId','reserve','reserveConfigHash','risks','rule','schema',
  'selectedFinality','sourceCommit','sourceTag','status','token','withdrawalDelaySeconds'];
const riskRegister=Object.freeze([
  ['R1','USDT issuer control'],['R2','Irreversible burns and destination mistakes'],
  ['R3','Ethereum consensus and execution'],['R4','DOM PoW and checkpoint finality'],
  ['R5','Zero-knowledge proof systems'],['R6','Privacy and public-chain correlation'],
  ['R7','Wallet keys, backups and rollback'],['R8','Governance, guardian and operational keys'],
  ['R9','Congestion, capacity and data availability'],['R10','Immutable implementation and migration'],
  ['R11','Compiler, build and supply chain'],['R12','Undiscovered defects and model limits'],
]);

function fail(message) { throw new Error(message); }
function exact(value,keys) {
  return value&&typeof value==='object'&&!Array.isArray(value)
    &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
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

export function buildResidualRiskReport({releaseEvidence,releaseConfig,requirements,draftSha256}={}) {
  if(!releaseEvidence||releaseEvidence.schema!==1) fail('release evidence is invalid');
  if(typeof releaseEvidence.releaseId!=='string'||releaseEvidence.releaseId.length===0
      || !commit.test(releaseEvidence.sourceCommit??'')
      ||!releaseTag.test(releaseEvidence.sourceTag??'')) fail('release provenance is incomplete');
  if(!releaseConfig||releaseConfig.productionReady!==true
      ||typeof releaseConfig.realFundsAuthorized!=='boolean') {
    fail('production release configuration is incomplete');
  }
  for(const key of ['reserveConfigHash','checkpointRegistryConfigHash']) {
    if(!bytes32.test(releaseConfig[key]??'')||BigInt(releaseConfig[key])===0n) fail(`${key} is invalid`);
  }
  if(releaseConfig.ethereumChainId!=='1') fail('Ethereum mainnet release is required');
  for(const key of ['activationScheduleCommitment']) {
    if(!bytes32.test(releaseConfig[key]??'')||BigInt(releaseConfig[key])===0n) fail(`${key} is invalid`);
  }
  for(const key of ['maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay',
    'withdrawalDelaySeconds','governanceDelaySeconds']) {
    const value=releaseConfig[key];
    if(!uint64.test(value??'')) fail(`${key} is invalid`);
    const parsed=BigInt(value);
    if(parsed===0n||parsed>=(1n<<64n)) fail(`${key} is invalid`);
  }
  if(!sha256.test(draftSha256??'')) fail('residual-risk draft SHA-256 is invalid');
  const selectedFinality=requirements?.finality_evaluation?.selected_production_mechanism;
  if(selectedFinality!=='ethereum-checkpoint-finality'
      || requirements?.checkpoint_poc_authorization?.production_mechanism_approved!==true) {
    fail('supported production finality is not selected and approved');
  }
  const evidenceEnvelope=structuredClone(releaseEvidence);
  evidenceEnvelope.residualRiskAcceptanceReport=null;
  return {
    schema:'usdom-residual-risk-report/v1',status:'presented-for-governance-acceptance',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:releaseConfig.ethereumChainId,
    governance:getAddress(releaseConfig.governance),reserve:getAddress(releaseConfig.reserve),
    token:getAddress(releaseConfig.token),reserveConfigHash:releaseConfig.reserveConfigHash,
    checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
    activationScheduleCommitment:releaseConfig.activationScheduleCommitment,
    selectedFinality,realFundsAuthorized:releaseConfig.realFundsAuthorized,
    maxOutstandingBaseUnits:releaseConfig.maxOutstandingBaseUnits,
    outflowCapacityBaseUnitsPerDay:releaseConfig.outflowCapacityBaseUnitsPerDay,
    withdrawalDelaySeconds:releaseConfig.withdrawalDelaySeconds,
    governanceDelaySeconds:releaseConfig.governanceDelaySeconds,
    evidenceEnvelopeSha256:digest(evidenceEnvelope),draftSha256,
    risks:riskRegister.map(([id,title])=>({id,title,accepted:false})),
    rule:'Governance acceptance applies only to documented residual risks for this exact release. It cannot waive a failed technical gate, mismatched artifact, unauthorized mint or payout path, missing production key, or failed recovery drill.',
  };
}

export function serializeResidualRiskReport(report) {
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}

export function validateResidualRiskReport(report,context={}) {
  if(!exact(report,reportKeys)) fail('residual-risk report must use the exact supported schema');
  if(!Array.isArray(report.risks)||report.risks.length!==riskRegister.length
      ||report.risks.some((risk,index)=>!exact(risk,['accepted','id','title'])
        ||risk.id!==riskRegister[index][0]||risk.title!==riskRegister[index][1]
        ||risk.accepted!==false)) fail('residual-risk register is incomplete or altered');
  const rebuilt=buildResidualRiskReport(context);
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(rebuilt))) {
    fail('residual-risk report differs from its canonical release binding');
  }
  return rebuilt;
}
