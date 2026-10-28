import {getAddress} from 'ethers';
import {
  _safeControlObservationInternals,
  safeControlConfigurationHash,
  validateRecoverableSafeControlBaseline,
} from './safe-control-observation.mjs';
import {
  buildProofBundle,
  buildRecoveryRosterDrill,
  nextRecoveryOrdinal,
  recoveryStepEnvelope,
} from './safe-recovery-roster-drill.mjs';

const {documentHash,canonicalJson}=_safeControlObservationInternals;
const HASH=/^0x[0-9a-f]{64}$/u;
const DECIMAL=/^(0|[1-9][0-9]*)$/u;
const ROLE_MAP=[
  ['governance','governance'],
  ['guardian','reserveGuardian'],
  ['checkpointGuardian','checkpointGuardian'],
  ['usdtCustody','usdtCustody'],
];
const COMPLETION_KEYS=[
  'ordinal','planHash','safeTxHash','status','ownersAfter','transactionHash','blockNumber',
  'blockHash','finalizedBlockNumber','finalizedBlockHash',
];

export const SAFE_CONTROL_RELEASE_EVIDENCE_V3_SCHEMA='usdom-safe-control-release-evidence/v3';

function fail(message) { throw new Error(message); }
function exactKeys(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||canonicalJson(Object.keys(value).sort())!==canonicalJson([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function sameAddresses(left,right) {
  return Array.isArray(left)&&Array.isArray(right)&&left.length===right.length
    &&left.every((value,index)=>getAddress(value)===getAddress(right[index]));
}
function hash(value,label) {
  if(typeof value!=='string'||!HASH.test(value)||BigInt(value)===0n) fail(`${label} is invalid`);
  return value;
}
function decimal(value,label) {
  if(typeof value!=='string'||!DECIMAL.test(value)) fail(`${label} is invalid`);
  return value;
}

function validateCompletion(plan,value,ordinal) {
  exactKeys(value,COMPLETION_KEYS,`recovery completion ${ordinal}`);
  const expected=recoveryStepEnvelope(plan,Math.floor(ordinal/3),ordinal%3);
  if(value.ordinal!==ordinal||value.planHash!==plan.planHash
      ||value.safeTxHash!==expected.safeTxHash||value.status!=='finalized-dual-rpc') {
    fail(`recovery completion ${ordinal} identity mismatch`);
  }
  hash(value.transactionHash,`recovery completion ${ordinal} transaction hash`);
  hash(value.blockHash,`recovery completion ${ordinal} block hash`);
  hash(value.finalizedBlockHash,`recovery completion ${ordinal} finalized block hash`);
  decimal(value.blockNumber,`recovery completion ${ordinal} block number`);
  decimal(value.finalizedBlockNumber,`recovery completion ${ordinal} finalized block number`);
  if(BigInt(value.blockNumber)>BigInt(value.finalizedBlockNumber)) {
    fail(`recovery completion ${ordinal} is not finalized`);
  }
  return value;
}

export function buildSafeControlReleaseEvidenceV3({
  packageDocument,baselineSnapshot,plan,proofs,completions,
}) {
  validateRecoverableSafeControlBaseline(baselineSnapshot,packageDocument);
  const rebuiltPlan=buildRecoveryRosterDrill(
    packageDocument,baselineSnapshot,plan.replacementOwners,[],
  );
  if(canonicalJson(rebuiltPlan)!==canonicalJson(plan)) fail('recovery v3 plan drift');
  const rebuiltProofs=buildProofBundle(
    plan,proofs.proofs.map(value=>({signer:value.replacementOwner,signature:value.signature})),
  );
  if(canonicalJson(rebuiltProofs)!==canonicalJson(proofs)) fail('recovery v3 proof drift');
  if(!Array.isArray(completions)||completions.length!==12) fail('twelve recovery completions required');
  completions.forEach((value,index)=>validateCompletion(plan,value,index));
  if(nextRecoveryOrdinal(plan,completions)!==null) fail('recovery v3 prefix is incomplete');
  if(new Set(completions.map(value=>value.transactionHash)).size!==12) {
    fail('recovery v3 transaction replay detected');
  }

  const roleReports={};
  for(const [roleIndex,[releaseRole,safeRole]] of ROLE_MAP.entries()) {
    const before=baselineSnapshot.roles.find(value=>value.role===safeRole);
    const role=plan.roles[roleIndex];
    if(!before||role?.role!==safeRole||getAddress(before.address)!==getAddress(role.safe)
        ||!sameAddresses(before.owners,plan.initialOwners)
        ||!sameAddresses(role.finalOwners,plan.replacementOwners)) {
      fail(`${safeRole} recovery baseline mismatch`);
    }
    const steps=completions.slice(roleIndex*3,roleIndex*3+3);
    const nonceAfter=String(BigInt(before.nonce)+3n);
    const configurationHash=safeControlConfigurationHash({
      ...before,safe:before.address,owners:role.finalOwners,nonce:nonceAfter,
      packageHash:baselineSnapshot.packageHash,
    });
    const unsigned={
      schema:'usdom-safe-control-role-evidence/v3',releaseRole,safeRole,
      address:getAddress(before.address),runtimeCodeHash:before.runtimeCodeHash,
      singleton:getAddress(before.singleton),fallbackHandler:getAddress(before.fallbackHandler),
      guard:getAddress(before.guard),modules:[...before.modules],ownersBefore:[...before.owners],
      ownersAfter:[...role.finalOwners],threshold:'2',nonceBefore:before.nonce,nonceAfter,
      baselineConfigurationHash:before.configurationHash,configurationHash,planHash:plan.planHash,
      recoveryTransactions:steps.map(value=>({
        ordinal:value.ordinal,transactionHash:value.transactionHash,safeTxHash:value.safeTxHash,
        blockNumber:value.blockNumber,blockHash:value.blockHash,
        finalizedBlockNumber:value.finalizedBlockNumber,
        finalizedBlockHash:value.finalizedBlockHash,
      })),
    };
    roleReports[releaseRole]={...unsigned,reportHash:documentHash(unsigned)};
  }
  const separation={
    schema:'usdom-safe-control-separation-evidence/v3',planHash:plan.planHash,
    threshold:'2',ownerCount:'3',
    roles:ROLE_MAP.map(([releaseRole,safeRole])=>({
      releaseRole,safeRole,address:roleReports[releaseRole].address,
      configurationHash:roleReports[releaseRole].configurationHash,
      reportHash:roleReports[releaseRole].reportHash,
    })),
  };
  separation.reportHash=documentHash(separation);
  const recoveryDrillReport={
    schema:'usdom-safe-control-recovery-drill-evidence/v3',planHash:plan.planHash,
    proofBundleHash:documentHash(proofs),finalizedStepCount:12,
    finalOwners:[...plan.replacementOwners],
    roles:ROLE_MAP.map(([releaseRole,safeRole])=>({
      releaseRole,safeRole,address:roleReports[releaseRole].address,
      transactions:roleReports[releaseRole].recoveryTransactions,
      configurationHash:roleReports[releaseRole].configurationHash,
      roleReportHash:roleReports[releaseRole].reportHash,
    })),
  };
  recoveryDrillReport.reportHash=documentHash(recoveryDrillReport);
  const bundle={
    schema:SAFE_CONTROL_RELEASE_EVIDENCE_V3_SCHEMA,ethereumChainId:'1',
    packageHash:baselineSnapshot.packageHash,baselineSnapshotHash:baselineSnapshot.snapshotHash,
    planHash:plan.planHash,proofBundleHash:documentHash(proofs),roleReports,
    separationReport:separation,recoveryDrillReport,
  };
  return {...bundle,bundleHash:documentHash(bundle)};
}

export function validateSafeControlReleaseEvidenceV3(bundle) {
  exactKeys(bundle,[
    'schema','ethereumChainId','packageHash','baselineSnapshotHash','planHash','proofBundleHash',
    'roleReports','separationReport','recoveryDrillReport','bundleHash',
  ],'Safe control release evidence v3');
  if(bundle.schema!==SAFE_CONTROL_RELEASE_EVIDENCE_V3_SCHEMA||bundle.ethereumChainId!=='1'
      ||bundle.bundleHash!==documentHash(Object.fromEntries(
        Object.entries(bundle).filter(([key])=>key!=='bundleHash'),
      ))) fail('Safe control release evidence v3 identity rejected');
  for(const [value,label] of [[bundle.packageHash,'package'],[bundle.baselineSnapshotHash,'baseline'],
    [bundle.planHash,'plan'],[bundle.proofBundleHash,'proof bundle'],[bundle.bundleHash,'bundle']]) {
    hash(value,`${label} hash`);
  }
  exactKeys(bundle.roleReports,ROLE_MAP.map(value=>value[0]),'Safe control role reports');
  const transactions=[];
  for(const [roleIndex,[releaseRole,safeRole]] of ROLE_MAP.entries()) {
    const report=bundle.roleReports[releaseRole];
    exactKeys(report,[
      'schema','releaseRole','safeRole','address','runtimeCodeHash','singleton','fallbackHandler',
      'guard','modules','ownersBefore','ownersAfter','threshold','nonceBefore','nonceAfter',
      'baselineConfigurationHash','configurationHash','planHash','recoveryTransactions','reportHash',
    ],`${releaseRole} v3 evidence`);
    if(report.schema!=='usdom-safe-control-role-evidence/v3'||report.releaseRole!==releaseRole
        ||report.safeRole!==safeRole||report.threshold!=='2'||report.planHash!==bundle.planHash
        ||report.ownersBefore?.length!==3||report.ownersAfter?.length!==3
        ||report.recoveryTransactions?.length!==3
        ||report.nonceAfter!==String(BigInt(decimal(report.nonceBefore,'nonce before'))+3n)
        ||report.reportHash!==documentHash(Object.fromEntries(
          Object.entries(report).filter(([key])=>key!=='reportHash'),
        ))) fail(`${releaseRole} v3 evidence rejected`);
    report.ownersBefore.map(getAddress); report.ownersAfter.map(getAddress);
    for(const [offset,transaction] of report.recoveryTransactions.entries()) {
      exactKeys(transaction,[
        'ordinal','transactionHash','safeTxHash','blockNumber','blockHash',
        'finalizedBlockNumber','finalizedBlockHash',
      ],`${releaseRole} recovery transaction ${offset}`);
      if(transaction.ordinal!==roleIndex*3+offset) fail('recovery transaction order rejected');
      hash(transaction.transactionHash,'recovery transaction hash');
      hash(transaction.safeTxHash,'Safe transaction hash');
      hash(transaction.blockHash,'recovery block hash');
      hash(transaction.finalizedBlockHash,'recovery finalized block hash');
      decimal(transaction.blockNumber,'recovery block number');
      decimal(transaction.finalizedBlockNumber,'recovery finalized block number');
      if(BigInt(transaction.blockNumber)>BigInt(transaction.finalizedBlockNumber)) {
        fail('recovery transaction finality rejected');
      }
      transactions.push(transaction.transactionHash);
    }
  }
  if(new Set(transactions).size!==12) fail('recovery transaction replay rejected');
  const separation=bundle.separationReport;
  exactKeys(separation,['schema','planHash','threshold','ownerCount','roles','reportHash'],
    'Safe separation evidence v3');
  if(separation?.schema!=='usdom-safe-control-separation-evidence/v3'
      ||separation.planHash!==bundle.planHash||separation.threshold!=='2'
      ||separation.ownerCount!=='3'||separation.roles?.length!==4
      ||separation.reportHash!==documentHash(Object.fromEntries(
        Object.entries(separation).filter(([key])=>key!=='reportHash'),
      ))) fail('Safe separation evidence v3 rejected');
  const recovery=bundle.recoveryDrillReport;
  exactKeys(recovery,[
    'schema','planHash','proofBundleHash','finalizedStepCount','finalOwners','roles','reportHash',
  ],'Safe recovery drill evidence v3');
  if(recovery?.schema!=='usdom-safe-control-recovery-drill-evidence/v3'
      ||recovery.planHash!==bundle.planHash||recovery.proofBundleHash!==bundle.proofBundleHash
      ||recovery.finalizedStepCount!==12||recovery.finalOwners?.length!==3
      ||recovery.roles?.length!==4||recovery.reportHash!==documentHash(Object.fromEntries(
        Object.entries(recovery).filter(([key])=>key!=='reportHash'),
      ))) fail('Safe recovery drill evidence v3 rejected');
  for(const [index,[releaseRole,safeRole]] of ROLE_MAP.entries()) {
    const report=bundle.roleReports[releaseRole],separated=separation.roles[index],recovered=recovery.roles[index];
    exactKeys(separated,[
      'releaseRole','safeRole','address','configurationHash','reportHash',
    ],`${releaseRole} separation role`);
    exactKeys(recovered,[
      'releaseRole','safeRole','address','transactions','configurationHash','roleReportHash',
    ],`${releaseRole} recovery drill role`);
    if(separated.releaseRole!==releaseRole||separated.safeRole!==safeRole
        ||separated.address!==report.address||separated.configurationHash!==report.configurationHash
        ||separated.reportHash!==report.reportHash||recovered.releaseRole!==releaseRole
        ||recovered.safeRole!==safeRole||recovered.address!==report.address
        ||recovered.configurationHash!==report.configurationHash
        ||recovered.roleReportHash!==report.reportHash
        ||canonicalJson(recovered.transactions)!==canonicalJson(report.recoveryTransactions)
        ||!sameAddresses(report.ownersAfter,recovery.finalOwners)) {
      fail(`${releaseRole} cross-document evidence rejected`);
    }
  }
  return bundle;
}

export function validateSafeControlReleaseArtifactSetV3({
  bundle,roleReports,separationReport,recoveryDrillReport,
}) {
  validateSafeControlReleaseEvidenceV3(bundle);
  if(canonicalJson(roleReports)!==canonicalJson(bundle.roleReports)
      ||canonicalJson(separationReport)!==canonicalJson(bundle.separationReport)
      ||canonicalJson(recoveryDrillReport)!==canonicalJson(bundle.recoveryDrillReport)) {
    fail('persisted v3 release artifacts disagree');
  }
  return bundle;
}
