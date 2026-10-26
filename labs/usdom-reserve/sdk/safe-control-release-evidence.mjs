import {getAddress,isAddress} from 'ethers';
import {
  _safeControlObservationInternals,
  safeControlConfigurationHash,
  validateRecoverableSafeControlRecoveryReport,
} from './safe-control-observation.mjs';
import {SAFE_MAINNET_IDENTITY} from './safe-control-deployment.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

export const SAFE_CONTROL_ROLE_EVIDENCE_SCHEMA='usdom-safe-control-role-evidence/v2';
export const SAFE_CONTROL_SEPARATION_EVIDENCE_SCHEMA=
  'usdom-safe-control-separation-evidence/v2';
export const SAFE_CONTROL_RECOVERY_DRILL_EVIDENCE_SCHEMA=
  'usdom-safe-control-recovery-drill-evidence/v2';
export const SAFE_CONTROL_RELEASE_EVIDENCE_SCHEMA='usdom-safe-control-release-evidence/v2';

const HASH=/^0x[0-9a-f]{64}$/;
const UINT64=/^(0|[1-9][0-9]{0,19})$/;
const ZERO_ADDRESS='0x0000000000000000000000000000000000000000';
const ROLE_MAP=Object.freeze([
  {releaseRole:'governance',safeRole:'governance'},
  {releaseRole:'guardian',safeRole:'reserveGuardian'},
  {releaseRole:'checkpointGuardian',safeRole:'checkpointGuardian'},
]);
const {canonicalJson,documentHash}=_safeControlObservationInternals;

function fail(message) { throw new Error(message); }
function sameAddress(left,right) { return getAddress(left)===getAddress(right); }
function exactKeys(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      || canonicalJson(Object.keys(value).sort())!==canonicalJson([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function canonicalAddress(value) {
  return typeof value==='string'&&isAddress(value)&&getAddress(value)===value;
}
function hash(value) { return typeof value==='string'&&HASH.test(value); }
function uint(value) {
  return typeof value==='string'&&UINT64.test(value)&&BigInt(value)<(1n<<64n);
}
function withHash(value,key) { return {...value,[key]:documentHash(value)}; }
function verifyHash(value,key,label) {
  if(!hash(value?.[key])) fail(`${label} hash is invalid`);
  const unsigned={...value}; delete unsigned[key];
  if(documentHash(unsigned)!==value[key]) fail(`${label} hash mismatch`);
}

function deriveReleaseEvidence(packageDocument,baselineSnapshot,recoveryReport) {
  validateRecoverableSafeControlRecoveryReport(
    recoveryReport,baselineSnapshot,packageDocument,
  );
  const after=recoveryReport.afterSnapshot;
  const roleReports={};
  for(const [index,mapping] of ROLE_MAP.entries()) {
    const before=baselineSnapshot.roles[index];
    const current=after.roles[index];
    const recovery=recoveryReport.recoveries[index];
    const transition=recoveryReport.transitionsByRole[mapping.safeRole];
    roleReports[mapping.releaseRole]=withHash({
      schema:SAFE_CONTROL_ROLE_EVIDENCE_SCHEMA,
      ethereumChainId:'1',
      releaseRole:mapping.releaseRole,
      safeRole:mapping.safeRole,
      packageHash:recoveryReport.packageHash,
      baselineSnapshotHash:baselineSnapshot.snapshotHash,
      baselineFinalizedBlockNumber:baselineSnapshot.finalizedBlockNumber,
      baselineFinalizedBlockHash:baselineSnapshot.finalizedBlockHash,
      afterSnapshotHash:after.snapshotHash,
      afterFinalizedBlockNumber:after.finalizedBlockNumber,
      afterFinalizedBlockHash:after.finalizedBlockHash,
      recoveryHash:recoveryReport.recoveryHash,
      lostOwner:transition.lostOwner,
      replacementOwner:transition.replacementOwner,
      address:current.address,
      runtimeCodeHash:current.runtimeCodeHash,
      singleton:current.singleton,
      fallbackHandler:current.fallbackHandler,
      guard:current.guard,
      ownersBefore:[...before.owners],
      ownersAfter:[...current.owners],
      threshold:current.threshold,
      nonceBefore:before.nonce,
      nonceAfter:current.nonce,
      modules:[...current.modules],
      baselineConfigurationHash:before.configurationHash,
      configurationHash:current.configurationHash,
      recoveryTransactionHash:recovery.transactionHash,
      recoveryBlockNumber:recovery.blockNumber,
      recoveryBlockHash:recovery.blockHash,
      recoverySafeTxHash:recovery.safeTxHash,
      recoverySigners:[...recovery.signers],
    },'reportHash');
  }
  const roleSummaries=ROLE_MAP.map(({releaseRole,safeRole})=>({
    releaseRole,safeRole,address:roleReports[releaseRole].address,
    configurationHash:roleReports[releaseRole].configurationHash,
    reportHash:roleReports[releaseRole].reportHash,
  }));
  const separationReport=withHash({
    schema:SAFE_CONTROL_SEPARATION_EVIDENCE_SCHEMA,
    ethereumChainId:'1',
    packageHash:recoveryReport.packageHash,
    baselineSnapshotHash:baselineSnapshot.snapshotHash,
    afterSnapshotHash:after.snapshotHash,
    recoveryHash:recoveryReport.recoveryHash,
    ownerCount:'3',
    threshold:'2',
    roles:roleSummaries,
  },'reportHash');
  const recoveryDrillReport=withHash({
    schema:SAFE_CONTROL_RECOVERY_DRILL_EVIDENCE_SCHEMA,
    ethereumChainId:'1',
    packageHash:recoveryReport.packageHash,
    baselineSnapshotHash:baselineSnapshot.snapshotHash,
    baselineFinalizedBlockNumber:baselineSnapshot.finalizedBlockNumber,
    baselineFinalizedBlockHash:baselineSnapshot.finalizedBlockHash,
    afterSnapshotHash:after.snapshotHash,
    afterFinalizedBlockNumber:after.finalizedBlockNumber,
    afterFinalizedBlockHash:after.finalizedBlockHash,
    recoveryHash:recoveryReport.recoveryHash,
    transitionsByRole:structuredClone(recoveryReport.transitionsByRole),
    roles:ROLE_MAP.map(({releaseRole,safeRole})=>({
      releaseRole,safeRole,address:roleReports[releaseRole].address,
      transactionHash:roleReports[releaseRole].recoveryTransactionHash,
      blockNumber:roleReports[releaseRole].recoveryBlockNumber,
      blockHash:roleReports[releaseRole].recoveryBlockHash,
      safeTxHash:roleReports[releaseRole].recoverySafeTxHash,
      signers:[...roleReports[releaseRole].recoverySigners],
      previousNonce:roleReports[releaseRole].nonceBefore,
      newNonce:roleReports[releaseRole].nonceAfter,
      configurationHash:roleReports[releaseRole].configurationHash,
      roleReportHash:roleReports[releaseRole].reportHash,
    })),
  },'reportHash');
  const bundle={
    schema:SAFE_CONTROL_RELEASE_EVIDENCE_SCHEMA,
    ethereumChainId:'1',
    packageHash:recoveryReport.packageHash,
    baselineSnapshotHash:baselineSnapshot.snapshotHash,
    afterSnapshotHash:after.snapshotHash,
    recoveryHash:recoveryReport.recoveryHash,
    baselineRpcConsensus:structuredClone(baselineSnapshot.rpcConsensus),
    recoveryRpcConsensus:structuredClone(recoveryReport.rpcConsensus),
    roleReports,
    separationReport,
    recoveryDrillReport,
  };
  return {...bundle,bundleHash:documentHash(bundle)};
}

export function validateRecoverableSafeControlReleaseEvidence(bundle) {
  exactKeys(bundle,['schema','ethereumChainId','packageHash','baselineSnapshotHash',
    'afterSnapshotHash','recoveryHash','baselineRpcConsensus','recoveryRpcConsensus',
    'roleReports','separationReport',
    'recoveryDrillReport','bundleHash'],'Safe control release evidence');
  if(bundle.schema!==SAFE_CONTROL_RELEASE_EVIDENCE_SCHEMA||bundle.ethereumChainId!=='1'
      || ![bundle.packageHash,bundle.baselineSnapshotHash,bundle.afterSnapshotHash,
        bundle.recoveryHash,bundle.bundleHash].every(hash)) {
    fail('Safe control release evidence identity is invalid');
  }
  validateRpcConsensusEvidence(bundle.baselineRpcConsensus);
  validateRpcConsensusEvidence(bundle.recoveryRpcConsensus);
  if(canonicalJson(bundle.baselineRpcConsensus)!==canonicalJson(bundle.recoveryRpcConsensus)) {
    fail('Safe control release evidence RPC source sets disagree');
  }
  const unsignedBundle={...bundle}; delete unsignedBundle.bundleHash;
  if(documentHash(unsignedBundle)!==bundle.bundleHash) fail('Safe control release evidence hash mismatch');
  exactKeys(bundle.roleReports,ROLE_MAP.map(({releaseRole})=>releaseRole),'Safe role reports');
  const common=['packageHash','baselineSnapshotHash','afterSnapshotHash','recoveryHash'];
  const addresses=[]; const configurationHashes=[]; const allOwnersBefore=[]; const allOwnersAfter=[];
  const transactionHashes=[]; const safeTxHashes=[];
  for(const [index,{releaseRole,safeRole}] of ROLE_MAP.entries()) {
    const report=bundle.roleReports[releaseRole];
    exactKeys(report,['schema','ethereumChainId','releaseRole','safeRole','packageHash',
      'baselineSnapshotHash','baselineFinalizedBlockNumber','baselineFinalizedBlockHash',
      'afterSnapshotHash','afterFinalizedBlockNumber','afterFinalizedBlockHash','recoveryHash',
      'lostOwner','replacementOwner','address','runtimeCodeHash','singleton','fallbackHandler',
      'guard','ownersBefore','ownersAfter','threshold','nonceBefore','nonceAfter','modules',
      'baselineConfigurationHash','configurationHash','recoveryTransactionHash',
      'recoveryBlockNumber','recoveryBlockHash','recoverySafeTxHash','recoverySigners',
      'reportHash'],`${releaseRole} Safe role report`);
    verifyHash(report,'reportHash',`${releaseRole} Safe role report`);
    if(report.schema!==SAFE_CONTROL_ROLE_EVIDENCE_SCHEMA||report.ethereumChainId!=='1'
        || report.releaseRole!==releaseRole||report.safeRole!==safeRole
        || common.some(key=>report[key]!==bundle[key])
        || ![report.address,report.singleton,report.fallbackHandler,report.guard,
          report.lostOwner,report.replacementOwner].every(canonicalAddress)
        || ![report.runtimeCodeHash,report.baselineConfigurationHash,report.configurationHash,
          report.baselineFinalizedBlockHash,report.afterFinalizedBlockHash,
          report.recoveryTransactionHash,report.recoveryBlockHash,
          report.recoverySafeTxHash].every(hash)
        || ![report.baselineFinalizedBlockNumber,report.afterFinalizedBlockNumber,
          report.recoveryBlockNumber,report.nonceBefore,report.nonceAfter].every(uint)
        || report.threshold!=='2'||report.nonceBefore!=='0'||report.nonceAfter!=='1'
        || BigInt(report.recoveryBlockNumber)<=BigInt(report.baselineFinalizedBlockNumber)
        || BigInt(report.recoveryBlockNumber)>BigInt(report.afterFinalizedBlockNumber)
        || !sameAddress(report.guard,ZERO_ADDRESS)
        || !sameAddress(report.singleton,SAFE_MAINNET_IDENTITY.singleton)
        || !sameAddress(report.fallbackHandler,SAFE_MAINNET_IDENTITY.fallbackHandler)
        || !Array.isArray(report.modules)||report.modules.length!==0
        || !Array.isArray(report.ownersBefore)||report.ownersBefore.length!==3
        || !Array.isArray(report.ownersAfter)||report.ownersAfter.length!==3
        || report.ownersBefore.some(owner=>!canonicalAddress(owner))
        || report.ownersAfter.some(owner=>!canonicalAddress(owner))
        || !report.ownersBefore.some(owner=>sameAddress(owner,report.lostOwner))
        || report.ownersBefore.some(owner=>sameAddress(owner,report.replacementOwner))
        || report.ownersAfter.some((owner,ownerIndex)=>!sameAddress(owner,
          sameAddress(report.ownersBefore[ownerIndex],report.lostOwner)
            ?report.replacementOwner:report.ownersBefore[ownerIndex]))) {
      fail(`${releaseRole} Safe role evidence violates recovery policy`);
    }
    if(new Set(report.ownersBefore.map(getAddress)).size!==3
        || new Set(report.ownersAfter.map(getAddress)).size!==3
        || report.ownersBefore.some((owner,ownerIndex)=>ownerIndex>0
          && BigInt(owner)<=BigInt(report.ownersBefore[ownerIndex-1]))
        || safeControlConfigurationHash({
          role:safeRole,safe:report.address,runtimeCodeHash:report.runtimeCodeHash,
          singleton:report.singleton,fallbackHandler:report.fallbackHandler,guard:report.guard,
          owners:report.ownersBefore,threshold:report.threshold,nonce:report.nonceBefore,
          packageHash:report.packageHash,
        })!==report.baselineConfigurationHash
        || safeControlConfigurationHash({
          role:safeRole,safe:report.address,runtimeCodeHash:report.runtimeCodeHash,
          singleton:report.singleton,fallbackHandler:report.fallbackHandler,guard:report.guard,
          owners:report.ownersAfter,threshold:report.threshold,nonce:report.nonceAfter,
          packageHash:report.packageHash,
        })!==report.configurationHash) {
      fail(`${releaseRole} Safe configuration commitment mismatch`);
    }
    const expectedSigners=report.ownersBefore.filter(owner=>!sameAddress(owner,report.lostOwner))
      .sort((left,right)=>BigInt(left)<BigInt(right)?-1:1);
    if(!Array.isArray(report.recoverySigners)||report.recoverySigners.length!==2
        || report.recoverySigners.some((signer,signerIndex)=>
          !canonicalAddress(signer)||!sameAddress(signer,expectedSigners[signerIndex]))) {
      fail(`${releaseRole} Safe recovery signers are invalid`);
    }
    allOwnersBefore.push(...report.ownersBefore.map(getAddress));
    allOwnersAfter.push(...report.ownersAfter.map(getAddress));
    if(index!==0 && (report.runtimeCodeHash!==bundle.roleReports.governance.runtimeCodeHash
        || !sameAddress(report.singleton,bundle.roleReports.governance.singleton)
        || !sameAddress(report.fallbackHandler,bundle.roleReports.governance.fallbackHandler)
        || report.baselineFinalizedBlockNumber
          !==bundle.roleReports.governance.baselineFinalizedBlockNumber
        || report.baselineFinalizedBlockHash
          !==bundle.roleReports.governance.baselineFinalizedBlockHash
        || report.afterFinalizedBlockNumber
          !==bundle.roleReports.governance.afterFinalizedBlockNumber
        || report.afterFinalizedBlockHash!==bundle.roleReports.governance.afterFinalizedBlockHash)) {
      fail('Safe role reports disagree on shared deployment evidence');
    }
    addresses.push(getAddress(report.address));
    configurationHashes.push(report.configurationHash);
    transactionHashes.push(report.recoveryTransactionHash);
    safeTxHashes.push(report.recoverySafeTxHash);
  }
  if(new Set(allOwnersBefore).size!==9||new Set(allOwnersAfter).size!==9) {
    fail('Safe role owner sets overlap globally');
  }
  if(new Set(addresses).size!==ROLE_MAP.length
      || new Set(configurationHashes).size!==ROLE_MAP.length
      || new Set(transactionHashes).size!==ROLE_MAP.length
      || new Set(safeTxHashes).size!==ROLE_MAP.length) {
    fail('Safe release roles or configurations are not separated');
  }

  const separation=bundle.separationReport;
  exactKeys(separation,['schema','ethereumChainId','packageHash','baselineSnapshotHash',
    'afterSnapshotHash','recoveryHash','ownerCount','threshold','roles','reportHash'],
  'Safe separation report');
  verifyHash(separation,'reportHash','Safe separation report');
  const expectedSummaries=ROLE_MAP.map(({releaseRole,safeRole})=>({
    releaseRole,safeRole,address:bundle.roleReports[releaseRole].address,
    configurationHash:bundle.roleReports[releaseRole].configurationHash,
    reportHash:bundle.roleReports[releaseRole].reportHash,
  }));
  if(separation.schema!==SAFE_CONTROL_SEPARATION_EVIDENCE_SCHEMA
      || separation.ethereumChainId!=='1'||separation.ownerCount!=='3'||separation.threshold!=='2'
      || common.some(key=>separation[key]!==bundle[key])
      || canonicalJson(separation.roles)!==canonicalJson(expectedSummaries)) {
    fail('Safe separation report mismatch');
  }

  const drill=bundle.recoveryDrillReport;
  exactKeys(drill,['schema','ethereumChainId','packageHash','baselineSnapshotHash',
    'baselineFinalizedBlockNumber','baselineFinalizedBlockHash','afterSnapshotHash',
    'afterFinalizedBlockNumber','afterFinalizedBlockHash','recoveryHash','transitionsByRole',
    'roles','reportHash'],
  'Safe recovery drill report');
  verifyHash(drill,'reportHash','Safe recovery drill report');
  const first=bundle.roleReports.governance;
  const expectedDrillRoles=ROLE_MAP.map(({releaseRole,safeRole})=>({
    releaseRole,safeRole,address:bundle.roleReports[releaseRole].address,
    transactionHash:bundle.roleReports[releaseRole].recoveryTransactionHash,
    blockNumber:bundle.roleReports[releaseRole].recoveryBlockNumber,
    blockHash:bundle.roleReports[releaseRole].recoveryBlockHash,
    safeTxHash:bundle.roleReports[releaseRole].recoverySafeTxHash,
    signers:[...bundle.roleReports[releaseRole].recoverySigners],
    previousNonce:bundle.roleReports[releaseRole].nonceBefore,
    newNonce:bundle.roleReports[releaseRole].nonceAfter,
    configurationHash:bundle.roleReports[releaseRole].configurationHash,
    roleReportHash:bundle.roleReports[releaseRole].reportHash,
  }));
  const expectedTransitions=Object.fromEntries(ROLE_MAP.map(({releaseRole,safeRole})=>[safeRole,{
    lostOwner:bundle.roleReports[releaseRole].lostOwner,
    replacementOwner:bundle.roleReports[releaseRole].replacementOwner,
  }]));
  if(drill.schema!==SAFE_CONTROL_RECOVERY_DRILL_EVIDENCE_SCHEMA
      || drill.ethereumChainId!=='1'||common.some(key=>drill[key]!==bundle[key])
      || drill.baselineFinalizedBlockNumber!==first.baselineFinalizedBlockNumber
      || drill.baselineFinalizedBlockHash!==first.baselineFinalizedBlockHash
      || drill.afterFinalizedBlockNumber!==first.afterFinalizedBlockNumber
      || drill.afterFinalizedBlockHash!==first.afterFinalizedBlockHash
      || canonicalJson(drill.transitionsByRole)!==canonicalJson(expectedTransitions)
      || canonicalJson(drill.roles)!==canonicalJson(expectedDrillRoles)) {
    fail('Safe recovery drill report mismatch');
  }
  return bundle;
}

export function buildRecoverableSafeControlReleaseEvidence({
  packageDocument,baselineSnapshot,recoveryReport,
}={}) {
  const result=deriveReleaseEvidence(packageDocument,baselineSnapshot,recoveryReport);
  validateRecoverableSafeControlReleaseEvidence(result);
  return result;
}

export function validateRecoverableSafeControlReleaseArtifactSet({
  bundle,roleReports,separationReport,recoveryDrillReport,
}={}) {
  validateRecoverableSafeControlReleaseEvidence(bundle);
  exactKeys(roleReports,ROLE_MAP.map(({releaseRole})=>releaseRole),'persisted Safe role reports');
  for(const {releaseRole} of ROLE_MAP) {
    if(canonicalJson(roleReports[releaseRole])
        !==canonicalJson(bundle.roleReports[releaseRole])) {
      fail(`${releaseRole} persisted Safe role report disagrees with its bundle`);
    }
  }
  if(canonicalJson(separationReport)!==canonicalJson(bundle.separationReport)) {
    fail('persisted Safe separation report disagrees with its bundle');
  }
  if(canonicalJson(recoveryDrillReport)!==canonicalJson(bundle.recoveryDrillReport)) {
    fail('persisted Safe recovery drill report disagrees with its bundle');
  }
  return bundle;
}

export const SAFE_CONTROL_RELEASE_ROLE_MAP=ROLE_MAP;
