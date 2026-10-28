import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {solidityArtifactExecutableFingerprint} from './solidity-artifact-executable-fingerprint.mjs';

const raw=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const dec=value=>typeof value==='string'&&/^[1-9][0-9]{0,19}$/.test(value)
  &&BigInt(value)<(1n<<64n);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function validateLocalOperationalGasEvidence(report,{root,artifactBytes}={}) {
  if(!report||report.schema!=='usdom-local-operational-gas-measurement/v3'
      ||report.network!=='anvil-local-chain-31337'||report.runs!==2
      ||report.productionRequirementsRemainFalse!==true
      ||report.anvil?.sha256!=='00f97668e1ae0fcca118fd7d2d1b6d25c0496447a523ca6bc2dfd10958c99604'
      ||!raw(report.node?.sha256)||!raw(report.safeFixture?.sha256)
      ||!/^0x[0-9a-f]{64}$/.test(report.safeFixture?.singletonRuntimeCodeHash??'')) {
    throw new Error('local operational gas evidence identity is invalid');
  }
  const q=report.scenarios?.queueWithdrawal,e=report.scenarios?.pruneExpired256;
  const d=report.scenarios?.pruneDiscardable256,s=report.scenarios?.safeAdminOverhead;
  const authorize=report.scenarios?.authorizePilotDeposit;
  const cancel=report.scenarios?.cancelPilotDepositAuthorization;
  const clear=report.scenarios?.clearExpiredPilotDepositAuthorization;
  const deposit=report.scenarios?.authorizedPilotDeposit;
  const schedule=report.scenarios?.schedulePermissionlessDeposits;
  const open=report.scenarios?.executePermissionlessDeposits;
  const safeModeled=value=>dec(value?.directOrGovernanceGasUsed)
    &&dec(value?.modeledSafeUpperBoundGas)&&dec(value?.safeOverheadBasisGas)
    &&BigInt(value.modeledSafeUpperBoundGas)
      ===BigInt(value.directOrGovernanceGasUsed)+BigInt(value.safeOverheadBasisGas);
  const within=(value,ceiling)=>dec(value)&&BigInt(value)<=BigInt(ceiling);
  if(!dec(q?.gasUsed)||q.proofBytes!==260||q.queueDepthBefore!==1||q.events<3
      ||!dec(e?.gasUsed)||e.inputCount!==256||e.removed!==256||e.queueDepthBefore!==256
      ||!dec(d?.gasUsed)||d.inputCount!==256||d.removed!==256||d.invalidatedByEmergency!==true
      ||!dec(s?.gasUsed)||s.safeVersion!=='1.4.1'||s.owners!==3||s.threshold!==2
      ||s.approvals!==2||s.action!=='swapOwner'||s.innerCalldataBytes!==100
      ||!Number.isSafeInteger(s.outerCalldataBytes)||s.outerCalldataBytes<400
      ||!safeModeled(authorize)||authorize.generation!==0||authorize.calldataBytes!==228
      ||!safeModeled(cancel)||cancel.generation!==0||cancel.calldataBytes!==68
      ||!dec(clear?.gasUsed)||clear.generation!==0||clear.calldataBytes!==68
      ||!dec(deposit?.gasUsed)||deposit.amountBaseUnits!=='1000000'||deposit.calldataBytes!==100
      ||deposit.generationAfter!==1||!safeModeled(schedule)||schedule.calldataBytes!==4
      ||!dec(open?.gasUsed)||open.calldataBytes!==4||open.opened!==true
      ||!within(authorize?.modeledSafeUpperBoundGas,250000)
      ||!within(cancel?.modeledSafeUpperBoundGas,175000)
      ||!within(clear?.gasUsed,75000)||!within(deposit?.gasUsed,300000)
      ||!within(schedule?.modeledSafeUpperBoundGas,200000)||!within(open?.gasUsed,100000)) {
    throw new Error('local operational gas scenario is not maximal and canonical');
  }
  if(!report.artifacts||Object.keys(report.artifacts).sort().join(',')
      !=='governance,registry,reserve,token,verifier') throw new Error('artifact inventory is incomplete');
  if(root) {
    for(const value of [...Object.values(report.artifacts),report.safeFixture]) {
      const relative=value.artifactPath??value.path;
      const bytes=artifactBytes?.get(relative)??readFileSync(path.join(root,relative));
      const observed=value.artifactExecutableSha256
        ?solidityArtifactExecutableFingerprint(JSON.parse(bytes)):sha(bytes);
      const expected=value.artifactExecutableSha256??value.sha256;
      if(observed!==expected) {
        throw new Error('operational gas input hash changed');
      }
    }
  }
  return report;
}

export function buildProductionOperationalGasMeasurementJob({localEvidence,release,
  releaseBytes,localEvidenceBytes,releaseSha256,localEvidenceSha256}) {
  if(!Buffer.isBuffer(releaseBytes)||!Buffer.isBuffer(localEvidenceBytes)
      ||JSON.stringify(parseStrictJsonBytes(releaseBytes,{label:'production release',maxDepth:64}))
        !==JSON.stringify(release)
      ||JSON.stringify(parseStrictJsonBytes(localEvidenceBytes,{label:'local operational gas evidence',
        maxDepth:64}))!==JSON.stringify(localEvidence)
      ||sha(releaseBytes)!==releaseSha256||sha(localEvidenceBytes)!==localEvidenceSha256) {
    throw new Error('operational gas job bytes differ from parsed authority');
  }
  validateLocalOperationalGasEvidence(localEvidence);
  const hash=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{64}$/.test(value);
  if(!raw(releaseSha256)||!raw(localEvidenceSha256)||release?.ethereumChainId!=='1'
      ||release.productionReady!==true||!hash(release.reserveRuntimeCodeHash)
      ||!hash(release.reserveConfigHash)||!hash(release.governanceImplementationCodeHash)
      ||!hash(release.guardianImplementationCodeHash)) {
    throw new Error('exact production release pins are required for the operational gas job');
  }
  return {schema:'usdom-production-operational-gas-measurement-job/v1',ethereumChainId:'1',
    releaseConfigSha256:releaseSha256,localBaselineSha256:localEvidenceSha256,
    reserve:release.reserve,reserveRuntimeCodeHash:release.reserveRuntimeCodeHash,
    reserveConfigHash:release.reserveConfigHash,
    safeImplementationCodeHashes:[release.governanceImplementationCodeHash,
      release.guardianImplementationCodeHash],
    scenarios:['queueWithdrawal-worst-case','pruneExpired-256','pruneDiscardable-256',
      'safe-admin-swapOwner-3-owner-2-threshold'],
    requiredRuns:2,requiredIndependentRpcSources:2,requiredFinalityTag:'finalized',
    localEvidenceSatisfiesProduction:false,measurementComplete:false};
}
