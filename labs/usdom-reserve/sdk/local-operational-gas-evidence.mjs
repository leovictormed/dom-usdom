import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import path from 'node:path';

const raw=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const dec=value=>typeof value==='string'&&/^[1-9][0-9]*$/.test(value);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function validateLocalOperationalGasEvidence(report,{root}={}) {
  if(!report||report.schema!=='usdom-local-operational-gas-measurement/v1'
      ||report.network!=='anvil-local-chain-31337'||report.runs!==2
      ||report.productionRequirementsRemainFalse!==true
      ||report.anvil?.sha256!=='00f97668e1ae0fcca118fd7d2d1b6d25c0496447a523ca6bc2dfd10958c99604'
      ||!raw(report.node?.sha256)||!raw(report.safeFixture?.sha256)
      ||!/^0x[0-9a-f]{64}$/.test(report.safeFixture?.singletonRuntimeCodeHash??'')) {
    throw new Error('local operational gas evidence identity is invalid');
  }
  const q=report.scenarios?.queueWithdrawal,e=report.scenarios?.pruneExpired256;
  const d=report.scenarios?.pruneDiscardable256,s=report.scenarios?.safeAdminOverhead;
  if(!dec(q?.gasUsed)||q.proofBytes!==260||q.queueDepthBefore!==1||q.events<3
      ||!dec(e?.gasUsed)||e.inputCount!==256||e.removed!==256||e.queueDepthBefore!==256
      ||!dec(d?.gasUsed)||d.inputCount!==256||d.removed!==256||d.invalidatedByEmergency!==true
      ||!dec(s?.gasUsed)||s.safeVersion!=='1.4.1'||s.owners!==3||s.threshold!==2
      ||s.approvals!==2||s.action!=='swapOwner'||s.innerCalldataBytes!==100
      ||!Number.isSafeInteger(s.outerCalldataBytes)||s.outerCalldataBytes<400) {
    throw new Error('local operational gas scenario is not maximal and canonical');
  }
  if(!report.artifacts||Object.keys(report.artifacts).sort().join(',')
      !=='governance,registry,reserve,token,verifier') throw new Error('artifact inventory is incomplete');
  if(root) {
    for(const value of [...Object.values(report.artifacts),report.safeFixture]) {
      const bytes=readFileSync(path.join(root,value.artifactPath??value.path));
      if(sha(bytes)!==value.artifactSha256&&sha(bytes)!==value.sha256) {
        throw new Error('operational gas input hash changed');
      }
    }
  }
  return report;
}

export function buildProductionOperationalGasMeasurementJob({localEvidence,release,
  releaseSha256,localEvidenceSha256}) {
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
