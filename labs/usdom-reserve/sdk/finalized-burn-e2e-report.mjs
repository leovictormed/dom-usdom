import {createHash} from 'node:crypto';
import {getAddress} from 'ethers';
import {uint} from './reserve.mjs';
import {finalizedBurnStatementHash,normalizeFinalizedBurn} from './proof-reserve.mjs';

const rawHashPattern=/^[0-9a-f]{64}$/;
const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const sourceCommitPattern=/^[0-9a-f]{40}$/;
const sourceIdPattern=/^[a-z][a-z0-9-]{0,31}$/;
const burnFields=Object.freeze([
  'amount','blockHash','burnId','domDomain','finalityBeaconSlot','height','recipient','requestId',
  'stateRoot','validUntil',
]);
const fields=Object.freeze([
  'adapterRuntimeCodeHash','broadcastAuthorized','burn','completedAt','compressionPeakResidentKiB',
  'compressionWallMilliseconds','devMode','ethereumChainId','evmCallAccepted','evmSealBytes',
  'evmSealSha256','evmVerificationGas','finalizedObservationBlockHash',
  'finalizedObservationBlockNumber','groth16ReceiptBytes','groth16ReceiptSha256','guestImageId',
  'guestProgramSha256','hostFingerprintSha256','inputBytes','inputSha256','mines',
  'observationEndpointHashes','observationSourceIds','peakResidentKiB','prover',
  'isolatedEvmBlockHash','isolatedEvmBlockNumber','isolatedEvmReceiptSha256',
  'isolatedEvmTransactionHash',
  'provingWallMilliseconds','rayonWorkers','receiptKind','receiptVerified','releaseId',
  'releaseSpecific','reserve','riscZeroVerifier','riscZeroVerifierCodeHash','risc0ZkvmVersion',
  'schema','segmentLimitPo2','sourceCommit','sourcePackageSha256','startedAt','statementHash',
  'succinctReceiptBytes','succinctReceiptSha256','verifier','verifierConfigHash',
]);

function exact(value) {
  return value && typeof value==='object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...fields].sort());
}

function exactBurn(value) {
  return value && typeof value==='object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...burnFields].sort());
}

function rawHash(value,label) {
  if(typeof value!=='string' || !rawHashPattern.test(value) || value==='0'.repeat(64)) {
    throw new Error(`${label} must be a nonzero canonical raw SHA-256`);
  }
  return value;
}

function bytes32(value,label) {
  if(typeof value!=='string' || !bytes32Pattern.test(value)
      || value.toLowerCase()==='0x'+'00'.repeat(32)) {
    throw new Error(`${label} must be a nonzero bytes32`);
  }
  return value.toLowerCase();
}

function canonicalUint(value,bits,label,{maximum=null}={}) {
  const maxDigits={8:3,16:5,32:10,64:20,128:39,256:78}[bits];
  if(maxDigits===undefined || typeof value!=='string' || value.length>maxDigits
      || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed=uint(value,bits);
  if(maximum!==null && parsed>maximum) throw new Error(`${label} exceeds its release bound`);
  return parsed;
}

function canonicalSources(ids,hashes) {
  if(!Array.isArray(ids) || !Array.isArray(hashes) || ids.length<2 || ids.length>4
      || hashes.length!==ids.length) {
    throw new Error('two to four finalized observation sources are required');
  }
  ids.forEach((id,index)=>{
    if(typeof id!=='string' || !sourceIdPattern.test(id)) {
      throw new Error(`observationSourceIds[${index}] is not canonical`);
    }
  });
  hashes.forEach((hash,index)=>rawHash(hash,`observationEndpointHashes[${index}]`));
  if(new Set(ids).size!==ids.length || new Set(hashes).size!==hashes.length
      || JSON.stringify(ids)!==JSON.stringify([...ids].sort())) {
    throw new Error('observation sources must be distinct and ordered');
  }
}

const isolatedReceiptFields=Object.freeze([
  'adapter','adapterRuntimeCodeHash','evmSealSha256','evmVerificationGas',
  'blockHash','blockNumber','statementHash','transactionHash','verifierConfigHash',
]);

export function finalizedBurnReleaseEvmReceiptCommitment(input) {
  if(!input || typeof input!=='object' || Array.isArray(input)
      || JSON.stringify(Object.keys(input).sort())!==JSON.stringify([...isolatedReceiptFields].sort())) {
    throw new Error('exact release isolated EVM receipt fields required');
  }
  const record={schema:'usdom-finalized-burn-release-evm-receipt-v1',
    transactionHash:bytes32(input.transactionHash,'transactionHash'),
    blockHash:bytes32(input.blockHash,'blockHash'),
    blockNumber:canonicalUint(input.blockNumber,64,'blockNumber').toString(),
    adapter:getAddress(input.adapter),
    adapterRuntimeCodeHash:bytes32(input.adapterRuntimeCodeHash,'adapterRuntimeCodeHash'),
    verifierConfigHash:bytes32(input.verifierConfigHash,'verifierConfigHash'),
    statementHash:bytes32(input.statementHash,'statementHash'),
    evmSealSha256:rawHash(input.evmSealSha256,'evmSealSha256'),
    evmVerificationGas:canonicalUint(input.evmVerificationGas,64,'evmVerificationGas',
      {maximum:5_000_000n}).toString(),status:'success'};
  if(record.blockNumber==='0' || record.evmVerificationGas==='0') {
    throw new Error('release isolated EVM receipt counters must be nonzero');
  }
  const canonicalTranscript=JSON.stringify(record,null,2)+'\n';
  return Object.freeze({record:Object.freeze(record),canonicalTranscript,
    sha256:createHash('sha256').update(canonicalTranscript).digest('hex')});
}

/**
 * Validate the semantic proof-capacity report bound to one exact release.
 * Hash-addressing the file alone is insufficient: a generic text file must
 * never satisfy receipt generation, real-verifier acceptance or gas evidence.
 */
export function validateFinalizedBurnE2eReport(report,{
  evidence,releaseConfig,verifierConfig,riscZeroReference,
}) {
  if(!exact(report)) throw new Error('exact finalized-burn E2E report fields required');
  if(report.schema!==FINALIZED_BURN_E2E_REPORT_SCHEMA) throw new Error('unsupported report schema');
  if(typeof report.releaseId!=='string' || report.releaseId.length===0
      || report.releaseId!==evidence?.releaseId) throw new Error('report releaseId mismatch');
  if(!sourceCommitPattern.test(report.sourceCommit)
      || report.sourceCommit!==evidence?.sourceCommit) throw new Error('report sourceCommit mismatch');
  if(report.ethereumChainId!=='1' || report.ethereumChainId!==releaseConfig?.ethereumChainId) {
    throw new Error('report Ethereum chain mismatch');
  }
  if(getAddress(report.reserve)!==getAddress(releaseConfig?.reserve)
      || getAddress(report.verifier)!==getAddress(releaseConfig?.verifier)) {
    throw new Error('report reserve or adapter mismatch');
  }
  if(bytes32(report.adapterRuntimeCodeHash,'adapterRuntimeCodeHash')
      !==bytes32(releaseConfig?.verifierCodeHash,'release verifierCodeHash')
      || bytes32(report.verifierConfigHash,'verifierConfigHash')
        !==bytes32(releaseConfig?.verifierConfigHash,'release verifierConfigHash')) {
    throw new Error('report adapter identity mismatch');
  }
  if(getAddress(report.riscZeroVerifier)!==getAddress(riscZeroReference?.verifier_address)
      || bytes32(report.riscZeroVerifierCodeHash,'riscZeroVerifierCodeHash')
        !==bytes32(riscZeroReference?.observed_runtime_code_hash,'reference verifier code hash')) {
    throw new Error('report RISC Zero verifier identity mismatch');
  }
  if(bytes32(report.guestImageId,'guestImageId')
      !==bytes32(verifierConfig?.finalizedBurnGuestImageId,'manifest guest ImageID')
      || bytes32(report.guestProgramSha256,'guestProgramSha256')
        !==bytes32(verifierConfig?.provingProgramSha256,'manifest proving program SHA-256')) {
    throw new Error('report proving program identity mismatch');
  }
  for(const name of [
    'inputSha256','succinctReceiptSha256','groth16ReceiptSha256','evmSealSha256',
    'sourcePackageSha256','hostFingerprintSha256',
  ]) rawHash(report[name],name);
  const statement=bytes32(report.statementHash,'statementHash');
  if(!exactBurn(report.burn)) throw new Error('exact finalized-burn report tuple required');
  const burn=normalizeFinalizedBurn(report.burn);
  const recomputedStatement=finalizedBurnStatementHash({
    chainId:releaseConfig.ethereumChainId,reserve:releaseConfig.reserve,
    activationScheduleCommitment:releaseConfig.activationScheduleCommitment,burn,
  });
  if(statement!==recomputedStatement.toLowerCase()) {
    throw new Error('report burn tuple does not reproduce statementHash');
  }
  bytes32(report.finalizedObservationBlockHash,'finalizedObservationBlockHash');
  rawHash(report.isolatedEvmReceiptSha256,'isolatedEvmReceiptSha256');
  const isolatedReceipt=finalizedBurnReleaseEvmReceiptCommitment({
    transactionHash:report.isolatedEvmTransactionHash,blockHash:report.isolatedEvmBlockHash,
    blockNumber:report.isolatedEvmBlockNumber,adapter:report.verifier,
    adapterRuntimeCodeHash:report.adapterRuntimeCodeHash,
    verifierConfigHash:report.verifierConfigHash,statementHash:report.statementHash,
    evmSealSha256:report.evmSealSha256,evmVerificationGas:report.evmVerificationGas,
  });
  if(isolatedReceipt.sha256!==report.isolatedEvmReceiptSha256) {
    throw new Error('release isolated EVM receipt transcript hash mismatch');
  }
  canonicalSources(report.observationSourceIds,report.observationEndpointHashes);
  if(new Set([
    report.inputSha256,report.succinctReceiptSha256,report.groth16ReceiptSha256,
    report.evmSealSha256,report.isolatedEvmReceiptSha256,
  ]).size!==5) throw new Error('report artifact hashes must be distinct');
  if(report.risc0ZkvmVersion!=='3.0.6' || report.receiptKind!=='groth16'
      || report.prover!=='local' || ![1,2].includes(report.rayonWorkers)
      || report.segmentLimitPo2!==18 || report.receiptVerified!==true
      || report.evmCallAccepted!==true || report.devMode!==false || report.mines!==false
      || report.broadcastAuthorized!==false || report.releaseSpecific!==true) {
    throw new Error('report proof execution claims are invalid');
  }
  const started=canonicalUint(report.startedAt,64,'startedAt');
  const completed=canonicalUint(report.completedAt,64,'completedAt');
  if(started===0n || completed===0n || completed<started) {
    throw new Error('report execution interval is invalid');
  }
  const provingWall=canonicalUint(report.provingWallMilliseconds,64,'provingWallMilliseconds',{
    maximum:30n*24n*60n*60n*1000n,
  });
  const compressionWall=canonicalUint(
    report.compressionWallMilliseconds,64,'compressionWallMilliseconds',{
      maximum:30n*24n*60n*60n*1000n,
    },
  );
  if(provingWall===0n || compressionWall===0n
      || provingWall+compressionWall>(completed-started+120n)*1000n) {
    throw new Error('report proof timing is invalid');
  }
  if(canonicalUint(report.peakResidentKiB,64,'peakResidentKiB',{
    maximum:64n*1024n*1024n,
  })===0n) throw new Error('peakResidentKiB must be nonzero');
  if(canonicalUint(report.compressionPeakResidentKiB,64,'compressionPeakResidentKiB',{
    maximum:64n*1024n*1024n,
  })===0n) throw new Error('compressionPeakResidentKiB must be nonzero');
  for(const [name,maximum] of [
    ['inputBytes',16n*1024n*1024n],['succinctReceiptBytes',256n*1024n*1024n],
    ['groth16ReceiptBytes',256n*1024n*1024n],['evmSealBytes',64n*1024n],
  ]) {
    if(canonicalUint(report[name],64,name,{maximum})===0n) throw new Error(`${name} must be nonzero`);
  }
  if(canonicalUint(report.finalizedObservationBlockNumber,64,
    'finalizedObservationBlockNumber')===0n) {
    throw new Error('finalizedObservationBlockNumber must be nonzero');
  }
  if(canonicalUint(report.evmVerificationGas,64,'evmVerificationGas',{
    maximum:5_000_000n,
  })===0n) throw new Error('evmVerificationGas must be nonzero');
  return Object.freeze({...report,burn:Object.freeze(Object.fromEntries(
    burnFields.map(field=>[field,typeof burn[field]==='bigint'?burn[field].toString():burn[field]]),
  )),
    observationSourceIds:Object.freeze([...report.observationSourceIds]),
    observationEndpointHashes:Object.freeze([...report.observationEndpointHashes]),
  });
}

export const FINALIZED_BURN_E2E_REPORT_SCHEMA='usdom-finalized-burn-e2e-report-v4';
