import {createHash} from 'node:crypto';
import {AbiCoder,getAddress,keccak256,toUtf8Bytes} from 'ethers';
import {uint} from './reserve.mjs';

const rawHashPattern=/^[0-9a-f]{64}$/;
const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const runIdPattern=/^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$/;
const sourceIdPattern=/^[a-z][a-z0-9-]{0,31}$/;
const fields=Object.freeze([
  'adapterCallAccepted','adapterRuntimeCodeHash','adapterVerificationGas','adapterVerifierConfigHash',
  'broadcastAuthorized','completedAt','devMode','ethereumChainId','evmSealBytes',
  'evmSealSha256','finalizedObservationBlockHash','finalizedObservationBlockNumber',
  'groth16ReceiptBytes','groth16ReceiptSha256','guestImageId','guestProgramSha256',
  'inputBytes','inputSha256','mines','observationEndpointHashes','observationSourceIds',
  'isolatedEvmAdapter','isolatedEvmBlockHash','isolatedEvmBlockNumber',
  'isolatedEvmReceiptSha256','isolatedEvmTransactionHash',
  'peakResidentKiB','prover','provingWallMilliseconds','rayonWorkers','receiptKind',
  'receiptVerified','releaseSpecific','riscZeroVerifier','riscZeroVerifierCodeHash',
  'risc0ZkvmVersion','runId','schema','segmentLimitPo2','startedAt','statementHash',
  'succinctReceiptBytes','succinctReceiptSha256',
]);

export const FINALIZED_BURN_CAPACITY_REPORT_SCHEMA=
  'usdom-finalized-burn-capacity-report-v2';
export const FINALIZED_BURN_CAPACITY_INPUT_SHA256=
  'f0256065e381b89d54df68fc860170bcbbd800b83eb2421d8727d94acfd837ee';
export const FINALIZED_BURN_CAPACITY_INPUT_BYTES=64264;
export const FINALIZED_BURN_CAPACITY_STATEMENT_HASH=
  'c0461e1c2bcff62d1dfd8e8fed0b094b5d19c2744cf9bad34c8ae3722e7eaef4';
export const FINALIZED_BURN_CAPACITY_PROGRAM_SHA256=
  '883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21';
export const FINALIZED_BURN_CAPACITY_IMAGE_ID=
  '2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea';
const adapterTypeHash=keccak256(toUtf8Bytes(
  'DOMFinalizedBurnRiscZeroVerifier(uint256 chainId,address riscZeroVerifier,bytes32 riscZeroVerifierCodeHash,bytes4 verifierSelector,bytes32 imageId,bytes32 journalSchemaHash,bytes32 proofAccepted)',
));
const journalSchemaHash=keccak256(toUtf8Bytes('raw-statement-hash-32-bytes-v1'));
const proofAccepted=keccak256(toUtf8Bytes('USDOM_FINALIZED_BURN_PROOF_V1'));

export function finalizedBurnCapacityAdapterConfigHash(reference) {
  const trustedAddress=getAddress(reference?.verifier_address);
  const trustedCodeHash=bytes32(reference?.observed_runtime_code_hash,'reference verifier code hash');
  return keccak256(AbiCoder.defaultAbiCoder().encode(
    ['bytes32','uint256','address','bytes32','bytes4','bytes32','bytes32','bytes32'],
    [adapterTypeHash,1n,trustedAddress,trustedCodeHash,'0x73c457ba',
      '0x'+FINALIZED_BURN_CAPACITY_IMAGE_ID,journalSchemaHash,proofAccepted],
  ));
}

function exact(value) {
  return value && typeof value==='object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...fields].sort());
}

function rawHash(value,label) {
  if(typeof value!=='string' || !rawHashPattern.test(value) || value==='0'.repeat(64)) {
    throw new Error(`${label} must be a nonzero canonical raw hash`);
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

function canonicalUint(value,bits,label,{maximum=null,nonzero=false}={}) {
  if(typeof value!=='string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed=uint(value,bits);
  if(nonzero && parsed===0n) throw new Error(`${label} must be nonzero`);
  if(maximum!==null && parsed>maximum) throw new Error(`${label} exceeds its bound`);
  return parsed;
}

function canonicalSources(ids,hashes) {
  if(!Array.isArray(ids) || !Array.isArray(hashes) || ids.length<2 || ids.length>4
      || hashes.length!==ids.length) {
    throw new Error('two to four capacity observation sources are required');
  }
  for(const id of ids) {
    if(typeof id!=='string' || !sourceIdPattern.test(id)) {
      throw new Error('observation source ID is not canonical');
    }
  }
  hashes.forEach((hash,index)=>rawHash(hash,`observationEndpointHashes[${index}]`));
  if(new Set(ids).size!==ids.length || new Set(hashes).size!==hashes.length
      || JSON.stringify(ids)!==JSON.stringify([...ids].sort())) {
    throw new Error('observation sources must be distinct and ordered');
  }
}

const isolatedReceiptFields=Object.freeze([
  'adapter','adapterRuntimeCodeHash','adapterVerificationGas','adapterVerifierConfigHash',
  'blockHash','blockNumber','evmSealSha256','statementHash','transactionHash',
]);

export function finalizedBurnIsolatedEvmReceiptCommitment(input) {
  if(!input || typeof input!=='object' || Array.isArray(input)
      || JSON.stringify(Object.keys(input).sort())!==JSON.stringify([...isolatedReceiptFields].sort())) {
    throw new Error('exact finalized-burn isolated EVM receipt fields required');
  }
  const record={schema:'usdom-finalized-burn-isolated-evm-receipt-v1',
    transactionHash:bytes32(input.transactionHash,'transactionHash'),
    blockHash:bytes32(input.blockHash,'blockHash'),
    blockNumber:canonicalUint(input.blockNumber,64,'blockNumber',{nonzero:true}).toString(),
    adapter:getAddress(input.adapter),
    adapterRuntimeCodeHash:bytes32(input.adapterRuntimeCodeHash,'adapterRuntimeCodeHash'),
    adapterVerifierConfigHash:bytes32(input.adapterVerifierConfigHash,'adapterVerifierConfigHash'),
    statementHash:rawHash(input.statementHash,'statementHash'),
    evmSealSha256:rawHash(input.evmSealSha256,'evmSealSha256'),
    adapterVerificationGas:canonicalUint(input.adapterVerificationGas,64,
      'adapterVerificationGas',{nonzero:true,maximum:5_000_000n}).toString(),status:'success'};
  const canonicalTranscript=JSON.stringify(record,null,2)+'\n';
  return Object.freeze({record:Object.freeze(record),canonicalTranscript,
    sha256:createHash('sha256').update(canonicalTranscript).digest('hex')});
}

/**
 * Validate a local proof-capacity measurement. This report deliberately cannot
 * satisfy the release-specific finalized-burn E2E evidence slot: it uses the
 * frozen capacity vector and records `releaseSpecific:false`.
 */
export function validateFinalizedBurnCapacityReport(report,{riscZeroReference}) {
  if(!exact(report)) throw new Error('exact finalized-burn capacity report fields required');
  if(report.schema!==FINALIZED_BURN_CAPACITY_REPORT_SCHEMA) {
    throw new Error('unsupported finalized-burn capacity report schema');
  }
  if(typeof report.runId!=='string' || !runIdPattern.test(report.runId)) {
    throw new Error('capacity run ID is not canonical');
  }
  if(report.inputSha256!==FINALIZED_BURN_CAPACITY_INPUT_SHA256
      || report.inputBytes!==FINALIZED_BURN_CAPACITY_INPUT_BYTES
      || report.statementHash!==FINALIZED_BURN_CAPACITY_STATEMENT_HASH
      || report.guestProgramSha256!==FINALIZED_BURN_CAPACITY_PROGRAM_SHA256
      || report.guestImageId!==FINALIZED_BURN_CAPACITY_IMAGE_ID) {
    throw new Error('capacity report differs from the frozen positive vector');
  }
  if(report.ethereumChainId!=='1'
      || getAddress(report.riscZeroVerifier)!==getAddress(riscZeroReference?.verifier_address)
      || bytes32(report.riscZeroVerifierCodeHash,'riscZeroVerifierCodeHash')
        !==bytes32(riscZeroReference?.observed_runtime_code_hash,'reference verifier code hash')) {
    throw new Error('capacity report differs from the pinned mainnet verifier');
  }
  for(const name of [
    'succinctReceiptSha256','groth16ReceiptSha256','evmSealSha256',
  ]) rawHash(report[name],name);
  if(new Set([
    report.inputSha256,report.succinctReceiptSha256,report.groth16ReceiptSha256,
    report.evmSealSha256,report.isolatedEvmReceiptSha256,
  ]).size!==5) throw new Error('capacity artifact hashes must be distinct');
  bytes32(report.adapterRuntimeCodeHash,'adapterRuntimeCodeHash');
  if(bytes32(report.adapterVerifierConfigHash,'adapterVerifierConfigHash')
      !==finalizedBurnCapacityAdapterConfigHash(riscZeroReference)) {
    throw new Error('capacity adapter config hash mismatch');
  }
  bytes32(report.finalizedObservationBlockHash,'finalizedObservationBlockHash');
  rawHash(report.isolatedEvmReceiptSha256,'isolatedEvmReceiptSha256');
  const isolatedReceipt=finalizedBurnIsolatedEvmReceiptCommitment({
    transactionHash:report.isolatedEvmTransactionHash,blockHash:report.isolatedEvmBlockHash,
    blockNumber:report.isolatedEvmBlockNumber,adapter:report.isolatedEvmAdapter,
    adapterRuntimeCodeHash:report.adapterRuntimeCodeHash,
    adapterVerifierConfigHash:report.adapterVerifierConfigHash,
    statementHash:report.statementHash,evmSealSha256:report.evmSealSha256,
    adapterVerificationGas:report.adapterVerificationGas,
  });
  if(isolatedReceipt.sha256!==report.isolatedEvmReceiptSha256) {
    throw new Error('isolated EVM receipt transcript hash mismatch');
  }
  canonicalSources(report.observationSourceIds,report.observationEndpointHashes);
  const started=canonicalUint(report.startedAt,64,'startedAt',{nonzero:true});
  const completed=canonicalUint(report.completedAt,64,'completedAt',{nonzero:true});
  if(completed<started) throw new Error('capacity completion precedes its start');
  const provingWall=canonicalUint(
    report.provingWallMilliseconds,64,'provingWallMilliseconds',
    {nonzero:true,maximum:30n*24n*60n*60n*1000n},
  );
  if(provingWall>(completed-started+60n)*1000n) {
    throw new Error('proving wall time exceeds the recorded run interval');
  }
  canonicalUint(report.peakResidentKiB,64,'peakResidentKiB',{
    nonzero:true,maximum:64n*1024n*1024n,
  });
  canonicalUint(report.succinctReceiptBytes,64,'succinctReceiptBytes',{
    nonzero:true,maximum:256n*1024n*1024n,
  });
  canonicalUint(report.groth16ReceiptBytes,64,'groth16ReceiptBytes',{
    nonzero:true,maximum:256n*1024n*1024n,
  });
  canonicalUint(report.evmSealBytes,64,'evmSealBytes',{
    nonzero:true,maximum:64n*1024n,
  });
  canonicalUint(report.finalizedObservationBlockNumber,64,'finalizedObservationBlockNumber',{
    nonzero:true,
  });
  canonicalUint(report.adapterVerificationGas,64,'adapterVerificationGas',{
    nonzero:true,maximum:5_000_000n,
  });
  if(report.risc0ZkvmVersion!=='3.0.6' || report.receiptKind!=='groth16'
      || report.prover!=='local' || ![1,2].includes(report.rayonWorkers)
      || report.segmentLimitPo2!==18 || report.receiptVerified!==true
      || report.adapterCallAccepted!==true || report.devMode!==false
      || report.mines!==false || report.broadcastAuthorized!==false
      || report.releaseSpecific!==false) {
    throw new Error('capacity execution claims are invalid');
  }
  return Object.freeze({...report,
    observationSourceIds:Object.freeze([...report.observationSourceIds]),
    observationEndpointHashes:Object.freeze([...report.observationEndpointHashes]),
  });
}
