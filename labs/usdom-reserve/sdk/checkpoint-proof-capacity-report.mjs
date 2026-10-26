import {createHash} from 'node:crypto';
import {getAddress,sha256} from 'ethers';
import {checkpointStatementHash} from './checkpoint-registry.mjs';
import {checkpointRegistryConfigurationFromRelease} from './checkpoint-submission.mjs';
import {checkpointVerifierConfigHash} from './checkpoint-verifier-config.mjs';
import {uint} from './reserve.mjs';

const rawHashPattern=/^[0-9a-f]{64}$/;
const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const sourceCommitPattern=/^[0-9a-f]{40}$/;
const topFields=Object.freeze([
  'adapter','adapterCallAccepted','adapterRuntimeCodeHash','adapterVerificationGas',
  'adapterVerifierConfigHash','artifactSetCommitmentSchema','broadcastAuthorized','checkpointEndHeight','checkpointRegistry',
  'checkpoint','checkpointSpan','checkpointStartHeight','completedAt','confirmationDepth','confirmationHeight',
  'compressionPeakResidentKiB','compressionWallMilliseconds',
  'devMode','ethereumChainId','evmSealBytes','evmSealSha256','hostFingerprintSha256',
  'isolatedEvmBlockHash','isolatedEvmBlockNumber','isolatedEvmReceiptSha256',
  'isolatedEvmTransactionHash',
  'layers','logicalCpus','memoryTotalKiB','mines','outerGroth16ReceiptBytes',
  'outerGroth16ReceiptSha256','outerJournalDigestSha256','prover','rayonWorkers','releaseId',
  'releaseSpecific','randomxProverTranscriptSha256','randomxResourceLogSha256',
  'riscZeroFinalizedBlockHash','riscZeroFinalizedBlockNumber','riscZeroObservationEndpointHashes',
  'riscZeroObservationSourceIds','riscZeroRuntimeArtifactSha256','riscZeroVerifier',
  'riscZeroVerifierCodeHash','risc0ZkvmVersion','schema','sourceCommit',
  'sourcePackageSha256','startedAt','statementHash',
]);
const layerFields=Object.freeze([
  'imageId','inputBytes','inputSetSha256','journalBytes','journalCount','journalSetSha256','name',
  'peakResidentKiB','programSha256','provingWallMilliseconds','receiptBytes',
  'receiptCount','receiptKind','receiptSetSha256','receiptVerified','segmentLimitPo2',
]);
const checkpointFields=Object.freeze([
  'blockHash','confirmationBlock','confirmationHeight','confirmationTimestamp',
  'confirmationTotalDifficulty','contextHash','height','previousBlock','previousContextHash',
  'previousHeight','previousStateRoot','previousTotalDifficulty','stateRoot','totalDifficulty',
  'totalIssued','totalBurned','issuanceClosed',
]);
const layerNames=Object.freeze([
  'randomx','randomx-aggregate','economic-chunk','economic-block','segment','outer',
]);
const artifactSetKinds=Object.freeze(['input','journal','receipt']);
const measuredLayerFields=Object.freeze([
  'imageId','inputs','journals','name','peakResidentKiB','programSha256',
  'provingWallMilliseconds','receiptKind','receiptVerified','receipts','segmentLimitPo2',
]);

export const CHECKPOINT_PROOF_CAPACITY_REPORT_SCHEMA=
  'usdom-checkpoint-proof-capacity-report-v5';
export const CHECKPOINT_CAPACITY_ARTIFACT_SET_SCHEMA=
  'sha256-domain-length-indexed-artifact-set-v1';
export const CHECKPOINT_RANDOMX_PROGRAM_SHA256=
  '0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd';
export const CHECKPOINT_RANDOMX_IMAGE_ID=
  '8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24';
export const CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256=
  '3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f';
export const CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID=
  '08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf';
export const CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256=
  '5e7bc30f65ab4eae7c8b19a8c1c386cd023cd648c85f64008be2bd4729231842';
export const CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID=
  '67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350';
export const CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256=
  'e16e6aea7d470baad85bec45578e0960c02c2d47bce267e26141a2f3fa4a6c1f';
export const CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID=
  '03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7';
export const CHECKPOINT_SEGMENT_PROGRAM_SHA256=
  'c4cc41b0b53d787c46b9293d1515c2d0c4ded982c3ae7b98d33877dd142d2b38';
export const CHECKPOINT_SEGMENT_IMAGE_ID=
  '4e711490f3ab7dde97636687972456da58da4287ce5017e38d4acaa7263a02d6';

function exact(value,fields) {
  return value && typeof value==='object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...fields].sort());
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

function canonicalUint(value,bits,label,{maximum=null,nonzero=false}={}) {
  const maxDigits={8:3,16:5,32:10,64:20,128:39,256:78}[bits];
  if(maxDigits===undefined || typeof value!=='string' || value.length>maxDigits
      || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed=uint(value,bits);
  if(nonzero && parsed===0n) throw new Error(`${label} must be nonzero`);
  if(maximum!==null && parsed>maximum) throw new Error(`${label} exceeds its bound`);
  return parsed;
}

const isolatedEvmReceiptFields=Object.freeze([
  'adapter','adapterRuntimeCodeHash','adapterVerificationGas','adapterVerifierConfigHash',
  'blockHash','blockNumber','evmSealSha256','statementHash','transactionHash',
]);

/** Canonical audit transcript for the exact isolated-EVM receipt that supplied
 * the adapter acceptance and gas measurement. */
export function checkpointIsolatedEvmReceiptCommitment(input) {
  if(!exact(input,isolatedEvmReceiptFields)) {
    throw new Error('exact isolated EVM receipt transcript fields required');
  }
  const record={schema:'usdom-checkpoint-isolated-evm-receipt-v1',
    transactionHash:bytes32(input.transactionHash,'transactionHash'),
    blockHash:bytes32(input.blockHash,'blockHash'),
    blockNumber:canonicalUint(input.blockNumber,64,'blockNumber',{nonzero:true}).toString(),
    adapter:getAddress(input.adapter),
    adapterRuntimeCodeHash:bytes32(input.adapterRuntimeCodeHash,'adapterRuntimeCodeHash'),
    adapterVerifierConfigHash:bytes32(input.adapterVerifierConfigHash,'adapterVerifierConfigHash'),
    statementHash:bytes32(input.statementHash,'statementHash'),
    evmSealSha256:rawHash(input.evmSealSha256,'evmSealSha256'),
    adapterVerificationGas:canonicalUint(input.adapterVerificationGas,64,
      'adapterVerificationGas',{nonzero:true,maximum:5_000_000n}).toString(),status:'success'};
  const canonicalTranscript=JSON.stringify(record,null,2)+'\n';
  return Object.freeze({record:Object.freeze(record),canonicalTranscript,
    sha256:createHash('sha256').update(canonicalTranscript).digest('hex')});
}

/** Domain-separated commitment for one ordered set consumed by a report layer. */
export function checkpointCapacityArtifactSetCommitment(layerName,kind,records) {
  if(!layerNames.includes(layerName) || !artifactSetKinds.includes(kind)) {
    throw new Error('unsupported checkpoint capacity artifact-set domain');
  }
  if(!Array.isArray(records) || records.length===0 || records.length>4096) {
    throw new Error('checkpoint capacity artifact set must contain one to 4096 records');
  }
  const hash=createHash('sha256');
  hash.update(`USDOM:checkpoint-capacity-artifact-set:v1:${layerName}:${kind}\0`,'ascii');
  const count=Buffer.alloc(4);
  count.writeUInt32BE(records.length);
  hash.update(count);
  let totalBytes=0n;
  records.forEach((record,index)=>{
    if(!exact(record,['bytes','sha256'])) {
      throw new Error(`exact checkpoint capacity artifact record ${index} required`);
    }
    const digest=rawHash(record.sha256,`artifact[${index}].sha256`);
    const length=canonicalUint(record.bytes,64,`artifact[${index}].bytes`,{
      nonzero:true,maximum:4n*1024n*1024n*1024n,
    });
    if(kind==='journal' && length!==32n) {
      throw new Error('checkpoint capacity journal records must be exactly 32 bytes');
    }
    const header=Buffer.alloc(12);
    header.writeUInt32BE(index,0);
    header.writeBigUInt64BE(length,4);
    hash.update(header);
    hash.update(Buffer.from(digest,'hex'));
    totalBytes+=length;
  });
  return Object.freeze({sha256:hash.digest('hex'),count:String(records.length),
    totalBytes:totalBytes.toString()});
}

/** Build the canonical report from measured artifact records, then revalidate it. */
export function buildCheckpointProofCapacityReport(base,measuredLayers,validation) {
  if(!base || typeof base!=='object' || Array.isArray(base)) {
    throw new Error('checkpoint capacity report base must be an object');
  }
  if(!Array.isArray(measuredLayers) || measuredLayers.length!==layerNames.length) {
    throw new Error('all six measured checkpoint layers are required');
  }
  const layers=measuredLayers.map((measured,index)=>{
    const name=layerNames[index];
    if(!exact(measured,measuredLayerFields) || measured.name!==name) {
      throw new Error(`exact measured ${name} layer required`);
    }
    const input=checkpointCapacityArtifactSetCommitment(name,'input',measured.inputs);
    const journal=checkpointCapacityArtifactSetCommitment(name,'journal',measured.journals);
    const receipt=checkpointCapacityArtifactSetCommitment(name,'receipt',measured.receipts);
    return {
      name,programSha256:measured.programSha256,imageId:measured.imageId,
      inputSetSha256:input.sha256,inputBytes:input.totalBytes,
      journalSetSha256:journal.sha256,journalBytes:journal.totalBytes,
      journalCount:journal.count,receiptSetSha256:receipt.sha256,
      receiptBytes:receipt.totalBytes,receiptCount:receipt.count,
      receiptKind:measured.receiptKind,receiptVerified:measured.receiptVerified,
      segmentLimitPo2:measured.segmentLimitPo2,
      provingWallMilliseconds:measured.provingWallMilliseconds,
      peakResidentKiB:measured.peakResidentKiB,
    };
  });
  return validateCheckpointProofCapacityReport({
    schema:CHECKPOINT_PROOF_CAPACITY_REPORT_SCHEMA,
    artifactSetCommitmentSchema:CHECKPOINT_CAPACITY_ARTIFACT_SET_SCHEMA,
    ...base,outerJournalDigestSha256:sha256(base.statementHash).slice(2),layers,
  },validation);
}

function expectedLayers(checkpointVerifierConfig) {
  return [
    {name:'randomx',programSha256:CHECKPOINT_RANDOMX_PROGRAM_SHA256,
      imageId:CHECKPOINT_RANDOMX_IMAGE_ID},
    {name:'randomx-aggregate',programSha256:CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256,
      imageId:CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID},
    {name:'economic-chunk',programSha256:CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256,
      imageId:CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID},
    {name:'economic-block',programSha256:CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256,
      imageId:CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID},
    {name:'segment',programSha256:CHECKPOINT_SEGMENT_PROGRAM_SHA256,
      imageId:CHECKPOINT_SEGMENT_IMAGE_ID},
    {name:'outer',programSha256:bytes32(checkpointVerifierConfig?.provingProgramSha256,
      'checkpoint provingProgramSha256').slice(2),
    imageId:bytes32(checkpointVerifierConfig?.checkpointGuestImageId,
      'checkpoint checkpointGuestImageId').slice(2)},
  ];
}

/**
 * Validate one release-bound, end-to-end checkpoint proving measurement. Every
 * recursive layer must have a real verified succinct receipt, and the outer
 * receipt must also be compressed and accepted by the exact release adapter.
 */
export function validateCheckpointProofCapacityReport(report,{
  evidence,releaseConfig,checkpointVerifierConfig,riscZeroReference,
}) {
  if(!exact(report,topFields)) throw new Error('exact checkpoint capacity report fields required');
  if(report.schema!==CHECKPOINT_PROOF_CAPACITY_REPORT_SCHEMA) {
    throw new Error('unsupported checkpoint capacity report schema');
  }
  if(report.artifactSetCommitmentSchema!==CHECKPOINT_CAPACITY_ARTIFACT_SET_SCHEMA) {
    throw new Error('unsupported checkpoint capacity artifact-set commitment schema');
  }
  if(typeof report.releaseId!=='string' || report.releaseId.length===0
      || report.releaseId!==evidence?.releaseId) throw new Error('report releaseId mismatch');
  if(!sourceCommitPattern.test(report.sourceCommit)
      || report.sourceCommit!==evidence?.sourceCommit) throw new Error('report sourceCommit mismatch');
  if(report.ethereumChainId!=='1' || report.ethereumChainId!==releaseConfig?.ethereumChainId) {
    throw new Error('report Ethereum chain mismatch');
  }
  if(getAddress(report.checkpointRegistry)!==getAddress(releaseConfig?.checkpointRegistry)
      || getAddress(report.adapter)!==getAddress(releaseConfig?.checkpointVerifier)) {
    throw new Error('report registry or adapter mismatch');
  }
  const finalizedConfig=checkpointVerifierConfigHash(checkpointVerifierConfig);
  if(bytes32(checkpointVerifierConfig?.randomxReceiptImageId,
    'checkpoint randomxReceiptImageId')!=='0x'+CHECKPOINT_RANDOMX_IMAGE_ID) {
    throw new Error('checkpoint config does not pin the per-block RandomX receipt ImageID');
  }
  if(bytes32(report.adapterRuntimeCodeHash,'adapterRuntimeCodeHash')
      !==bytes32(releaseConfig?.checkpointVerifierCodeHash,'release checkpointVerifierCodeHash')
      || bytes32(report.adapterVerifierConfigHash,'adapterVerifierConfigHash')
        !==bytes32(releaseConfig?.checkpointVerifierConfigHash,
          'release checkpointVerifierConfigHash')
      || bytes32(report.adapterVerifierConfigHash,'adapterVerifierConfigHash')
        !==bytes32(finalizedConfig.verifierConfigHash,'computed checkpoint verifier config hash')) {
    throw new Error('report checkpoint adapter identity mismatch');
  }
  if(getAddress(report.riscZeroVerifier)!==getAddress(riscZeroReference?.verifier_address)
      || bytes32(report.riscZeroVerifierCodeHash,'riscZeroVerifierCodeHash')
        !==bytes32(riscZeroReference?.observed_runtime_code_hash,'reference verifier code hash')) {
    throw new Error('report RISC Zero verifier identity mismatch');
  }
  rawHash(report.sourcePackageSha256,'sourcePackageSha256');
  rawHash(report.randomxProverTranscriptSha256,'randomxProverTranscriptSha256');
  rawHash(report.randomxResourceLogSha256,'randomxResourceLogSha256');
  rawHash(report.riscZeroRuntimeArtifactSha256,'riscZeroRuntimeArtifactSha256');
  rawHash(report.isolatedEvmReceiptSha256,'isolatedEvmReceiptSha256');
  bytes32(report.riscZeroFinalizedBlockHash,'riscZeroFinalizedBlockHash');
  canonicalUint(report.riscZeroFinalizedBlockNumber,64,'riscZeroFinalizedBlockNumber',{
    nonzero:true,
  });
  const expectedSourceIds=['drpc','publicnode'];
  const expectedEndpointHashes=[
    'c5b9f7564a09b1b2bbdff2c7145d474bbc2ccd025460d9c5b097a39474b7980c',
    '7b71d04b616d2ce47598465ad04d63da212a14b1317f965044bf325b749a6746',
  ];
  if(JSON.stringify(report.riscZeroObservationSourceIds)!==JSON.stringify(expectedSourceIds)
      || JSON.stringify(report.riscZeroObservationEndpointHashes)
        !==JSON.stringify(expectedEndpointHashes)) {
    throw new Error('checkpoint capacity RISC Zero observation sources are not the fixed set');
  }
  const isolatedEvmReceipt=checkpointIsolatedEvmReceiptCommitment({
    transactionHash:report.isolatedEvmTransactionHash,blockHash:report.isolatedEvmBlockHash,
    blockNumber:report.isolatedEvmBlockNumber,adapter:report.adapter,
    adapterRuntimeCodeHash:report.adapterRuntimeCodeHash,
    adapterVerifierConfigHash:report.adapterVerifierConfigHash,
    statementHash:report.statementHash,evmSealSha256:report.evmSealSha256,
    adapterVerificationGas:report.adapterVerificationGas,
  });
  if(isolatedEvmReceipt.sha256!==report.isolatedEvmReceiptSha256) {
    throw new Error('isolated EVM receipt commitment does not match the reported measurement');
  }
  const statementHash=bytes32(report.statementHash,'statementHash');
  rawHash(report.hostFingerprintSha256,'hostFingerprintSha256');
  rawHash(report.outerGroth16ReceiptSha256,'outerGroth16ReceiptSha256');
  rawHash(report.outerJournalDigestSha256,'outerJournalDigestSha256');
  rawHash(report.evmSealSha256,'evmSealSha256');

  if(!exact(report.checkpoint,checkpointFields)) {
    throw new Error('exact checkpoint statement fields required');
  }
  for(const name of [
    'previousBlock','previousStateRoot','previousContextHash','blockHash','stateRoot','contextHash',
    'confirmationBlock',
  ]) bytes32(report.checkpoint[name],`checkpoint.${name}`);
  for(const name of [
    'previousHeight','height','confirmationHeight','confirmationTimestamp',
  ]) canonicalUint(report.checkpoint[name],64,`checkpoint.${name}`,{nonzero:true});
  for(const name of [
    'previousTotalDifficulty','totalDifficulty','confirmationTotalDifficulty',
  ]) canonicalUint(report.checkpoint[name],256,`checkpoint.${name}`,{nonzero:true});
  const totalIssued=canonicalUint(report.checkpoint.totalIssued,128,'checkpoint.totalIssued');
  const totalBurned=canonicalUint(report.checkpoint.totalBurned,128,'checkpoint.totalBurned');
  if(totalBurned>totalIssued || typeof report.checkpoint.issuanceClosed!=='boolean') {
    throw new Error('checkpoint economic totals or closure flag are invalid');
  }
  const computedStatementHash=checkpointStatementHash(
    checkpointRegistryConfigurationFromRelease(releaseConfig),report.checkpoint,
  );
  if(statementHash!==computedStatementHash) {
    throw new Error('checkpoint statement hash does not match the exact release checkpoint');
  }

  const startHeight=canonicalUint(report.checkpointStartHeight,64,'checkpointStartHeight',{
    nonzero:true,
  });
  const endHeight=canonicalUint(report.checkpointEndHeight,64,'checkpointEndHeight',{
    nonzero:true,
  });
  const confirmationHeight=canonicalUint(
    report.confirmationHeight,64,'confirmationHeight',{nonzero:true},
  );
  const span=canonicalUint(report.checkpointSpan,32,'checkpointSpan',{nonzero:true});
  const depth=canonicalUint(report.confirmationDepth,32,'confirmationDepth',{nonzero:true});
  if(startHeight!==uint(report.checkpoint.previousHeight,64)
      || endHeight!==uint(report.checkpoint.height,64)
      || confirmationHeight!==uint(report.checkpoint.confirmationHeight,64)
      || endHeight<=startHeight || endHeight-startHeight!==span
      || confirmationHeight-endHeight!==depth
      || span>uint(checkpointVerifierConfig.maxCheckpointSpan,32)
      || depth!==uint(checkpointVerifierConfig.confirmationDepth,32)) {
    throw new Error('checkpoint measurement height window is invalid');
  }

  const expected=expectedLayers(checkpointVerifierConfig);
  if(!Array.isArray(report.layers) || report.layers.length!==expected.length) {
    throw new Error('all six checkpoint proof layers are required');
  }
  const artifactHashes=[report.sourcePackageSha256,report.randomxProverTranscriptSha256,
    report.randomxResourceLogSha256,report.riscZeroRuntimeArtifactSha256,
    report.isolatedEvmReceiptSha256,report.outerGroth16ReceiptSha256,report.evmSealSha256];
  let totalWall=0n;
  for(let index=0;index<expected.length;index++) {
    const layer=report.layers[index];
    const identity=expected[index];
    if(!exact(layer,layerFields)) throw new Error(`exact ${identity.name} layer fields required`);
    if(layer.name!==identity.name || layer.programSha256!==identity.programSha256
        || layer.imageId!==identity.imageId) {
      throw new Error(`${identity.name} proving identity mismatch`);
    }
    rawHash(layer.inputSetSha256,`${identity.name}.inputSetSha256`);
    rawHash(layer.journalSetSha256,`${identity.name}.journalSetSha256`);
    rawHash(layer.receiptSetSha256,`${identity.name}.receiptSetSha256`);
    artifactHashes.push(layer.inputSetSha256,layer.journalSetSha256,layer.receiptSetSha256);
    canonicalUint(layer.inputBytes,64,`${identity.name}.inputBytes`,{
      nonzero:true,maximum:4n*1024n*1024n*1024n,
    });
    const journalBytes=canonicalUint(layer.journalBytes,64,`${identity.name}.journalBytes`,{
      nonzero:true,maximum:4n*1024n*1024n,
    });
    canonicalUint(layer.receiptBytes,64,`${identity.name}.receiptBytes`,{
      nonzero:true,maximum:1024n*1024n*1024n,
    });
    const receiptCount=canonicalUint(layer.receiptCount,32,`${identity.name}.receiptCount`,{
      nonzero:true,maximum:4096n,
    });
    const journalCount=canonicalUint(layer.journalCount,32,`${identity.name}.journalCount`,{
      nonzero:true,maximum:4096n,
    });
    if(journalCount!==receiptCount || journalBytes!==journalCount*32n) {
      throw new Error(`${identity.name} must bind one 32-byte journal per receipt`);
    }
    totalWall+=canonicalUint(
      layer.provingWallMilliseconds,64,`${identity.name}.provingWallMilliseconds`,
      {nonzero:true,maximum:30n*24n*60n*60n*1000n},
    );
    canonicalUint(layer.peakResidentKiB,64,`${identity.name}.peakResidentKiB`,{
      nonzero:true,maximum:64n*1024n*1024n,
    });
    if(layer.receiptKind!=='succinct' || layer.receiptVerified!==true
        || !Number.isSafeInteger(layer.segmentLimitPo2)
        || layer.segmentLimitPo2<16 || layer.segmentLimitPo2>22) {
      throw new Error(`${identity.name} proof execution claim is invalid`);
    }
  }
  if(new Set(artifactHashes).size!==artifactHashes.length) {
    throw new Error('checkpoint capacity artifact hashes must be distinct');
  }
  if(report.layers.at(-1).journalCount!=='1'
      || report.outerJournalDigestSha256!==sha256(statementHash).slice(2)) {
    throw new Error('outer journal does not bind the checkpoint statement hash');
  }

  const started=canonicalUint(report.startedAt,64,'startedAt',{nonzero:true});
  const completed=canonicalUint(report.completedAt,64,'completedAt',{nonzero:true});
  totalWall+=canonicalUint(
    report.compressionWallMilliseconds,64,'compressionWallMilliseconds',
    {nonzero:true,maximum:30n*24n*60n*60n*1000n},
  );
  canonicalUint(report.compressionPeakResidentKiB,64,'compressionPeakResidentKiB',{
    nonzero:true,maximum:64n*1024n*1024n,
  });
  if(completed<started || totalWall>(completed-started+300n)*1000n) {
    throw new Error('checkpoint proving time exceeds the recorded run interval');
  }
  canonicalUint(report.outerGroth16ReceiptBytes,64,'outerGroth16ReceiptBytes',{
    nonzero:true,maximum:256n*1024n*1024n,
  });
  canonicalUint(report.evmSealBytes,64,'evmSealBytes',{
    nonzero:true,maximum:uint(checkpointVerifierConfig.maxProofBytes,32),
  });
  canonicalUint(report.adapterVerificationGas,64,'adapterVerificationGas',{
    nonzero:true,maximum:5_000_000n,
  });
  canonicalUint(report.memoryTotalKiB,64,'memoryTotalKiB',{
    nonzero:true,maximum:1024n*1024n*1024n,
  });
  if(!Number.isSafeInteger(report.logicalCpus) || report.logicalCpus<1 || report.logicalCpus>4096
      || report.risc0ZkvmVersion!=='3.0.6' || report.prover!=='local'
      || report.rayonWorkers!==1 || report.devMode!==false || report.mines!==false
      || report.broadcastAuthorized!==false || report.releaseSpecific!==true
      || report.adapterCallAccepted!==true) {
    throw new Error('checkpoint capacity execution claims are invalid');
  }
  return Object.freeze({...report,layers:Object.freeze(report.layers.map(layer=>Object.freeze({...layer})))});
}
