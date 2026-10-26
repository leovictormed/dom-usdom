import {createHash} from 'node:crypto';
import {lstat} from 'node:fs/promises';
import path from 'node:path';
import {
  CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256,
  CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256,
  CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256,
  CHECKPOINT_RANDOMX_IMAGE_ID,CHECKPOINT_RANDOMX_PROGRAM_SHA256,
  CHECKPOINT_SEGMENT_IMAGE_ID,CHECKPOINT_SEGMENT_PROGRAM_SHA256,
} from './checkpoint-proof-capacity-report.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {readDirectFile} from './direct-project-file.mjs';
import {CHECKPOINT_EVM_SEAL_BYTES} from './checkpoint-submission.mjs';

const currentUid=process.getuid();
const rawHashPattern=/^[0-9a-f]{64}$/;
// All collected checkpoint receipts are succinct or Groth16 and use the same
// ceiling as the Rust decoders. Composite receipts never cross this collector.
const maximumArtifactBytes=256*1024*1024;
const groth16VerifierParameters=
  '73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc';
const evmVerifierSelector='73c457ba';
const indexSpecifications=Object.freeze({
  randomx:Object.freeze({
    index:'evidence/randomx-receipt-set/randomx-receipt-set-index.json',
    job:'evidence/randomx-proof-jobs/randomx-proof-job-index.json',
    directory:'evidence/randomx-receipt-set',schema:'usdom-randomx-receipt-set-v1',
    imageField:'randomx_receipt_image_id',imageId:CHECKPOINT_RANDOMX_IMAGE_ID,
    jobPathField:'proof_job_index_path',jobHashField:'proof_job_index_sha256',
    countField:'receipt_count',recordsField:'receipts',verifiedFields:[
      'randomx_relations_executed','receipts_verified',
    ],filePrefix:'randomx-receipt-',programSha256:CHECKPOINT_RANDOMX_PROGRAM_SHA256,
    recordFields:['block_height','block_index','expected_journal','index','receipt_bytes',
      'receipt_file','receipt_sha256','segment_index','statement_sha256'],
  }),
  'randomx-aggregate':Object.freeze({
    index:'evidence/randomx-aggregate-receipt-set/randomx-aggregate-receipt-set-index.json',
    job:'evidence/randomx-aggregate-jobs/randomx-aggregate-job-index.json',
    directory:'evidence/randomx-aggregate-receipt-set',
    schema:'usdom-randomx-aggregate-receipt-set-v1',imageField:'aggregate_image_id',
    imageId:CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,jobPathField:'aggregate_job_index_path',
    jobHashField:'aggregate_job_index_sha256',countField:'receipt_count',recordsField:'receipts',
    verifiedFields:['inner_receipts_verified','aggregate_receipts_verified'],
    filePrefix:'randomx-aggregate-receipt-',programSha256:CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256,
    recordFields:['block_count','expected_journal','index','next_height','previous_height',
      'receipt_bytes','receipt_file','receipt_sha256'],
  }),
  segment:Object.freeze({
    index:'evidence/checkpoint-segment-receipt-set/checkpoint-segment-receipt-set-index.json',
    job:'evidence/checkpoint-segment-proof-jobs/checkpoint-segment-proof-job-index.json',
    directory:'evidence/checkpoint-segment-receipt-set',
    schema:'usdom-checkpoint-segment-receipt-set-v1',imageField:'segment_image_id',
    imageId:CHECKPOINT_SEGMENT_IMAGE_ID,jobPathField:'proof_job_index_path',
    jobHashField:'proof_job_index_sha256',countField:'receipt_count',recordsField:'receipts',
    verifiedFields:['inner_receipts_verified','segment_receipts_verified'],
    filePrefix:'checkpoint-segment-receipt-',programSha256:CHECKPOINT_SEGMENT_PROGRAM_SHA256,
    recordFields:['block_count','expected_journal','index','next_height','previous_height',
      'receipt_bytes','receipt_file','receipt_sha256'],
  }),
});

const commonIndexFields=Object.freeze([
  'dev_mode','generates_proofs','mines','receipt_kind','risc0_zkvm_version','schema',
]);

function exact(value,fields,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...fields].sort())) {
    throw new Error(`exact ${label} fields required`);
  }
}

function rawHash(value,label) {
  if(typeof value!=='string' || !rawHashPattern.test(value) || value==='0'.repeat(64)) {
    throw new Error(`${label} must be a nonzero canonical raw hash`);
  }
  return value;
}

function boundedCount(value,label,{maximum=4096}={}) {
  if(!Number.isSafeInteger(value) || value<1 || value>maximum) {
    throw new Error(`${label} must be a positive bounded integer`);
  }
  return value;
}

function boundedIndex(value,label,{maximum=4095}={}) {
  if(!Number.isSafeInteger(value) || value<0 || value>maximum) {
    throw new Error(`${label} must be a bounded nonnegative integer`);
  }
  return value;
}

function boundedHeight(value,label) {
  if(!Number.isSafeInteger(value) || value<1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function validateOrderedRecords(name,records) {
  let priorHeight=0,priorNext=null,priorPosition=null;
  for(const [position,record] of records.entries()) {
    if(name==='randomx') {
      const segment=boundedIndex(record.segment_index,`${name}[${position}].segment_index`);
      const block=boundedIndex(record.block_index,`${name}[${position}].block_index`);
      const height=boundedHeight(record.block_height,`${name}[${position}].block_height`);
      rawHash(record.statement_sha256,`${name}[${position}].statement_sha256`);
      if(height<=priorHeight) throw new Error(`${name} receipt heights must be strictly ordered`);
      const current=[segment,block];
      if(priorPosition!==null && (current[0]<priorPosition[0]
          || (current[0]===priorPosition[0] && current[1]<=priorPosition[1]))) {
        throw new Error(`${name} receipt positions must be canonically ordered`);
      }
      priorHeight=height; priorPosition=current;
    } else {
      const previous=boundedHeight(record.previous_height,`${name}[${position}].previous_height`);
      const next=boundedHeight(record.next_height,`${name}[${position}].next_height`);
      const count=boundedCount(record.block_count,`${name}[${position}].block_count`);
      if(next-previous!==count || (priorNext!==null && previous!==priorNext)) {
        throw new Error(`${name} receipt spans must be ordered and contiguous`);
      }
      priorNext=next;
    }
  }
}

function safeRelative(value,label) {
  if(typeof value!=='string' || value.length===0 || value.startsWith('/') || value.includes('\\')
      || value.includes('\0') || value.split('/').some(part=>part==='' || part==='.' || part==='..')) {
    throw new Error(`${label} must be a canonical relative POSIX path`);
  }
  return value;
}

async function privateArtifact(root,relative,{minimum=1,maximum=maximumArtifactBytes}={}) {
  safeRelative(relative,'artifact path');
  const absolute=path.resolve(root,relative);
  if(absolute===root || !absolute.startsWith(root+path.sep)) throw new Error('artifact escapes root');
  const rootMetadata=await lstat(root);
  if(!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()
      || rootMetadata.uid!==currentUid) throw new Error('unsafe checkpoint capacity root');
  let directory=root;
  for(const component of relative.split('/').slice(0,-1)) {
    directory=path.join(directory,component);
    const directoryMetadata=await lstat(directory);
    if(!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()
        || directoryMetadata.uid!==currentUid || (directoryMetadata.mode&0o077)!==0) {
      throw new Error(`unsafe checkpoint capacity directory: ${directory}`);
    }
  }
  const bytes=await readDirectFile(absolute,{minimum,maximum,privateMode:true,
    label:`checkpoint capacity artifact ${relative}`});
  return {bytes,record:{sha256:createHash('sha256').update(bytes).digest('hex'),
    bytes:String(bytes.length)}};
}

async function privateArtifactRecord(root,relative,options) {
  const artifact=await privateArtifact(root,relative,options);
  return {record:artifact.record};
}

async function strictIndex(root,relative) {
  const artifact=await privateArtifact(root,relative,{maximum:64*1024*1024});
  return {...artifact,value:parseStrictJsonBytes(artifact.bytes,{
    label:relative,maxBytes:64*1024*1024,maxDepth:32,
  })};
}

function metric(value,label) {
  exact(value,['peakResidentKiB','provingWallMilliseconds'],`${label} metrics`);
  if(!/^[1-9][0-9]*$/.test(value.provingWallMilliseconds)
      || !/^[1-9][0-9]*$/.test(value.peakResidentKiB)) {
    throw new Error(`${label} metrics must be canonical positive decimal strings`);
  }
  return value;
}

function journalRecord(value,label) {
  const raw=rawHash(value,label);
  return {sha256:createHash('sha256').update(Buffer.from(raw,'hex')).digest('hex'),bytes:'32'};
}

async function receiptRecord(root,directory,record,index,prefix,fields) {
  exact(record,fields,`${prefix} receipt record ${index}`);
  if(record.index!==index || record.receipt_file!==`${prefix}${String(index).padStart(4,'0')}.bin`
      || !Number.isSafeInteger(record.receipt_bytes) || record.receipt_bytes<1
      || record.receipt_bytes>maximumArtifactBytes) {
    throw new Error(`noncanonical ${prefix} receipt record ${index}`);
  }
  const artifact=await privateArtifact(root,`${directory}/${record.receipt_file}`);
  if(artifact.record.sha256!==rawHash(record.receipt_sha256,'receipt_sha256')
      || artifact.record.bytes!==String(record.receipt_bytes)) {
    throw new Error(`checkpoint capacity receipt ${index} differs from its index`);
  }
  return {receipt:artifact.record,journal:journalRecord(record.expected_journal,'expected_journal')};
}

function validateCommon(index,specification) {
  if(index.schema!==specification.schema || index.risc0_zkvm_version!=='3.0.6'
      || index.receipt_kind!=='succinct' || index.dev_mode!==false
      || index.generates_proofs!==true || index.mines!==false
      || index[specification.imageField]!==specification.imageId
      || specification.verifiedFields.some(field=>index[field]!==true)) {
    throw new Error(`invalid ${specification.schema} execution claims`);
  }
}

async function simpleLayer(root,name,metrics) {
  const specification=indexSpecifications[name];
  const [{value:index,record:indexRecord},job]=await Promise.all([
    strictIndex(root,specification.index),privateArtifact(root,specification.job,{maximum:64*1024*1024}),
  ]);
  const required=[...commonIndexFields,specification.imageField,specification.jobPathField,
    specification.jobHashField,specification.countField,specification.recordsField,
    ...specification.verifiedFields];
  if(name==='randomx') required.push('confirmation_height','manifest_sha256','previous_height',
    'randomx_user_elf_sha256','segment_count','target_height');
  exact(index,required,`${name} receipt index`);
  validateCommon(index,specification);
  if(index[specification.jobPathField]!==specification.job
      || index[specification.jobHashField]!==job.record.sha256) {
    throw new Error(`${name} job index identity mismatch`);
  }
  const count=boundedCount(index[specification.countField],`${name} receipt count`);
  const records=index[specification.recordsField];
  if(!Array.isArray(records) || records.length!==count) throw new Error(`${name} receipt count mismatch`);
  validateOrderedRecords(name,records);
  const artifacts=[];
  for(let index=0;index<records.length;index++) {
    artifacts.push(await receiptRecord(root,specification.directory,records[index],index,
      specification.filePrefix,specification.recordFields));
  }
  const resources=metric(metrics,name);
  return {layer:{name,programSha256:specification.programSha256,imageId:specification.imageId,
    inputs:[job.record,indexRecord],journals:artifacts.map(item=>item.journal),
    receipts:artifacts.map(item=>item.receipt),receiptKind:'succinct',receiptVerified:true,
    segmentLimitPo2:18,provingWallMilliseconds:resources.provingWallMilliseconds,
    peakResidentKiB:resources.peakResidentKiB},receiptIndexSha256:indexRecord.sha256,
    jobIndexSha256:job.record.sha256,receiptCount:count};
}

const economicIndexFields=Object.freeze([
  ...commonIndexFields,'block_image_id','block_peak_resident_kib','block_proving_wall_milliseconds',
  'block_receipt_count','block_receipts','block_receipts_verified','chunk_image_id',
  'chunk_peak_resident_kib','chunk_proving_wall_milliseconds','chunk_receipt_count',
  'chunk_receipts','chunk_receipts_verified','proof_job_index_path','proof_job_index_sha256',
]);

async function economicLayers(root) {
  const indexPath='evidence/economic-receipt-set/economic-receipt-set-index.json';
  const jobPath='evidence/economic-proof-jobs/economic-proof-job-index.json';
  const [{value:index},job]=await Promise.all([
    strictIndex(root,indexPath),privateArtifact(root,jobPath,{maximum:64*1024*1024}),
  ]);
  exact(index,economicIndexFields,'economic receipt index');
  if(index.schema!=='usdom-economic-receipt-set-v1'
      || index.proof_job_index_path!==jobPath || index.proof_job_index_sha256!==job.record.sha256
      || index.chunk_image_id!==CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID
      || index.block_image_id!==CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID
      || index.risc0_zkvm_version!=='3.0.6' || index.receipt_kind!=='succinct'
      || index.chunk_receipts_verified!==true || index.block_receipts_verified!==true
      || index.dev_mode!==false || index.generates_proofs!==true || index.mines!==false) {
    throw new Error('invalid economic receipt-set execution claims');
  }
  const build=async(kind,records,count,prefix,programSha256,imageId,wall,resident)=>{
    boundedCount(count,`${kind} receipt count`);
    if(!Array.isArray(records) || records.length!==count) throw new Error(`${kind} count mismatch`);
    let priorBlockHeight=0,priorPosition=null;
    const seenPositions=new Set();
    const artifacts=[];
    const fields=kind==='economic-chunk'
      ? ['block_height','block_index','chunk_index','expected_journal','index','receipt_bytes',
        'receipt_file','receipt_sha256','segment_index']
      : ['block_height','block_index','expected_journal','index','receipt_bytes','receipt_file',
        'receipt_sha256','segment_index'];
    for(let position=0;position<records.length;position++) {
      const record=records[position];
      const segment=boundedIndex(record.segment_index,`${kind}[${position}].segment_index`);
      const block=boundedIndex(record.block_index,`${kind}[${position}].block_index`);
      const height=boundedHeight(record.block_height,`${kind}[${position}].block_height`);
      let key=`${segment}:${block}`;
      if(kind==='economic-chunk') {
        const chunk=boundedIndex(record.chunk_index,`${kind}[${position}].chunk_index`);
        key+=`:${chunk}`;
        if(height<priorBlockHeight) throw new Error(`${kind} heights must be nondecreasing`);
        const current=[segment,block,chunk];
        if(priorPosition!==null && (current[0]<priorPosition[0]
            || (current[0]===priorPosition[0] && current[1]<priorPosition[1])
            || (current[0]===priorPosition[0] && current[1]===priorPosition[1]
              && current[2]<=priorPosition[2]))) {
          throw new Error(`${kind} positions must be canonically ordered`);
        }
        priorPosition=current;
      } else if(height<=priorBlockHeight) {
        throw new Error(`${kind} heights must be strictly ordered`);
      } else {
        const current=[segment,block];
        if(priorPosition!==null && (current[0]<priorPosition[0]
            || (current[0]===priorPosition[0] && current[1]<=priorPosition[1]))) {
          throw new Error(`${kind} positions must be canonically ordered`);
        }
        priorPosition=current;
      }
      if(seenPositions.has(key)) throw new Error(`${kind} positions must be unique`);
      seenPositions.add(key); priorBlockHeight=height;
      artifacts.push(await receiptRecord(root,'evidence/economic-receipt-set',records[position],
        position,prefix,fields));
    }
    const resources=metric({provingWallMilliseconds:String(wall),peakResidentKiB:String(resident)},kind);
    return {name:kind,programSha256,imageId,inputs:[job.record],
      journals:artifacts.map(item=>item.journal),receipts:artifacts.map(item=>item.receipt),
      receiptKind:'succinct',receiptVerified:true,segmentLimitPo2:18,
      provingWallMilliseconds:resources.provingWallMilliseconds,
      peakResidentKiB:resources.peakResidentKiB};
  };
  return [
    await build('economic-chunk',index.chunk_receipts,index.chunk_receipt_count,
      'economic-chunk-receipt-',CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256,
      CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,index.chunk_proving_wall_milliseconds,
      index.chunk_peak_resident_kib),
    await build('economic-block',index.block_receipts,index.block_receipt_count,
      'economic-block-receipt-',CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256,
      CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,index.block_proving_wall_milliseconds,
      index.block_peak_resident_kib),
  ];
}

const outerIndexFields=Object.freeze([
  ...commonIndexFields,'outer_image_id','outer_receipt_verified','proof_job_index_path',
  'proof_job_index_sha256','receipt_bytes','receipt_file','receipt_sha256','segment_receipt_count',
  'segment_receipts_verified','statement_hash',
]);

async function outerLayer(root,metrics,checkpointVerifierConfig) {
  const indexPath='evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json';
  const jobPath='evidence/checkpoint-outer-proof-job/checkpoint-outer-proof-job-index.json';
  const [receiptIndex,job]=await Promise.all([
    strictIndex(root,indexPath),privateArtifact(root,jobPath,{maximum:64*1024*1024}),
  ]);
  const index=receiptIndex.value;
  exact(index,outerIndexFields,'outer receipt index');
  const imageId=String(checkpointVerifierConfig?.checkpointGuestImageId??'').replace(/^0x/,'');
  const programSha256=String(checkpointVerifierConfig?.provingProgramSha256??'').replace(/^0x/,'');
  rawHash(imageId,'outer ImageID'); rawHash(programSha256,'outer program SHA-256');
  if(index.schema!=='usdom-checkpoint-outer-receipt-set-v1'
      || index.proof_job_index_path!==jobPath || index.proof_job_index_sha256!==job.record.sha256
      || index.outer_image_id!==imageId || index.risc0_zkvm_version!=='3.0.6'
      || index.receipt_kind!=='succinct'
      || index.segment_receipts_verified!==true || index.outer_receipt_verified!==true
      || index.dev_mode!==false || index.generates_proofs!==true || index.mines!==false
      || index.receipt_file!=='checkpoint-outer-receipt.bin') {
    throw new Error('invalid outer receipt-set execution claims');
  }
  boundedCount(index.segment_receipt_count,'outer segment receipt count');
  if(!Number.isSafeInteger(index.receipt_bytes) || index.receipt_bytes<1
      || index.receipt_bytes>maximumArtifactBytes) {
    throw new Error('outer receipt byte count is invalid');
  }
  const artifact=await privateArtifact(root,
    `evidence/checkpoint-outer-receipt-set/${index.receipt_file}`);
  if(artifact.record.sha256!==rawHash(index.receipt_sha256,'outer receipt SHA-256')
      || artifact.record.bytes!==String(index.receipt_bytes)) {
    throw new Error('outer receipt differs from its index');
  }
  const resources=metric(metrics,'outer');
  return {layer:{name:'outer',programSha256,imageId,inputs:[job.record],
    journals:[journalRecord(index.statement_hash,'outer statement hash')],receipts:[artifact.record],
    receiptKind:'succinct',receiptVerified:true,segmentLimitPo2:18,
    provingWallMilliseconds:resources.provingWallMilliseconds,
    peakResidentKiB:resources.peakResidentKiB},statementHash:'0x'+index.statement_hash,
  receiptIndex:receiptIndex.record};
}

const outerEvmIndexFields=Object.freeze([
  'dev_mode','evm_seal_bytes','evm_seal_file','evm_seal_sha256','evm_verifier_selector',
  'generates_proofs','groth16_receipt_bytes','groth16_receipt_file',
  'groth16_receipt_sha256','groth16_verifier_parameters','journal_digest','mines',
  'outer_image_id','outer_receipt_index_path','outer_receipt_index_sha256','receipt_kind',
  'receipt_verified','risc0_zkvm_version','schema','statement_hash',
]);

function boundedArtifactCount(value,label,maximum) {
  if(!Number.isSafeInteger(value) || value<1 || value>maximum) {
    throw new Error(`${label} must be a positive bounded integer`);
  }
  return value;
}

async function outerEvmArtifacts(root,indexRecord,statementHash,checkpointVerifierConfig) {
  const indexPath='evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-proof-index.json';
  const proofIndex=await strictIndex(root,indexPath);
  const statement=await privateArtifact(root,
    'evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin',{minimum:551,maximum:551});
  const groth16=await privateArtifactRecord(root,
    'evidence/checkpoint-outer-evm-proof/checkpoint-outer-groth16-receipt.bin');
  const seal=await privateArtifact(root,
    'evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-seal.bin',{maximum:64*1024});
  const sourceIndex=await privateArtifactRecord(root,
    'evidence/checkpoint-source-set/checkpoint-source-set-index.json',{maximum:64*1024*1024});
  const index=proofIndex.value;
  exact(index,outerEvmIndexFields,'outer EVM proof index');
  const imageId=String(checkpointVerifierConfig?.checkpointGuestImageId??'').replace(/^0x/,'');
  const maximumProof=Number(checkpointVerifierConfig?.maxProofBytes);
  if(maximumProof!==CHECKPOINT_EVM_SEAL_BYTES) {
    throw new Error('checkpoint maxProofBytes must be a bounded integer');
  }
  const groth16Bytes=boundedArtifactCount(index.groth16_receipt_bytes,
    'outer Groth16 receipt bytes',maximumArtifactBytes);
  const sealBytes=boundedArtifactCount(index.evm_seal_bytes,'outer EVM seal bytes',maximumProof);
  const expectedJournal=createHash('sha256')
    .update(Buffer.from(statementHash.slice(2),'hex')).digest('hex');
  if(index.schema!=='usdom-checkpoint-outer-evm-proof-v1'
      || index.outer_receipt_index_path
        !=='evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json'
      || index.outer_receipt_index_sha256!==indexRecord.sha256
      || index.outer_image_id!==imageId || index.statement_hash!==statementHash.slice(2)
      || index.journal_digest!==expectedJournal || index.risc0_zkvm_version!=='3.0.6'
      || index.receipt_kind!=='groth16'
      || index.groth16_verifier_parameters!==groth16VerifierParameters
      || index.evm_verifier_selector!==evmVerifierSelector
      || index.groth16_receipt_file!=='checkpoint-outer-groth16-receipt.bin'
      || index.evm_seal_file!=='checkpoint-outer-evm-seal.bin'
      || index.receipt_verified!==true || index.dev_mode!==false
      || index.generates_proofs!==true || index.mines!==false) {
    throw new Error('invalid outer EVM proof execution claims');
  }
  if(groth16.record.sha256!==rawHash(index.groth16_receipt_sha256,
    'outer Groth16 receipt SHA-256') || groth16.record.bytes!==String(groth16Bytes)
      || seal.record.sha256!==rawHash(index.evm_seal_sha256,'outer EVM seal SHA-256')
      || seal.record.bytes!==String(sealBytes)
      || seal.bytes.length!==CHECKPOINT_EVM_SEAL_BYTES
      || seal.bytes.subarray(0,4).toString('hex')!==evmVerifierSelector
      || statement.bytes.length!==551) {
    throw new Error('outer EVM proof artifacts differ from their index');
  }
  return Object.freeze({
    statement:statement.bytes,proofIndex:proofIndex.bytes,seal:seal.bytes,
    sourcePackageSha256:sourceIndex.record.sha256,
    outerGroth16ReceiptSha256:groth16.record.sha256,
    outerGroth16ReceiptBytes:groth16.record.bytes,
    evmSealSha256:seal.record.sha256,evmSealBytes:seal.record.bytes,
  });
}

/** Verify the exact on-disk receipt graph and return measured report layers. */
export async function collectCheckpointCapacityArtifacts(root,{metrics,checkpointVerifierConfig}) {
  const canonicalRoot=path.resolve(root);
  exact(metrics,['compression','outer','randomx','randomxAggregate','segment'],
    'checkpoint phase metrics');
  const compressionMetrics=metric(metrics.compression,'compression');
  // Each layer can contain a near-limit receipt. Capture them serially so an
  // attacker cannot multiply the bounded per-file allocation across six
  // concurrent layer readers on the constrained release host.
  const randomx=await simpleLayer(canonicalRoot,'randomx',metrics.randomx);
  const aggregate=await simpleLayer(canonicalRoot,'randomx-aggregate',metrics.randomxAggregate);
  const economic=await economicLayers(canonicalRoot);
  const segment=await simpleLayer(canonicalRoot,'segment',metrics.segment);
  const outer=await outerLayer(canonicalRoot,metrics.outer,checkpointVerifierConfig);
  const evmArtifacts=await outerEvmArtifacts(canonicalRoot,outer.receiptIndex,
    outer.statementHash,checkpointVerifierConfig);
  return Object.freeze({measuredLayers:Object.freeze([
    randomx.layer,aggregate.layer,...economic,segment.layer,outer.layer,
  ]),statementHash:outer.statementHash,compressionMetrics:Object.freeze(compressionMetrics),
  randomxVerifiedGraph:Object.freeze({receiptCount:randomx.receiptCount,
    jobIndexSha256:randomx.jobIndexSha256,receiptIndexSha256:randomx.receiptIndexSha256}),
  evmArtifacts});
}
