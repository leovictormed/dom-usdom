import {createHash} from 'node:crypto';
import {chmod,lstat,mkdir,mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  FINALIZED_BURN_EVM_SEAL_BYTES,FINALIZED_BURN_IMAGE_ID,
  buildAuthenticatedFinalizedBurnSubmission,
} from './finalized-burn-submission.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {readDirectFile} from './direct-project-file.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';

const currentUid=process.getuid();
// Succinct and Groth16 receipts use the same ceiling as their Rust decoders.
// Keeping this below the composite-only host ceiling also caps the collector's
// concurrent snapshot memory on constrained operator machines.
const maximumArtifactBytes=256*1024*1024;
const rawHashPattern=/^[0-9a-f]{64}$/;
const finalizedBurnProgramSha256=
  '883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21';
const groth16VerifierParameters=
  '73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc';
const jobFields=Object.freeze([
  'generates_proofs','image_id','image_id_file_sha256','image_id_path','input_bytes','input_file',
  'input_sha256','mines','program_path','program_sha256','receipt_file','receipt_kind',
  'relation_executed','risc0_zkvm_version','schema','source_input_path','source_input_sha256',
  'statement_hash',
]);
const receiptFields=Object.freeze([
  'dev_mode','generates_proofs','image_id','input_path','input_sha256','mines','program_path',
  'program_sha256','proof_job_index_path','proof_job_index_sha256','receipt_bytes','receipt_file',
  'receipt_kind','receipt_sha256','receipt_verified','relation_executed','risc0_zkvm_version',
  'schema','segment_limit_po2','statement_hash',
]);
const proofFields=Object.freeze([
  'dev_mode','evm_seal_bytes','evm_seal_file','evm_seal_sha256','evm_verifier_selector',
  'generates_proofs','groth16_receipt_bytes','groth16_receipt_file','groth16_receipt_sha256',
  'groth16_verifier_parameters','image_id','journal_digest','mines','receipt_index_path',
  'receipt_index_sha256','receipt_kind','receipt_verified','risc0_zkvm_version','schema',
  'statement_hash',
]);

const rawSha=value=>createHash('sha256').update(value).digest('hex');

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

function positiveCount(value,label,maximum) {
  if(!Number.isSafeInteger(value) || value<1 || value>maximum) {
    throw new Error(`${label} must be a positive bounded integer`);
  }
  return value;
}

function canonicalRoot(value) {
  if(typeof value!=='string' || !path.isAbsolute(value) || path.normalize(value)!==value
      || value===path.parse(value).root) throw new Error('workspace root must be canonical and absolute');
  return value;
}

function safeRelative(value) {
  if(typeof value!=='string' || value==='' || value.startsWith('/') || value.includes('\\')
      || value.includes('\0') || value.split('/').some(part=>part==='' || part==='.' || part==='..')) {
    throw new Error('artifact path must be canonical and relative');
  }
  return value;
}

async function privateArtifact(root,relative,{maximum=maximumArtifactBytes}={}) {
  safeRelative(relative);
  const absolute=path.resolve(root,relative);
  if(absolute===root || !absolute.startsWith(root+path.sep)) throw new Error('artifact escapes workspace');
  const rootMetadata=await lstat(root);
  if(!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink() || rootMetadata.uid!==currentUid) {
    throw new Error('unsafe finalized-burn workspace root');
  }
  let directory=root;
  for(const component of relative.split('/').slice(0,-1)) {
    directory=path.join(directory,component);
    const metadata=await lstat(directory);
    if(!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid!==currentUid
        || (metadata.mode&0o077)!==0) {
      throw new Error(`unsafe finalized-burn artifact directory: ${directory}`);
    }
  }
  const bytes=await readDirectFile(absolute,{minimum:1,maximum,privateMode:true,
    label:`finalized-burn artifact ${relative}`});
  return Object.freeze({bytes,sha256:rawSha(bytes),size:bytes.length});
}

async function strictIndex(root,relative) {
  const artifact=await privateArtifact(root,relative,{maximum:1024*1024});
  return Object.freeze({...artifact,value:parseStrictJsonBytes(artifact.bytes,{
    label:relative,maxBytes:1024*1024,maxDepth:32,
  })});
}

async function privateReplica(originRoot,catalog,expected) {
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-finalized-burn-collector.'));
  await chmod(root,0o700);
  try {
    const directories=new Set();
    for(const [relative] of catalog) {
      let directory=path.dirname(relative);
      while(directory!=='.') {
        directories.add(directory);
        directory=path.dirname(directory);
      }
    }
    for(const directory of [...directories].sort((a,b)=>a.split('/').length-b.split('/').length)) {
      const target=path.join(root,directory);
      await mkdir(target,{mode:0o700});
      await chmod(target,0o700);
    }
    for(let index=0;index<catalog.length;index++) {
      const [relative,maximum]=catalog[index];
      const artifact=await privateArtifact(originRoot,relative,{maximum});
      if(artifact.sha256!==expected[index].sha256 || artifact.size!==expected[index].size) {
        throw new Error(`finalized-burn artifact changed while capturing: ${relative}`);
      }
      await writePrivateFileDurableNew(path.join(root,relative),artifact.bytes,{
        maximum,
      });
    }
    return root;
  } catch(error) {
    await rm(root,{recursive:true,force:true});
    throw error;
  }
}

/** Validate the complete release-specific finalized-burn artifact graph on disk. */
export async function collectFinalizedBurnArtifacts(workspaceRoot,{
  reserveConfiguration,verifierConfiguration,releaseConfigSha256,verifierManifestSha256,
  beforeOriginRecheck,
}) {
  const originRoot=canonicalRoot(path.resolve(workspaceRoot));
  const prefix='labs/usdom-reserve/evidence';
  const paths=Object.freeze({
    sourceIndex:`${prefix}/finalized-burn-source/finalized-burn-source-index.json`,
    sourceInput:`${prefix}/finalized-burn-source/finalized-burn-input.bin`,
    jobIndex:`${prefix}/finalized-burn-proof-job/finalized-burn-proof-job-index.json`,
    jobInput:`${prefix}/finalized-burn-proof-job/finalized-burn-input.bin`,
    receiptIndex:`${prefix}/finalized-burn-receipt/finalized-burn-receipt-index.json`,
    receipt:`${prefix}/finalized-burn-receipt/finalized-burn-receipt.bin`,
    proofIndex:`${prefix}/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json`,
    groth16:`${prefix}/finalized-burn-evm-proof/finalized-burn-groth16-receipt.bin`,
    seal:`${prefix}/finalized-burn-evm-proof/finalized-burn-evm-seal.bin`,
    program:'crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf',
    imageId:'crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid',
  });
  const catalog=Object.freeze([
    [paths.sourceIndex,1024*1024],[paths.sourceInput,16*1024*1024],
    [paths.jobIndex,1024*1024],[paths.jobInput,16*1024*1024],
    [paths.receiptIndex,1024*1024],[paths.receipt,maximumArtifactBytes],
    [paths.proofIndex,1024*1024],[paths.groth16,maximumArtifactBytes],
    [paths.seal,64*1024],[paths.program,4*1024*1024],[paths.imageId,32],
  ]);
  if(beforeOriginRecheck!==undefined && typeof beforeOriginRecheck!=='function') {
    throw new Error('beforeOriginRecheck must be a function');
  }
  const origins=[];
  for(const [relative,maximum] of catalog) {
    const artifact=await privateArtifact(originRoot,relative,{maximum});
    origins.push(Object.freeze({relative,maximum,sha256:artifact.sha256,size:artifact.size}));
  }
  const replicaRoot=await privateReplica(originRoot,catalog,origins);
  const root=canonicalRoot(replicaRoot);
  try {
  const [sourceIndex,sourceInput,jobIndex,jobInput,receiptIndex,receipt,proofIndex,groth16,
    seal,program,imageId]=await Promise.all([
    strictIndex(root,paths.sourceIndex),privateArtifact(root,paths.sourceInput,{maximum:16*1024*1024}),
    strictIndex(root,paths.jobIndex),privateArtifact(root,paths.jobInput,{maximum:16*1024*1024}),
    strictIndex(root,paths.receiptIndex),privateArtifact(root,paths.receipt),
    strictIndex(root,paths.proofIndex),privateArtifact(root,paths.groth16),
    privateArtifact(root,paths.seal,{maximum:64*1024}),privateArtifact(root,paths.program,{maximum:4*1024*1024}),
    privateArtifact(root,paths.imageId,{maximum:32}),
  ]);
  exact(jobIndex.value,jobFields,'finalized-burn proof job index');
  exact(receiptIndex.value,receiptFields,'finalized-burn receipt index');
  exact(proofIndex.value,proofFields,'finalized-burn EVM proof index');
  const job=jobIndex.value,receiptRecord=receiptIndex.value,proof=proofIndex.value;
  const imageIdRaw=String(verifierConfiguration?.finalizedBurnGuestImageId??'').replace(/^0x/,'');
  const programSha=String(verifierConfiguration?.provingProgramSha256??'').replace(/^0x/,'');
  rawHash(imageIdRaw,'finalized-burn ImageID'); rawHash(programSha,'finalized-burn program SHA-256');
  if(imageIdRaw!==FINALIZED_BURN_IMAGE_ID.slice(2) || programSha!==finalizedBurnProgramSha256
      || imageId.size!==32
      || imageId.bytes.toString('hex')!==imageIdRaw || program.sha256!==programSha) {
    throw new Error('finalized-burn guest artifacts differ from the verifier manifest');
  }
  if(job.schema!=='usdom-finalized-burn-proof-job-v1'
      || job.source_input_path!=='evidence/finalized-burn-source/finalized-burn-input.bin'
      || job.source_input_sha256!==sourceInput.sha256 || job.input_file!=='finalized-burn-input.bin'
      || job.input_sha256!==sourceInput.sha256 || job.input_bytes!==sourceInput.size
      || jobInput.sha256!==sourceInput.sha256 || jobInput.size!==sourceInput.size
      || job.program_path!=='evidence/finalized-burn-guest/usdom-finalized-burn.elf'
      || job.program_sha256!==program.sha256
      || job.image_id_path!=='evidence/finalized-burn-guest/usdom-finalized-burn.iid'
      || job.image_id_file_sha256!==imageId.sha256 || job.image_id!==imageIdRaw
      || job.risc0_zkvm_version!=='3.0.6' || job.receipt_kind!=='succinct'
      || job.relation_executed!==true || job.generates_proofs!==false || job.mines!==false
      || job.receipt_file!=='finalized-burn-receipt.bin') {
    throw new Error('finalized-burn proof job differs from its source and pinned guest');
  }
  if(receiptRecord.schema!=='usdom-finalized-burn-receipt-v1'
      || receiptRecord.proof_job_index_path
        !=='evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json'
      || receiptRecord.proof_job_index_sha256!==jobIndex.sha256
      || receiptRecord.input_path!=='evidence/finalized-burn-proof-job/finalized-burn-input.bin'
      || receiptRecord.input_sha256!==jobInput.sha256
      || receiptRecord.program_path!=='evidence/finalized-burn-guest/usdom-finalized-burn.elf'
      || receiptRecord.program_sha256!==program.sha256 || receiptRecord.image_id!==imageIdRaw
      || receiptRecord.risc0_zkvm_version!=='3.0.6' || receiptRecord.receipt_kind!=='succinct'
      || receiptRecord.segment_limit_po2!==18
      || receiptRecord.receipt_file!=='finalized-burn-receipt.bin'
      || receiptRecord.receipt_sha256!==receipt.sha256
      || positiveCount(receiptRecord.receipt_bytes,'succinct receipt bytes',maximumArtifactBytes)!==receipt.size
      || receiptRecord.statement_hash!==job.statement_hash || receiptRecord.relation_executed!==true
      || receiptRecord.receipt_verified!==true || receiptRecord.dev_mode!==false
      || receiptRecord.generates_proofs!==true || receiptRecord.mines!==false) {
    throw new Error('finalized-burn succinct receipt differs from its proof job');
  }
  const maximumProof=Number(verifierConfiguration?.maxProofBytes);
  if(maximumProof!==FINALIZED_BURN_EVM_SEAL_BYTES) {
    throw new Error('finalized-burn maxProofBytes is invalid');
  }
  if(proof.schema!=='usdom-finalized-burn-evm-proof-v1'
      || proof.receipt_index_path
        !=='evidence/finalized-burn-receipt/finalized-burn-receipt-index.json'
      || proof.receipt_index_sha256!==receiptIndex.sha256 || proof.image_id!==imageIdRaw
      || proof.journal_digest!==rawSha(Buffer.from(job.statement_hash,'hex'))
      || proof.risc0_zkvm_version!=='3.0.6' || proof.receipt_kind!=='groth16'
      || proof.groth16_verifier_parameters!==groth16VerifierParameters
      || proof.evm_verifier_selector!=='73c457ba'
      || proof.groth16_receipt_file!=='finalized-burn-groth16-receipt.bin'
      || proof.groth16_receipt_sha256!==groth16.sha256
      || positiveCount(proof.groth16_receipt_bytes,'Groth16 receipt bytes',maximumArtifactBytes)!==groth16.size
      || proof.evm_seal_file!=='finalized-burn-evm-seal.bin'
      || proof.evm_seal_sha256!==seal.sha256
      || positiveCount(proof.evm_seal_bytes,'EVM seal bytes',maximumProof)!==seal.size
      || seal.size!==FINALIZED_BURN_EVM_SEAL_BYTES
      || seal.bytes.subarray(0,4).toString('hex')!=='73c457ba'
      || proof.statement_hash!==job.statement_hash || proof.receipt_verified!==true
      || proof.dev_mode!==false || proof.generates_proofs!==true || proof.mines!==false) {
    throw new Error('finalized-burn Groth16 artifacts differ from their receipt graph');
  }
  const submission=buildAuthenticatedFinalizedBurnSubmission({
    reserveConfiguration,verifierConfiguration,sourceIndex:sourceIndex.bytes,
    sourceInput:sourceInput.bytes,receiptIndex:receiptIndex.bytes,proofIndex:proofIndex.bytes,
    evmSeal:seal.bytes,releaseConfigSha256,verifierManifestSha256,
  });
  if(submission.statementHash.slice(2)!==job.statement_hash) {
    throw new Error('finalized-burn submission statement differs from the proof job');
  }
  if(beforeOriginRecheck) await beforeOriginRecheck();
  const currentOrigins=[];
  for(const [relative,maximum] of catalog) {
    const artifact=await privateArtifact(originRoot,relative,{maximum});
    currentOrigins.push({sha256:artifact.sha256,size:artifact.size});
  }
  if(currentOrigins.some((artifact,index)=>artifact.sha256!==origins[index].sha256
      || artifact.size!==origins[index].size)) {
    throw new Error('finalized-burn artifact origins changed during collection');
  }
  return Object.freeze({submission,sourcePackageSha256:sourceIndex.sha256,
    inputSha256:sourceInput.sha256,inputBytes:String(sourceInput.size),
    succinctReceiptSha256:receipt.sha256,succinctReceiptBytes:String(receipt.size),
    groth16ReceiptSha256:groth16.sha256,groth16ReceiptBytes:String(groth16.size),
    evmSealSha256:seal.sha256,evmSealBytes:String(seal.size),evmSeal:seal.bytes,
  });
  } finally {
    await rm(replicaRoot,{recursive:true,force:true});
  }
}
