import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmod,link,mkdir,mkdtemp,readFile,rm,symlink,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {collectCheckpointCapacityArtifacts} from '../../sdk/checkpoint-capacity-artifact-collector.mjs';
import {
  CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,
  CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,CHECKPOINT_RANDOMX_IMAGE_ID,CHECKPOINT_SEGMENT_IMAGE_ID,
} from '../../sdk/checkpoint-proof-capacity-report.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const raw=byte=>byte.repeat(32);
const metrics=()=>({randomx:{provingWallMilliseconds:'1000',peakResidentKiB:'100000'},
  randomxAggregate:{provingWallMilliseconds:'1000',peakResidentKiB:'100000'},
  segment:{provingWallMilliseconds:'1000',peakResidentKiB:'100000'},
  outer:{provingWallMilliseconds:'1000',peakResidentKiB:'100000'},
  compression:{provingWallMilliseconds:'1000',peakResidentKiB:'100000'}});

async function privateFile(root,relative,bytes) {
  const target=path.join(root,relative);
  await mkdir(path.dirname(target),{recursive:true,mode:0o700});
  await chmod(path.dirname(target),0o700);
  await writeFile(target,bytes,{mode:0o600});
  await chmod(target,0o600);
  return {sha256:hash(bytes),bytes:Buffer.byteLength(bytes)};
}

async function indexFile(root,relative,value) {
  return privateFile(root,relative,JSON.stringify(value,null,2)+'\n');
}

async function receipt(root,directory,name,contents) {
  const artifact=await privateFile(root,`${directory}/${name}`,Buffer.from(contents));
  return {receipt_file:name,receipt_sha256:artifact.sha256,receipt_bytes:artifact.bytes};
}

async function fixture() {
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-checkpoint-capacity-'));
  await chmod(root,0o700);
  const jobs={};
  for(const [name,relative] of Object.entries({
    randomx:'evidence/randomx-proof-jobs/randomx-proof-job-index.json',
    aggregate:'evidence/randomx-aggregate-jobs/randomx-aggregate-job-index.json',
    economic:'evidence/economic-proof-jobs/economic-proof-job-index.json',
    segment:'evidence/checkpoint-segment-proof-jobs/checkpoint-segment-proof-job-index.json',
    outer:'evidence/checkpoint-outer-proof-job/checkpoint-outer-proof-job-index.json',
  })) jobs[name]=await privateFile(root,relative,Buffer.from(`job-${name}`));

  const randomxReceipt=await receipt(root,'evidence/randomx-receipt-set',
    'randomx-receipt-0000.bin','randomx-receipt');
  await indexFile(root,'evidence/randomx-receipt-set/randomx-receipt-set-index.json',{
    schema:'usdom-randomx-receipt-set-v1',
    proof_job_index_path:'evidence/randomx-proof-jobs/randomx-proof-job-index.json',
    proof_job_index_sha256:jobs.randomx.sha256,manifest_sha256:raw('11'),
    randomx_receipt_image_id:CHECKPOINT_RANDOMX_IMAGE_ID,randomx_user_elf_sha256:raw('12'),
    risc0_zkvm_version:'3.0.6',receipt_kind:'succinct',previous_height:100000,
    target_height:100360,confirmation_height:100390,segment_count:1,receipt_count:1,
    randomx_relations_executed:true,receipts_verified:true,dev_mode:false,
    generates_proofs:true,mines:false,receipts:[{index:0,segment_index:0,block_index:0,
      block_height:100001,statement_sha256:raw('13'),expected_journal:raw('14'),...randomxReceipt}],
  });

  const aggregateReceipt=await receipt(root,'evidence/randomx-aggregate-receipt-set',
    'randomx-aggregate-receipt-0000.bin','aggregate-receipt');
  await indexFile(root,
    'evidence/randomx-aggregate-receipt-set/randomx-aggregate-receipt-set-index.json',{
      schema:'usdom-randomx-aggregate-receipt-set-v1',
      aggregate_job_index_path:'evidence/randomx-aggregate-jobs/randomx-aggregate-job-index.json',
      aggregate_job_index_sha256:jobs.aggregate.sha256,
      aggregate_image_id:CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,risc0_zkvm_version:'3.0.6',
      receipt_kind:'succinct',receipt_count:1,inner_receipts_verified:true,
      aggregate_receipts_verified:true,dev_mode:false,generates_proofs:true,mines:false,
      receipts:[{index:0,previous_height:100000,next_height:100360,block_count:360,
        expected_journal:raw('15'),...aggregateReceipt}],
    });

  const chunkReceipt=await receipt(root,'evidence/economic-receipt-set',
    'economic-chunk-receipt-0000.bin','chunk-receipt');
  const blockReceipt=await receipt(root,'evidence/economic-receipt-set',
    'economic-block-receipt-0000.bin','block-receipt');
  await indexFile(root,'evidence/economic-receipt-set/economic-receipt-set-index.json',{
    schema:'usdom-economic-receipt-set-v1',
    proof_job_index_path:'evidence/economic-proof-jobs/economic-proof-job-index.json',
    proof_job_index_sha256:jobs.economic.sha256,chunk_image_id:CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,
    block_image_id:CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,risc0_zkvm_version:'3.0.6',
    receipt_kind:'succinct',chunk_receipt_count:1,block_receipt_count:1,
    chunk_proving_wall_milliseconds:1000,chunk_peak_resident_kib:100000,
    block_proving_wall_milliseconds:1000,block_peak_resident_kib:100000,
    chunk_receipts_verified:true,block_receipts_verified:true,dev_mode:false,
    generates_proofs:true,mines:false,chunk_receipts:[{index:0,segment_index:0,block_index:0,
      chunk_index:0,block_height:100001,expected_journal:raw('16'),...chunkReceipt}],
    block_receipts:[{index:0,segment_index:0,block_index:0,block_height:100001,
      expected_journal:raw('17'),...blockReceipt}],
  });

  const segmentReceipt=await receipt(root,'evidence/checkpoint-segment-receipt-set',
    'checkpoint-segment-receipt-0000.bin','segment-receipt');
  await indexFile(root,
    'evidence/checkpoint-segment-receipt-set/checkpoint-segment-receipt-set-index.json',{
      schema:'usdom-checkpoint-segment-receipt-set-v1',
      proof_job_index_path:'evidence/checkpoint-segment-proof-jobs/checkpoint-segment-proof-job-index.json',
      proof_job_index_sha256:jobs.segment.sha256,segment_image_id:CHECKPOINT_SEGMENT_IMAGE_ID,
      risc0_zkvm_version:'3.0.6',receipt_kind:'succinct',receipt_count:1,
      inner_receipts_verified:true,segment_receipts_verified:true,dev_mode:false,
      generates_proofs:true,mines:false,receipts:[{index:0,previous_height:100000,
        next_height:100390,block_count:390,expected_journal:raw('18'),...segmentReceipt}],
    });

  const outerReceipt=await receipt(root,'evidence/checkpoint-outer-receipt-set',
    'checkpoint-outer-receipt.bin','outer-receipt');
  const outerImage=raw('19'),outerProgram=raw('1a'),statementHash=raw('1b');
  const outerIndex=await indexFile(root,
    'evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json',{
      schema:'usdom-checkpoint-outer-receipt-set-v1',
      proof_job_index_path:'evidence/checkpoint-outer-proof-job/checkpoint-outer-proof-job-index.json',
      proof_job_index_sha256:jobs.outer.sha256,outer_image_id:outerImage,statement_hash:statementHash,
      risc0_zkvm_version:'3.0.6',receipt_kind:'succinct',segment_receipt_count:1,
      segment_receipts_verified:true,outer_receipt_verified:true,dev_mode:false,
      generates_proofs:true,mines:false,...outerReceipt,
    });
  await privateFile(root,'evidence/checkpoint-source-set/checkpoint-source-set-index.json',
    Buffer.from('checkpoint-source-index'));
  const statement=Buffer.alloc(551,0x22);
  await privateFile(root,'evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin',statement);
  const groth16=await privateFile(root,
    'evidence/checkpoint-outer-evm-proof/checkpoint-outer-groth16-receipt.bin',
    Buffer.from('groth16-receipt'));
  const sealBytes=Buffer.concat([Buffer.from('73c457ba','hex'),Buffer.alloc(256,1)]);
  const seal=await privateFile(root,
    'evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-seal.bin',sealBytes);
  await indexFile(root,
    'evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-proof-index.json',{
      schema:'usdom-checkpoint-outer-evm-proof-v1',
      outer_receipt_index_path:
        'evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json',
      outer_receipt_index_sha256:outerIndex.sha256,outer_image_id:outerImage,
      statement_hash:statementHash,
      journal_digest:hash(Buffer.from(statementHash,'hex')),risc0_zkvm_version:'3.0.6',
      receipt_kind:'groth16',
      groth16_verifier_parameters:
        '73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc',
      evm_verifier_selector:'73c457ba',
      groth16_receipt_file:'checkpoint-outer-groth16-receipt.bin',
      groth16_receipt_sha256:groth16.sha256,groth16_receipt_bytes:groth16.bytes,
      evm_seal_file:'checkpoint-outer-evm-seal.bin',evm_seal_sha256:seal.sha256,
      evm_seal_bytes:seal.bytes,receipt_verified:true,dev_mode:false,
      generates_proofs:true,mines:false,
    });
  return {root,checkpointVerifierConfig:{checkpointGuestImageId:'0x'+outerImage,
    provingProgramSha256:'0x'+outerProgram,maxProofBytes:'260'},statementHash};
}

test('collector verifies private on-disk receipt graph and returns six measured layers',async t=>{
  const value=await fixture(); t.after(()=>rm(value.root,{recursive:true,force:true}));
  const collected=await collectCheckpointCapacityArtifacts(value.root,{
    metrics:metrics(),checkpointVerifierConfig:value.checkpointVerifierConfig,
  });
  assert.deepEqual(collected.measuredLayers.map(layer=>layer.name),[
    'randomx','randomx-aggregate','economic-chunk','economic-block','segment','outer',
  ]);
  assert.equal(collected.statementHash,'0x'+value.statementHash);
  assert.equal(collected.measuredLayers[2].provingWallMilliseconds,'1000');
  assert.equal(collected.measuredLayers[0].inputs.length,2);
  assert.equal(collected.randomxVerifiedGraph.receiptCount,1);
  assert.match(collected.randomxVerifiedGraph.jobIndexSha256,/^[0-9a-f]{64}$/);
  assert.match(collected.randomxVerifiedGraph.receiptIndexSha256,/^[0-9a-f]{64}$/);
  assert.equal(collected.compressionMetrics.provingWallMilliseconds,'1000');
  assert.equal(collected.evmArtifacts.statement.length,551);
  assert.equal(collected.evmArtifacts.seal.subarray(0,4).toString('hex'),'73c457ba');
});

test('collector rejects a legacy 550-byte V5 statement at the current artifact path',async t=>{
  const value=await fixture(); t.after(()=>rm(value.root,{recursive:true,force:true}));
  await privateFile(value.root,
    'evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin',Buffer.alloc(550,0x22));
  await assert.rejects(()=>collectCheckpointCapacityArtifacts(value.root,{
    metrics:metrics(),checkpointVerifierConfig:value.checkpointVerifierConfig,
  }),/not a safe direct regular file/);
});

test('collector rejects receipt substitution, extra fields and public permissions',async t=>{
  const substitutions=[
    async value=>writeFile(path.join(value.root,
      'evidence/randomx-receipt-set/randomx-receipt-0000.bin'),'substituted'),
    async value=>{
      const target=path.join(value.root,
        'evidence/randomx-aggregate-receipt-set/randomx-aggregate-receipt-set-index.json');
      const parsed=JSON.parse(await readFile(target,'utf8')); parsed.extra=true;
      await writeFile(target,JSON.stringify(parsed),{mode:0o600});
    },
    async value=>chmod(path.join(value.root,
      'evidence/checkpoint-segment-receipt-set/checkpoint-segment-receipt-0000.bin'),0o644),
    async value=>writeFile(path.join(value.root,
      'evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-seal.bin'),'substituted'),
  ];
  for(const mutate of substitutions) {
    const value=await fixture(); t.after(()=>rm(value.root,{recursive:true,force:true}));
    await mutate(value);
    await assert.rejects(()=>collectCheckpointCapacityArtifacts(value.root,{
      metrics:metrics(),checkpointVerifierConfig:value.checkpointVerifierConfig,
    }));
  }
});

test('collector rejects indirect checkpoint artifacts with valid bytes',async t=>{
  const relative='evidence/randomx-receipt-set/randomx-receipt-0000.bin';
  for(const kind of ['symlink','hardlink']) {
    const value=await fixture(); t.after(()=>rm(value.root,{recursive:true,force:true}));
    const target=path.join(value.root,relative);
    const copy=path.join(value.root,`valid-${kind}-receipt.bin`);
    await writeFile(copy,await readFile(target),{mode:0o600});
    await rm(target);
    if(kind==='symlink') await symlink(copy,target);
    else await link(copy,target);
    await assert.rejects(()=>collectCheckpointCapacityArtifacts(value.root,{
      metrics:metrics(),checkpointVerifierConfig:value.checkpointVerifierConfig,
    }),/not a safe direct regular file/);
  }
});

test('collector rejects noncanonical receipt metadata before artifact loops',async t=>{
  const mutations=[
    ['evidence/randomx-receipt-set/randomx-receipt-set-index.json',
      value=>{ value.receipts[0].block_height=0; }],
    ['evidence/randomx-aggregate-receipt-set/randomx-aggregate-receipt-set-index.json',
      value=>{ value.receipts[0].block_count=359; }],
    ['evidence/economic-receipt-set/economic-receipt-set-index.json',
      value=>{ value.chunk_receipts[0].chunk_index=-1; }],
  ];
  for(const [relative,mutate] of mutations) {
    const value=await fixture(); t.after(()=>rm(value.root,{recursive:true,force:true}));
    const target=path.join(value.root,relative),index=JSON.parse(await readFile(target,'utf8'));
    mutate(index); await writeFile(target,JSON.stringify(index,null,2)+'\n',{mode:0o600});
    await assert.rejects(()=>collectCheckpointCapacityArtifacts(value.root,{
      metrics:metrics(),checkpointVerifierConfig:value.checkpointVerifierConfig,
    }));
  }
});

test('collector rejects ambiguous checkpoint index bytes before graph authority',async t=>{
  const relative='evidence/randomx-receipt-set/randomx-receipt-set-index.json';
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) {
    const value=await fixture(); t.after(()=>rm(value.root,{recursive:true,force:true}));
    await privateFile(value.root,relative,bytes);
    await assert.rejects(()=>collectCheckpointCapacityArtifacts(value.root,{
      metrics:metrics(),checkpointVerifierConfig:value.checkpointVerifierConfig,
    }),/duplicate (?:object )?key|invalid UTF-8/);
  }
});

test('checkpoint index authority uses the byte-strict JSON boundary',async()=>{
  const source=await readFile(new URL('../../sdk/checkpoint-capacity-artifact-collector.mjs',
    import.meta.url),'utf8');
  assert.match(source,/parseStrictJsonBytes\(artifact\.bytes/);
  assert.doesNotMatch(source,/artifact\.bytes\.toString\(['"]utf8['"]\)/);
});
