import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmod,copyFile,link,mkdir,mkdtemp,readFile,rm,symlink,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {sha256} from 'ethers';
import {collectFinalizedBurnArtifacts} from '../../sdk/finalized-burn-artifact-collector.mjs';
import {
  FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS,FINALIZED_BURN_IMAGE_ID,
} from '../../sdk/finalized-burn-submission.mjs';
import {
  BURN_INTENT_TYPEHASH,BURN_STATEMENT_TYPEHASH,PRIVATE_BURN_ID_TYPEHASH,
  finalizedBurnStatementHash,
} from '../../sdk/proof-reserve.mjs';
import {
  FINALIZED_BURN_PROOF_SYSTEM,FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
  FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,VERIFIER_CONFIG_SCHEMA,
  finalizedBurnVerifierConfigHash,
} from '../../sdk/verifier-config.mjs';

const hash=byte=>'0x'+byte.toString(16).padStart(2,'0').repeat(32);
const rawSha=bytes=>createHash('sha256').update(bytes).digest('hex');
const zero=hash(0);
const programSource=new URL(
  '../../../../crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf',
  import.meta.url,
);
const imageIdSource=new URL(
  '../../../../crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid',
  import.meta.url,
);

async function privateDirectory(root,relative) {
  const target=path.join(root,relative);
  await mkdir(target,{recursive:true,mode:0o700});
  for(let current=target;current.startsWith(root) && current!==path.dirname(root);
    current=path.dirname(current)) await chmod(current,0o700);
  return target;
}

async function privateFile(root,relative,bytes) {
  await privateDirectory(root,path.dirname(relative));
  const target=path.join(root,relative);
  await writeFile(target,bytes,{mode:0o600});
  await chmod(target,0o600);
  return target;
}

async function fixture() {
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-finalized-collector-'));
  await chmod(root,0o700);
  const reserveConfiguration={
    ethereumChainId:'1',reserve:'0x0000000000000000000000000000000000000020',
    token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',tokenCodeHash:hash(21),
    verifier:'0x0000000000000000000000000000000000000021',verifierCodeHash:hash(22),
    verifierConfigHash:zero,
    checkpointRegistry:'0x0000000000000000000000000000000000000024',
    checkpointRegistryRuntimeCodeHash:hash(27),checkpointRegistryConfigHash:hash(28),
    domDomain:hash(23),activationScheduleCommitment:hash(24),
    governance:'0x0000000000000000000000000000000000000022',governanceCodeHash:hash(25),
    governanceImplementation:'0x0000000000000000000000000000000000000022',
    governanceImplementationCodeHash:hash(25),
    governanceOwnersCommitment:hash(35),
    guardian:'0x0000000000000000000000000000000000000023',guardianCodeHash:hash(26),
    guardianImplementation:'0x0000000000000000000000000000000000000023',
    guardianImplementationCodeHash:hash(26),
    guardianOwnersCommitment:hash(36),
    withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',
    maxOutstandingBaseUnits:'100000000000',outflowCapacityBaseUnitsPerDay:'2000000000',
  };
  const verifierConfiguration={
    schema:VERIFIER_CONFIG_SCHEMA,statementVersion:'1',transitionCommitmentVersion:'2',
    burnStateWitnessVersion:'3',finalizedBurnProverInputVersion:'2',publicOutputVersion:'1',
    burnStatementTypeHash:BURN_STATEMENT_TYPEHASH,burnIntentTypeHash:BURN_INTENT_TYPEHASH,
    privateBurnIdTypeHash:PRIVATE_BURN_ID_TYPEHASH,
    activationScheduleCommitment:reserveConfiguration.activationScheduleCommitment,
    domGenesisHash:hash(2),domNetworkMagic:'2712847316',domChainId:hash(3),firstV4Height:'100000',
    activationEmptyStateRoot:hash(16),consensusRulesHash:hash(4),forkChoiceRulesHash:hash(5),
    powRulesHash:hash(6),nativeAssetId:hash(7),noteTreeRulesHash:hash(8),nullifierRulesHash:hash(9),
    balanceRulesHash:hash(10),finalityRulesHash:hash(11),proofSystem:FINALIZED_BURN_PROOF_SYSTEM,
    verifyingKeySha256:hash(12),trustedSetupRequired:true,trustedSetupTranscriptSha256:hash(19),
    provingProgramSha256:'0x883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21',
    sourceManifestSha256:hash(14),verifierArtifactSha256:hash(15),maxProofBytes:'260',
    minimumFinalityBeaconSlot:'12000000',ethereumChainId:'1',
    riscZeroVerifier:'0x0000000000000000000000000000000000000010',riscZeroVerifierCodeHash:hash(17),
    riscZeroVerifierSelector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
    finalizedBurnGuestImageId:FINALIZED_BURN_IMAGE_ID,
    journalSchemaHash:FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,
  };
  reserveConfiguration.verifierConfigHash=
    finalizedBurnVerifierConfigHash(verifierConfiguration).verifierConfigHash;
  const burn={burnId:hash(31),requestId:hash(32),
    recipient:'0x0000000000000000000000000000000000000030',amount:'1000000',
    domDomain:reserveConfiguration.domDomain,height:'100360',blockHash:hash(33),stateRoot:hash(34),
    finalityBeaconSlot:'16000010',validUntil:'1800000000'};
  const statementHash=finalizedBurnStatementHash({chainId:'1',reserve:reserveConfiguration.reserve,
    activationScheduleCommitment:reserveConfiguration.activationScheduleCommitment,burn});
  const sourceInput=Buffer.from('canonical UDFINL04 collector fixture');
  const sourceIndex=Buffer.from(JSON.stringify({schema:'usdom-finalized-burn-source-v3',
    network:'mainnet',manifest_sha256:'35'.repeat(32),candidate_v2_first_height:100000,
    burn_id:burn.burnId.slice(2),checkpoint_dom_height:100360,
    checkpoint_dom_block:burn.blockHash.slice(2),checkpoint_dom_state_root:burn.stateRoot.slice(2),
    checkpoint_ethereum_block_number:20000010,checkpoint_ethereum_block:'38'.repeat(32),
    checkpoint_beacon_slot:16000010,checkpoint_witness_sha256:'39'.repeat(32),
    statement_hash:statementHash.slice(2),burn,ethereum_chain_id:'1',
    reserve:reserveConfiguration.reserve,
    activation_schedule_commitment:reserveConfiguration.activationScheduleCommitment,
    input_file:'finalized-burn-input.bin',input_sha256:rawSha(sourceInput),
    input_length:sourceInput.length},null,2)+'\n');
  const program=await readFile(programSource),imageId=await readFile(imageIdSource);
  const jobIndex=Buffer.from(JSON.stringify({schema:'usdom-finalized-burn-proof-job-v1',
    source_input_path:'evidence/finalized-burn-source/finalized-burn-input.bin',
    source_input_sha256:rawSha(sourceInput),input_file:'finalized-burn-input.bin',
    input_sha256:rawSha(sourceInput),input_bytes:sourceInput.length,statement_hash:statementHash.slice(2),
    program_path:'evidence/finalized-burn-guest/usdom-finalized-burn.elf',
    program_sha256:rawSha(program),
    image_id_path:'evidence/finalized-burn-guest/usdom-finalized-burn.iid',
    image_id_file_sha256:rawSha(imageId),image_id:imageId.toString('hex'),risc0_zkvm_version:'3.0.6',
    receipt_kind:'succinct',relation_executed:true,generates_proofs:false,mines:false,
    receipt_file:'finalized-burn-receipt.bin'},null,2)+'\n');
  const receipt=Buffer.from('verified succinct receipt fixture');
  const receiptIndex=Buffer.from(JSON.stringify({schema:'usdom-finalized-burn-receipt-v1',
    proof_job_index_path:'evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json',
    proof_job_index_sha256:rawSha(jobIndex),
    input_path:'evidence/finalized-burn-proof-job/finalized-burn-input.bin',
    input_sha256:rawSha(sourceInput),statement_hash:statementHash.slice(2),
    program_path:'evidence/finalized-burn-guest/usdom-finalized-burn.elf',
    program_sha256:rawSha(program),image_id:imageId.toString('hex'),risc0_zkvm_version:'3.0.6',
    receipt_kind:'succinct',segment_limit_po2:18,receipt_file:'finalized-burn-receipt.bin',
    receipt_sha256:rawSha(receipt),receipt_bytes:receipt.length,relation_executed:true,
    receipt_verified:true,dev_mode:false,generates_proofs:true,mines:false},null,2)+'\n');
  const groth16=Buffer.from('verified Groth16 receipt fixture');
  const seal=Buffer.concat([
    Buffer.from(FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2),'hex'),Buffer.alloc(256,1),
  ]);
  const proofIndex=Buffer.from(JSON.stringify({schema:'usdom-finalized-burn-evm-proof-v1',
    receipt_index_path:'evidence/finalized-burn-receipt/finalized-burn-receipt-index.json',
    receipt_index_sha256:rawSha(receiptIndex),image_id:imageId.toString('hex'),
    statement_hash:statementHash.slice(2),journal_digest:sha256(statementHash).slice(2),
    risc0_zkvm_version:'3.0.6',receipt_kind:'groth16',
    groth16_verifier_parameters:FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS.slice(2),
    evm_verifier_selector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2),
    groth16_receipt_file:'finalized-burn-groth16-receipt.bin',
    groth16_receipt_sha256:rawSha(groth16),groth16_receipt_bytes:groth16.length,
    evm_seal_file:'finalized-burn-evm-seal.bin',evm_seal_sha256:rawSha(seal),
    evm_seal_bytes:seal.length,receipt_verified:true,dev_mode:false,generates_proofs:true,
    mines:false},null,2)+'\n');
  const files={
    'labs/usdom-reserve/evidence/finalized-burn-source/finalized-burn-source-index.json':sourceIndex,
    'labs/usdom-reserve/evidence/finalized-burn-source/finalized-burn-input.bin':sourceInput,
    'labs/usdom-reserve/evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json':jobIndex,
    'labs/usdom-reserve/evidence/finalized-burn-proof-job/finalized-burn-input.bin':sourceInput,
    'labs/usdom-reserve/evidence/finalized-burn-receipt/finalized-burn-receipt-index.json':receiptIndex,
    'labs/usdom-reserve/evidence/finalized-burn-receipt/finalized-burn-receipt.bin':receipt,
    'labs/usdom-reserve/evidence/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json':proofIndex,
    'labs/usdom-reserve/evidence/finalized-burn-evm-proof/finalized-burn-groth16-receipt.bin':groth16,
    'labs/usdom-reserve/evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin':seal,
  };
  for(const [relative,bytes] of Object.entries(files)) await privateFile(root,relative,bytes);
  for(const [source,relative] of [[programSource,'crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf'],
    [imageIdSource,'crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid']]) {
    const target=path.join(root,relative); await privateDirectory(root,path.dirname(relative));
    await copyFile(source,target); await chmod(target,0o600);
  }
  return {root,reserveConfiguration,verifierConfiguration,files};
}

async function collect(f) {
  return collectFinalizedBurnArtifacts(f.root,{reserveConfiguration:f.reserveConfiguration,
    verifierConfiguration:f.verifierConfiguration,releaseConfigSha256:'51'.repeat(32),
    verifierManifestSha256:
      finalizedBurnVerifierConfigHash(f.verifierConfiguration).manifestSha256.slice(2)});
}

async function mutateIndex(root,relative,change) {
  const target=path.join(root,relative);
  const value=JSON.parse(await readFile(target,'utf8'));
  change(value);
  await writeFile(target,JSON.stringify(value,null,2)+'\n',{mode:0o600});
  await chmod(target,0o600);
  return rawSha(await readFile(target));
}

test('collector binds the complete private finalized-burn receipt graph',async()=>{
  const f=await fixture();
  try {
    const result=await collect(f);
    assert.equal(result.submission.broadcastAuthorized,false);
    assert.equal(result.evmSealSha256,result.submission.proof.sha256);
    assert.equal(result.inputBytes,String(f.files[
      'labs/usdom-reserve/evidence/finalized-burn-source/finalized-burn-input.bin'].length));
  } finally { await rm(f.root,{recursive:true,force:true}); }
});

test('collector rejects substituted artifacts and public permissions',async()=>{
  for(const mutate of [
    async f=>privateFile(f.root,
      'labs/usdom-reserve/evidence/finalized-burn-receipt/finalized-burn-receipt.bin',
      Buffer.from('substituted')),
    async f=>chmod(path.join(f.root,
      'labs/usdom-reserve/evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin'),0o644),
  ]) {
    const f=await fixture();
    try { await mutate(f); await assert.rejects(()=>collect(f)); }
    finally { await rm(f.root,{recursive:true,force:true}); }
  }
});

test('collector rejects false receipt and Groth16 verification metadata',async()=>{
  const receiptRelative=
    'labs/usdom-reserve/evidence/finalized-burn-receipt/finalized-burn-receipt-index.json';
  const proofRelative=
    'labs/usdom-reserve/evidence/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json';
  for(const mutate of [
    async f=>{
      const receiptHash=await mutateIndex(f.root,receiptRelative,value=>{
        value.receipt_verified=false;
      });
      await mutateIndex(f.root,proofRelative,value=>{ value.receipt_index_sha256=receiptHash; });
    },
    async f=>mutateIndex(f.root,receiptRelative,value=>{ value.receipt_kind='fake'; }),
    async f=>mutateIndex(f.root,proofRelative,value=>{ value.receipt_verified=false; }),
    async f=>mutateIndex(f.root,proofRelative,value=>{ value.groth16_verifier_parameters='01'.repeat(32); }),
  ]) {
    const f=await fixture();
    try { await mutate(f); await assert.rejects(()=>collect(f)); }
    finally { await rm(f.root,{recursive:true,force:true}); }
  }
});

test('collector rejects indirect finalized-burn artifacts with valid bytes',async()=>{
  const relative='labs/usdom-reserve/evidence/finalized-burn-receipt/finalized-burn-receipt.bin';
  for(const kind of ['symlink','hardlink']) {
    const f=await fixture();
    try {
      const target=path.join(f.root,relative),copy=path.join(f.root,`valid-${kind}-receipt.bin`);
      await writeFile(copy,await readFile(target),{mode:0o600});
      await rm(target);
      if(kind==='symlink') await symlink(copy,target);
      else await link(copy,target);
      await assert.rejects(()=>collect(f),/not a safe direct regular file/);
    } finally { await rm(f.root,{recursive:true,force:true}); }
  }
});

test('collector rejects origin mutation after its private replica is complete',async()=>{
  const f=await fixture();
  const relative='labs/usdom-reserve/evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin';
  try {
    await assert.rejects(()=>collectFinalizedBurnArtifacts(f.root,{
      reserveConfiguration:f.reserveConfiguration,verifierConfiguration:f.verifierConfiguration,
      releaseConfigSha256:'51'.repeat(32),
      verifierManifestSha256:
        finalizedBurnVerifierConfigHash(f.verifierConfiguration).manifestSha256.slice(2),
      beforeOriginRecheck:async()=>writeFile(path.join(f.root,relative),Buffer.alloc(260,7)),
    }),/origins changed during collection/);
  } finally { await rm(f.root,{recursive:true,force:true}); }
});

test('collector rejects ambiguous finalized-burn index bytes before authority',async()=>{
  const relative='labs/usdom-reserve/evidence/finalized-burn-source/finalized-burn-source-index.json';
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) {
    const f=await fixture();
    try {
      await privateFile(f.root,relative,bytes);
      await assert.rejects(()=>collect(f),/duplicate (?:object )?key|invalid UTF-8/);
    } finally { await rm(f.root,{recursive:true,force:true}); }
  }
});

test('finalized-burn index authority uses the byte-strict JSON boundary',async()=>{
  const source=await readFile(new URL('../../sdk/finalized-burn-artifact-collector.mjs',
    import.meta.url),'utf8');
  assert.match(source,/parseStrictJsonBytes\(artifact\.bytes/);
  assert.doesNotMatch(source,/artifact\.bytes\.toString\(['"]utf8['"]\)/);
});
