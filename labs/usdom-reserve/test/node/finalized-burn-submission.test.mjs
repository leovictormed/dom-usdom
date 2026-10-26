import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sha256} from 'ethers';
import {
  FINALIZED_BURN_EVM_SEAL_BYTES,FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS,
  FINALIZED_BURN_IMAGE_ID,
  buildAuthenticatedFinalizedBurnSubmission,validateAuthenticatedFinalizedBurnSubmission,
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
const rawHash=bytes=>createHash('sha256').update(bytes).digest('hex');
const zero=hash(0);

function fixture() {
  const reserveConfiguration={
    ethereumChainId:'1',reserve:'0x0000000000000000000000000000000000000020',
    token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',tokenCodeHash:hash(21),
    verifier:'0x0000000000000000000000000000000000000021',verifierCodeHash:hash(22),
    verifierConfigHash:zero,checkpointRegistry:'0x0000000000000000000000000000000000000024',
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
    sourceManifestSha256:hash(14),verifierArtifactSha256:hash(15),
    maxProofBytes:'260',minimumFinalityBeaconSlot:'12000000',ethereumChainId:'1',
    riscZeroVerifier:'0x0000000000000000000000000000000000000010',
    riscZeroVerifierCodeHash:hash(17),
    riscZeroVerifierSelector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
    finalizedBurnGuestImageId:FINALIZED_BURN_IMAGE_ID,
    journalSchemaHash:FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,
  };
  reserveConfiguration.verifierConfigHash=
    finalizedBurnVerifierConfigHash(verifierConfiguration).verifierConfigHash;
  const burn={
    burnId:hash(31),requestId:hash(32),recipient:'0x0000000000000000000000000000000000000030',
    amount:'1000000',domDomain:reserveConfiguration.domDomain,height:'100360',blockHash:hash(33),
    stateRoot:hash(34),finalityBeaconSlot:'16000010',validUntil:'1800000000',
  };
  const statementHash=finalizedBurnStatementHash({
    chainId:'1',reserve:reserveConfiguration.reserve,
    activationScheduleCommitment:reserveConfiguration.activationScheduleCommitment,burn,
  });
  const sourceInput=Buffer.from('canonical UDFINL04 fixture');
  const sourceIndex=Buffer.from(JSON.stringify({
    schema:'usdom-finalized-burn-source-v3',network:'mainnet',manifest_sha256:'35'.repeat(32),
    candidate_v2_first_height:100000,burn_id:burn.burnId.slice(2),checkpoint_dom_height:100360,
    checkpoint_dom_block:burn.blockHash.slice(2),checkpoint_dom_state_root:burn.stateRoot.slice(2),
    checkpoint_ethereum_block_number:20000010,checkpoint_ethereum_block:'38'.repeat(32),
    checkpoint_beacon_slot:16000010,checkpoint_witness_sha256:'39'.repeat(32),
    statement_hash:statementHash.slice(2),burn,ethereum_chain_id:'1',
    reserve:reserveConfiguration.reserve,
    activation_schedule_commitment:reserveConfiguration.activationScheduleCommitment,
    input_file:'finalized-burn-input.bin',input_sha256:rawHash(sourceInput),input_length:sourceInput.length,
  },null,2)+'\n');
  const receiptIndex=Buffer.from(JSON.stringify({
    schema:'usdom-finalized-burn-receipt-v1',
    proof_job_index_path:'evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json',
    proof_job_index_sha256:'40'.repeat(32),
    input_path:'evidence/finalized-burn-proof-job/finalized-burn-input.bin',
    input_sha256:rawHash(sourceInput),statement_hash:statementHash.slice(2),
    program_path:'evidence/finalized-burn-guest/usdom-finalized-burn.elf',
    program_sha256:'883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21',
    image_id:FINALIZED_BURN_IMAGE_ID.slice(2),risc0_zkvm_version:'3.0.6',receipt_kind:'succinct',
    segment_limit_po2:18,receipt_file:'finalized-burn-receipt.bin',receipt_sha256:'41'.repeat(32),
    receipt_bytes:4096,relation_executed:true,receipt_verified:true,dev_mode:false,
    generates_proofs:true,mines:false,
  },null,2)+'\n');
  const evmSeal=Buffer.concat([
    Buffer.from(FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2),'hex'),Buffer.alloc(256,1),
  ]);
  const proofIndex=Buffer.from(JSON.stringify({
    schema:'usdom-finalized-burn-evm-proof-v1',
    receipt_index_path:'evidence/finalized-burn-receipt/finalized-burn-receipt-index.json',
    receipt_index_sha256:rawHash(receiptIndex),image_id:FINALIZED_BURN_IMAGE_ID.slice(2),
    statement_hash:statementHash.slice(2),journal_digest:sha256(statementHash).slice(2),
    risc0_zkvm_version:'3.0.6',receipt_kind:'groth16',
    groth16_verifier_parameters:FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS.slice(2),
    evm_verifier_selector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2),
    groth16_receipt_file:'finalized-burn-groth16-receipt.bin',
    groth16_receipt_sha256:'42'.repeat(32),groth16_receipt_bytes:1024,
    evm_seal_file:'finalized-burn-evm-seal.bin',evm_seal_sha256:rawHash(evmSeal),
    evm_seal_bytes:evmSeal.length,receipt_verified:true,dev_mode:false,generates_proofs:true,mines:false,
  },null,2)+'\n');
  return {reserveConfiguration,verifierConfiguration,sourceIndex,sourceInput,receiptIndex,proofIndex,
    evmSeal,statementHash,burn};
}

test('authenticated finalized-burn artifacts produce canonical unsigned reserve calldata',()=>{
  const f=fixture();
  const submission=buildAuthenticatedFinalizedBurnSubmission(f);
  const parsed=validateAuthenticatedFinalizedBurnSubmission(submission);
  assert.equal(submission.broadcastAuthorized,false);
  assert.equal(submission.method,'queueWithdrawal');
  assert.equal(submission.statementHash,f.statementHash);
  assert.equal(submission.proof.selector,FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR);
  assert.equal(parsed.burn.burnId,f.burn.burnId);
  assert.deepEqual(Buffer.from(parsed.proof),f.evmSeal);
});

test('submission construction rejects substitutions across every authenticated handoff',()=>{
  for(const mutate of [
    f=>{f.sourceInput=Buffer.from('changed');},
    f=>{const o=JSON.parse(f.sourceIndex);o.burn.amount='1000001';f.sourceIndex=Buffer.from(JSON.stringify(o)+'\n');},
    f=>{const o=JSON.parse(f.receiptIndex);o.input_sha256='44'.repeat(32);f.receiptIndex=Buffer.from(JSON.stringify(o)+'\n');},
    f=>{const o=JSON.parse(f.proofIndex);o.statement_hash='45'.repeat(32);f.proofIndex=Buffer.from(JSON.stringify(o)+'\n');},
    f=>{f.evmSeal=Buffer.from('01020304','hex');},
  ]) {
    const f=fixture(); mutate(f);
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(f));
  }
});

test('finalized-burn indexes reject invalid UTF-8 and duplicate keys before authority',()=>{
  for(const field of ['sourceIndex','receiptIndex','proofIndex']) {
    const invalid=fixture();
    invalid[field]=Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]);
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(invalid),/invalid UTF-8/);

    const duplicate=fixture();
    duplicate[field]=Buffer.concat([
      Buffer.from('{"schema":"ambiguous",'),duplicate[field].subarray(1),
    ]);
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(duplicate),
      /duplicate object key "schema"/);
  }
});

test('submission construction rejects inconsistent checkpoint and proving-program metadata',()=>{
  for(const mutate of [
    o=>{o.checkpoint_dom_height+=1;},
    o=>{o.checkpoint_dom_block='44'.repeat(32);},
    o=>{o.checkpoint_dom_state_root='45'.repeat(32);},
    o=>{o.checkpoint_beacon_slot+=1;},
    o=>{o.candidate_v2_first_height=o.checkpoint_dom_height+1;},
  ]) {
    const f=fixture(); const source=JSON.parse(f.sourceIndex); mutate(source);
    f.sourceIndex=Buffer.from(JSON.stringify(source)+'\n');
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(f),/checkpoint/);
  }
  for(const mutate of [
    o=>{o.program_path='evidence/finalized-burn-guest/substitute.elf';},
    o=>{o.program_sha256='46'.repeat(32);},
  ]) {
    const f=fixture(); const receipt=JSON.parse(f.receiptIndex); mutate(receipt);
    f.receiptIndex=Buffer.from(JSON.stringify(receipt)+'\n');
    const proof=JSON.parse(f.proofIndex);
    proof.receipt_index_sha256=rawHash(f.receiptIndex);
    f.proofIndex=Buffer.from(JSON.stringify(proof)+'\n');
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(f),/receipt index/);
  }
});

test('submission construction rejects internally consistent noncanonical EVM seal lengths',()=>{
  for(const length of [FINALIZED_BURN_EVM_SEAL_BYTES-1,FINALIZED_BURN_EVM_SEAL_BYTES+1]) {
    const f=fixture();
    f.evmSeal=Buffer.concat([
      Buffer.from(FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2),'hex'),
      Buffer.alloc(length-4,1),
    ]);
    const proof=JSON.parse(f.proofIndex);
    proof.evm_seal_bytes=f.evmSeal.length;
    proof.evm_seal_sha256=rawHash(f.evmSeal);
    f.proofIndex=Buffer.from(JSON.stringify(proof)+'\n');
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(f),/bounded|identity|seal/);
  }
});

test('serialized submission validator rejects calldata, proof and metadata substitution',()=>{
  const valid=buildAuthenticatedFinalizedBurnSubmission(fixture());
  for(const changed of [
    {...valid,data:valid.data.slice(0,-2)+(valid.data.endsWith('00')?'01':'00')},
    {...valid,statementHash:hash(46)},
    {...valid,proof:{...valid.proof,sha256:'47'.repeat(32)}},
    {...valid,broadcastAuthorized:true},
    {...valid,extra:true},
  ]) assert.throws(()=>validateAuthenticatedFinalizedBurnSubmission(changed));
});
