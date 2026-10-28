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
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';
const hash=byte=>'0x'+byte.toString(16).padStart(2,'0').repeat(32);
const rawHash=bytes=>createHash('sha256').update(bytes).digest('hex');
const zero=hash(0);

export function finalizedBurnAuthorityFixture() {
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
    provingProgramSha256:'0xbf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511',
    sourceManifestSha256:hash(14),verifierArtifactSha256:hash(15),
    maxProofBytes:'260',minimumFinalityBeaconSlot:'12000000',ethereumChainId:'1',
    riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
    riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
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
    program_sha256:'bf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511',
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
    evmSeal,statementHash,burn,releaseConfigSha256:'43'.repeat(32)};
}

