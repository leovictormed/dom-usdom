import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FINALIZED_BURN_CAPACITY_IMAGE_ID,FINALIZED_BURN_CAPACITY_INPUT_BYTES,
  FINALIZED_BURN_CAPACITY_INPUT_SHA256,FINALIZED_BURN_CAPACITY_PROGRAM_SHA256,
  FINALIZED_BURN_CAPACITY_REPORT_SCHEMA,FINALIZED_BURN_CAPACITY_STATEMENT_HASH,
  finalizedBurnCapacityAdapterConfigHash,
  finalizedBurnIsolatedEvmReceiptCommitment,
  validateFinalizedBurnCapacityReport,
} from '../../sdk/finalized-burn-capacity-report.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';

const report=()=>{
 const value=({
  schema:FINALIZED_BURN_CAPACITY_REPORT_SCHEMA,runId:'20261022T043544Z-1676533',
  startedAt:'1792643744',completedAt:'1792647344',provingWallMilliseconds:'3540000',
  peakResidentKiB:'2097152',rayonWorkers:1,segmentLimitPo2:18,prover:'local',
  devMode:false,receiptKind:'groth16',receiptVerified:true,risc0ZkvmVersion:'3.0.6',mines:false,
  broadcastAuthorized:false,releaseSpecific:false,ethereumChainId:'1',
  inputSha256:FINALIZED_BURN_CAPACITY_INPUT_SHA256,inputBytes:FINALIZED_BURN_CAPACITY_INPUT_BYTES,
  statementHash:FINALIZED_BURN_CAPACITY_STATEMENT_HASH,
  guestProgramSha256:FINALIZED_BURN_CAPACITY_PROGRAM_SHA256,
  guestImageId:FINALIZED_BURN_CAPACITY_IMAGE_ID,
  succinctReceiptSha256:'11'.repeat(32),succinctReceiptBytes:'4096',
  groth16ReceiptSha256:'22'.repeat(32),groth16ReceiptBytes:'2048',
  evmSealSha256:'33'.repeat(32),evmSealBytes:'260',
  riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
  riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
  finalizedObservationBlockNumber:'26245816',
  finalizedObservationBlockHash:'0x'+'44'.repeat(32),
  observationSourceIds:['drpc','publicnode'],
  observationEndpointHashes:['55'.repeat(32),'66'.repeat(32)],
  adapterRuntimeCodeHash:'0x'+'77'.repeat(32),
  adapterVerifierConfigHash:finalizedBurnCapacityAdapterConfigHash(PINNED_RISC0_MAINNET_V3),
  adapterCallAccepted:true,
  adapterVerificationGas:'400000',
  isolatedEvmAdapter:'0x0000000000000000000000000000000000000002',
  isolatedEvmTransactionHash:'0x'+'88'.repeat(32),
  isolatedEvmBlockHash:'0x'+'99'.repeat(32),isolatedEvmBlockNumber:'2',
  isolatedEvmReceiptSha256:'aa'.repeat(32),
 });
 value.isolatedEvmReceiptSha256=finalizedBurnIsolatedEvmReceiptCommitment({
  transactionHash:value.isolatedEvmTransactionHash,blockHash:value.isolatedEvmBlockHash,
  blockNumber:value.isolatedEvmBlockNumber,adapter:value.isolatedEvmAdapter,
  adapterRuntimeCodeHash:value.adapterRuntimeCodeHash,
  adapterVerifierConfigHash:value.adapterVerifierConfigHash,
  statementHash:value.statementHash,evmSealSha256:value.evmSealSha256,
  adapterVerificationGas:value.adapterVerificationGas,
 }).sha256;
 return value;
};

const validate=value=>validateFinalizedBurnCapacityReport(value,{
  riscZeroReference:PINNED_RISC0_MAINNET_V3,
});

test('finalized-burn capacity report binds a real non-release proof measurement',()=>{
  const value=report();
  const validated=validate(value);
  assert.equal(validated.runId,value.runId);
  assert.equal(validated.releaseSpecific,false);
  assert(Object.isFrozen(validated));
  assert(Object.isFrozen(validated.observationSourceIds));
});

test('finalized-burn capacity report rejects semantic substitutions',()=>{
  const mutations=[
    value=>{value.extra=true;},
    value=>{value.runId='../latest';},
    value=>{value.inputSha256='88'.repeat(32);},
    value=>{value.inputBytes--;},
    value=>{value.statementHash='88'.repeat(32);},
    value=>{value.guestProgramSha256='88'.repeat(32);},
    value=>{value.guestImageId='88'.repeat(32);},
    value=>{value.ethereumChainId='31337';},
    value=>{value.riscZeroVerifier='0x0000000000000000000000000000000000000001';},
    value=>{value.riscZeroVerifierCodeHash='0x'+'88'.repeat(32);},
    value=>{value.observationSourceIds=['publicnode','drpc'];},
    value=>{value.observationEndpointHashes[1]=value.observationEndpointHashes[0];},
    value=>{value.finalizedObservationBlockNumber='00';},
    value=>{value.completedAt=(BigInt(value.startedAt)-1n).toString();},
    value=>{value.provingWallMilliseconds='4000000';},
    value=>{value.succinctReceiptSha256=value.inputSha256;},
    value=>{value.evmSealBytes='65537';},
    value=>{value.adapterVerificationGas='5000001';},
    value=>{value.isolatedEvmTransactionHash='0x'+'aa'.repeat(32);},
    value=>{value.isolatedEvmBlockHash='0x'+'aa'.repeat(32);},
    value=>{value.isolatedEvmBlockNumber='0';},
    value=>{value.isolatedEvmReceiptSha256='aa'.repeat(32);},
    value=>{value.adapterVerifierConfigHash='0x'+'00'.repeat(32);},
    value=>{value.adapterCallAccepted=false;},
    value=>{value.receiptVerified=false;},
    value=>{value.devMode=true;},
    value=>{value.releaseSpecific=true;},
    value=>{value.broadcastAuthorized=true;},
    value=>{value.mines=true;},
  ];
  for(const mutate of mutations) {
    const value=report();
    mutate(value);
    assert.throws(()=>validate(value));
  }
});
