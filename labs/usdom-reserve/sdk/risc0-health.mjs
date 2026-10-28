import {getAddress} from 'ethers';
import {validateRiscZeroMainnetReference} from './risc0-verifier-reference.mjs';

const hashPattern=/^0x[0-9a-fA-F]{64}$/;
const canonicalUintPattern=/^(0|[1-9][0-9]*)$/;
const uint64Max=(1n<<64n)-1n;
const zeroHash='0x'+'00'.repeat(32);
const ethereumMainnetGenesis=
  '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
const add=(blockers,code,detail)=>blockers.push({code,detail});
const sameHash=(left,right)=>hashPattern.test(left??'') && hashPattern.test(right??'')
  && left.toLowerCase()===right.toLowerCase();
const sameAddress=(left,right)=>{
  try { return getAddress(left)===getAddress(right); } catch { return false; }
};
const exactKeys=(value,keys)=>value && typeof value==='object' && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());

/** A read-only status check for the immutable verifier and the upstream
 * emergency-stop signal. It does not grant proof authority or authorize any
 * transaction. Supervisors must treat every blocker as a pause incident. */
export function assessRiscZeroMainnetHealth({reference,observation,standalone=true}) {
  const blockers=[];
  let trusted;
  try { trusted=validateRiscZeroMainnetReference(reference); }
  catch(error) {
    add(blockers,'risc0_reference_invalid',error.message);
    return {healthy:false,blockerCount:blockers.length,blockers};
  }
  if(standalone!==true && standalone!==false) {
    add(blockers,'risc0_observation_scope_invalid','health observation scope must be explicit');
  } else if(standalone && !exactKeys(observation,
    ['chainId','genesisBlockHash','finalizedBlockNumber','finalizedBlockHash','snapshotBlockHashAfter',
      'riscZeroVerifier','riscZeroEmergencyStop'])) {
    add(blockers,'risc0_observation_schema_invalid','health observation must match the exact collector schema');
  }
  if(!exactKeys(observation?.riscZeroVerifier,['address','codeHash','selector','version'])) {
    add(blockers,'risc0_verifier_observation_schema_invalid',
      'direct verifier observation must match the exact collector schema');
  }
  if(!exactKeys(observation?.riscZeroEmergencyStop,['address','codeHash','paused','verifier'])) {
    add(blockers,'risc0_estop_observation_schema_invalid',
      'emergency-stop observation must match the exact collector schema');
  }
  if(observation?.chainId!=='1') {
    add(blockers,'risc0_wrong_chain','health observation is not Ethereum mainnet');
  }
  if(String(observation?.genesisBlockHash??'').toLowerCase()!==ethereumMainnetGenesis) {
    add(blockers,'risc0_wrong_genesis','health observation is not canonical Ethereum mainnet');
  }
  if(typeof observation?.finalizedBlockNumber!=='string'
      || observation.finalizedBlockNumber.length>20
      || !canonicalUintPattern.test(observation.finalizedBlockNumber)
      || BigInt(observation.finalizedBlockNumber)>uint64Max) {
    add(blockers,'risc0_finalized_block_number_invalid','finalized block number is invalid');
  }
  if(!hashPattern.test(observation?.finalizedBlockHash??'')
      || observation.finalizedBlockHash.toLowerCase()===zeroHash) {
    add(blockers,'risc0_finalized_block_hash_invalid','finalized block hash is absent or zero');
  }
  if(!sameHash(observation?.snapshotBlockHashAfter,observation?.finalizedBlockHash)) {
    add(blockers,'risc0_finalized_snapshot_changed',
      'the fixed finalized block hash changed or was unavailable during the health observation');
  }
  const direct=observation?.riscZeroVerifier;
  if(!sameAddress(direct?.address,trusted.verifier_address)) {
    add(blockers,'risc0_verifier_address_mismatch','direct verifier address differs from the reviewed pin');
  }
  if(!sameHash(direct?.codeHash,trusted.observed_runtime_code_hash)) {
    add(blockers,'risc0_verifier_codehash_mismatch','direct verifier bytecode differs from the reviewed pin');
  }
  if(typeof direct?.selector!=='string' || direct.selector!==trusted.verifier_selector) {
    add(blockers,'risc0_verifier_selector_mismatch','direct verifier selector differs from the reviewed pin');
  }
  if(direct?.version!==trusted.verifier_version) {
    add(blockers,'risc0_verifier_version_mismatch','direct verifier version differs from the reviewed pin');
  }
  const stop=observation?.riscZeroEmergencyStop;
  if(!sameAddress(stop?.address,trusted.emergency_stop_wrapper_address)) {
    add(blockers,'risc0_estop_address_mismatch','emergency-stop wrapper address differs from the reviewed pin');
  }
  if(!sameHash(stop?.codeHash,trusted.emergency_stop_wrapper_runtime_code_hash)) {
    add(blockers,'risc0_estop_codehash_mismatch','emergency-stop wrapper bytecode differs from the reviewed pin');
  }
  if(!sameAddress(stop?.verifier,trusted.verifier_address)) {
    add(blockers,'risc0_estop_verifier_mismatch','emergency-stop wrapper does not reference the pinned direct verifier');
  }
  if(stop?.paused!==true && stop?.paused!==false) {
    add(blockers,'risc0_estop_state_invalid','emergency-stop state is unavailable or is not boolean');
  } else if(stop.paused) {
    add(blockers,'risc0_estop_active','RISC Zero emergency-stop wrapper is paused or its state is unavailable');
  }
  return {healthy:blockers.length===0,blockerCount:blockers.length,blockers,
    finalizedBlockNumber:observation?.finalizedBlockNumber??null,
    finalizedBlockHash:observation?.finalizedBlockHash??null,
    snapshotBlockHashAfter:observation?.snapshotBlockHashAfter??null};
}
