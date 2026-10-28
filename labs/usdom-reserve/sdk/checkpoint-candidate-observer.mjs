import {Interface,getAddress,keccak256} from 'ethers';
import {
  checkpointRegistryConfigurationFromRelease,validateAuthenticatedCheckpointSubmission,
} from './checkpoint-submission.mjs';
import {uint} from './reserve.mjs';

const zeroHash='0x'+'00'.repeat(32);
const observationFields=Object.freeze([
  'chainId','finalizedBlockNumber','finalizedBlockHash','finalizedBlockTimestamp',
  'snapshotBlockHashAfter','registryRuntimeCodeHash','onchainStatementHash',
  'submissionCallAccepted','registry','candidate',
]);
const registryFields=Object.freeze([
  'checkpointConfigHash','halted','gracefullyShutdown','latestIssuanceClosed','latestHeight','latestBlock','latestStateRoot',
  'latestContextHash','latestTotalDifficulty','latestTotalIssued','latestTotalBurned',
]);
const candidateFields=Object.freeze([
  'statementHash','height','readyAt','blockHash','stateRoot','contextHash','totalDifficulty',
  'totalIssued','totalBurned','issuanceClosed','confirmationHeight','confirmationBlock',
  'confirmationTotalDifficulty','confirmationTimestamp',
]);
const registryInterface=new Interface(['function finalizeCheckpoint()']);

export const CHECKPOINT_FINALIZE_CALLDATA=registryInterface.encodeFunctionData('finalizeCheckpoint');

function exact(value,fields,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...fields].sort())) {
    throw new Error(`exact ${label} fields required`);
  }
}

function same(left,right) {
  return typeof left==='string' && typeof right==='string' && left.toLowerCase()===right.toLowerCase();
}

function canonicalHash(value,{zero=false}={}) {
  return typeof value==='string' && /^0x[0-9a-fA-F]{64}$/.test(value)
    && (zero || value.toLowerCase()!==zeroHash);
}

function add(blockers,code,detail) { blockers.push({code,detail}); }

function canonicalUint(value,bits,label,blockers) {
  try { return uint(value,bits); }
  catch { add(blockers,`${label}_invalid`,`${label} must be a canonical uint${bits}`); return null; }
}

/**
 * Assess one single-finalized-snapshot observation of an authenticated
 * checkpoint package. The result never authorizes or sends a transaction.
 */
export function assessCheckpointCandidateObservation({releaseConfig,submission,observation}) {
  validateAuthenticatedCheckpointSubmission(submission);
  exact(observation,observationFields,'checkpoint candidate observation');
  exact(observation.registry,registryFields,'checkpoint registry observation');
  exact(observation.candidate,candidateFields,'checkpoint candidate state');
  const configuration=checkpointRegistryConfigurationFromRelease(releaseConfig);
  const blockers=[];
  if(submission.ethereumChainId!==configuration.ethereumChainId.toString()
      || observation.chainId!==submission.ethereumChainId) {
    add(blockers,'chain_id_mismatch','submission, release and observed EVM chain IDs differ');
  }
  if(getAddress(submission.to)!==getAddress(configuration.registry)) {
    add(blockers,'registry_address_mismatch','submission target differs from the release registry');
  }
  if(!canonicalHash(observation.finalizedBlockHash)
      || !same(observation.finalizedBlockHash,observation.snapshotBlockHashAfter)) {
    add(blockers,'finalized_snapshot_changed','the finalized Ethereum snapshot changed during observation');
  }
  canonicalUint(observation.finalizedBlockNumber,64,'finalized_block_number',blockers);
  const finalizedTimestamp=canonicalUint(
    observation.finalizedBlockTimestamp,64,'finalized_block_timestamp',blockers,
  );
  if(!canonicalHash(observation.registryRuntimeCodeHash)
      || !same(observation.registryRuntimeCodeHash,releaseConfig.checkpointRegistryRuntimeCodeHash)) {
    add(blockers,'registry_runtime_mismatch','observed registry runtime differs from the exact release');
  }
  if(!same(observation.onchainStatementHash,submission.statementHash)) {
    add(blockers,'statement_hash_mismatch','registry statement hashing differs from the package');
  }
  if(!same(observation.registry.checkpointConfigHash,releaseConfig.checkpointRegistryConfigHash)) {
    add(blockers,'checkpoint_config_mismatch','observed registry configuration differs from the release');
  }
  if(observation.registry.halted!==false) {
    add(blockers,'registry_halted','checkpoint registry is halted');
  }
  if(observation.registry.gracefullyShutdown!==false) {
    add(blockers,'registry_gracefully_shutdown','checkpoint registry is already terminal');
  }
  if(typeof observation.registry.latestIssuanceClosed!=='boolean') {
    add(blockers,'latest_issuance_closed_invalid','latest issuance closure must be boolean');
  }
  const latestHeight=canonicalUint(observation.registry.latestHeight,64,'latest_height',blockers);
  const latestDifficulty=canonicalUint(
    observation.registry.latestTotalDifficulty,256,'latest_total_difficulty',blockers,
  );
  const latestIssued=canonicalUint(
    observation.registry.latestTotalIssued,128,'latest_total_issued',blockers,
  );
  const latestBurned=canonicalUint(
    observation.registry.latestTotalBurned,128,'latest_total_burned',blockers,
  );
  const checkpoint=submission.checkpoint;
  const previousMatches=latestHeight===BigInt(checkpoint.previousHeight)
    && same(observation.registry.latestBlock,checkpoint.previousBlock)
    && same(observation.registry.latestStateRoot,checkpoint.previousStateRoot)
    && same(observation.registry.latestContextHash,checkpoint.previousContextHash)
    && latestDifficulty===BigInt(checkpoint.previousTotalDifficulty);
  const finalizedMatches=latestHeight===BigInt(checkpoint.height)
    && same(observation.registry.latestBlock,checkpoint.blockHash)
    && same(observation.registry.latestStateRoot,checkpoint.stateRoot)
    && same(observation.registry.latestContextHash,checkpoint.contextHash)
    && latestDifficulty===BigInt(checkpoint.totalDifficulty)
    && latestIssued===BigInt(checkpoint.totalIssued)
    && latestBurned===BigInt(checkpoint.totalBurned)
    && observation.registry.latestIssuanceClosed===checkpoint.issuanceClosed;
  let status='invalid';
  let submissionReady=false;
  let finalizationReady=false;
  const candidate=observation.candidate;
  if(blockers.length===0 && finalizedMatches) {
    status='finalized';
  } else if(blockers.length===0 && previousMatches) {
    if(candidate.statementHash===zeroHash) {
      if(observation.submissionCallAccepted===true) {
        status='submission-ready'; submissionReady=true;
      } else add(blockers,'submission_call_rejected','the full package failed read-only EVM execution');
    } else if(same(candidate.statementHash,submission.statementHash)) {
      const readyAt=canonicalUint(candidate.readyAt,64,'candidate_ready_at',blockers);
      const candidateMatches=candidate.height===checkpoint.height
        && same(candidate.blockHash,checkpoint.blockHash)
        && same(candidate.stateRoot,checkpoint.stateRoot)
        && same(candidate.contextHash,checkpoint.contextHash)
        && candidate.totalDifficulty===checkpoint.totalDifficulty
        && candidate.totalIssued===checkpoint.totalIssued
        && candidate.totalBurned===checkpoint.totalBurned
        && candidate.issuanceClosed===checkpoint.issuanceClosed
        && candidate.confirmationHeight===checkpoint.confirmationHeight
        && same(candidate.confirmationBlock,checkpoint.confirmationBlock)
        && candidate.confirmationTotalDifficulty===checkpoint.confirmationTotalDifficulty
        && candidate.confirmationTimestamp===checkpoint.confirmationTimestamp;
      if(!candidateMatches) add(blockers,'candidate_fields_mismatch','candidate fields do not open the package statement');
      else if(readyAt!==null && finalizedTimestamp!==null && finalizedTimestamp>=readyAt) {
        status='finalization-ready'; finalizationReady=true;
      } else if(readyAt!==null) status='challenge-window';
    } else {
      add(blockers,'competing_candidate','another checkpoint candidate occupies the fixed round');
    }
  } else if(blockers.length===0) {
    add(blockers,'registry_predecessor_mismatch','registry state is neither the package predecessor nor its result');
  }
  if(blockers.length!==0) {
    status='invalid'; submissionReady=false; finalizationReady=false;
  }
  return {
    schema:'usdom-checkpoint-candidate-observation-assessment-v1',
    valid:blockers.length===0,status,submissionReady,finalizationReady,
    finalizeTransaction:{to:submission.to,value:'0',data:CHECKPOINT_FINALIZE_CALLDATA,
      broadcastAuthorized:false},
    finalizedBlockNumber:observation.finalizedBlockNumber,
    finalizedBlockHash:observation.finalizedBlockHash,statementHash:submission.statementHash,
    blockers,
  };
}

/** Hash exact EVM runtime code returned by a finalized-snapshot collector. */
export function runtimeCodeHash(code) {
  if(typeof code!=='string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(code)) {
    throw new Error('registry runtime code must be nonempty canonical bytes');
  }
  return keccak256(code);
}
