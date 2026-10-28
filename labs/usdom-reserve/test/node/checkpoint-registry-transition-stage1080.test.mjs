import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const root=new URL('../../../../',import.meta.url);
const read=path=>readFile(new URL(path,root),'utf8');
const [registry,adapter,statement,outer,transition]=await Promise.all([
  read('labs/usdom-reserve/contracts/DOMCheckpointRegistry.sol'),
  read('labs/usdom-reserve/contracts/DOMCheckpointRiscZeroVerifier.sol'),
  read('crates/dom-usdom-checkpoint-statement/src/lib.rs'),
  read('crates/dom-usdom-checkpoint-program/src/outer.rs'),
  read('crates/dom-usdom-checkpoint-program/src/lib.rs'),
]);

const section=(source,start,end)=>{
  const match=source.match(new RegExp(`${start}[\\s\\S]*?${end}`));
  assert.ok(match,`missing section ${start}`);
  return match[0];
};

test('candidate admission is anchored to the complete current checkpoint',()=>{
  const submit=section(registry,'function submitCheckpointCandidate','function _selectCandidate');
  for(const binding of [
    'checkpoint.previousHeight != latestHeight',
    'checkpoint.previousBlock != latestBlock',
    'checkpoint.previousStateRoot != latestStateRoot',
    'checkpoint.previousContextHash != latestContextHash',
    'checkpoint.previousTotalDifficulty != latestTotalDifficulty',
    'checkpoint.totalIssued < latestTotalIssued',
    'checkpoint.totalBurned < latestTotalBurned',
    '(latestIssuanceClosed && !checkpoint.issuanceClosed)',
  ]) assert.ok(submit.includes(binding),`missing admission binding: ${binding}`);
  assert.match(submit,/expectedHeight = uint256\(latestHeight\) \+ checkpointInterval/);
  assert.match(submit,/expectedConfirmationHeight = expectedHeight \+ confirmationDepth/);
  assert.match(submit,/_requireGuardianUnchanged\(\)[\s\S]*_requireVerifierUnchanged\(\)[\s\S]*checkpointStatementHash\(checkpoint\)[\s\S]*verifyDOMCheckpoint[\s\S]*_requireVerifierUnchanged\(\)/);
});

test('public statement binds V6 economics, predecessor, release and EVM identity',()=>{
  const hash=section(registry,'function checkpointStatementHash','function guardianControlHealthy');
  for(const binding of [
    'checkpoint.previousHeight','checkpoint.previousBlock','checkpoint.previousStateRoot',
    'checkpoint.previousContextHash','checkpoint.previousTotalDifficulty','checkpoint.totalIssued',
    'checkpoint.totalBurned','checkpoint.issuanceClosed','checkpoint.confirmationTotalDifficulty',
    'deploymentChainId','address(this)','activationScheduleCommitment','checkpointConfigHash',
  ]) assert.ok(hash.includes(binding),`statement omits ${binding}`);
  assert.match(registry,/deploymentChainId = block\.chainid/);
  assert.match(statement,/pub struct CheckpointStatementV6[\s\S]*pub total_issued: u128[\s\S]*pub total_burned: u128[\s\S]*pub issuance_closed: bool/);
  assert.match(outer,/execution\.target_total_issued != statement\.total_issued[\s\S]*execution\.target_total_burned != statement\.total_burned[\s\S]*execution\.target_issuance_closed != statement\.issuance_closed/);
  assert.match(transition,/self\.previous_issuance_closed && !self\.new_issuance_closed/);
});

test('replacement follows a strict total order without resetting its deadline',()=>{
  const select=section(registry,'function _selectCandidate','function _emitCandidate');
  assert.match(select,/block\.timestamp >= current\.readyAt[\s\S]*CandidateWindowClosed/);
  assert.match(select,/_candidateIsBetter\(checkpoint, statementHash, current\)[\s\S]*CandidateNotBetter/);
  assert.match(select,/current\.statementHash == bytes32\(0\) \? _timestampAfter\(challengePeriod\) : current\.readyAt/);
  assert.match(select,/confirmationTotalDifficulty > current\.confirmationTotalDifficulty/);
  assert.match(select,/uint256\(checkpoint\.confirmationBlock\) < uint256\(current\.confirmationBlock\)/);
  assert.match(select,/uint256\(statementHash\) < uint256\(current\.statementHash\)/);
});

test('finalization consumes one current candidate and advances economic history atomically',()=>{
  const finalize=section(registry,'function finalizeCheckpoint','function finalizeGracefulShutdown');
  assert.match(finalize,/PendingCandidate memory current = candidate[\s\S]*current\.statementHash == bytes32\(0\)[\s\S]*block\.timestamp < current\.readyAt[\s\S]*_requireVerifierUnchanged\(\)/);
  assert.match(finalize,/previousTotalIssued = latestTotalIssued[\s\S]*previousTotalBurned = latestTotalBurned[\s\S]*latestTotalIssued = current\.totalIssued[\s\S]*latestTotalBurned = current\.totalBurned[\s\S]*latestIssuanceClosed = candidateIssuanceClosed/);
  assert.match(finalize,/\+\+checkpointCount[\s\S]*delete candidate[\s\S]*delete candidateIssuanceClosed/);
  assert.doesNotMatch(registry,/function (rollback|revertCheckpoint|replaceFinalizedCheckpoint)\s*\(/);
});

test('graceful closure and guardian emergency halt remain distinct terminal states',()=>{
  const graceful=section(registry,'function finalizeGracefulShutdown','function haltPermanently');
  const emergency=section(registry,'function haltPermanently','function _checkpointConfigHash');
  assert.match(graceful,/latestIssuanceClosed[\s\S]*latestTotalBurned != latestTotalIssued[\s\S]*halted = true[\s\S]*gracefullyShutdown = true[\s\S]*delete candidate/);
  assert.match(emergency,/msg\.sender != guardian[\s\S]*_requireGuardianUnchanged\(\)[\s\S]*halted = true/);
  assert.doesNotMatch(emergency,/gracefullyShutdown = true/);
});

test('immutable verifier identity reaches the exact upstream ImageID',()=>{
  const guard=section(registry,'function _requireVerifierUnchanged','function _requireGuardianUnchanged');
  assert.match(guard,/address\(verifier\)\.codehash != verifierCodeHash[\s\S]*_readVerifierConfig\(verifier\) != verifierConfigHash[\s\S]*_readVerifierCapability\(address\(verifier\)\) != PROOF_ACCEPTED/);
  assert.match(adapter,/verifierConfigHash = keccak256\([\s\S]*imageId_[\s\S]*JOURNAL_SCHEMA_HASH[\s\S]*PROOF_ACCEPTED/);
  assert.match(adapter,/abi\.encodeCall\(IRiscZeroVerifierV3\.verify, \(proof, imageId, digest\)\)/);
  assert.match(adapter,/journalDigest\(bytes32 statementHash\)[\s\S]*sha256\(abi\.encodePacked\(statementHash\)\)/);
});
