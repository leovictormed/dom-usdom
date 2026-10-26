import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const reserve = readFileSync(new URL('../../contracts/USDOMProofReserve.sol', import.meta.url), 'utf8');
const registry = readFileSync(new URL('../../contracts/DOMCheckpointRegistry.sol', import.meta.url), 'utf8');

test('reserve pause invalidates exactly one queue generation and cancels stale resume', () => {
  assert.match(reserve, /if \(!paused\) \{[\s\S]*paused = true;[\s\S]*\+\+queueEpoch;[\s\S]*pendingCount = 0;[\s\S]*totalPendingAmount = 0;[\s\S]*firstPendingBurn = bytes32\(0\);[\s\S]*lastPendingBurn = bytes32\(0\)/);
  assert.match(reserve, /resumeReadyAt = 0;\s*emit Paused\(msg\.sender\)/);
  assert.match(reserve, /pauseQueueEpoch\(uint64 expectedQueueEpoch\)[\s\S]*expectedQueueEpoch != queueEpoch[\s\S]*revert StaleEmergency/);
  assert.match(reserve, /pending\.queueEpoch != queueEpoch\) revert StaleCertificate/);
});

test('reserve resume is delayed, revalidates both immutable roles, verifier and token', () => {
  assert.match(reserve, /function scheduleResume\(\) external onlyGovernance[\s\S]*if \(!paused\) revert NotPaused\(\);[\s\S]*_requireControlPlaneUnchanged\(\);[\s\S]*resumeReadyAt = _timestampAfter\(governanceDelay\)/);
  assert.match(reserve, /function executeResume\(\) external[\s\S]*block\.timestamp < resumeReadyAt[\s\S]*_requireControlPlaneUnchanged\(\);[\s\S]*_requireVerifierUnchanged\(\);[\s\S]*_requireTokenUsable\(address\(this\), address\(this\)\);[\s\S]*paused = false;[\s\S]*resumeReadyAt = 0/);
  assert.match(reserve, /currentOwnersCommitment == ownersCommitment/);
  assert.match(reserve, /uint256\(thresholdWord\) == CONTROL_PLANE_THRESHOLD/);
  assert.doesNotMatch(reserve, /function (?:set|rotate|replace|upgrade)(?:Governance|Guardian|Verifier|Token)/i);
});

test('checkpoint candidates cannot cross predecessor, config, verifier or challenge epochs', () => {
  assert.match(registry, /checkpoint\.previousHeight != latestHeight \|\| checkpoint\.previousBlock != latestBlock[\s\S]*checkpoint\.previousStateRoot != latestStateRoot[\s\S]*checkpoint\.previousContextHash != latestContextHash[\s\S]*checkpoint\.previousTotalDifficulty != latestTotalDifficulty/);
  assert.match(registry, /block\.timestamp >= current\.readyAt[\s\S]*revert CandidateWindowClosed/);
  assert.match(registry, /current\.statementHash == bytes32\(0\)[\s\S]*_timestampAfter\(challengePeriod\)[\s\S]*current\.readyAt/);
  assert.match(registry, /checkpointConfigHash[\s\S]*function guardianControlHealthy/);
  assert.match(registry, /function finalizeCheckpoint\(\) external[\s\S]*_requireGuardianUnchanged\(\);[\s\S]*block\.timestamp < current\.readyAt[\s\S]*_requireVerifierUnchanged\(\);[\s\S]*delete candidate/);
});

test('permanent halt is fail-closed and grants no mutation or payout authority', () => {
  assert.match(registry, /function haltPermanently\(\) external \{\s*if \(msg\.sender != guardian\) revert Unauthorized\(\);\s*_requireGuardianUnchanged\(\);\s*if \(halted\) revert IsHalted\(\);\s*halted = true/);
  assert.match(registry, /function submitCheckpointCandidate[\s\S]*if \(halted\) revert IsHalted/);
  assert.match(registry, /function finalizeCheckpoint[\s\S]*if \(halted\) revert IsHalted/);
  assert.doesNotMatch(registry, /function (?:unhalt|resume|rotate|upgrade|setGuardian)/i);
  assert.doesNotMatch(registry, /call\{|delegatecall|selfdestruct/);
});

test('mainnet roles require unchanged 2-of-3 Safes, limiting one signer compromise', () => {
  for (const source of [reserve, registry]) {
    assert.match(source, /CONTROL_PLANE_THRESHOLD = 2/);
    assert.match(source, /CONTROL_PLANE_OWNER_COUNT = 3/);
    assert.match(source, /block\.chainid == 1/);
    assert.match(source, /_safeModulesEmpty/);
    assert.match(source, /_safeGuardEmpty/);
    assert.match(source, /_safeFallbackHandlerIntact/);
  }
});
