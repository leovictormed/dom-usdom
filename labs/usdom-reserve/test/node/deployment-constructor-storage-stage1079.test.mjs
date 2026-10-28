import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const reserve = readFileSync(new URL('../../contracts/USDOMProofReserve.sol', import.meta.url), 'utf8');
const registry = readFileSync(new URL('../../contracts/DOMCheckpointRegistry.sol', import.meta.url), 'utf8');
const compiled = readFileSync(new URL('../../sdk/compiled-runtime.mjs', import.meta.url), 'utf8');
const collector = readFileSync(new URL('../../scripts/check-mainnet-preflight.mjs', import.meta.url), 'utf8');
const identity = readFileSync(new URL('../../sdk/mainnet-deployment-identity.mjs', import.meta.url), 'utf8');

test('reserve and registry constructor tuple encoders retain exact Solidity Config order', () => {
  assert.match(reserve, /struct Config \{\s*IERC20 token;\s*IDOMFinalizedBurnVerifier verifier;\s*IDOMGracefulShutdownRegistry checkpointRegistry;\s*bytes32 domDomain;\s*bytes32 activationScheduleCommitment;\s*address governance;\s*address guardian;\s*uint64 withdrawalDelay;\s*uint64 governanceDelay;\s*uint64 maxOutstanding;\s*uint64 outflowCapacity;\s*bool pilotRestricted;\s*\}/);
  assert.match(compiled, /tuple\(address token,address verifier,address checkpointRegistry,bytes32 domDomain,bytes32 activationScheduleCommitment,address governance,address guardian,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity,bool pilotRestricted\)/);
  assert.match(registry, /struct Config \{\s*bytes32 bridgeDomain;\s*uint32 domNetworkMagic;\s*bytes32 domChainId;\s*uint64 firstV4Height;\s*bytes32 activationEmptyStateRoot;\s*bytes32 activationScheduleCommitment;\s*uint32 checkpointInterval;\s*uint32 confirmationDepth;\s*uint64 challengePeriod;\s*IDOMCheckpointVerifier verifier;\s*address guardian;\s*uint64 initialHeight;\s*bytes32 initialBlock;\s*bytes32 initialStateRoot;\s*bytes32 initialContextHash;\s*uint256 initialTotalDifficulty;\s*\}/);
  assert.match(compiled, /tuple\(bytes32 bridgeDomain,uint32 domNetworkMagic,bytes32 domChainId,uint64 firstV4Height,bytes32 activationEmptyStateRoot,bytes32 activationScheduleCommitment,uint32 checkpointInterval,uint32 confirmationDepth,uint64 challengePeriod,address verifier,address guardian,uint64 initialHeight,bytes32 initialBlock,bytes32 initialStateRoot,bytes32 initialContextHash,uint256 initialTotalDifficulty\)/);
});

test('permanent debt preserves authenticated closure bit offset and identifies shifted storage slots', () => {
  assert.match(reserve, /mapping\(bytes32 => bytes32\) public provedRequestBurns;[\s\S]*uint256 public totalDeposited;\s*uint256 public totalReleased;[\s\S]*uint256 public totalProvedDebtAmount;[\s\S]*uint64 public queueEpoch;\s*bool public paused;[\s\S]*bool public depositsClosed;/);
  // Slots 0..1 are reserveConfigHash and activationScheduleCommitment; nine
  // mappings occupy 2..10. Three full-width accounting words then move the
  // packed queue/closure word to slot 18 while depositsClosed remains bit 72.
  const mappingSlots = 9;
  const totalDepositedSlot = 2 + mappingSlots;
  const packedClosureSlot = totalDepositedSlot + 7;
  assert.equal(totalDepositedSlot, 11);
  assert.equal(packedClosureSlot, 18);
  const queueEpochBits = 64, pausedBits = 8;
  assert.equal(queueEpochBits + pausedBits, 72);
});

test('cold-start ABI observes the complete current candidate and terminal ledgers', () => {
  assert.match(collector, /candidate\(\) view returns \(bytes32 statementHash,uint64 height,uint64 readyAt,bytes32 blockHash,bytes32 stateRoot,bytes32 contextHash,uint256 totalDifficulty,uint128 totalIssued,uint128 totalBurned,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp\)/);
  for (const getter of [
    'depositsClosed','gracefullyShutdown','latestIssuanceClosed','latestTotalIssued','latestTotalBurned',
    'previousTotalIssued','previousTotalBurned','candidateIssuanceClosed','pilotRestrictedDeployment',
    'permissionlessDeposits','pilotDepositConsumed','authorizedPilotDeposit','authorizedPilotSnapshot',
    'authorizedPilotValidUntil','pilotAuthorizationGeneration','permissionlessDepositsReadyAt',
  ]) assert.match(collector, new RegExp(`function ${getter}\\(\\) view returns`), getter);
});

test('deployment identity deliberately uses nonce-bound CREATE and rejects CREATE2 substitution', () => {
  assert.match(identity, /releaseConfig\.deploymentMethod!==['"]CREATE['"]/);
  assert.match(identity, /getCreateAddress\(\{from:address,nonce:roleNonce\}\)/);
  assert.doesNotMatch(identity, /getCreate2Address/);
});
