import {getAddress,getCreateAddress} from 'ethers';
import {assessRiscZeroMainnetHealth} from './risc0-health.mjs';

export const EMPTY_CODE_HASH = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
const zeroHash = '0x' + '00'.repeat(32);
const bytes32Pattern = /^0x[0-9a-fA-F]{64}$/;
const canonicalUintPattern = /^(0|[1-9][0-9]*)$/;

function add(blockers, code, detail) {
  blockers.push({code, detail});
}

function requireExactKeys(blockers,value,code,keys) {
  const expected=[...keys].sort();
  if (!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify(expected)) {
    add(blockers,code,`${code.replaceAll('_',' ')} must match the exact collector schema`);
  }
}

function requireObservationSchema(blockers,phase,observation) {
  const common=['chainId','finalizedBlockNumber','finalizedBlockHash','snapshotBlockHashAfter',
    'deployerNonce','checkpointRegistryDeployerNonce','codeHashes','verifierConfigHash',
    'checkpointVerifierConfigHash','riscZeroVerifier','riscZeroEmergencyStop','token',
    'finalizedBurnVerifierDeployment','checkpointVerifierDeployment'];
  const post=['deployment','checkpointRegistryDeployment','reserve','checkpointRegistry',
    'checkpointRegistryCandidate','checkpointRegistrySlot0'];
  requireExactKeys(blockers,observation,'observation_schema_invalid',
    phase==='postdeployment'?[...common,...post]:common);
  requireExactKeys(blockers,observation?.codeHashes,'observation_code_hashes_schema_invalid',
    ['reserve','token','verifier','governance','guardian','checkpointRegistry','checkpointVerifier',
      'checkpointGuardian']);
  requireExactKeys(blockers,observation?.riscZeroVerifier,'observation_risc0_verifier_schema_invalid',
    ['address','codeHash','selector','version']);
  requireExactKeys(blockers,observation?.riscZeroEmergencyStop,'observation_risc0_estop_schema_invalid',
    ['address','codeHash','paused','verifier']);
  requireExactKeys(blockers,observation?.token,'observation_token_schema_invalid',
    ['decimals','paused','deprecated','basisPointsRate','maximumFee','reserveBlacklisted','reserveBalance']);
  const deployment=['status','from','nonce','creates','derivedCreateAddress','blockNumber','blockHash',
    'canonicalBlockHash','transactionHash','to','value','inputHash'];
  requireExactKeys(blockers,observation?.finalizedBurnVerifierDeployment,
    'finalized_burn_verifier_deployment_schema_invalid',deployment);
  requireExactKeys(blockers,observation?.checkpointVerifierDeployment,
    'checkpoint_verifier_deployment_schema_invalid',deployment);
  if(phase!=='postdeployment') return;
  requireExactKeys(blockers,observation?.deployment,'reserve_deployment_schema_invalid',deployment);
  requireExactKeys(blockers,observation?.checkpointRegistryDeployment,
    'checkpoint_registry_deployment_schema_invalid',[...deployment,'checkpointEventCount','checkpointEvent']);
  requireExactKeys(blockers,observation?.checkpointRegistryDeployment?.checkpointEvent,
    'checkpoint_registry_bootstrap_event_schema_invalid',
    ['address','bridgeDomain','domNetworkMagic','domHeight','domBlock','domStateRoot','checkpointConfigHash']);
  requireExactKeys(blockers,observation?.reserve,'reserve_observation_schema_invalid',
    ['token','tokenCodeHash','verifier','verifierCodeHash','verifierConfigHash','reserveConfigHash',
      'domDomain','activationScheduleCommitment','governance','governanceCodeHash','guardian',
      'guardianCodeHash','withdrawalDelay','governanceDelay','maxOutstanding','outflowCapacity','paused',
      'queueEpoch','resumeReadyAt','totalDeposited','totalReleased','totalPendingAmount','pendingCount']);
  requireExactKeys(blockers,observation?.checkpointRegistry,'checkpoint_registry_observation_schema_invalid',
    ['checkpointConfigHash','bridgeDomain','domNetworkMagic','domChainId','firstV4Height',
      'activationEmptyStateRoot','activationScheduleCommitment','checkpointInterval','confirmationDepth',
      'challengePeriod','verifier','verifierCodeHash','verifierConfigHash','guardian','guardianCodeHash',
      'latestHeight','checkpointCount','halted','latestBlock','latestStateRoot','latestContextHash',
      'latestTotalDifficulty']);
  requireExactKeys(blockers,observation?.checkpointRegistryCandidate,
    'checkpoint_registry_candidate_schema_invalid',
    ['statementHash','height','readyAt','blockHash','stateRoot','contextHash','totalDifficulty',
      'confirmationHeight','confirmationBlock','confirmationTotalDifficulty','confirmationTimestamp']);
}

function sameAddress(left, right) {
  try { return getAddress(left) === getAddress(right); } catch { return false; }
}

function sameHash(left, right) {
  return bytes32Pattern.test(left ?? '') && bytes32Pattern.test(right ?? '')
    && left.toLowerCase() === right.toLowerCase();
}

function sameUint(observed, expected) {
  if (typeof observed !== 'string' || !canonicalUintPattern.test(observed)) return false;
  try {
    let expectedValue;
    if (typeof expected === 'string' && canonicalUintPattern.test(expected)) {
      expectedValue=BigInt(expected);
    } else if (typeof expected === 'number' && Number.isSafeInteger(expected) && expected >= 0) {
      expectedValue=BigInt(expected);
    } else if (typeof expected === 'bigint' && expected >= 0n) {
      expectedValue=expected;
    } else {
      return false;
    }
    return BigInt(observed) === expectedValue;
  } catch { return false; }
}

function requireFinalizedIdentity(blockers, observation) {
  if (observation?.chainId !== '1') add(blockers, 'wrong_chain', 'the observed chain ID is not Ethereum mainnet');
  if (!sameUint(observation?.finalizedBlockNumber, observation?.finalizedBlockNumber)
      || BigInt(observation.finalizedBlockNumber) < 0n) {
    add(blockers, 'finalized_block_number_invalid', 'a canonical nonnegative finalized block number is required');
  }
  if (!bytes32Pattern.test(observation?.finalizedBlockHash ?? '')
      || observation.finalizedBlockHash.toLowerCase() === zeroHash) {
    add(blockers, 'finalized_block_hash_invalid', 'a nonzero finalized block hash is required');
  }
  if (!sameHash(observation?.snapshotBlockHashAfter,observation?.finalizedBlockHash)) {
    add(blockers,'finalized_snapshot_changed',
      'the fixed finalized block hash changed or was unavailable during observation');
  }
}

function requireLiveIdentities(blockers, release, observation) {
  for (const role of ['token','verifier','governance','guardian']) {
    const expected = release?.[`${role}CodeHash`];
    if (!sameHash(observation?.codeHashes?.[role], expected)) {
      add(blockers, `${role}_codehash_mismatch`, `${role} runtime code hash differs from the release`);
    }
  }
  if (!sameHash(observation?.verifierConfigHash, release?.verifierConfigHash)) {
    add(blockers, 'verifier_config_mismatch', 'the live verifier configuration differs from the release');
  }
  for (const role of ['checkpointVerifier','checkpointGuardian']) {
    const expected = release?.[`${role}CodeHash`];
    if (!sameHash(observation?.codeHashes?.[role], expected)) {
      add(blockers, `${role}_codehash_mismatch`, `${role} runtime code hash differs from the release`);
    }
  }
  if (!sameHash(observation?.checkpointVerifierConfigHash, release?.checkpointVerifierConfigHash)) {
    add(blockers, 'checkpoint_verifier_config_mismatch',
      'the live checkpoint verifier configuration differs from the release');
  }
  const token = observation?.token;
  if (!sameUint(token?.decimals, 6)) add(blockers, 'token_decimals_invalid', 'USDT decimals must equal six');
  if (token?.paused !== false) add(blockers, 'token_paused', 'USDT is paused or its status was not observed');
  if (token?.deprecated !== false) add(blockers, 'token_deprecated', 'USDT is deprecated or its status was not observed');
  if (!sameUint(token?.basisPointsRate, 0)) add(blockers, 'token_fee_rate_nonzero', 'USDT basis-points fee must be zero');
  if (!sameUint(token?.maximumFee, 0)) add(blockers, 'token_maximum_fee_nonzero', 'USDT maximum fee must be zero');
  if (token?.reserveBlacklisted !== false) add(blockers, 'reserve_blacklisted', 'the planned reserve is blacklisted by USDT');
}

function requireLiveRiscZeroVerifier(blockers,reference,observation) {
  const report=assessRiscZeroMainnetHealth({reference,observation,standalone:false});
  for(const blocker of report.blockers) add(blockers,blocker.code,blocker.detail);
}

function requireCreatePlan(blockers, release, prefix, deployerField, nonceField, addressField) {
  try {
    const expected=getCreateAddress({from:release?.[deployerField],nonce:BigInt(release?.[nonceField])});
    if (!sameAddress(expected,release?.[addressField])) {
      add(blockers, `${prefix}_address_invalid`, `${prefix} address does not match deployer and nonce`);
    }
  } catch {
    add(blockers, `${prefix}_address_invalid`, `${prefix} deployer, nonce or address is invalid`);
  }
}

function requireDeployment(blockers, deployment, release, {
  prefix,deployerField,nonceField,addressField,initcodeField,
}, finalizedBlockNumber) {
  if (deployment?.status !== true) add(blockers, `${prefix}_deployment_failed`, 'the deployment receipt was not successful');
  if (!sameAddress(deployment?.from, release?.[deployerField])) {
    add(blockers, `${prefix}_deployment_sender_mismatch`, 'deployment sender differs from the release plan');
  }
  if (!sameUint(deployment?.nonce, release?.[nonceField])) {
    add(blockers, `${prefix}_deployment_nonce_mismatch`, 'deployment nonce differs from the release plan');
  }
  if (!sameAddress(deployment?.creates, release?.[addressField])) {
    add(blockers, `${prefix}_deployment_address_mismatch`, 'deployment did not create the planned address');
  }
  if (!sameAddress(deployment?.derivedCreateAddress, release?.[addressField])) {
    add(blockers, `${prefix}_deployment_derived_address_mismatch`,
      'transaction sender and nonce do not derive the planned CREATE address');
  }
  if (deployment?.to!==null) add(blockers, `${prefix}_deployment_not_contract_creation`, 'deployment transaction has a destination');
  if (!sameUint(deployment?.value,0)) add(blockers, `${prefix}_deployment_value_nonzero`, 'deployment transaction value must be zero');
  if (!sameHash(deployment?.inputHash,release?.[initcodeField])) {
    add(blockers, `${prefix}_deployment_initcode_mismatch`, 'deployment input differs from the approved initcode');
  }
  if (!bytes32Pattern.test(deployment?.transactionHash??'')
      || deployment.transactionHash.toLowerCase()===zeroHash) {
    add(blockers,`${prefix}_deployment_transaction_hash_invalid`,
      'deployment transaction hash must be a canonical nonzero bytes32 identifier');
  }
  if (!sameHash(deployment?.blockHash, deployment?.canonicalBlockHash)) {
    add(blockers, `${prefix}_deployment_block_noncanonical`, 'deployment receipt is not in the canonical observed block');
  }
  if (!sameUint(deployment?.blockNumber, deployment?.blockNumber)
      || !sameUint(finalizedBlockNumber, finalizedBlockNumber)
      || BigInt(deployment.blockNumber) > BigInt(finalizedBlockNumber)) {
    add(blockers, `${prefix}_deployment_not_finalized`, 'deployment block is not at or below the observed finalized head');
  }
}

function requireReserveGetter(blockers, reserve, name, expected, comparison = 'hash') {
  const actual = reserve?.[name];
  const matches = comparison === 'address' ? sameAddress(actual, expected)
    : comparison === 'uint' ? sameUint(actual, expected) : sameHash(actual, expected);
  if (!matches) add(blockers, `reserve_${name}_mismatch`, `reserve ${name} differs from the release`);
}

function requireRegistryGetter(blockers, registry, name, expected, comparison = 'hash') {
  const actual = registry?.[name];
  const matches = comparison === 'address' ? sameAddress(actual, expected)
    : comparison === 'uint' ? sameUint(actual, expected) : sameHash(actual, expected);
  if (!matches) add(blockers, `checkpoint_registry_${name}_mismatch`,
    `checkpoint registry ${name} differs from the release`);
}

export function assessMainnetPreflight({phase, releaseConfig, observation, riscZeroReference}) {
  if (!['predeployment','postdeployment'].includes(phase)) {
    throw new Error('phase must be predeployment or postdeployment');
  }
  const blockers = [];
  requireObservationSchema(blockers,phase,observation);
  if (releaseConfig?.ethereumChainId !== '1' || releaseConfig?.deploymentMethod !== 'CREATE') {
    add(blockers, 'release_plan_invalid', 'preflight requires an Ethereum mainnet CREATE release plan');
  } else {
    requireCreatePlan(blockers,releaseConfig,'release_verifier','verifierDeployer',
      'verifierDeployerNonce','verifier');
    requireCreatePlan(blockers,releaseConfig,'release_checkpoint_verifier','checkpointVerifierDeployer',
      'checkpointVerifierDeployerNonce','checkpointVerifier');
    requireCreatePlan(blockers,releaseConfig,'release_reserve','deployer','deployerNonce','reserve');
    requireCreatePlan(blockers,releaseConfig,'release_checkpoint_registry','checkpointRegistryDeployer',
      'checkpointRegistryDeployerNonce','checkpointRegistry');
  }
  requireFinalizedIdentity(blockers, observation);
  requireLiveIdentities(blockers, releaseConfig, observation);
  requireLiveRiscZeroVerifier(blockers,riscZeroReference,observation);
  requireDeployment(blockers,observation?.finalizedBurnVerifierDeployment,releaseConfig,{
    prefix:'finalized_burn_verifier',deployerField:'verifierDeployer',
    nonceField:'verifierDeployerNonce',addressField:'verifier',initcodeField:'verifierInitcodeHash',
  },observation?.finalizedBlockNumber);
  requireDeployment(blockers,observation?.checkpointVerifierDeployment,releaseConfig,{
    prefix:'checkpoint_verifier',deployerField:'checkpointVerifierDeployer',
    nonceField:'checkpointVerifierDeployerNonce',addressField:'checkpointVerifier',
    initcodeField:'checkpointVerifierInitcodeHash',
  },observation?.finalizedBlockNumber);

  if (phase === 'predeployment') {
    if (!sameUint(observation?.deployerNonce, releaseConfig?.deployerNonce)) {
      add(blockers, 'deployer_nonce_mismatch', 'the finalized deployer nonce differs from the release plan');
    }
    if (!sameUint(observation?.checkpointRegistryDeployerNonce,
      releaseConfig?.checkpointRegistryDeployerNonce)) {
      add(blockers, 'checkpoint_registry_deployer_nonce_mismatch',
        'the finalized checkpoint registry deployer nonce differs from the release plan');
    }
    if (!sameHash(observation?.codeHashes?.reserve, EMPTY_CODE_HASH)) {
      add(blockers, 'reserve_address_occupied', 'the planned reserve address already contains code');
    }
    if (!sameHash(observation?.codeHashes?.checkpointRegistry, EMPTY_CODE_HASH)) {
      add(blockers, 'checkpoint_registry_address_occupied',
        'the planned checkpoint registry address already contains code');
    }
    if (!sameUint(observation?.token?.reserveBalance, 0)) {
      add(blockers, 'reserve_preloaded', 'the planned reserve address already holds USDT');
    }
  } else {
    if (!sameHash(observation?.codeHashes?.reserve, releaseConfig?.reserveRuntimeCodeHash)) {
      add(blockers, 'reserve_runtime_codehash_mismatch', 'deployed reserve runtime code differs from the release');
    }
    if (!sameHash(observation?.codeHashes?.checkpointRegistry,
      releaseConfig?.checkpointRegistryRuntimeCodeHash)) {
      add(blockers, 'checkpoint_registry_runtime_codehash_mismatch',
        'deployed checkpoint registry runtime code differs from the release');
    }
    requireDeployment(blockers,observation?.deployment,releaseConfig,{
      prefix:'reserve',deployerField:'deployer',nonceField:'deployerNonce',addressField:'reserve',
      initcodeField:'reserveInitcodeHash',
    },observation?.finalizedBlockNumber);
    requireDeployment(blockers,observation?.checkpointRegistryDeployment,releaseConfig,{
      prefix:'checkpoint_registry',deployerField:'checkpointRegistryDeployer',
      nonceField:'checkpointRegistryDeployerNonce',addressField:'checkpointRegistry',
      initcodeField:'checkpointRegistryInitcodeHash',
    },observation?.finalizedBlockNumber);
    const checkpointDeployment=observation?.checkpointRegistryDeployment;
    if (!sameUint(checkpointDeployment?.checkpointEventCount,1)) {
      add(blockers,'checkpoint_registry_bootstrap_event_count_invalid',
        'registry deployment must emit exactly one checkpoint bootstrap event');
    }
    const checkpointEvent=checkpointDeployment?.checkpointEvent;
    if (!sameAddress(checkpointEvent?.address,releaseConfig?.checkpointRegistry)) {
      add(blockers,'checkpoint_registry_bootstrap_event_address_mismatch',
        'checkpoint bootstrap event was not emitted by the approved registry');
    }
    for (const [name,field] of Object.entries({
      bridgeDomain:'domDomain',domBlock:'checkpointInitialBlock',domStateRoot:'checkpointInitialStateRoot',
      checkpointConfigHash:'checkpointRegistryConfigHash',
    })) {
      if (!sameHash(checkpointEvent?.[name],releaseConfig?.[field])) {
        add(blockers,`checkpoint_registry_bootstrap_event_${name}_mismatch`,
          `checkpoint bootstrap event ${name} differs from the release`);
      }
    }
    for (const [name,field] of Object.entries({
      domNetworkMagic:'checkpointDomNetworkMagic',domHeight:'checkpointInitialHeight',
    })) {
      if (!sameUint(checkpointEvent?.[name],releaseConfig?.[field])) {
        add(blockers,`checkpoint_registry_bootstrap_event_${name}_mismatch`,
          `checkpoint bootstrap event ${name} differs from the release`);
      }
    }

    const reserve = observation?.reserve;
    for (const name of ['token','verifier','governance','guardian']) {
      requireReserveGetter(blockers, reserve, name, releaseConfig?.[name], 'address');
    }
    for (const name of ['tokenCodeHash','verifierCodeHash','verifierConfigHash','reserveConfigHash','domDomain',
      'activationScheduleCommitment',
      'governanceCodeHash','guardianCodeHash']) {
      requireReserveGetter(blockers, reserve, name, releaseConfig?.[name]);
    }
    const uintFields = {
      withdrawalDelay:'withdrawalDelaySeconds',governanceDelay:'governanceDelaySeconds',
      maxOutstanding:'maxOutstandingBaseUnits',outflowCapacity:'outflowCapacityBaseUnitsPerDay',
    };
    for (const [getter,field] of Object.entries(uintFields)) {
      requireReserveGetter(blockers, reserve, getter, releaseConfig?.[field], 'uint');
    }
    if (reserve?.paused !== true) add(blockers, 'reserve_not_paused', 'a mainnet deployment must remain paused');
    for (const [name,expected] of Object.entries({queueEpoch:1,resumeReadyAt:0,totalDeposited:0,totalReleased:0,
      totalPendingAmount:0,pendingCount:0})) {
      if (!sameUint(reserve?.[name], expected)) add(blockers, `reserve_${name}_unsafe`, `reserve ${name} is not ${expected}`);
    }
    if (!sameUint(observation?.token?.reserveBalance, 0)) {
      add(blockers, 'reserve_balance_nonzero', 'cold-start reserve unexpectedly holds USDT');
    }

    const registry=observation?.checkpointRegistry;
    for (const [name,field] of Object.entries({
      checkpointConfigHash:'checkpointRegistryConfigHash',bridgeDomain:'domDomain',
      domChainId:'checkpointDomChainId',activationEmptyStateRoot:'checkpointActivationEmptyStateRoot',
      activationScheduleCommitment:'activationScheduleCommitment',
      verifierCodeHash:'checkpointVerifierCodeHash',verifierConfigHash:'checkpointVerifierConfigHash',
      guardianCodeHash:'checkpointGuardianCodeHash',latestBlock:'checkpointInitialBlock',
      latestStateRoot:'checkpointInitialStateRoot',latestContextHash:'checkpointInitialContextHash',
    })) requireRegistryGetter(blockers,registry,name,releaseConfig?.[field]);
    for (const [name,field] of Object.entries({
      verifier:'checkpointVerifier',guardian:'checkpointGuardian',
    })) requireRegistryGetter(blockers,registry,name,releaseConfig?.[field],'address');
    for (const [name,field] of Object.entries({
      domNetworkMagic:'checkpointDomNetworkMagic',firstV4Height:'checkpointFirstV4Height',
      checkpointInterval:'checkpointIntervalBlocks',confirmationDepth:'checkpointConfirmationDepthBlocks',
      challengePeriod:'checkpointChallengePeriodSeconds',latestHeight:'checkpointInitialHeight',
      latestTotalDifficulty:'checkpointInitialTotalDifficulty',
    })) requireRegistryGetter(blockers,registry,name,releaseConfig?.[field],'uint');
    if (!sameUint(registry?.checkpointCount,1)) {
      add(blockers,'checkpoint_registry_checkpointCount_unsafe','checkpoint registry must contain only the ratified bootstrap');
    }
    if (registry?.halted !== false) {
      add(blockers,'checkpoint_registry_halted','checkpoint registry is halted or its status was not observed');
    }
    const candidate=observation?.checkpointRegistryCandidate;
    for (const name of ['statementHash','blockHash','stateRoot','contextHash','confirmationBlock']) {
      if (!sameHash(candidate?.[name],zeroHash)) {
        add(blockers,`checkpoint_registry_candidate_${name}_unsafe`,
          `checkpoint registry pending candidate ${name} is not zero`);
      }
    }
    for (const name of ['height','readyAt','totalDifficulty','confirmationHeight','confirmationTotalDifficulty',
      'confirmationTimestamp']) {
      if (!sameUint(candidate?.[name],0)) {
        add(blockers,`checkpoint_registry_candidate_${name}_unsafe`,
          `checkpoint registry pending candidate ${name} is not zero`);
      }
    }
    if (!sameHash(observation?.checkpointRegistrySlot0,releaseConfig?.checkpointRegistryConfigHash)) {
      add(blockers,'checkpoint_registry_slot0_mismatch',
        'checkpoint registry storage slot zero differs from the approved configuration hash');
    }
  }

  return {phase,ready:blockers.length === 0,blockerCount:blockers.length,blockers,
    finalizedBlockNumber:observation?.finalizedBlockNumber ?? null,
    finalizedBlockHash:observation?.finalizedBlockHash ?? null};
}
