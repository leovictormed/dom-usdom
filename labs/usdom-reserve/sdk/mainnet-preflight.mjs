import {getAddress,getCreateAddress} from 'ethers';
import {assessRiscZeroMainnetHealth} from './risc0-health.mjs';
import {SAFE_MAINNET_IDENTITY} from './safe-control-deployment.mjs';
import {safeOwnersCommitment} from './configuration.mjs';
import {FINALIZED_BURN_PROOF_ACCEPTED_HASH} from './verifier-config.mjs';
import {CHECKPOINT_PROOF_ACCEPTED_HASH} from './checkpoint-verifier-config.mjs';
import {validateMainnetDeploymentTopology} from './mainnet-deployment-identity.mjs';

export const EMPTY_CODE_HASH = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
export const ETHEREUM_MAINNET_USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
export const ETHEREUM_MAINNET_USDT_CODE_HASH =
  '0xb44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55';
export const ETHEREUM_MAINNET_GENESIS_BLOCK_HASH =
  '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
const zeroHash = '0x' + '00'.repeat(32);
const bytes32Pattern = /^0x[0-9a-fA-F]{64}$/;
// uint256 has at most 78 decimal digits. The lexical cap rejects oversized
// hostile inputs before BigInt performs work proportional to an arbitrary JSON
// string; the numeric bound then rejects the unused top of that digit range.
const canonicalUintPattern = /^(0|[1-9][0-9]{0,77})$/;

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
  const common=['chainId','genesisBlockHash','finalizedBlockNumber','finalizedBlockHash','snapshotBlockHashAfter',
    'deployerNonce','checkpointRegistryDeployerNonce','codeHashes','verifierConfigHash',
    'checkpointVerifierConfigHash','verifierProofAccepted','checkpointVerifierProofAccepted',
    'finalizedBurnVerifier','checkpointVerifier','riscZeroVerifier','riscZeroEmergencyStop','token',
    'controlPlaneImplementations','controlPlanePolicies','finalizedBurnVerifierDeployment',
    'checkpointVerifierDeployment'];
  const post=['deployment','checkpointRegistryDeployment','reserve','checkpointRegistry',
    'checkpointRegistryCandidate','checkpointRegistrySlot0'];
  requireExactKeys(blockers,observation,'observation_schema_invalid',
    phase==='postdeployment'?[...common,...post]:common);
  requireExactKeys(blockers,observation?.codeHashes,'observation_code_hashes_schema_invalid',
    ['reserve','token','verifier','governance','guardian','checkpointRegistry','checkpointVerifier',
      'checkpointGuardian','governanceImplementation','guardianImplementation',
      'checkpointGuardianImplementation']);
  requireExactKeys(blockers,observation?.riscZeroVerifier,'observation_risc0_verifier_schema_invalid',
    ['address','codeHash','selector','version']);
  for(const role of ['finalizedBurnVerifier','checkpointVerifier']) {
    requireExactKeys(blockers,observation?.[role],`observation_${role}_schema_invalid`,
      ['address','riscZeroVerifier','riscZeroVerifierCodeHash','verifierSelector','imageId',
        'deploymentChainId','verifierConfigHash','proofAccepted']);
  }
  requireExactKeys(blockers,observation?.riscZeroEmergencyStop,'observation_risc0_estop_schema_invalid',
    ['address','codeHash','paused','verifier']);
  requireExactKeys(blockers,observation?.token,'observation_token_schema_invalid',
    ['name','symbol','decimals','totalSupply','owner','ownerCodeHash','paused','deprecated',
      'upgradedAddress','basisPointsRate','maximumFee','reserveBlacklisted','reserveBalance',
      'eip1967Implementation','eip1967Admin','eip1967Beacon']);
  requireExactKeys(blockers,observation?.controlPlaneImplementations,
    'observation_control_plane_implementations_schema_invalid',
    ['governance','guardian','checkpointGuardian']);
  requireExactKeys(blockers,observation?.controlPlanePolicies,
    'observation_control_plane_policies_schema_invalid',['governance','guardian','checkpointGuardian']);
  for(const role of ['governance','guardian','checkpointGuardian']) {
    requireExactKeys(blockers,observation?.controlPlanePolicies?.[role],
      `observation_${role}_policy_schema_invalid`,
      ['nonce','threshold','owners','ownerCodeHashes','modules','modulesNext','guard','fallbackHandler',
        'fallbackHandlerCodeHash']);
  }
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
      'governanceImplementation','governanceImplementationCodeHash','governanceOwnersCommitment',
      'guardianCodeHash','guardianImplementation','guardianImplementationCodeHash',
      'guardianOwnersCommitment',
      'withdrawalDelay','governanceDelay','maxOutstanding','outflowCapacity','paused',
      'pilotRestrictedDeployment','permissionlessDeposits','pilotDepositConsumed',
      'authorizedPilotDeposit','authorizedPilotSnapshot','authorizedPilotValidUntil',
      'pilotAuthorizationGeneration','permissionlessDepositsReadyAt',
      'depositsClosed','gracefullyShutdown','resumeReadyAt','totalDeposited','totalReleased','pendingQueue',
      'outstanding','unreservedCollateral','availableOutflow','totalProvedDebtAmount','controlPlaneHealthy']);
  requireExactKeys(blockers,observation?.reserve?.pendingQueue,'reserve_pending_queue_schema_invalid',
    ['epoch','count','amount','firstBurnId','lastBurnId']);
  requireExactKeys(blockers,observation?.checkpointRegistry,'checkpoint_registry_observation_schema_invalid',
    ['checkpointConfigHash','bridgeDomain','domNetworkMagic','domChainId','firstV4Height',
      'activationEmptyStateRoot','activationScheduleCommitment','checkpointInterval','confirmationDepth',
      'challengePeriod','verifier','verifierCodeHash','verifierConfigHash','guardian','guardianCodeHash',
      'guardianImplementation','guardianImplementationCodeHash','guardianOwnersCommitment',
      'latestHeight','checkpointCount','halted','gracefullyShutdown','latestIssuanceClosed','latestBlock',
      'latestStateRoot','latestContextHash','latestTotalDifficulty','latestTotalIssued','latestTotalBurned',
      'previousTotalIssued','previousTotalBurned','guardianControlHealthy']);
  requireExactKeys(blockers,observation?.checkpointRegistryCandidate,
    'checkpoint_registry_candidate_schema_invalid',
    ['statementHash','height','readyAt','blockHash','stateRoot','contextHash','totalDifficulty',
      'totalIssued','totalBurned','issuanceClosed','confirmationHeight','confirmationBlock',
      'confirmationTotalDifficulty','confirmationTimestamp']);
}

function sameAddress(left, right) {
  try { return getAddress(left) === getAddress(right); } catch { return false; }
}

function sameHash(left, right) {
  return bytes32Pattern.test(left ?? '') && bytes32Pattern.test(right ?? '')
    && left.toLowerCase() === right.toLowerCase();
}

function canonicalUint(value,bits=256) {
  if(typeof value!=='string'||!canonicalUintPattern.test(value)) return null;
  try {
    const parsed=BigInt(value);
    return parsed<(1n<<BigInt(bits))?parsed:null;
  } catch { return null; }
}

function sameUint(observed, expected) {
  const observedValue=canonicalUint(observed);
  if(observedValue===null) return false;
  let expectedValue;
  if(typeof expected==='string') expectedValue=canonicalUint(expected);
  else if(typeof expected==='number'&&Number.isSafeInteger(expected)&&expected>=0) {
    expectedValue=BigInt(expected);
  } else if(typeof expected==='bigint'&&expected>=0n&&expected<(1n<<256n)) {
    expectedValue=expected;
  } else return false;
  return expectedValue!==null&&observedValue===expectedValue;
}

function requireFinalizedIdentity(blockers, observation) {
  if (observation?.chainId !== '1') add(blockers, 'wrong_chain', 'the observed chain ID is not Ethereum mainnet');
  if (!sameHash(observation?.genesisBlockHash,ETHEREUM_MAINNET_GENESIS_BLOCK_HASH)) {
    add(blockers,'wrong_genesis','the observed execution genesis is not Ethereum mainnet');
  }
  if(canonicalUint(observation?.finalizedBlockNumber,64)===null) {
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
  if (!sameAddress(release?.token,ETHEREUM_MAINNET_USDT)
      || !sameHash(release?.tokenCodeHash,ETHEREUM_MAINNET_USDT_CODE_HASH)) {
    add(blockers,'release_token_identity_invalid',
      'the release must bind the canonical Ethereum mainnet USDT address and runtime code hash');
  }
  const expectedOwnersByRole={};
  for(const role of ['governance','guardian','checkpointGuardian']) {
    expectedOwnersByRole[role]=(release?.[`${role}Owners`]??[]).map(value=>{
      try{return getAddress(value);}catch{return null;}
    });
    if(expectedOwnersByRole[role].length!==3||expectedOwnersByRole[role].includes(null)
        ||new Set(expectedOwnersByRole[role]).size!==3) add(blockers,`release_${role}_owners_invalid`,
      `${role} must bind three distinct owners`);
  }
  const safeAddresses=['governance','guardian','checkpointGuardian'].map(role=>release?.[role]);
  if(safeAddresses.some((safe,index)=>safeAddresses.some((other,otherIndex)=>
    otherIndex<index && sameAddress(safe,other)))) {
    add(blockers,'release_control_plane_safe_reuse','governance, guardian and checkpoint guardian Safes must differ');
  }
  const isolatedRoles=['reserve','token','verifier','checkpointVerifier','checkpointRegistry',
    'governance','guardian','checkpointGuardian'];
  const normalizedRoles=isolatedRoles.map(role=>{
    try{return getAddress(release?.[role]);}catch{return null;}
  });
  if(normalizedRoles.includes(null)||new Set(normalizedRoles).size!==isolatedRoles.length) {
    add(blockers,'release_contract_role_separation_invalid',
      'reserve, token, adapters, registry and all control roles must use distinct addresses');
  }
  for (const role of ['token','verifier','governance','governanceImplementation','guardian','guardianImplementation']) {
    const expected = release?.[`${role}CodeHash`];
    if (!sameHash(observation?.codeHashes?.[role], expected)) {
      add(blockers, `${role}_codehash_mismatch`, `${role} runtime code hash differs from the release`);
    }
  }
  if (!sameHash(observation?.verifierConfigHash, release?.verifierConfigHash)) {
    add(blockers, 'verifier_config_mismatch', 'the live verifier configuration differs from the release');
  }
  for (const role of ['checkpointVerifier','checkpointGuardian','checkpointGuardianImplementation']) {
    const expected = release?.[`${role}CodeHash`];
    if (!sameHash(observation?.codeHashes?.[role], expected)) {
      add(blockers, `${role}_codehash_mismatch`, `${role} runtime code hash differs from the release`);
    }
  }
  if (!sameHash(observation?.checkpointVerifierConfigHash, release?.checkpointVerifierConfigHash)) {
    add(blockers, 'checkpoint_verifier_config_mismatch',
      'the live checkpoint verifier configuration differs from the release');
  }
  if (!sameHash(observation?.verifierProofAccepted,FINALIZED_BURN_PROOF_ACCEPTED_HASH)) {
    add(blockers,'verifier_capability_mismatch',
      'the finalized-burn adapter does not expose the required runtime capability');
  }
  if (!sameHash(observation?.checkpointVerifierProofAccepted,CHECKPOINT_PROOF_ACCEPTED_HASH)) {
    add(blockers,'checkpoint_verifier_capability_mismatch',
      'the checkpoint adapter does not expose the required runtime capability');
  }
  for(const [role,addressField,configField,accepted] of [
    ['finalizedBurnVerifier','verifier','verifierConfigHash',FINALIZED_BURN_PROOF_ACCEPTED_HASH],
    ['checkpointVerifier','checkpointVerifier','checkpointVerifierConfigHash',CHECKPOINT_PROOF_ACCEPTED_HASH],
  ]) {
    const adapter=observation?.[role];
    if(!sameAddress(adapter?.address,release?.[addressField])
        ||!sameAddress(adapter?.riscZeroVerifier,observation?.riscZeroVerifier?.address)
        ||!sameHash(adapter?.riscZeroVerifierCodeHash,observation?.riscZeroVerifier?.codeHash)
        ||String(adapter?.verifierSelector).toLowerCase()!==String(observation?.riscZeroVerifier?.selector).toLowerCase()
        ||!sameUint(adapter?.deploymentChainId,release?.ethereumChainId)
        ||!sameHash(adapter?.verifierConfigHash,release?.[configField])
        ||!sameHash(adapter?.proofAccepted,accepted)
        ||!bytes32Pattern.test(adapter?.imageId??'')||adapter.imageId.toLowerCase()===zeroHash) {
      add(blockers,`${role}_initial_state_mismatch`,
        `${role} immutable constructor state differs from the exact release and RISC Zero authority`);
    }
  }
  // The adapter ABI and acceptance magic are bookkeeping capabilities, not a
  // cryptographic domain separator. If both adapters share one ImageID then an
  // identical (seal, statement journal) tuple is valid in both proof domains.
  // Require independent guest programs at the observed immutable boundary.
  if(sameHash(observation?.finalizedBurnVerifier?.imageId,
    observation?.checkpointVerifier?.imageId)) {
    add(blockers,'risc0_adapter_image_capability_collision',
      'finalized-burn and checkpoint adapters must use distinct guest ImageIDs');
  }
  for (const role of ['governance','guardian','checkpointGuardian']) {
    const expectedOwners=expectedOwnersByRole[role];
    if (!sameAddress(observation?.controlPlaneImplementations?.[role],release?.[`${role}Implementation`])) {
      add(blockers,`${role}_implementation_mismatch`,
        `${role} proxy implementation differs from the release at the finalized snapshot`);
    }
    const policy=observation?.controlPlanePolicies?.[role];
    if(!sameUint(policy?.nonce,0)) {
      add(blockers,`${role}_nonce_not_zero`,`${role} Safe must have nonce zero before the first authorized operation`);
    }
    if (!sameUint(policy?.threshold,2)) {
      add(blockers,`${role}_threshold_invalid`,`${role} Safe threshold must equal two at the finalized snapshot`);
    }
    const owners=policy?.owners;
    const normalizedOwners=[];
    if (Array.isArray(owners) && owners.length===3) {
      for(const owner of owners) {
        try { normalizedOwners.push(getAddress(owner)); } catch { /* rejected below */ }
      }
    }
    if (normalizedOwners.length!==3 || new Set(normalizedOwners).size!==3
        || normalizedOwners.some(owner=>owner===getAddress('0x0000000000000000000000000000000000000000'))) {
      add(blockers,`${role}_owners_invalid`,`${role} Safe must have exactly three distinct nonzero owners`);
    }
    if(expectedOwners.length===3 && (normalizedOwners.length!==3
        || normalizedOwners.some((owner,index)=>owner!==expectedOwners[index]))) {
      add(blockers,`${role}_owners_release_mismatch`,
        `${role} Safe ordered owners differ from the exact approved release`);
    }
    if (!Array.isArray(policy?.ownerCodeHashes) || policy.ownerCodeHashes.length!==3
        || policy.ownerCodeHashes.some(codeHash=>!sameHash(codeHash,EMPTY_CODE_HASH))) {
      add(blockers,`${role}_owner_code_invalid`,`${role} Safe owners must be code-free EOAs at the finalized snapshot`);
    }
    if (!Array.isArray(policy?.modules) || policy.modules.length!==0) {
      add(blockers,`${role}_modules_enabled`,`${role} Safe must have no enabled modules`);
    }
    if (!sameAddress(policy?.modulesNext,'0x0000000000000000000000000000000000000001')) {
      add(blockers,`${role}_module_cursor_invalid`,`${role} Safe module enumeration must terminate at the sentinel`);
    }
    if (!sameAddress(policy?.guard,'0x0000000000000000000000000000000000000000')) {
      add(blockers,`${role}_guard_enabled`,`${role} Safe must have no transaction guard`);
    }
    if (!sameAddress(policy?.fallbackHandler,SAFE_MAINNET_IDENTITY.fallbackHandler)
        || !sameHash(policy?.fallbackHandlerCodeHash,SAFE_MAINNET_IDENTITY.fallbackHandlerCodeHash)) {
      add(blockers,`${role}_fallback_handler_invalid`,
        `${role} Safe fallback handler address or code differs from the pinned Safe v1.4.1 release`);
    }
  }
  const token = observation?.token;
  if (token?.name !== 'Tether USD') add(blockers,'token_name_invalid','USDT name must equal Tether USD');
  if (token?.symbol !== 'USDT') add(blockers,'token_symbol_invalid','USDT symbol must equal USDT');
  if (!sameUint(token?.decimals, 6)) add(blockers, 'token_decimals_invalid', 'USDT decimals must equal six');
  if (!sameUint(token?.totalSupply,token?.totalSupply) || BigInt(token.totalSupply) === 0n) {
    add(blockers,'token_total_supply_invalid','USDT total supply must be a positive canonical integer');
  }
  if (sameUint(token?.totalSupply,token?.totalSupply) && sameUint(token?.reserveBalance,token?.reserveBalance)
      && BigInt(token.reserveBalance) > BigInt(token.totalSupply)) {
    add(blockers,'token_balance_exceeds_supply','reserve USDT balance exceeds the observed total supply');
  }
  if (!sameAddress(token?.owner,token?.owner)
      || sameAddress(token?.owner,'0x0000000000000000000000000000000000000000')) {
    add(blockers,'token_owner_invalid','USDT legacy administrator must be a nonzero canonical address');
  }
  if (!sameHash(token?.ownerCodeHash,token?.ownerCodeHash)) {
    add(blockers,'token_owner_codehash_invalid','USDT legacy administrator code identity was not observed');
  }
  if (!sameAddress(token?.owner,release?.tokenOwner)
      || !sameHash(token?.ownerCodeHash,release?.tokenOwnerCodeHash)) {
    add(blockers,'token_owner_release_mismatch',
      'USDT legacy administrator address or code identity differs from the approved release');
  }
  if (token?.paused !== false) add(blockers, 'token_paused', 'USDT is paused or its status was not observed');
  if (token?.deprecated !== false) add(blockers, 'token_deprecated', 'USDT is deprecated or its status was not observed');
  if (!sameAddress(token?.upgradedAddress,'0x0000000000000000000000000000000000000000')) {
    add(blockers,'token_upgrade_target_nonzero','USDT legacy upgrade target must be zero');
  }
  for (const field of ['eip1967Implementation','eip1967Admin','eip1967Beacon']) {
    if (!sameHash(token?.[field],zeroHash)) {
      add(blockers,`token_${field}_nonzero`,`USDT ${field} slot must be zero for the pinned direct implementation`);
    }
  }
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
    const nonce=canonicalUint(release?.[nonceField],64);
    if(nonce===null) throw new Error('CREATE nonce is not uint64');
    const expected=getCreateAddress({from:release?.[deployerField],nonce});
    if (!sameAddress(expected,release?.[addressField])) {
      add(blockers, `${prefix}_address_invalid`, `${prefix} address does not match deployer and nonce`);
    }
  } catch {
    add(blockers, `${prefix}_address_invalid`, `${prefix} deployer, nonce or address is invalid`);
  }
}

function requireReleasedArtifacts(blockers,release) {
  const groups={
    finalized_burn_verifier:['verifierCodeHash','verifierInitcodeHash','verifierConfigHash'],
    checkpoint_verifier:['checkpointVerifierCodeHash','checkpointVerifierInitcodeHash',
      'checkpointVerifierConfigHash'],
    checkpoint_registry:['checkpointRegistryRuntimeCodeHash','checkpointRegistryInitcodeHash',
      'checkpointRegistryConfigHash'],
    reserve:['reserveRuntimeCodeHash','reserveInitcodeHash','reserveConfigHash'],
  };
  for(const [name,fields] of Object.entries(groups)) {
    for(const field of fields) {
      if(!bytes32Pattern.test(release?.[field]??'')||release[field].toLowerCase()===zeroHash) {
        add(blockers,`${name}_release_artifact_incomplete`,
          `${name} release artifact requires a nonzero ${field}`);
      }
    }
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
  if (!['predeployment','postdeployment','authority-recheck'].includes(phase)) {
    throw new Error('phase must be predeployment, postdeployment or authority-recheck');
  }
  const blockers = [];
  requireObservationSchema(blockers,phase,observation);
  if (releaseConfig?.productionReady !== true || typeof releaseConfig?.realFundsAuthorized!=='boolean'
      || releaseConfig?.ethereumChainId !== '1' || releaseConfig?.deploymentMethod !== 'CREATE') {
    add(blockers, 'release_plan_invalid', 'preflight requires an Ethereum mainnet CREATE release plan');
  } else {
    requireReleasedArtifacts(blockers,releaseConfig);
    requireCreatePlan(blockers,releaseConfig,'release_verifier','verifierDeployer',
      'verifierDeployerNonce','verifier');
    requireCreatePlan(blockers,releaseConfig,'release_checkpoint_verifier','checkpointVerifierDeployer',
      'checkpointVerifierDeployerNonce','checkpointVerifier');
    requireCreatePlan(blockers,releaseConfig,'release_reserve','deployer','deployerNonce','reserve');
    requireCreatePlan(blockers,releaseConfig,'release_checkpoint_registry','checkpointRegistryDeployer',
      'checkpointRegistryDeployerNonce','checkpointRegistry');
    try {
      const deployments=[observation?.finalizedBurnVerifierDeployment,
        observation?.checkpointVerifierDeployment];
      if(phase!=='predeployment') deployments.push(observation?.checkpointRegistryDeployment,
        observation?.deployment);
      validateMainnetDeploymentTopology(releaseConfig,{deployments});
    } catch(error) {
      add(blockers,'release_deployment_topology_invalid',error.message);
    }
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
    if (!sameUint(observation?.deployerNonce, releaseConfig?.checkpointRegistryDeployerNonce)) {
      add(blockers, 'deployer_nonce_mismatch',
        'the finalized deployer nonce differs from the next deployment in the release plan');
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
  } else if(phase==='authority-recheck') {
    if (!sameHash(observation?.codeHashes?.reserve, releaseConfig?.reserveRuntimeCodeHash)) {
      add(blockers,'reserve_runtime_codehash_mismatch','deployed reserve runtime code differs from the release');
    }
    if (!sameHash(observation?.codeHashes?.checkpointRegistry,
      releaseConfig?.checkpointRegistryRuntimeCodeHash)) {
      add(blockers,'checkpoint_registry_runtime_codehash_mismatch',
        'deployed checkpoint registry runtime code differs from the release');
    }
    if (!sameUint(observation?.token?.reserveBalance,0)) {
      add(blockers,'reserve_balance_nonzero_before_first_deposit',
        'reserve USDT balance must remain zero immediately before the first deposit signature');
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
    for (const name of ['token','verifier','governance','governanceImplementation','guardian','guardianImplementation']) {
      requireReserveGetter(blockers, reserve, name, releaseConfig?.[name], 'address');
    }
    for (const name of ['tokenCodeHash','verifierCodeHash','verifierConfigHash','reserveConfigHash','domDomain',
      'activationScheduleCommitment',
      'governanceCodeHash','governanceImplementationCodeHash','governanceOwnersCommitment',
      'guardianCodeHash','guardianImplementationCodeHash','guardianOwnersCommitment']) {
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
    if (reserve?.pilotRestrictedDeployment !== true) {
      add(blockers,'reserve_pilot_restriction_disabled',
        'a production reserve must be deployed with the immutable closed-pilot restriction');
    }
    if (reserve?.permissionlessDeposits !== false) {
      add(blockers,'reserve_permissionless_deposits_open_at_cold_start',
        'permissionless deposits must remain closed at cold start');
    }
    if (reserve?.pilotDepositConsumed !== false) {
      add(blockers,'reserve_pilot_deposit_already_consumed',
        'the one-shot pilot deposit must be unused at cold start');
    }
    for (const name of ['authorizedPilotDeposit','authorizedPilotSnapshot']) {
      if (!sameHash(reserve?.[name],zeroHash)) {
        add(blockers,`reserve_${name}_unsafe`,`${name} must be zero at cold start`);
      }
    }
    if (reserve?.depositsClosed !== false) {
      add(blockers,'reserve_deposits_closed_at_cold_start','a fresh reserve must not start with deposits closed');
    }
    if (reserve?.gracefullyShutdown !== false) {
      add(blockers,'reserve_gracefully_shutdown_at_cold_start','a fresh reserve must not start terminal');
    }
    if (reserve?.controlPlaneHealthy !== true) {
      add(blockers,'reserve_control_plane_unhealthy','the deployed reserve rejects its current control-plane identity or policy');
    }
    for (const [name,expected] of Object.entries({resumeReadyAt:0,authorizedPilotValidUntil:0,
      pilotAuthorizationGeneration:0,
      permissionlessDepositsReadyAt:0,
      totalDeposited:0,totalReleased:0,
      outstanding:0,unreservedCollateral:0,totalProvedDebtAmount:0})) {
      if (!sameUint(reserve?.[name], expected)) add(blockers, `reserve_${name}_unsafe`, `reserve ${name} is not ${expected}`);
    }
    if(!sameUint(reserve?.availableOutflow,releaseConfig?.outflowCapacityBaseUnitsPerDay)) {
      add(blockers,'reserve_bucket_not_full_at_cold_start',
        'the fresh reserve outflow bucket must equal its complete configured capacity');
    }
    for(const [name,expected] of Object.entries({epoch:1,count:0,amount:0})) {
      if(!sameUint(reserve?.pendingQueue?.[name],expected)) {
        add(blockers,`reserve_pending_queue_${name}_unsafe`,`reserve pending queue ${name} is not ${expected}`);
      }
    }
    for(const name of ['firstBurnId','lastBurnId']) {
      if(!sameHash(reserve?.pendingQueue?.[name],zeroHash)) {
        add(blockers,`reserve_pending_queue_${name}_unsafe`,`reserve pending queue ${name} is not zero at cold start`);
      }
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
      guardianCodeHash:'checkpointGuardianCodeHash',
      guardianImplementationCodeHash:'checkpointGuardianImplementationCodeHash',latestBlock:'checkpointInitialBlock',
      latestStateRoot:'checkpointInitialStateRoot',latestContextHash:'checkpointInitialContextHash',
    })) requireRegistryGetter(blockers,registry,name,releaseConfig?.[field]);
    let checkpointGuardianOwnersCommitment;
    try { checkpointGuardianOwnersCommitment=safeOwnersCommitment(releaseConfig?.checkpointGuardianOwners); }
    catch { checkpointGuardianOwnersCommitment=undefined; }
    requireRegistryGetter(blockers,registry,'guardianOwnersCommitment',checkpointGuardianOwnersCommitment);
    for (const [name,field] of Object.entries({
      verifier:'checkpointVerifier',guardian:'checkpointGuardian',
      guardianImplementation:'checkpointGuardianImplementation',
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
    if (registry?.gracefullyShutdown !== false || registry?.latestIssuanceClosed !== false) {
      add(blockers,'checkpoint_registry_terminal_at_cold_start',
        'checkpoint registry terminal or issuance-closure state must be false at cold start');
    }
    for (const name of ['latestTotalIssued','latestTotalBurned','previousTotalIssued','previousTotalBurned']) {
      if (!sameUint(registry?.[name],0)) {
        add(blockers,`checkpoint_registry_${name}_unsafe`,`checkpoint registry ${name} is not zero at cold start`);
      }
    }
    if (registry?.guardianControlHealthy !== true) {
      add(blockers,'checkpoint_registry_guardian_unhealthy',
        'the deployed checkpoint registry rejects its current guardian identity or policy');
    }
    const candidate=observation?.checkpointRegistryCandidate;
    for (const name of ['statementHash','blockHash','stateRoot','contextHash','confirmationBlock']) {
      if (!sameHash(candidate?.[name],zeroHash)) {
        add(blockers,`checkpoint_registry_candidate_${name}_unsafe`,
          `checkpoint registry pending candidate ${name} is not zero`);
      }
    }
    for (const name of ['height','readyAt','totalDifficulty','totalIssued','totalBurned','confirmationHeight','confirmationTotalDifficulty',
      'confirmationTimestamp']) {
      if (!sameUint(candidate?.[name],0)) {
        add(blockers,`checkpoint_registry_candidate_${name}_unsafe`,
          `checkpoint registry pending candidate ${name} is not zero`);
      }
    }
    if (candidate?.issuanceClosed !== false) {
      add(blockers,'checkpoint_registry_candidate_issuance_closed_unsafe',
        'checkpoint registry pending candidate issuance closure is not false');
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
