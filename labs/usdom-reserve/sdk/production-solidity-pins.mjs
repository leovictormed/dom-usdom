import {checkpointRegistryPreActivationConfigHash} from './checkpoint-registry.mjs';
import {proofReservePreActivationConfigHash,safeOwnersCommitment} from './configuration.mjs';

const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;

const specifications=Object.freeze({
  reserve:Object.freeze({
    contract:'USDOMProofReserve',
    fields:Object.freeze({
      PRODUCTION_VERIFIER_CODE_HASH:'verifierCodeHash',
      PRODUCTION_VERIFIER_CONFIG_HASH:'verifierConfigHash',
      PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH:'reservePreActivationConfigHash',
    }),
  }),
  checkpointRegistry:Object.freeze({
    contract:'DOMCheckpointRegistry',
    fields:Object.freeze({
      PRODUCTION_VERIFIER_CODE_HASH:'checkpointVerifierCodeHash',
      PRODUCTION_VERIFIER_CONFIG_HASH:'checkpointVerifierConfigHash',
      PRODUCTION_CHECKPOINT_CONFIG_HASH:'checkpointRegistryConfigHash',
    }),
  }),
});

function requireHash(value,label) {
  if(!bytes32Pattern.test(value??'')||value.toLowerCase()==='0x'+'00'.repeat(32)) {
    throw new Error(`${label} must be a nonzero bytes32 release value`);
  }
  return value.toLowerCase();
}

function replacePin(source,constant,value) {
  const declaration=new RegExp(`(bytes32\\s+public\\s+constant\\s+${constant}\\s*=\\s*)(?:bytes32\\(0\\)|0x[0-9a-fA-F]{64})(\\s*;)`,'g');
  const matches=[...source.matchAll(declaration)];
  if(matches.length!==1) throw new Error(`${constant} must have exactly one canonical declaration`);
  const current=matches[0][0].match(/(?:bytes32\(0\)|0x[0-9a-fA-F]{64})(?=\s*;)/)?.[0];
  if(current!=='bytes32(0)'&&current?.toLowerCase()!==value) {
    throw new Error(`${constant} already differs from the exact release`);
  }
  return source.replace(declaration,(_match,prefix,suffix)=>`${prefix}${value}${suffix}`);
}

function materializeOne({source,releaseConfig,specification}) {
  if(typeof source!=='string'||!source.includes(`contract ${specification.contract}`)) {
    throw new Error(`${specification.contract} source is invalid`);
  }
  let result=source;
  for(const [constant,field] of Object.entries(specification.fields)) {
    result=replacePin(result,constant,requireHash(releaseConfig[field],field));
  }
  return result;
}

/** Materialize only compile-time mainnet pins. The caller owns durable writes.
 * This transformation cannot authorize production, deployment or real funds. */
export function materializeProductionSolidityPins({releaseConfig,reserveSource,checkpointRegistrySource}) {
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)
      ||releaseConfig.ethereumChainId!=='1'||releaseConfig.productionReady!==false
      ||releaseConfig.realFundsAuthorized!==false) {
    throw new Error('production pins require the unapproved Ethereum mainnet release');
  }
  const reserve=proofReservePreActivationConfigHash({
    ethereumChainId:releaseConfig.ethereumChainId,reserve:releaseConfig.reserve,token:releaseConfig.token,
    tokenCodeHash:releaseConfig.tokenCodeHash,verifier:releaseConfig.verifier,
    verifierCodeHash:releaseConfig.verifierCodeHash,verifierConfigHash:releaseConfig.verifierConfigHash,
    checkpointRegistry:releaseConfig.checkpointRegistry,
    checkpointRegistryRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,
    checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
    domDomain:releaseConfig.domDomain,
    governance:releaseConfig.governance,governanceCodeHash:releaseConfig.governanceCodeHash,
    governanceImplementation:releaseConfig.governanceImplementation,
    governanceImplementationCodeHash:releaseConfig.governanceImplementationCodeHash,
    governanceOwnersCommitment:releaseConfig.governanceOwnersCommitment,
    guardian:releaseConfig.guardian,guardianCodeHash:releaseConfig.guardianCodeHash,
    guardianImplementation:releaseConfig.guardianImplementation,
    guardianImplementationCodeHash:releaseConfig.guardianImplementationCodeHash,
    guardianOwnersCommitment:releaseConfig.guardianOwnersCommitment,
    withdrawalDelaySeconds:releaseConfig.withdrawalDelaySeconds,
    governanceDelaySeconds:releaseConfig.governanceDelaySeconds,
    maxOutstandingBaseUnits:releaseConfig.maxOutstandingBaseUnits,
    outflowCapacityBaseUnitsPerDay:releaseConfig.outflowCapacityBaseUnitsPerDay,
  });
  const registry=checkpointRegistryPreActivationConfigHash({
    ethereumChainId:releaseConfig.ethereumChainId,registry:releaseConfig.checkpointRegistry,
    bridgeDomain:releaseConfig.domDomain,domNetworkMagic:releaseConfig.checkpointDomNetworkMagic,
    domChainId:releaseConfig.checkpointDomChainId,firstV4Height:releaseConfig.checkpointFirstV4Height,
    checkpointInterval:releaseConfig.checkpointIntervalBlocks,
    confirmationDepth:releaseConfig.checkpointConfirmationDepthBlocks,
    challengePeriod:releaseConfig.checkpointChallengePeriodSeconds,verifier:releaseConfig.checkpointVerifier,
    verifierCodeHash:releaseConfig.checkpointVerifierCodeHash,
    verifierConfigHash:releaseConfig.checkpointVerifierConfigHash,guardian:releaseConfig.checkpointGuardian,
    guardianCodeHash:releaseConfig.checkpointGuardianCodeHash,
    guardianImplementation:releaseConfig.checkpointGuardianImplementation,
    guardianImplementationCodeHash:releaseConfig.checkpointGuardianImplementationCodeHash,
    guardianOwnersCommitment:safeOwnersCommitment(releaseConfig.checkpointGuardianOwners),
    initialHeight:releaseConfig.checkpointInitialHeight,initialBlock:releaseConfig.checkpointInitialBlock,
    initialContextHash:releaseConfig.checkpointInitialContextHash,
    initialTotalDifficulty:releaseConfig.checkpointInitialTotalDifficulty,
  });
  const pins={...releaseConfig,reservePreActivationConfigHash:reserve.reservePreActivationConfigHash,
    checkpointRegistryConfigHash:registry.checkpointConfigHash};
  return Object.freeze({
    reserveSource:materializeOne({source:reserveSource,releaseConfig:pins,specification:specifications.reserve}),
    checkpointRegistrySource:materializeOne({source:checkpointRegistrySource,releaseConfig:pins,
      specification:specifications.checkpointRegistry}),
  });
}
