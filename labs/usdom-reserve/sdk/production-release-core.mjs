import {checkpointRegistryConfigHash} from './checkpoint-registry.mjs';
import {proofReserveDeploymentConfigHash,safeOwnersCommitment} from './configuration.mjs';

export const NATIVE_RELEASE_FACTS_SCHEMA='usdom-native-release-facts-v1';
const factFields=Object.freeze([
  'schema','nativeEthereumTrustedCheckpoint','domDomain','activationScheduleCommitment',
  'checkpointDomNetworkMagic','checkpointDomChainId','checkpointFirstV4Height',
  'checkpointActivationEmptyStateRoot','checkpointIntervalBlocks','checkpointConfirmationDepthBlocks',
  'checkpointChallengePeriodSeconds','checkpointInitialHeight','checkpointInitialBlock',
  'checkpointInitialStateRoot','checkpointInitialContextHash','checkpointInitialTotalDifficulty',
]);
const hashPattern=/^0x[0-9a-fA-F]{64}$/;

function exact(value,fields,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||Object.keys(value).length!==fields.length||fields.some(field=>!(field in value))) {
    throw new Error(`${label} must use the exact supported schema`);
  }
}
function hash(value,label) {
  if(!hashPattern.test(value??'')||value.toLowerCase()==='0x'+'00'.repeat(32)) {
    throw new Error(`${label} must be nonzero bytes32`);
  }
  return value.toLowerCase();
}
function decimal(value,bits,label) {
  if(typeof value!=='string'||!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed=BigInt(value);
  if(parsed>=(1n<<BigInt(bits))) throw new Error(`${label} exceeds uint${bits}`);
  return parsed.toString();
}
function assign(target,field,value) {
  if(target[field]!==null&&target[field]!==value) {
    throw new Error(`${field} already differs from the derived production release`);
  }
  target[field]=value;
}
function identity(value,label) {
  exact(value,['runtimeCodeHash','initcodeHash','configHash'],label);
  return {runtimeCodeHash:hash(value.runtimeCodeHash,`${label}.runtimeCodeHash`),
    initcodeHash:hash(value.initcodeHash,`${label}.initcodeHash`),
    configHash:hash(value.configHash,`${label}.configHash`)};
}
function requireAtomicPins(target,fields,label) {
  const states=fields.map(field=>target[field]===null);
  if(states.some(Boolean)&&!states.every(Boolean)) throw new Error(`${label} pins are partially materialized`);
  if(!states[0]) for(const field of fields) hash(target[field],field);
  return states[0];
}

/** Assemble the release fields that precede Solidity pinning. All proof and
 * artifact validation happens before this pure reconciliation boundary. */
export function materializeProductionReleaseCore({releaseConfig,nativeFacts,
  finalizedBurnVerifier,checkpointVerifier,reserveArtifact,checkpointRegistryArtifact,
  deferReserveArtifact=false,deferCheckpointRegistryArtifact=false}) {
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)
      ||releaseConfig.ethereumChainId!=='1'||releaseConfig.productionReady!==false
      ||releaseConfig.realFundsAuthorized!==false) {
    throw new Error('release core requires the unapproved Ethereum mainnet template');
  }
  exact(nativeFacts,factFields,'native release facts');
  if(nativeFacts.schema!==NATIVE_RELEASE_FACTS_SCHEMA) throw new Error('unsupported native release facts schema');
  const finalized=identity(finalizedBurnVerifier,'finalized-burn verifier');
  const checkpoint=identity(checkpointVerifier,'checkpoint verifier');
  const governanceOwnersCommitment=safeOwnersCommitment(releaseConfig.governanceOwners);
  const guardianOwnersCommitment=safeOwnersCommitment(releaseConfig.guardianOwners);
  if(typeof releaseConfig.governanceOwnersCommitment!=='string'
      ||typeof releaseConfig.guardianOwnersCommitment!=='string'
      ||releaseConfig.governanceOwnersCommitment.toLowerCase()!==governanceOwnersCommitment
      ||releaseConfig.guardianOwnersCommitment.toLowerCase()!==guardianOwnersCommitment) {
    throw new Error('control-plane owner commitments differ from the canonical owner set');
  }
  const facts={...nativeFacts,
    nativeEthereumTrustedCheckpoint:hash(nativeFacts.nativeEthereumTrustedCheckpoint,
      'nativeEthereumTrustedCheckpoint'),domDomain:hash(nativeFacts.domDomain,'domDomain'),
    activationScheduleCommitment:hash(nativeFacts.activationScheduleCommitment,'activationScheduleCommitment'),
    checkpointDomNetworkMagic:decimal(nativeFacts.checkpointDomNetworkMagic,32,'checkpointDomNetworkMagic'),
    checkpointDomChainId:hash(nativeFacts.checkpointDomChainId,'checkpointDomChainId'),
    checkpointFirstV4Height:decimal(nativeFacts.checkpointFirstV4Height,64,'checkpointFirstV4Height'),
    checkpointActivationEmptyStateRoot:hash(nativeFacts.checkpointActivationEmptyStateRoot,
      'checkpointActivationEmptyStateRoot'),
    checkpointIntervalBlocks:decimal(nativeFacts.checkpointIntervalBlocks,32,'checkpointIntervalBlocks'),
    checkpointConfirmationDepthBlocks:decimal(nativeFacts.checkpointConfirmationDepthBlocks,32,
      'checkpointConfirmationDepthBlocks'),
    checkpointChallengePeriodSeconds:decimal(nativeFacts.checkpointChallengePeriodSeconds,64,
      'checkpointChallengePeriodSeconds'),
    checkpointInitialHeight:decimal(nativeFacts.checkpointInitialHeight,64,'checkpointInitialHeight'),
    checkpointInitialBlock:hash(nativeFacts.checkpointInitialBlock,'checkpointInitialBlock'),
    checkpointInitialStateRoot:hash(nativeFacts.checkpointInitialStateRoot,'checkpointInitialStateRoot'),
    checkpointInitialContextHash:hash(nativeFacts.checkpointInitialContextHash,'checkpointInitialContextHash'),
    checkpointInitialTotalDifficulty:decimal(nativeFacts.checkpointInitialTotalDifficulty,256,
      'checkpointInitialTotalDifficulty')};
  if(BigInt(facts.checkpointFirstV4Height)!==BigInt(facts.checkpointInitialHeight)+1n
      ||facts.checkpointInitialStateRoot!==facts.checkpointActivationEmptyStateRoot) {
    throw new Error('native activation predecessor does not match the checkpoint bootstrap');
  }
  const result=structuredClone(releaseConfig);
  requireAtomicPins(result,['verifierCodeHash','verifierInitcodeHash','verifierConfigHash'],
    'finalized-burn verifier');
  requireAtomicPins(result,['checkpointVerifierCodeHash','checkpointVerifierInitcodeHash',
    'checkpointVerifierConfigHash'],'checkpoint verifier');
  if(typeof deferReserveArtifact!=='boolean'||(deferReserveArtifact&&reserveArtifact!==undefined)) {
    throw new Error('reserve artifact transition mode is invalid');
  }
  if(typeof deferCheckpointRegistryArtifact!=='boolean'
      ||(deferCheckpointRegistryArtifact&&checkpointRegistryArtifact!==undefined)) {
    throw new Error('checkpoint registry artifact transition mode is invalid');
  }
  const registryPinsUnset=requireAtomicPins(result,
    ['checkpointRegistryRuntimeCodeHash','checkpointRegistryInitcodeHash'],'checkpoint registry');
  const runtimeUnset=result.reserveRuntimeCodeHash===null;
  const initcodeUnset=result.reserveInitcodeHash===null;
  if(runtimeUnset!==initcodeUnset) throw new Error('reserve bytecode pins are partially materialized');
  if(!runtimeUnset) {
    hash(result.reserveRuntimeCodeHash,'reserveRuntimeCodeHash');
    hash(result.reserveInitcodeHash,'reserveInitcodeHash');
  }
  for(const field of factFields.slice(1)) assign(result,field,facts[field]);
  assign(result,'verifierCodeHash',finalized.runtimeCodeHash);
  assign(result,'verifierInitcodeHash',finalized.initcodeHash);
  assign(result,'verifierConfigHash',finalized.configHash);
  assign(result,'checkpointVerifierCodeHash',checkpoint.runtimeCodeHash);
  assign(result,'checkpointVerifierInitcodeHash',checkpoint.initcodeHash);
  assign(result,'checkpointVerifierConfigHash',checkpoint.configHash);
  const registry=checkpointRegistryConfigHash({
    ethereumChainId:result.ethereumChainId,registry:result.checkpointRegistry,bridgeDomain:result.domDomain,
    domNetworkMagic:result.checkpointDomNetworkMagic,domChainId:result.checkpointDomChainId,
    firstV4Height:result.checkpointFirstV4Height,
    activationEmptyStateRoot:result.checkpointActivationEmptyStateRoot,
    activationScheduleCommitment:result.activationScheduleCommitment,
    checkpointInterval:result.checkpointIntervalBlocks,
    confirmationDepth:result.checkpointConfirmationDepthBlocks,
    challengePeriod:result.checkpointChallengePeriodSeconds,verifier:result.checkpointVerifier,
    verifierCodeHash:result.checkpointVerifierCodeHash,
    verifierConfigHash:result.checkpointVerifierConfigHash,guardian:result.checkpointGuardian,
    guardianCodeHash:result.checkpointGuardianCodeHash,
    guardianImplementation:result.checkpointGuardianImplementation,
    guardianImplementationCodeHash:result.checkpointGuardianImplementationCodeHash,
    guardianOwnersCommitment:safeOwnersCommitment(releaseConfig.checkpointGuardianOwners),
    initialHeight:result.checkpointInitialHeight,initialBlock:result.checkpointInitialBlock,
    initialStateRoot:result.checkpointInitialStateRoot,initialContextHash:result.checkpointInitialContextHash,
    initialTotalDifficulty:result.checkpointInitialTotalDifficulty,
  });
  assign(result,'checkpointRegistryConfigHash',registry.checkpointConfigHash);
  if(checkpointRegistryArtifact!==undefined) {
    const compiledRegistry=identity(checkpointRegistryArtifact,'checkpoint registry artifact');
    if(compiledRegistry.configHash!==registry.checkpointConfigHash) {
      throw new Error('checkpoint registry artifact config hash differs from the derived release');
    }
    assign(result,'checkpointRegistryRuntimeCodeHash',compiledRegistry.runtimeCodeHash);
    assign(result,'checkpointRegistryInitcodeHash',compiledRegistry.initcodeHash);
  } else if(!deferCheckpointRegistryArtifact) {
    throw new Error('checkpoint registry artifact is required to complete the production release');
  } else if(!registryPinsUnset) {
    throw new Error('checkpoint registry derivation can only be deferred from the null-pin state');
  }
  if(result.checkpointRegistryRuntimeCodeHash===null && deferReserveArtifact) {
    if(!runtimeUnset) throw new Error('reserve derivation cannot be deferred from a materialized state');
  } else {
    const reserve=proofReserveDeploymentConfigHash({
      ethereumChainId:result.ethereumChainId,reserve:result.reserve,token:result.token,
      tokenCodeHash:result.tokenCodeHash,verifier:result.verifier,verifierCodeHash:result.verifierCodeHash,
      verifierConfigHash:result.verifierConfigHash,checkpointRegistry:result.checkpointRegistry,
      checkpointRegistryRuntimeCodeHash:result.checkpointRegistryRuntimeCodeHash,
      checkpointRegistryConfigHash:result.checkpointRegistryConfigHash,domDomain:result.domDomain,
      activationScheduleCommitment:result.activationScheduleCommitment,governance:result.governance,
      governanceCodeHash:result.governanceCodeHash,governanceImplementation:result.governanceImplementation,
      governanceImplementationCodeHash:result.governanceImplementationCodeHash,
      governanceOwnersCommitment:result.governanceOwnersCommitment,guardian:result.guardian,
      guardianCodeHash:result.guardianCodeHash,guardianImplementation:result.guardianImplementation,
      guardianImplementationCodeHash:result.guardianImplementationCodeHash,
      guardianOwnersCommitment:result.guardianOwnersCommitment,
      withdrawalDelaySeconds:result.withdrawalDelaySeconds,governanceDelaySeconds:result.governanceDelaySeconds,
      maxOutstandingBaseUnits:result.maxOutstandingBaseUnits,
      outflowCapacityBaseUnitsPerDay:result.outflowCapacityBaseUnitsPerDay,
    });
    assign(result,'reserveConfigHash',reserve.reserveConfigHash);
    if(reserveArtifact!==undefined) {
      const compiledReserve=identity(reserveArtifact,'reserve artifact');
      if(compiledReserve.configHash!==reserve.reserveConfigHash) {
        throw new Error('reserve artifact config hash differs from the derived release');
      }
      assign(result,'reserveRuntimeCodeHash',compiledReserve.runtimeCodeHash);
      assign(result,'reserveInitcodeHash',compiledReserve.initcodeHash);
    } else if(!deferReserveArtifact) {
      throw new Error('reserve artifact is required to complete the production release');
    } else if(!runtimeUnset) {
      throw new Error('reserve artifact derivation can only be deferred from the null-pin state');
    }
  }
  if(result.productionReady!==false||result.realFundsAuthorized!==false) {
    throw new Error('release core cannot change authorization');
  }
  return result;
}
