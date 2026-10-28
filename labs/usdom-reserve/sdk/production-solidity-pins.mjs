import {checkpointRegistryPreActivationConfigHash} from './checkpoint-registry.mjs';
import {proofReservePreActivationConfigHash,safeOwnersCommitment} from './configuration.mjs';
import {getAddress,getCreateAddress} from 'ethers';
import {deriveDomDomain} from './preactivation-policy.mjs';
import {uint} from './reserve.mjs';

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

function requireBinding(value,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||Object.keys(value).length!==3
      ||!['runtimeCodeHash','initcodeHash','configHash'].every(field=>field in value)) {
    throw new Error(`${label} must be the exact source-verified artifact binding`);
  }
  return Object.freeze({runtimeCodeHash:requireHash(value.runtimeCodeHash,`${label}.runtimeCodeHash`),
    initcodeHash:requireHash(value.initcodeHash,`${label}.initcodeHash`),
    configHash:requireHash(value.configHash,`${label}.configHash`)});
}

/** Reconcile the release pins with bindings independently derived from the
 * canonical verifier configurations and source-verified compiler artifacts. */
export function verifyProductionVerifierBindings({releaseConfig,finalizedBurnVerifier,checkpointVerifier}={}) {
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)) {
    throw new Error('release configuration is required');
  }
  const finalized=requireBinding(finalizedBurnVerifier,'finalized-burn verifier');
  const checkpoint=requireBinding(checkpointVerifier,'checkpoint verifier');
  for(const [field,actual] of [
    ['verifierCodeHash',finalized.runtimeCodeHash],['verifierInitcodeHash',finalized.initcodeHash],
    ['verifierConfigHash',finalized.configHash],
    ['checkpointVerifierCodeHash',checkpoint.runtimeCodeHash],
    ['checkpointVerifierInitcodeHash',checkpoint.initcodeHash],
    ['checkpointVerifierConfigHash',checkpoint.configHash],
  ]) {
    if(requireHash(releaseConfig[field],field)!==actual) {
      throw new Error(`${field} differs from the source-verified verifier artifact`);
    }
  }
  return Object.freeze({finalizedBurnVerifier:finalized,checkpointVerifier:checkpoint});
}

function replacePin(source,constant,value) {
  const declaration=new RegExp(`(bytes32\\s+(?:public|private)\\s+constant\\s+${constant}\\s*=\\s*)(?:bytes32\\(0\\)|0x[0-9a-fA-F]{64})(\\s*;)`,'g');
  const matches=[...source.matchAll(declaration)];
  if(matches.length!==1) throw new Error(`${constant} must have exactly one canonical declaration`);
  const current=matches[0][0].match(/(?:bytes32\(0\)|0x[0-9a-fA-F]{64})(?=\s*;)/)?.[0];
  if(current!=='bytes32(0)'&&current?.toLowerCase()!==value) {
    throw new Error(`${constant} already differs from the exact release`);
  }
  return source.replace(declaration,(_match,prefix,suffix)=>`${prefix}${value}${suffix}`);
}

function requireCreatePlan(releaseConfig) {
  if(releaseConfig.deploymentMethod!=='CREATE') {
    throw new Error('production source pinning requires the CREATE deployment method');
  }
  for(const [label,deployerField,nonceField,addressField] of [
    ['reserve','deployer','deployerNonce','reserve'],
    ['finalized-burn verifier','verifierDeployer','verifierDeployerNonce','verifier'],
    ['checkpoint registry','checkpointRegistryDeployer','checkpointRegistryDeployerNonce',
      'checkpointRegistry'],
    ['checkpoint verifier','checkpointVerifierDeployer','checkpointVerifierDeployerNonce',
      'checkpointVerifier'],
  ]) {
    const deployer=getAddress(releaseConfig[deployerField]);
    if(BigInt(deployer)===0n) throw new Error(`${label} deployer must be nonzero`);
    const nonce=uint(releaseConfig[nonceField],64);
    if(getAddress(releaseConfig[addressField])!==getCreateAddress({from:deployer,nonce})) {
      throw new Error(`${label} address differs from its CREATE deployment plan`);
    }
  }
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
export function materializeProductionSolidityPins({releaseConfig,reserveSource,checkpointRegistrySource,
  component='both'}) {
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)
      ||releaseConfig.ethereumChainId!=='1'||releaseConfig.productionReady!==false
      ||releaseConfig.realFundsAuthorized!==false) {
    throw new Error('production pins require the unapproved Ethereum mainnet release');
  }
  if(!['reserve','checkpointRegistry','both'].includes(component)) {
    throw new Error('production pin component is invalid');
  }
  requireCreatePlan(releaseConfig);
  const expectedDomDomain=deriveDomDomain({domNetworkMagic:releaseConfig.checkpointDomNetworkMagic,
    domChainId:releaseConfig.checkpointDomChainId,ethereumChainId:releaseConfig.ethereumChainId,
    reserve:releaseConfig.reserve,checkpointRegistry:releaseConfig.checkpointRegistry});
  if(requireHash(releaseConfig.domDomain,'domDomain')!==expectedDomDomain) {
    throw new Error('DOM domain differs from the production deployment identity');
  }
  // Source pinning is an irreversible release transition. Bind every Safe
  // owner list to the commitments consumed by the constructors and preserve
  // separation across all three roles before changing Solidity source.
  const governanceOwnersCommitment=safeOwnersCommitment(releaseConfig.governanceOwners);
  const guardianOwnersCommitment=safeOwnersCommitment(releaseConfig.guardianOwners);
  const checkpointGuardianOwnersCommitment=safeOwnersCommitment(
    releaseConfig.checkpointGuardianOwners);
  if(requireHash(releaseConfig.governanceOwnersCommitment,'governanceOwnersCommitment')
      !==governanceOwnersCommitment
      ||requireHash(releaseConfig.guardianOwnersCommitment,'guardianOwnersCommitment')
        !==guardianOwnersCommitment) {
    throw new Error('Safe owner commitments differ from the canonical owner sets');
  }
  const allOwners=[...releaseConfig.governanceOwners,...releaseConfig.guardianOwners,
    ...releaseConfig.checkpointGuardianOwners].map(owner=>owner.toLowerCase());
  if(new Set(allOwners).size!==9) throw new Error('production Safe owners must be globally distinct');
  // The reserve pin commits the registry configuration even when only the
  // reserve source is requested. Recompute it for every mode and reject a
  // stale declaration before producing any candidate source.
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
    guardianOwnersCommitment:checkpointGuardianOwnersCommitment,
    initialHeight:releaseConfig.checkpointInitialHeight,initialBlock:releaseConfig.checkpointInitialBlock,
    initialContextHash:releaseConfig.checkpointInitialContextHash,
    initialTotalDifficulty:releaseConfig.checkpointInitialTotalDifficulty,
  });
  const declaredRegistryHash=requireHash(
    releaseConfig.checkpointRegistryConfigHash,'checkpointRegistryConfigHash');
  if(declaredRegistryHash!==registry.checkpointConfigHash) {
    throw new Error('checkpointRegistryConfigHash differs from the exact release fields');
  }
  let pins={...releaseConfig};
  if(component!=='checkpointRegistry') {
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
    pins={...pins,reservePreActivationConfigHash:reserve.reservePreActivationConfigHash};
  }
  if(component!=='reserve') {
    pins={...pins,checkpointRegistryConfigHash:registry.checkpointConfigHash};
  }
  const result={};
  if(component!=='checkpointRegistry') result.reserveSource=materializeOne({source:reserveSource,
    releaseConfig:pins,specification:specifications.reserve});
  if(component!=='reserve') result.checkpointRegistrySource=materializeOne({source:checkpointRegistrySource,
    releaseConfig:pins,specification:specifications.checkpointRegistry});
  return Object.freeze(result);
}
