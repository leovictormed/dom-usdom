import {checkpointRegistryPreActivationConfigHash} from './checkpoint-registry.mjs';
import {safeOwnersCommitment} from './configuration.mjs';
import {deriveDomDomain} from './preactivation-policy.mjs';

export const NATIVE_PREACTIVATION_FACTS_SCHEMA='usdom-native-preactivation-facts-v1';
const fields=Object.freeze([
  'schema','nativeEthereumTrustedCheckpoint','domDomain','checkpointDomNetworkMagic',
  'checkpointDomChainId','checkpointFirstV4Height','checkpointIntervalBlocks',
  'checkpointConfirmationDepthBlocks','checkpointChallengePeriodSeconds','checkpointInitialHeight',
  'checkpointInitialBlock','checkpointInitialContextHash','checkpointInitialTotalDifficulty',
]);
const hashPattern=/^0x[0-9a-fA-F]{64}$/;

function exact(value,expected,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||Object.keys(value).length!==expected.length||expected.some(field=>!(field in value))) {
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
  const maxDigits={32:10,64:20,256:78}[bits];
  if(maxDigits===undefined||typeof value!=='string'||value.length>maxDigits
      ||!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed=BigInt(value);
  if(parsed>=(1n<<BigInt(bits))) throw new Error(`${label} exceeds uint${bits}`);
  return parsed.toString();
}
function identity(value,label) {
  exact(value,['runtimeCodeHash','initcodeHash','configHash'],label);
  return {runtimeCodeHash:hash(value.runtimeCodeHash,`${label}.runtimeCodeHash`),
    initcodeHash:hash(value.initcodeHash,`${label}.initcodeHash`),
    configHash:hash(value.configHash,`${label}.configHash`)};
}
function assign(target,field,value) {
  if(target[field]!==null&&target[field]!==value) throw new Error(`${field} already differs`);
  target[field]=value;
}
function requireAtomicPins(target,fields,label) {
  const states=fields.map(field=>target[field]===null);
  if(states.some(Boolean)&&!states.every(Boolean)) throw new Error(`${label} pins are partially materialized`);
}

/** Materialize only facts that exist before the native empty state. The four
 * dependent fields remain null until the post-compilation activation phase. */
export function materializeProductionPreActivationCore({releaseConfig,nativeFacts,
  finalizedBurnVerifier,checkpointVerifier}) {
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)
      ||releaseConfig.ethereumChainId!=='1'||releaseConfig.productionReady!==false
      ||releaseConfig.realFundsAuthorized!==false) {
    throw new Error('pre-activation core requires the unapproved Ethereum mainnet template');
  }
  for(const field of ['activationScheduleCommitment','checkpointActivationEmptyStateRoot',
    'checkpointInitialStateRoot','reserveConfigHash','reserveRuntimeCodeHash','reserveInitcodeHash']) {
    if(releaseConfig[field]!==null) throw new Error(`${field} must remain unset before activation`);
  }
  exact(nativeFacts,fields,'native pre-activation facts');
  if(nativeFacts.schema!==NATIVE_PREACTIVATION_FACTS_SCHEMA) throw new Error('unsupported pre-activation schema');
  const governanceOwnersCommitment=safeOwnersCommitment(releaseConfig.governanceOwners);
  const guardianOwnersCommitment=safeOwnersCommitment(releaseConfig.guardianOwners);
  const allOwners=[...releaseConfig.governanceOwners,...releaseConfig.guardianOwners,
    ...releaseConfig.checkpointGuardianOwners].map(owner=>owner.toLowerCase());
  if(new Set(allOwners).size!==9) throw new Error('pre-activation Safe owners must be globally distinct');
  if(typeof releaseConfig.governanceOwnersCommitment!=='string'
      ||typeof releaseConfig.guardianOwnersCommitment!=='string'
      ||releaseConfig.governanceOwnersCommitment.toLowerCase()!==governanceOwnersCommitment
      ||releaseConfig.guardianOwnersCommitment.toLowerCase()!==guardianOwnersCommitment) {
    throw new Error('pre-activation owner commitments differ from canonical owner set');
  }
  const facts={...nativeFacts,
    nativeEthereumTrustedCheckpoint:hash(nativeFacts.nativeEthereumTrustedCheckpoint,
      'nativeEthereumTrustedCheckpoint'),domDomain:hash(nativeFacts.domDomain,'domDomain'),
    checkpointDomNetworkMagic:decimal(nativeFacts.checkpointDomNetworkMagic,32,'checkpointDomNetworkMagic'),
    checkpointDomChainId:hash(nativeFacts.checkpointDomChainId,'checkpointDomChainId'),
    checkpointFirstV4Height:decimal(nativeFacts.checkpointFirstV4Height,64,'checkpointFirstV4Height'),
    checkpointIntervalBlocks:decimal(nativeFacts.checkpointIntervalBlocks,32,'checkpointIntervalBlocks'),
    checkpointConfirmationDepthBlocks:decimal(nativeFacts.checkpointConfirmationDepthBlocks,32,
      'checkpointConfirmationDepthBlocks'),
    checkpointChallengePeriodSeconds:decimal(nativeFacts.checkpointChallengePeriodSeconds,64,
      'checkpointChallengePeriodSeconds'),
    checkpointInitialHeight:decimal(nativeFacts.checkpointInitialHeight,64,'checkpointInitialHeight'),
    checkpointInitialBlock:hash(nativeFacts.checkpointInitialBlock,'checkpointInitialBlock'),
    checkpointInitialContextHash:hash(nativeFacts.checkpointInitialContextHash,'checkpointInitialContextHash'),
    checkpointInitialTotalDifficulty:decimal(nativeFacts.checkpointInitialTotalDifficulty,256,
      'checkpointInitialTotalDifficulty')};
  if(BigInt(facts.checkpointFirstV4Height)!==BigInt(facts.checkpointInitialHeight)+1n) {
    throw new Error('pre-activation predecessor height mismatch');
  }
  const expectedDomDomain=deriveDomDomain({domNetworkMagic:facts.checkpointDomNetworkMagic,
    domChainId:facts.checkpointDomChainId,ethereumChainId:releaseConfig.ethereumChainId,
    reserve:releaseConfig.reserve,checkpointRegistry:releaseConfig.checkpointRegistry});
  if(facts.domDomain!==expectedDomDomain) {
    throw new Error('pre-activation DOM domain does not match the production deployment identity');
  }
  const finalized=identity(finalizedBurnVerifier,'finalized-burn verifier');
  const checkpoint=identity(checkpointVerifier,'checkpoint verifier');
  const result=structuredClone(releaseConfig);
  requireAtomicPins(result,['verifierCodeHash','verifierInitcodeHash','verifierConfigHash'],
    'finalized-burn verifier');
  requireAtomicPins(result,['checkpointVerifierCodeHash','checkpointVerifierInitcodeHash',
    'checkpointVerifierConfigHash'],'checkpoint verifier');
  requireAtomicPins(result,['checkpointRegistryRuntimeCodeHash','checkpointRegistryInitcodeHash'],
    'checkpoint registry');
  if(result.checkpointRegistryRuntimeCodeHash!==null) {
    throw new Error('checkpoint registry bytecode pins must remain unset before activation');
  }
  for(const field of fields.slice(1)) assign(result,field,facts[field]);
  assign(result,'verifierCodeHash',finalized.runtimeCodeHash);
  assign(result,'verifierInitcodeHash',finalized.initcodeHash);
  assign(result,'verifierConfigHash',finalized.configHash);
  assign(result,'checkpointVerifierCodeHash',checkpoint.runtimeCodeHash);
  assign(result,'checkpointVerifierInitcodeHash',checkpoint.initcodeHash);
  assign(result,'checkpointVerifierConfigHash',checkpoint.configHash);
  const registry=checkpointRegistryPreActivationConfigHash({
    ethereumChainId:result.ethereumChainId,registry:result.checkpointRegistry,bridgeDomain:result.domDomain,
    domNetworkMagic:result.checkpointDomNetworkMagic,domChainId:result.checkpointDomChainId,
    firstV4Height:result.checkpointFirstV4Height,checkpointInterval:result.checkpointIntervalBlocks,
    confirmationDepth:result.checkpointConfirmationDepthBlocks,
    challengePeriod:result.checkpointChallengePeriodSeconds,verifier:result.checkpointVerifier,
    verifierCodeHash:result.checkpointVerifierCodeHash,verifierConfigHash:result.checkpointVerifierConfigHash,
    guardian:result.checkpointGuardian,guardianCodeHash:result.checkpointGuardianCodeHash,
    guardianImplementation:result.checkpointGuardianImplementation,
    guardianImplementationCodeHash:result.checkpointGuardianImplementationCodeHash,
    guardianOwnersCommitment:safeOwnersCommitment(releaseConfig.checkpointGuardianOwners),
    initialHeight:result.checkpointInitialHeight,initialBlock:result.checkpointInitialBlock,
    initialContextHash:result.checkpointInitialContextHash,
    initialTotalDifficulty:result.checkpointInitialTotalDifficulty,
  });
  assign(result,'checkpointRegistryConfigHash',registry.checkpointConfigHash);
  // The reserve identity commits to the Registry runtime hash. That runtime does
  // not exist until activation roots are known and the Registry has been built.
  // Keep the reserve pin absent here instead of hashing a placeholder identity.
  return Object.freeze({releaseConfig:result,
    reservePreActivationConfigHash:null,
    checkpointRegistryConfigHash:registry.checkpointConfigHash});
}
