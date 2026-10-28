import {AbiCoder, getAddress, keccak256, toUtf8Bytes} from 'ethers';
import {uint} from './reserve.mjs';

const ETHEREUM_USDT = getAddress('0xdAC17F958D2ee523a2206206994597C13D831ec7');
const zeroHash = '0x' + '00'.repeat(32);
const fields = ['chainId','token','domDomain','governance','guardian','notaries','threshold','withdrawalDelay','governanceDelay','maxOutstanding','outflowCapacity'];
const proofFields = [
  'productionReady','ethereumChainId','token','verifier','verifierCodeHash','verifierConfigHash',
  'checkpointRegistry','checkpointRegistryRuntimeCodeHash','checkpointRegistryConfigHash','domDomain',
  'activationScheduleCommitment',
  'governance','guardian','withdrawalDelaySeconds','governanceDelaySeconds','maxOutstandingBaseUnits',
  'outflowCapacityBaseUnitsPerDay','realFundsAuthorized',
];
const deploymentFields = [
  'ethereumChainId','reserve','token','tokenCodeHash','verifier','verifierCodeHash','verifierConfigHash',
  'checkpointRegistry','checkpointRegistryRuntimeCodeHash','checkpointRegistryConfigHash',
  'domDomain','activationScheduleCommitment','governance','governanceCodeHash',
  'governanceImplementation','governanceImplementationCodeHash','governanceOwnersCommitment',
  'guardian','guardianCodeHash','guardianImplementation','guardianImplementationCodeHash',
  'guardianOwnersCommitment',
  'withdrawalDelaySeconds','governanceDelaySeconds',
  'maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay',
];
const preActivationDeploymentFields=deploymentFields.filter(
  field=>field!=='activationScheduleCommitment',
);
const abi = AbiCoder.defaultAbiCoder();
export const RESERVE_IDENTITY_TYPEHASH = keccak256(toUtf8Bytes(
  'ReserveIdentity(uint256 ethereumChainId,address reserve,address token,bytes32 tokenCodeHash,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash,address checkpointRegistry,bytes32 checkpointRegistryCodeHash,bytes32 checkpointConfigHash,bytes32 domDomain,bytes32 activationScheduleCommitment)',
));
export const RESERVE_PREACTIVATION_IDENTITY_TYPEHASH = keccak256(toUtf8Bytes(
  'ReservePreActivationIdentity(uint256 ethereumChainId,address reserve,address token,bytes32 tokenCodeHash,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash,address checkpointRegistry,bytes32 checkpointRegistryCodeHash,bytes32 checkpointConfigHash,bytes32 domDomain)',
));
export const RESERVE_POLICY_TYPEHASH = keccak256(toUtf8Bytes(
  'ReservePolicy(bytes32 governanceIdentityHash,bytes32 guardianIdentityHash,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity,bool pilotRestricted)',
));
export const CONTROL_PLANE_IDENTITY_TYPEHASH = keccak256(toUtf8Bytes(
  'ControlPlaneIdentity(address account,bytes32 accountCodeHash,address implementation,bytes32 implementationCodeHash,bytes32 ownersCommitment)',
));
export const RESERVE_CONFIG_TYPEHASH = keccak256(toUtf8Bytes(
  'ReserveConfig(bytes32 identityHash,bytes32 policyHash)',
));
export const RESERVE_PREACTIVATION_CONFIG_TYPEHASH = keccak256(toUtf8Bytes(
  'ReservePreActivationConfig(bytes32 identityHash,bytes32 policyHash)',
));

function exactObject(input, expected, message) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).length !== expected.length || expected.some(key => !(key in input))) {
    throw new Error(message);
  }
}

function nonzeroHash(value, name) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value) || value.toLowerCase() === zeroHash) {
    throw new Error(`${name} must be a nonzero bytes32`);
  }
  return value.toLowerCase();
}

/** Canonical Safe owner-set identity used by the production contracts. */
export function safeOwnersCommitment(owners) {
  if (!Array.isArray(owners) || owners.length !== 3) {
    throw new Error('Safe owners must contain exactly three addresses');
  }
  const normalized=owners.map((owner,index)=>{
    const value=getAddress(owner);
    if(BigInt(value)<=0x11n) throw new Error(`Safe owner ${index} must not be a reserved precompile`);
    return value;
  });
  if(new Set(normalized).size!==3) throw new Error('Safe owners must be distinct');
  const canonical=[...normalized].sort((a,b)=>BigInt(a)<BigInt(b)?-1:BigInt(a)>BigInt(b)?1:0);
  return keccak256(abi.encode(['address','address','address'],canonical));
}

export function validateConfiguration(input) {
  exactObject(input, fields, 'exact configuration fields required');
  const c = {...input};
  c.chainId = uint(c.chainId,256);
  if (!c.chainId) throw new Error('chainId required');
  if(c.chainId===1n) throw new Error('quorum prototype refuses Ethereum mainnet; production requires verified DOM proofs');
  for(const key of ['token','governance','guardian']) {
    c[key]=getAddress(c[key]); if(BigInt(c[key])===0n) throw new Error(`${key} required`);
  }
  if(new Set([c.token,c.governance,c.guardian]).size!==3) throw new Error('roles and token must differ');
  if(typeof c.domDomain!=='string' || !/^0x[0-9a-fA-F]{64}$/.test(c.domDomain) || BigInt(c.domDomain)===0n) throw new Error('DOM domain required');
  // These values are constructor arguments declared as uint64 in USDOMReserve.
  // Reject an unencodable configuration at the first gate instead of allowing
  // it to fail later while deriving or encoding deployment calldata.
  for(const key of ['withdrawalDelay','governanceDelay','maxOutstanding','outflowCapacity']) c[key]=uint(c[key],64);
  if(c.withdrawalDelay<21600n || c.withdrawalDelay>259200n || c.governanceDelay<172800n || c.governanceDelay>2592000n
      || c.maxOutstanding===0n || c.outflowCapacity===0n || c.outflowCapacity>c.maxOutstanding) throw new Error('configuration bounds');
  if(!Array.isArray(c.notaries) || c.notaries.length<3 || c.notaries.length>16) throw new Error('notary count');
  c.notaries=c.notaries.map(getAddress);
  for(let i=0;i<c.notaries.length;i++) {
    if(BigInt(c.notaries[i])===0n || (i && BigInt(c.notaries[i-1])>=BigInt(c.notaries[i]))
       || [c.token,c.governance,c.guardian].includes(c.notaries[i])) throw new Error('notaries must be distinct, sorted and separate from roles');
  }
  if(!Number.isInteger(c.threshold) || c.threshold<=Math.floor(c.notaries.length*2/3) || c.threshold>c.notaries.length) throw new Error('threshold must exceed two thirds');
  return c;
}

/**
 * Validates the exact constructor inputs for the proof-authorized reserve.
 * This is deliberately a syntax/bounds check only. It cannot establish that
 * addresses contain the expected code, that a verifier is sound, or that a
 * deployment is authorized. Ethereum mainnet remains unconditionally closed
 * until ratified verifier hashes are compiled into both contract and tooling.
 */
export function validateProofConfiguration(input) {
  exactObject(input, proofFields, 'exact proof-reserve configuration fields required');
  const c = {...input};
  if (c.productionReady !== false || c.realFundsAuthorized !== false) {
    throw new Error('configuration cannot assert production readiness or real-funds authorization');
  }

  c.ethereumChainId = uint(c.ethereumChainId, 256);
  if (c.ethereumChainId === 0n) throw new Error('ethereumChainId required');
  for (const key of ['token','verifier','checkpointRegistry','governance','guardian']) {
    c[key] = getAddress(c[key]);
    if (BigInt(c[key]) === 0n) throw new Error(`${key} required`);
  }
  if (new Set([c.token,c.verifier,c.checkpointRegistry,c.governance,c.guardian]).size !== 5) {
    throw new Error('token, verifier, checkpoint registry and administrative roles must differ');
  }
  c.verifierCodeHash = nonzeroHash(c.verifierCodeHash, 'verifierCodeHash');
  c.verifierConfigHash = nonzeroHash(c.verifierConfigHash, 'verifierConfigHash');
  c.checkpointRegistryRuntimeCodeHash = nonzeroHash(c.checkpointRegistryRuntimeCodeHash, 'checkpointRegistryRuntimeCodeHash');
  c.checkpointRegistryConfigHash = nonzeroHash(c.checkpointRegistryConfigHash, 'checkpointRegistryConfigHash');
  c.domDomain = nonzeroHash(c.domDomain, 'domDomain');
  c.activationScheduleCommitment = nonzeroHash(c.activationScheduleCommitment, 'activationScheduleCommitment');

  for (const key of [
    'withdrawalDelaySeconds','governanceDelaySeconds','maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay',
  // Keep this syntax gate identical to the uint64 Solidity constructor ABI.
  // The deployment commitment path repeats the bound as defense in depth.
  ]) c[key] = uint(c[key], 64);
  if (c.withdrawalDelaySeconds < 21600n || c.withdrawalDelaySeconds > 259200n
      || c.governanceDelaySeconds < 172800n || c.governanceDelaySeconds > 2592000n
      || c.maxOutstandingBaseUnits === 0n || c.outflowCapacityBaseUnitsPerDay === 0n
      || c.outflowCapacityBaseUnitsPerDay > c.maxOutstandingBaseUnits) {
    throw new Error('proof-reserve configuration bounds');
  }

  if (c.ethereumChainId === 1n) {
    if (c.token !== ETHEREUM_USDT) throw new Error('Ethereum mainnet token must be the intended USDT deployment');
    throw new Error('proof reserve production verifier release unavailable');
  }
  return c;
}

/** Compute the exact immutable deployment commitment enforced by
 * USDOMProofReserve. This does not authorize a deployment; release tooling must
 * compare the result with the independently reviewed manifest and the constant
 * compiled into the contract. */
export function proofReserveDeploymentConfigHash(input) {
  exactObject(input, deploymentFields, 'exact proof-reserve deployment fields required');
  const c = {...input};
  c.ethereumChainId = uint(c.ethereumChainId, 256);
  if (c.ethereumChainId === 0n) throw new Error('ethereumChainId required');
  for (const key of [
    'reserve','token','verifier','checkpointRegistry','governance','governanceImplementation','guardian','guardianImplementation',
  ]) {
    c[key] = getAddress(c[key]);
    if (BigInt(c[key]) === 0n) throw new Error(`${key} required`);
  }
  if (new Set([c.reserve,c.token,c.verifier,c.checkpointRegistry,c.governance,c.guardian]).size !== 6) {
    throw new Error('reserve, token, verifier, checkpoint registry and administrative roles must differ');
  }
  for (const key of [
    'tokenCodeHash','verifierCodeHash','verifierConfigHash','checkpointRegistryRuntimeCodeHash',
    'checkpointRegistryConfigHash','domDomain',
    'activationScheduleCommitment','governanceCodeHash','governanceImplementationCodeHash',
    'governanceOwnersCommitment','guardianCodeHash','guardianImplementationCodeHash',
    'guardianOwnersCommitment',
  ]) {
    c[key] = nonzeroHash(c[key], key);
  }
  for (const key of [
    'withdrawalDelaySeconds','governanceDelaySeconds','maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay',
  ]) c[key] = uint(c[key], 64);
  if (c.withdrawalDelaySeconds < 21600n || c.withdrawalDelaySeconds > 259200n
      || c.governanceDelaySeconds < 172800n || c.governanceDelaySeconds > 2592000n
      || c.maxOutstandingBaseUnits === 0n || c.outflowCapacityBaseUnitsPerDay === 0n
      || c.outflowCapacityBaseUnitsPerDay > c.maxOutstandingBaseUnits) {
    throw new Error('proof-reserve deployment bounds');
  }
  const identityHash = keccak256(abi.encode(
    ['bytes32','uint256','address','address','bytes32','address','bytes32','bytes32','address','bytes32','bytes32','bytes32','bytes32'],
    [RESERVE_IDENTITY_TYPEHASH,c.ethereumChainId,c.reserve,c.token,c.tokenCodeHash,c.verifier,
      c.verifierCodeHash,c.verifierConfigHash,c.checkpointRegistry,c.checkpointRegistryRuntimeCodeHash,
      c.checkpointRegistryConfigHash,c.domDomain,c.activationScheduleCommitment],
  ));
  const preActivationIdentityHash = keccak256(abi.encode(
    ['bytes32','uint256','address','address','bytes32','address','bytes32','bytes32','address','bytes32','bytes32','bytes32'],
    [RESERVE_PREACTIVATION_IDENTITY_TYPEHASH,c.ethereumChainId,c.reserve,c.token,c.tokenCodeHash,c.verifier,
      c.verifierCodeHash,c.verifierConfigHash,c.checkpointRegistry,c.checkpointRegistryRuntimeCodeHash,
      c.checkpointRegistryConfigHash,c.domDomain],
  ));
  const governanceIdentityHash=keccak256(abi.encode(
    ['bytes32','address','bytes32','address','bytes32','bytes32'],
    [CONTROL_PLANE_IDENTITY_TYPEHASH,c.governance,c.governanceCodeHash,
      c.governanceImplementation,c.governanceImplementationCodeHash,c.governanceOwnersCommitment],
  ));
  const guardianIdentityHash=keccak256(abi.encode(
    ['bytes32','address','bytes32','address','bytes32','bytes32'],
    [CONTROL_PLANE_IDENTITY_TYPEHASH,c.guardian,c.guardianCodeHash,
      c.guardianImplementation,c.guardianImplementationCodeHash,c.guardianOwnersCommitment],
  ));
  const policyHash = keccak256(abi.encode(
    ['bytes32','bytes32','bytes32','uint64','uint64','uint64','uint64','bool'],
    [RESERVE_POLICY_TYPEHASH,governanceIdentityHash,guardianIdentityHash,
      c.withdrawalDelaySeconds,c.governanceDelaySeconds,
      c.maxOutstandingBaseUnits,c.outflowCapacityBaseUnitsPerDay,true],
  ));
  const reserveConfigHash = keccak256(abi.encode(
    ['bytes32','bytes32','bytes32'], [RESERVE_CONFIG_TYPEHASH,identityHash,policyHash],
  ));
  const reservePreActivationConfigHash = keccak256(abi.encode(
    ['bytes32','bytes32','bytes32'],
    [RESERVE_PREACTIVATION_CONFIG_TYPEHASH,preActivationIdentityHash,policyHash],
  ));
  return {...c,pilotRestrictedDeployment:true,
    governanceIdentityHash,guardianIdentityHash,identityHash,preActivationIdentityHash,
    policyHash,reserveConfigHash,reservePreActivationConfigHash};
}

/** Derive the exact compile-time reserve pin before native activation exists. */
export function proofReservePreActivationConfigHash(input) {
  exactObject(input,preActivationDeploymentFields,
    'exact proof-reserve pre-activation deployment fields required');
  const computed=proofReserveDeploymentConfigHash({
    ...input,activationScheduleCommitment:'0x'+'01'.padStart(64,'0'),
  });
  const {activationScheduleCommitment: _activation,identityHash: _identity,
    reserveConfigHash: _full,...preActivation}=computed;
  return preActivation;
}
