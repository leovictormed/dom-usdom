import {AbiCoder, getAddress, id, keccak256} from 'ethers';
import {uint} from './reserve.mjs';

export const finalizedBurnFields = Object.freeze([
  ['burnId','bytes32'], ['requestId','bytes32'], ['recipient','address'], ['amount','uint64'],
  ['domDomain','bytes32'], ['height','uint64'], ['blockHash','bytes32'], ['stateRoot','bytes32'],
  ['finalityBeaconSlot','uint64'], ['validUntil','uint64'],
].map(([name,type]) => Object.freeze({name,type})));

export const BURN_STATEMENT_TYPE =
  'FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)';
export const BURN_STATEMENT_TYPEHASH = id(BURN_STATEMENT_TYPE);
export const BURN_INTENT_TYPE =
  'BurnIntent(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 validUntil,uint256 ethereumChainId,address reserve)';
export const BURN_INTENT_TYPEHASH = id(BURN_INTENT_TYPE);
export const BURN_DEBT_TYPE =
  'FinalizedBurnDebt(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)';
export const BURN_DEBT_TYPEHASH = id(BURN_DEBT_TYPE);
export const PRIVATE_BURN_ID_TYPE =
  'PrivateBurnId(bytes32 domDomain,bytes32 privacyPolicyHash,bytes32 verifierConfigHash,uint256 ethereumChainId,address reserve,address recipient,uint64 amount,uint64 validUntil,bytes32 nullifier0,bytes32 nullifier1)';
export const PRIVATE_BURN_ID_TYPEHASH = id(PRIVATE_BURN_ID_TYPE);

const zero = '0x' + '00'.repeat(32);
const bn254ScalarField = BigInt(
  '0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001',
);
const coder = AbiCoder.defaultAbiCoder();
function hash(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value) || value.toLowerCase() === zero) {
    throw new Error('nonzero bytes32 required');
  }
  return value.toLowerCase();
}
function scalar(value) {
  const canonical = hash(value);
  if (BigInt(canonical) >= bn254ScalarField) {
    throw new Error('canonical nonzero BN254 scalar required');
  }
  return canonical;
}

/** Deterministic native burn identity derived from proof-authenticated
 * nullifiers and the immutable payout target. This helper does not verify a
 * spend proof; consensus must authenticate the supplied nullifiers. */
export function derivePrivateBurnId({
  domDomain, privacyPolicyHash, verifierConfigHash, chainId, reserve, recipient,
  amount, validUntil, nullifiers,
}) {
  const domain = hash(domDomain);
  const privacy = hash(privacyPolicyHash);
  const verifier = hash(verifierConfigHash);
  const idValue = uint(chainId, 256);
  const amountValue = uint(amount);
  const deadline = uint(validUntil);
  const reserveAddress = getAddress(reserve);
  const recipientAddress = getAddress(recipient);
  if (idValue === 0n || amountValue === 0n || deadline === 0n || BigInt(reserveAddress) === 0n
      || BigInt(recipientAddress) === 0n || !Array.isArray(nullifiers)
      || nullifiers.length < 1 || nullifiers.length > 2) {
    throw new Error('invalid private burn identity input');
  }
  const canonical = nullifiers.map(scalar);
  if (canonical.length === 2 && canonical[0] >= canonical[1]) {
    throw new Error('private burn nullifiers must be strictly sorted');
  }
  return keccak256(coder.encode(
    ['bytes32','bytes32','bytes32','bytes32','uint256','address','address','uint64','uint64','bytes32','bytes32'],
    [PRIVATE_BURN_ID_TYPEHASH, domain, privacy, verifier, idValue, reserveAddress, recipientAddress,
      amountValue, deadline, canonical[0], canonical[1] ?? zero],
  ));
}

export function normalizeFinalizedBurn(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('finalized burn object required');
  const names = finalizedBurnFields.map(field => field.name);
  if (Object.keys(input).length !== names.length || Object.keys(input).some(name => !names.includes(name))) {
    throw new Error('exact FinalizedBurn fields required');
  }
  const result = {};
  for (const {name,type} of finalizedBurnFields) {
    result[name] = type === 'uint64' ? uint(input[name]) : type === 'bytes32' ? hash(input[name]) : getAddress(input[name]);
    if ((type === 'uint64' || type === 'address') && BigInt(result[name]) === 0n) throw new Error(`${name} is zero`);
  }
  return result;
}

/** Hash of the exact public statement consumed by USDOMProofReserve.
 * This helper does not prove DOM validity, finality, privacy or conservation. */
export function finalizedBurnStatementHash({chainId, reserve, activationScheduleCommitment, burn}) {
  const idValue = uint(chainId, 256);
  if (idValue === 0n) throw new Error('zero chain id');
  const reserveAddress = getAddress(reserve);
  if (BigInt(reserveAddress) === 0n) throw new Error('zero reserve');
  const schedule = hash(activationScheduleCommitment);
  const normalized = normalizeFinalizedBurn(burn);
  return keccak256(coder.encode(
    ['bytes32', ...finalizedBurnFields.map(field => field.type), 'uint256', 'address','bytes32'],
    [BURN_STATEMENT_TYPEHASH, ...finalizedBurnFields.map(field => normalized[field.name]), idValue,
      reserveAddress,schedule],
  ));
}

/** Stable proved-debt identity used for lease renewal. It binds every public
 * finalized-burn field except the Ethereum finality slot that a fresh proof
 * is specifically allowed to advance. */
export function finalizedBurnDebtHash({chainId, reserve, activationScheduleCommitment, burn}) {
  const idValue = uint(chainId, 256);
  if (idValue === 0n) throw new Error('zero chain id');
  const reserveAddress = getAddress(reserve);
  if (BigInt(reserveAddress) === 0n) throw new Error('zero reserve');
  const schedule = hash(activationScheduleCommitment);
  const normalized = normalizeFinalizedBurn(burn);
  return keccak256(coder.encode(
    ['bytes32','bytes32','bytes32','address','uint64','bytes32','uint64','bytes32','bytes32','uint64','uint256','address','bytes32'],
    [BURN_DEBT_TYPEHASH, normalized.burnId, normalized.requestId, normalized.recipient,
      normalized.amount, normalized.domDomain, normalized.height, normalized.blockHash,
      normalized.stateRoot, normalized.validUntil, idValue, reserveAddress, schedule],
  ));
}

/** Canonical native burn intent, before DOM block/finality identity is known. */
export function burnIntentHash({chainId, reserve, burn}) {
  const idValue = uint(chainId, 256);
  if (idValue === 0n) throw new Error('zero chain id');
  const reserveAddress = getAddress(reserve);
  if (BigInt(reserveAddress) === 0n) throw new Error('zero reserve');
  const normalized = normalizeFinalizedBurn(burn);
  return keccak256(coder.encode(
    ['bytes32', 'bytes32', 'bytes32', 'address', 'uint64', 'bytes32', 'uint64', 'uint256', 'address'],
    [BURN_INTENT_TYPEHASH, normalized.burnId, normalized.requestId, normalized.recipient, normalized.amount,
      normalized.domDomain, normalized.validUntil, idValue, reserveAddress],
  ));
}
