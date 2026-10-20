import {AbiCoder, getAddress, id, keccak256, sha256, toUtf8Bytes} from 'ethers';
import {uint} from './reserve.mjs';
import {
  BURN_INTENT_TYPEHASH,
  BURN_STATEMENT_TYPEHASH,
  PRIVATE_BURN_ID_TYPEHASH,
} from './proof-reserve.mjs';

const zeroHash = '0x' + '00'.repeat(32);
const fields = Object.freeze([
  'schema','statementVersion','transitionCommitmentVersion','burnStateWitnessVersion',
  'finalizedBurnProverInputVersion','publicOutputVersion',
  'burnStatementTypeHash','burnIntentTypeHash','privateBurnIdTypeHash',
  'activationScheduleCommitment','domGenesisHash','domNetworkMagic','domChainId','firstV4Height',
  'activationEmptyStateRoot',
  'consensusRulesHash','forkChoiceRulesHash','powRulesHash','nativeAssetId','noteTreeRulesHash',
  'nullifierRulesHash','balanceRulesHash','finalityRulesHash','proofSystem','verifyingKeySha256',
  'trustedSetupRequired','trustedSetupTranscriptSha256','provingProgramSha256','sourceManifestSha256',
  'verifierArtifactSha256','maxProofBytes','minimumFinalityBeaconSlot',
  'ethereumChainId','riscZeroVerifier','riscZeroVerifierCodeHash','riscZeroVerifierSelector',
  'finalizedBurnGuestImageId','journalSchemaHash',
]);
const abi = AbiCoder.defaultAbiCoder();

export const VERIFIER_CONFIG_SCHEMA = 'usdom-finalized-burn-verifier-config-v5';
export const FINALIZED_BURN_PROOF_ACCEPTED_HASH = id('USDOM_FINALIZED_BURN_PROOF_V1');
export const FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH = id('raw-statement-hash-32-bytes-v1');
export const FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR = '0x73c457ba';
export const FINALIZED_BURN_PROOF_SYSTEM = 'risc0-groth16-v3';
export const VERIFIER_PROTOCOL_TYPEHASH = id(
  'VerifierProtocol(uint16 statementVersion,uint16 transitionCommitmentVersion,uint16 burnStateWitnessVersion,uint16 finalizedBurnProverInputVersion,uint16 publicOutputVersion,bytes32 burnStatementTypeHash,bytes32 burnIntentTypeHash,bytes32 privateBurnIdTypeHash,bytes32 activationScheduleCommitment,bytes32 domGenesisHash,uint32 domNetworkMagic,bytes32 domChainId,uint64 firstV4Height,bytes32 activationEmptyStateRoot)',
);
export const VERIFIER_STATE_RULES_TYPEHASH = id(
  'VerifierStateRules(bytes32 consensusRulesHash,bytes32 forkChoiceRulesHash,bytes32 powRulesHash,bytes32 nativeAssetId,bytes32 noteTreeRulesHash,bytes32 nullifierRulesHash,bytes32 balanceRulesHash,bytes32 finalityRulesHash)',
);
export const VERIFIER_PROOF_SYSTEM_TYPEHASH = id(
  'VerifierProofSystem(bytes32 proofSystemHash,bytes32 verifyingKeySha256,bool trustedSetupRequired,bytes32 trustedSetupTranscriptSha256,bytes32 provingProgramSha256,bytes32 sourceManifestSha256,bytes32 verifierArtifactSha256,uint32 maxProofBytes,uint64 minimumFinalityBeaconSlot)',
);
export const VERIFIER_CONFIG_TYPEHASH = id(
  'FinalizedBurnVerifierConfig(bytes32 protocolHash,bytes32 stateRulesHash,bytes32 proofSystemHash)',
);
export const FINALIZED_BURN_RISC0_ADAPTER_CONFIG_TYPEHASH = id(
  'DOMFinalizedBurnRiscZeroVerifier(uint256 chainId,address riscZeroVerifier,bytes32 riscZeroVerifierCodeHash,bytes4 verifierSelector,bytes32 imageId,bytes32 journalSchemaHash,bytes32 proofAccepted)',
);

function exactObject(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).length !== fields.length || fields.some(field => !(field in input))) {
    throw new Error('exact finalized-burn verifier configuration fields required');
  }
}

function hash(value, name, {zero = false} = {}) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${name} must be bytes32`);
  }
  const normalized = value.toLowerCase();
  if (zero ? normalized !== zeroHash : normalized === zeroHash) {
    throw new Error(`${name} has invalid zero semantics`);
  }
  return normalized;
}

/**
 * Validate and hash the complete immutable verifier configuration. The hash is
 * The on-chain verifierConfigHash is the exact immutable RISC Zero adapter
 * identity. The complete native rules and proof artifacts are retained in the
 * canonical manifest and separately committed by provingProgramConfigHash.
 * Neither hash grants proof authority or validates the referenced artifacts.
 */
export function finalizedBurnVerifierConfigHash(input) {
  exactObject(input);
  const c = {...input};
  if (c.schema !== VERIFIER_CONFIG_SCHEMA) throw new Error('unsupported verifier configuration schema');
  c.statementVersion = uint(c.statementVersion, 16);
  c.transitionCommitmentVersion = uint(c.transitionCommitmentVersion, 16);
  c.burnStateWitnessVersion = uint(c.burnStateWitnessVersion, 16);
  c.finalizedBurnProverInputVersion = uint(c.finalizedBurnProverInputVersion, 16);
  c.publicOutputVersion = uint(c.publicOutputVersion, 16);
  if (c.statementVersion !== 1n || c.transitionCommitmentVersion !== 2n
      || c.burnStateWitnessVersion !== 3n || c.finalizedBurnProverInputVersion !== 2n
      || c.publicOutputVersion !== 1n) {
    throw new Error('unsupported finalized-burn protocol version');
  }
  for (const name of [
    'burnStatementTypeHash','burnIntentTypeHash','privateBurnIdTypeHash','activationScheduleCommitment',
    'domGenesisHash','domChainId','activationEmptyStateRoot','consensusRulesHash','forkChoiceRulesHash',
    'powRulesHash','nativeAssetId',
    'noteTreeRulesHash','nullifierRulesHash','balanceRulesHash','finalityRulesHash','verifyingKeySha256',
    'provingProgramSha256','sourceManifestSha256','verifierArtifactSha256',
    'riscZeroVerifierCodeHash','finalizedBurnGuestImageId','journalSchemaHash',
  ]) c[name] = hash(c[name], name);
  if (c.burnStatementTypeHash !== BURN_STATEMENT_TYPEHASH
      || c.burnIntentTypeHash !== BURN_INTENT_TYPEHASH
      || c.privateBurnIdTypeHash !== PRIVATE_BURN_ID_TYPEHASH) {
    throw new Error('verifier configuration uses an unexpected public statement type');
  }
  c.domNetworkMagic = uint(c.domNetworkMagic, 32);
  c.firstV4Height = uint(c.firstV4Height, 64);
  c.maxProofBytes = uint(c.maxProofBytes, 32);
  c.minimumFinalityBeaconSlot = uint(c.minimumFinalityBeaconSlot, 64);
  if (c.domNetworkMagic === 0n || c.firstV4Height === 0n || c.maxProofBytes !== 65_536n
      || c.minimumFinalityBeaconSlot === 0n) {
    throw new Error('invalid finalized-burn verifier numeric policy');
  }
  if (c.proofSystem !== FINALIZED_BURN_PROOF_SYSTEM) {
    throw new Error('unsupported finalized-burn proof system');
  }
  c.ethereumChainId=uint(c.ethereumChainId,256);
  if(c.ethereumChainId===0n) throw new Error('ethereumChainId must be nonzero');
  try {
    c.riscZeroVerifier=getAddress(c.riscZeroVerifier);
  } catch {
    throw new Error('riscZeroVerifier must be a nonzero canonical address');
  }
  if(c.riscZeroVerifier===getAddress('0x0000000000000000000000000000000000000000')) {
    throw new Error('riscZeroVerifier must be a nonzero canonical address');
  }
  if(typeof c.riscZeroVerifierSelector!=='string'
      || !/^0x[0-9a-fA-F]{8}$/.test(c.riscZeroVerifierSelector)
      || c.riscZeroVerifierSelector.toLowerCase()!==FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR
      || c.journalSchemaHash!==FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH) {
    throw new Error('unsupported RISC Zero verifier or journal identity');
  }
  c.riscZeroVerifierSelector=c.riscZeroVerifierSelector.toLowerCase();
  if (typeof c.trustedSetupRequired !== 'boolean') throw new Error('trustedSetupRequired must be boolean');
  c.trustedSetupTranscriptSha256 = hash(
    c.trustedSetupTranscriptSha256,
    'trustedSetupTranscriptSha256',
    {zero:!c.trustedSetupRequired},
  );
  const proofSystemIdHash = keccak256(toUtf8Bytes(c.proofSystem));
  const protocolHash = keccak256(abi.encode(
    ['bytes32','uint16','uint16','uint16','uint16','uint16','bytes32','bytes32','bytes32','bytes32','bytes32','uint32','bytes32','uint64','bytes32'],
    [VERIFIER_PROTOCOL_TYPEHASH,c.statementVersion,c.transitionCommitmentVersion,
      c.burnStateWitnessVersion,c.finalizedBurnProverInputVersion,c.publicOutputVersion,
      c.burnStatementTypeHash,c.burnIntentTypeHash,c.privateBurnIdTypeHash,c.activationScheduleCommitment,
      c.domGenesisHash,c.domNetworkMagic,c.domChainId,c.firstV4Height,c.activationEmptyStateRoot],
  ));
  const stateRulesHash = keccak256(abi.encode(
    ['bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','bytes32'],
    [VERIFIER_STATE_RULES_TYPEHASH,c.consensusRulesHash,c.forkChoiceRulesHash,c.powRulesHash,
      c.nativeAssetId,c.noteTreeRulesHash,c.nullifierRulesHash,c.balanceRulesHash,c.finalityRulesHash],
  ));
  const proofSystemHash = keccak256(abi.encode(
    ['bytes32','bytes32','bytes32','bool','bytes32','bytes32','bytes32','bytes32','uint32','uint64'],
    [VERIFIER_PROOF_SYSTEM_TYPEHASH,proofSystemIdHash,c.verifyingKeySha256,c.trustedSetupRequired,
      c.trustedSetupTranscriptSha256,c.provingProgramSha256,c.sourceManifestSha256,
      c.verifierArtifactSha256,c.maxProofBytes,c.minimumFinalityBeaconSlot],
  ));
  const provingProgramConfigHash = keccak256(abi.encode(
    ['bytes32','bytes32','bytes32','bytes32'],
    [VERIFIER_CONFIG_TYPEHASH,protocolHash,stateRulesHash,proofSystemHash],
  ));
  const verifierConfigHash=keccak256(abi.encode(
    ['bytes32','uint256','address','bytes32','bytes4','bytes32','bytes32','bytes32'],
    [FINALIZED_BURN_RISC0_ADAPTER_CONFIG_TYPEHASH,c.ethereumChainId,c.riscZeroVerifier,
      c.riscZeroVerifierCodeHash,c.riscZeroVerifierSelector,c.finalizedBurnGuestImageId,
      c.journalSchemaHash,FINALIZED_BURN_PROOF_ACCEPTED_HASH],
  ));
  const manifest=Object.fromEntries(fields.map(name=>[
    name,typeof c[name] === 'bigint' ? c[name].toString() : c[name],
  ]));
  const canonicalManifest=JSON.stringify(manifest,null,2)+'\n';
  const manifestSha256=sha256(toUtf8Bytes(canonicalManifest));
  return {...c, proofSystemIdHash, protocolHash, stateRulesHash, proofSystemHash,
    provingProgramConfigHash,verifierConfigHash,canonicalManifest,manifestSha256};
}
