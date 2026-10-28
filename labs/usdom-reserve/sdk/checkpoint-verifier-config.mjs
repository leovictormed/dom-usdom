import {AbiCoder, getAddress, id, keccak256, sha256, toUtf8Bytes} from 'ethers';
import {uint} from './reserve.mjs';
import {CHECKPOINT_STATEMENT_TYPEHASH} from './checkpoint-registry.mjs';
import {PINNED_RISC0_MAINNET_V3} from './risc0-verifier-reference.mjs';

const abi=AbiCoder.defaultAbiCoder();
const zeroHash='0x'+'00'.repeat(32);
const fields=Object.freeze([
  'schema','statementVersion','checkpointProverInputVersion','continuationContextVersion',
  'transitionCommitmentVersion','activationScheduleVersion','publicOutputVersion','publicStatementBytes',
  'continuationContextBytes','segmentStateVersion','segmentTransitionVersion','randomxStatementVersion',
  'segmentStateBytes','segmentTransitionBytes','randomxStatementBytes','segmentStateDomainHash',
  'segmentTransitionDomainHash','randomxStatementDomainHash','randomxReceiptImageId',
  'checkpointStatementTypeHash','proofAcceptedHash','activationScheduleCommitment','domGenesisHash',
  'domNetworkMagic','domChainId','firstV4Height','activationEmptyStateRoot','checkpointInterval',
  'confirmationDepth','challengePeriod','maxCheckpointSpan',
  'consensusRulesHash','forkChoiceRulesHash','powRulesHash','nativeStateRulesHash','continuationContextRulesHash',
  'consensusExtensionWitnessRulesHash','proofSystem','verifyingKeySha256','trustedSetupRequired',
  'trustedSetupTranscriptSha256','provingProgramSha256','sourceManifestSha256',
  'verifierArtifactSha256','maxProofBytes','ethereumChainId','riscZeroVerifier',
  'riscZeroVerifierCodeHash','riscZeroVerifierSelector','checkpointGuestImageId','journalSchemaHash',
]);
const adapterFields=Object.freeze([
  'ethereumChainId','riscZeroVerifier','riscZeroVerifierCodeHash','riscZeroVerifierSelector',
  'checkpointGuestImageId',
]);

export const CHECKPOINT_VERIFIER_CONFIG_SCHEMA='usdom-checkpoint-verifier-config-v8';
export const CHECKPOINT_PROOF_ACCEPTED_HASH=id('DOM_CHECKPOINT_PROOF_V3');
export const CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH=keccak256(
  toUtf8Bytes('DOM:checkpoint-segment-state:v2'),
);
export const CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH=keccak256(
  toUtf8Bytes('DOM:checkpoint-segment-transition:v4'),
);
export const CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH=keccak256(
  toUtf8Bytes('DOM:checkpoint-randomx-statement:v1'),
);
export const CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH=id('raw-statement-hash-32-bytes-v1');
export const CHECKPOINT_RISC0_GROTH16_V3_SELECTOR='0x73c457ba';
export const CHECKPOINT_EVM_SEAL_BYTES=4+8*32;
export const CHECKPOINT_PROOF_SYSTEM='risc0-groth16-v3';
export const CHECKPOINT_VERIFIER_PROTOCOL_TYPEHASH=id(
  'CheckpointVerifierProtocol(uint16 statementVersion,uint16 checkpointProverInputVersion,uint16 continuationContextVersion,uint16 transitionCommitmentVersion,uint16 activationScheduleVersion,uint16 publicOutputVersion,uint16 publicStatementBytes,uint16 continuationContextBytes,uint16 segmentStateVersion,uint16 segmentTransitionVersion,uint16 randomxStatementVersion,uint16 segmentStateBytes,uint16 segmentTransitionBytes,uint16 randomxStatementBytes,bytes32 segmentStateDomainHash,bytes32 segmentTransitionDomainHash,bytes32 randomxStatementDomainHash,bytes32 randomxReceiptImageId,bytes32 checkpointStatementTypeHash,bytes32 proofAcceptedHash,bytes32 activationScheduleCommitment,bytes32 domGenesisHash,uint32 domNetworkMagic,bytes32 domChainId,uint64 firstV4Height,bytes32 activationEmptyStateRoot,uint32 checkpointInterval,uint32 confirmationDepth,uint64 challengePeriod,uint32 maxCheckpointSpan)',
);
export const CHECKPOINT_VERIFIER_STATE_RULES_TYPEHASH=id(
  'CheckpointVerifierStateRules(bytes32 consensusRulesHash,bytes32 forkChoiceRulesHash,bytes32 powRulesHash,bytes32 nativeStateRulesHash,bytes32 continuationContextRulesHash,bytes32 consensusExtensionWitnessRulesHash)',
);
export const CHECKPOINT_VERIFIER_PROOF_SYSTEM_TYPEHASH=id(
  'CheckpointVerifierProofSystem(bytes32 proofSystemHash,bytes32 verifyingKeySha256,bool trustedSetupRequired,bytes32 trustedSetupTranscriptSha256,bytes32 provingProgramSha256,bytes32 sourceManifestSha256,bytes32 verifierArtifactSha256,uint32 maxProofBytes)',
);
export const CHECKPOINT_PROVING_PROGRAM_CONFIG_TYPEHASH=id(
  'CheckpointProvingProgramConfig(bytes32 protocolHash,bytes32 stateRulesHash,bytes32 proofSystemHash)',
);
export const CHECKPOINT_RISC0_ADAPTER_CONFIG_TYPEHASH=id(
  'DOMCheckpointRiscZeroVerifier(uint256 chainId,address riscZeroVerifier,bytes32 riscZeroVerifierCodeHash,bytes4 verifierSelector,bytes32 imageId,bytes32 journalSchemaHash,bytes32 proofAccepted)',
);

function exact(input) {
  if(!input || typeof input!=='object' || Array.isArray(input)
      || Object.keys(input).length!==fields.length || fields.some(field=>!(field in input))) {
    throw new Error('exact checkpoint verifier configuration fields required');
  }
}

function hash(value,name,{zero=false}={}) {
  if(typeof value!=='string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${name} must be bytes32`);
  }
  const normalized=value.toLowerCase();
  if(zero ? normalized!==zeroHash : normalized===zeroHash) {
    throw new Error(`${name} has invalid zero semantics`);
  }
  return normalized;
}

function requireReviewedMainnetVerifier(c) {
  if(c.ethereumChainId!==1n) return;
  if(c.riscZeroVerifier!==getAddress(PINNED_RISC0_MAINNET_V3.verifier_address)
      ||c.riscZeroVerifierCodeHash
        !==PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash
      ||c.riscZeroVerifierSelector!==PINNED_RISC0_MAINNET_V3.verifier_selector) {
    throw new Error('Ethereum mainnet requires the reviewed direct RISC Zero verifier pin');
  }
}

export function checkpointAdapterConfigHash(input) {
  if(!input||typeof input!=='object'||Array.isArray(input)
      ||Object.keys(input).length!==adapterFields.length||adapterFields.some(field=>!(field in input))) {
    throw new Error('exact checkpoint adapter fields required');
  }
  const c={...input};
  c.ethereumChainId=uint(c.ethereumChainId,256);
  if(c.ethereumChainId===0n) throw new Error('ethereumChainId must be nonzero');
  try { c.riscZeroVerifier=getAddress(c.riscZeroVerifier); }
  catch { throw new Error('riscZeroVerifier must be a nonzero canonical address'); }
  if(c.riscZeroVerifier===getAddress('0x0000000000000000000000000000000000000000')) {
    throw new Error('riscZeroVerifier must be nonzero');
  }
  c.riscZeroVerifierCodeHash=hash(c.riscZeroVerifierCodeHash,'riscZeroVerifierCodeHash');
  c.checkpointGuestImageId=hash(c.checkpointGuestImageId,'checkpointGuestImageId');
  if(typeof c.riscZeroVerifierSelector!=='string'
      ||c.riscZeroVerifierSelector.toLowerCase()!==CHECKPOINT_RISC0_GROTH16_V3_SELECTOR) {
    throw new Error('unsupported RISC Zero verifier selector');
  }
  c.riscZeroVerifierSelector=c.riscZeroVerifierSelector.toLowerCase();
  requireReviewedMainnetVerifier(c);
  const verifierConfigHash=keccak256(abi.encode(
    ['bytes32','uint256','address','bytes32','bytes4','bytes32','bytes32','bytes32'],
    [CHECKPOINT_RISC0_ADAPTER_CONFIG_TYPEHASH,c.ethereumChainId,c.riscZeroVerifier,
      c.riscZeroVerifierCodeHash,c.riscZeroVerifierSelector,c.checkpointGuestImageId,
      CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,CHECKPOINT_PROOF_ACCEPTED_HASH],
  ));
  return {...c,journalSchemaHash:CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,
    proofAcceptedHash:CHECKPOINT_PROOF_ACCEPTED_HASH,verifierConfigHash};
}

/**
 * Prove that one complete checkpoint verifier manifest is the configuration
 * of the outer guest selected by a release.  This is deliberately separate
 * from selecting/approving that ImageID: callers must supply the exact ImageID
 * obtained from their authenticated outer-guest artifact set.
 *
 * The returned adapter hash is the value committed by
 * DOMCheckpointRiscZeroVerifier.verifierConfigHash().  Consequently an ImageID
 * substitution, a journal-schema substitution, or any immutable adapter drift
 * cannot retain the same binding.
 */
export function checkpointOuterAdapterBinding(input,expectedOuterImageId) {
  const expected=hash(expectedOuterImageId,'expectedOuterImageId');
  const computed=checkpointVerifierConfigHash(input);
  if(computed.checkpointGuestImageId!==expected) {
    throw new Error('checkpoint verifier ImageID is not the selected outer guest');
  }
  return Object.freeze({
    checkpointGuestImageId:computed.checkpointGuestImageId,
    journalSchemaHash:computed.journalSchemaHash,
    proofAcceptedHash:computed.proofAcceptedHash,
    verifierConfigHash:computed.verifierConfigHash,
  });
}

/**
 * Commit every immutable rule and artifact that can affect acceptance of a DOM
 * consensus-extension checkpoint proof. This manifest grants no proof authority.
 */
export function checkpointVerifierConfigHash(input) {
  exact(input);
  const c={...input};
  if(c.schema!==CHECKPOINT_VERIFIER_CONFIG_SCHEMA) {
    throw new Error('unsupported checkpoint verifier configuration schema');
  }
  for(const name of ['statementVersion','checkpointProverInputVersion','continuationContextVersion',
    'transitionCommitmentVersion','activationScheduleVersion','publicOutputVersion','publicStatementBytes',
    'continuationContextBytes','segmentStateVersion','segmentTransitionVersion','randomxStatementVersion',
    'segmentStateBytes','segmentTransitionBytes','randomxStatementBytes']) c[name]=uint(c[name],16);
  if(c.statementVersion!==6n || c.checkpointProverInputVersion!==4n || c.continuationContextVersion!==2n
      || c.transitionCommitmentVersion!==4n || c.activationScheduleVersion!==2n
      || c.publicOutputVersion!==1n || c.publicStatementBytes!==551n
      || c.continuationContextBytes!==695n || c.segmentStateVersion!==2n
      || c.segmentTransitionVersion!==4n || c.randomxStatementVersion!==1n
      || c.segmentStateBytes!==1105n || c.segmentTransitionBytes!==2320n
      || c.randomxStatementBytes!==384n) {
    throw new Error('unsupported checkpoint verifier protocol version');
  }
  for(const name of ['checkpointStatementTypeHash','proofAcceptedHash','activationScheduleCommitment',
    'domGenesisHash','domChainId','activationEmptyStateRoot','consensusRulesHash','forkChoiceRulesHash',
    'powRulesHash','nativeStateRulesHash','continuationContextRulesHash',
    'consensusExtensionWitnessRulesHash','verifyingKeySha256',
    'provingProgramSha256','sourceManifestSha256','verifierArtifactSha256','segmentStateDomainHash',
    'segmentTransitionDomainHash','randomxStatementDomainHash','randomxReceiptImageId',
    'riscZeroVerifierCodeHash','checkpointGuestImageId','journalSchemaHash']) c[name]=hash(c[name],name);
  if(c.checkpointStatementTypeHash!==CHECKPOINT_STATEMENT_TYPEHASH
      || c.proofAcceptedHash!==CHECKPOINT_PROOF_ACCEPTED_HASH
      || c.segmentStateDomainHash!==CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH
      || c.segmentTransitionDomainHash!==CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH
      || c.randomxStatementDomainHash!==CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH) {
    throw new Error('unexpected checkpoint statement or acceptance identity');
  }
  c.domNetworkMagic=uint(c.domNetworkMagic,32);
  c.firstV4Height=uint(c.firstV4Height,64);
  c.checkpointInterval=uint(c.checkpointInterval,32);
  c.confirmationDepth=uint(c.confirmationDepth,32);
  c.challengePeriod=uint(c.challengePeriod,64);
  c.maxCheckpointSpan=uint(c.maxCheckpointSpan,32);
  c.maxProofBytes=uint(c.maxProofBytes,32);
  c.ethereumChainId=uint(c.ethereumChainId,256);
  if(c.domNetworkMagic===0n || c.firstV4Height===0n || c.ethereumChainId===0n
      || c.checkpointInterval===0n || c.checkpointInterval>360n
      || c.confirmationDepth===0n || c.confirmationDepth>c.checkpointInterval
      || c.challengePeriod<86_400n || c.challengePeriod>2_592_000n
      || c.maxCheckpointSpan!==c.checkpointInterval+c.confirmationDepth
      || c.maxCheckpointSpan>720n || c.maxProofBytes!==BigInt(CHECKPOINT_EVM_SEAL_BYTES)) {
    throw new Error('invalid checkpoint verifier numeric policy');
  }
  if(c.proofSystem!==CHECKPOINT_PROOF_SYSTEM) {
    throw new Error('unsupported checkpoint proof system');
  }
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
      || c.riscZeroVerifierSelector.toLowerCase()!==CHECKPOINT_RISC0_GROTH16_V3_SELECTOR
      || c.journalSchemaHash!==CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH) {
    throw new Error('unsupported RISC Zero verifier or journal identity');
  }
  c.riscZeroVerifierSelector=c.riscZeroVerifierSelector.toLowerCase();
  if(c.trustedSetupRequired!==true) {
    throw new Error('risc0-groth16-v3 requires the RISC Zero trusted setup to be declared');
  }
  c.trustedSetupTranscriptSha256=hash(c.trustedSetupTranscriptSha256,
    'trustedSetupTranscriptSha256');
  const proofSystemIdHash=keccak256(toUtf8Bytes(c.proofSystem));
  const protocolHash=keccak256(abi.encode(
    ['bytes32','uint16','uint16','uint16','uint16','uint16','uint16','uint16','uint16',
      'uint16','uint16','uint16','uint16','uint16','uint16','bytes32','bytes32','bytes32','bytes32',
      'bytes32','bytes32','bytes32','bytes32','uint32','bytes32','uint64','bytes32','uint32','uint32','uint64','uint32'],
    [CHECKPOINT_VERIFIER_PROTOCOL_TYPEHASH,c.statementVersion,c.checkpointProverInputVersion,
      c.continuationContextVersion,c.transitionCommitmentVersion,c.activationScheduleVersion,c.publicOutputVersion,
      c.publicStatementBytes,c.continuationContextBytes,c.segmentStateVersion,c.segmentTransitionVersion,
      c.randomxStatementVersion,c.segmentStateBytes,c.segmentTransitionBytes,c.randomxStatementBytes,
      c.segmentStateDomainHash,c.segmentTransitionDomainHash,c.randomxStatementDomainHash,
      c.randomxReceiptImageId,c.checkpointStatementTypeHash,c.proofAcceptedHash,
      c.activationScheduleCommitment,c.domGenesisHash,c.domNetworkMagic,c.domChainId,c.firstV4Height,
      c.activationEmptyStateRoot,c.checkpointInterval,c.confirmationDepth,c.challengePeriod,
      c.maxCheckpointSpan],
  ));
  const stateRulesHash=keccak256(abi.encode(
    ['bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','bytes32'],
    [CHECKPOINT_VERIFIER_STATE_RULES_TYPEHASH,c.consensusRulesHash,c.forkChoiceRulesHash,
      c.powRulesHash,c.nativeStateRulesHash,c.continuationContextRulesHash,
      c.consensusExtensionWitnessRulesHash],
  ));
  const proofSystemHash=keccak256(abi.encode(
    ['bytes32','bytes32','bytes32','bool','bytes32','bytes32','bytes32','bytes32','uint32'],
    [CHECKPOINT_VERIFIER_PROOF_SYSTEM_TYPEHASH,proofSystemIdHash,c.verifyingKeySha256,
      c.trustedSetupRequired,c.trustedSetupTranscriptSha256,c.provingProgramSha256,
      c.sourceManifestSha256,c.verifierArtifactSha256,c.maxProofBytes],
  ));
  const provingProgramConfigHash=keccak256(abi.encode(
    ['bytes32','bytes32','bytes32','bytes32'],
    [CHECKPOINT_PROVING_PROGRAM_CONFIG_TYPEHASH,protocolHash,stateRulesHash,proofSystemHash],
  ));
  const verifierConfigHash=checkpointAdapterConfigHash({ethereumChainId:c.ethereumChainId,
    riscZeroVerifier:c.riscZeroVerifier,riscZeroVerifierCodeHash:c.riscZeroVerifierCodeHash,
    riscZeroVerifierSelector:c.riscZeroVerifierSelector,
    checkpointGuestImageId:c.checkpointGuestImageId}).verifierConfigHash;
  const manifest=Object.fromEntries(fields.map(name=>[
    name,typeof c[name]==='bigint' ? c[name].toString() : c[name],
  ]));
  const canonicalManifest=JSON.stringify(manifest,null,2)+'\n';
  const manifestSha256=sha256(toUtf8Bytes(canonicalManifest));
  return {...c,proofSystemIdHash,protocolHash,stateRulesHash,proofSystemHash,provingProgramConfigHash,
    verifierConfigHash,
    canonicalManifest,manifestSha256};
}
