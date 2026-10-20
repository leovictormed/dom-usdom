import {AbiCoder, getAddress, id, keccak256} from 'ethers';
import {uint} from './reserve.mjs';

const abi=AbiCoder.defaultAbiCoder();
const zeroAddress='0x0000000000000000000000000000000000000000';
const zeroHash='0x'+'00'.repeat(32);
const configFields=Object.freeze([
  'ethereumChainId','registry','bridgeDomain','domNetworkMagic','activationScheduleCommitment',
  'domChainId','firstV4Height','activationEmptyStateRoot',
  'checkpointInterval','confirmationDepth','challengePeriod',
  'verifier','verifierCodeHash','verifierConfigHash','guardian','guardianCodeHash',
  'initialHeight','initialBlock','initialStateRoot','initialContextHash','initialTotalDifficulty',
]);
const checkpointFields=Object.freeze([
  'previousHeight','previousBlock','previousStateRoot','previousContextHash','previousTotalDifficulty',
  'height','blockHash','stateRoot','contextHash','totalDifficulty',
  'confirmationHeight','confirmationBlock','confirmationTotalDifficulty','confirmationTimestamp',
]);

export const CHECKPOINT_EVENT_SIGNATURE='Checkpoint(bytes32,uint32,uint64,bytes32,bytes32,bytes32)';
export const CHECKPOINT_EVENT_TOPIC0=id(CHECKPOINT_EVENT_SIGNATURE);
export const CHECKPOINT_BOOTSTRAP_EVENT_SIGNATURE=
  'CheckpointBootstrap(bytes32,uint32,uint64,bytes32,bytes32,bytes32)';
export const CHECKPOINT_BOOTSTRAP_EVENT_TOPIC0=id(CHECKPOINT_BOOTSTRAP_EVENT_SIGNATURE);
export const NATIVE_STATE_VERSION=2n;
export const TRANSITION_BATCH_VERSION=3n;
export const LEGACY_CHECKPOINT_STATEMENT_TYPEHASH=id(
  'DOMCheckpoint(bytes32 bridgeDomain,uint32 domNetworkMagic,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)',
);
export const CHECKPOINT_STATEMENT_TYPEHASH=id(
  'DOMCheckpointV2(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)',
);
export const CHECKPOINT_IDENTITY_TYPEHASH=id(
  'DOMCheckpointIdentity(uint256 ethereumChainId,address registry,bytes32 bridgeDomain,uint32 domNetworkMagic,bytes32 domChainId,uint64 firstV4Height,bytes32 activationEmptyStateRoot,bytes32 activationScheduleCommitment,uint32 checkpointInterval,uint32 confirmationDepth,uint64 challengePeriod,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash)',
);
export const CHECKPOINT_BOOTSTRAP_TYPEHASH=id(
  'DOMCheckpointBootstrap(address guardian,bytes32 guardianCodeHash,uint64 initialHeight,bytes32 initialBlock,bytes32 initialStateRoot,bytes32 initialContextHash,uint256 initialTotalDifficulty)',
);
export const CHECKPOINT_CONFIG_TYPEHASH=id('DOMCheckpointConfig(bytes32 identityHash,bytes32 bootstrapHash)');

function exact(input,fields,name) {
  if(!input || typeof input!=='object' || Array.isArray(input)
      || Object.keys(input).length!==fields.length || fields.some(field=>!(field in input))) {
    throw new Error(`exact ${name} fields required`);
  }
}

function hash(value,name) {
  if(typeof value!=='string' || !/^0x[0-9a-fA-F]{64}$/.test(value) || value.toLowerCase()===zeroHash) {
    throw new Error(`${name} must be nonzero bytes32`);
  }
  return value.toLowerCase();
}

function address(value,name) {
  let normalized;
  try { normalized=getAddress(value); } catch { throw new Error(`${name} must be an address`); }
  if(normalized===zeroAddress) throw new Error(`${name} must be nonzero`);
  return normalized;
}

/** Hash the exact immutable registry identity and ratified bootstrap anchor. */
export function checkpointRegistryConfigHash(input) {
  exact(input,configFields,'checkpoint registry configuration');
  const c={...input};
  c.ethereumChainId=uint(c.ethereumChainId,256);
  c.registry=address(c.registry,'registry');
  c.bridgeDomain=hash(c.bridgeDomain,'bridgeDomain');
  c.domNetworkMagic=uint(c.domNetworkMagic,32);
  c.domChainId=hash(c.domChainId,'domChainId');
  c.firstV4Height=uint(c.firstV4Height,64);
  c.activationEmptyStateRoot=hash(c.activationEmptyStateRoot,'activationEmptyStateRoot');
  c.activationScheduleCommitment=hash(c.activationScheduleCommitment,'activationScheduleCommitment');
  c.checkpointInterval=uint(c.checkpointInterval,32);
  c.confirmationDepth=uint(c.confirmationDepth,32);
  c.challengePeriod=uint(c.challengePeriod,64);
  c.verifier=address(c.verifier,'verifier');
  c.verifierCodeHash=hash(c.verifierCodeHash,'verifierCodeHash');
  c.verifierConfigHash=hash(c.verifierConfigHash,'verifierConfigHash');
  c.guardian=address(c.guardian,'guardian');
  c.guardianCodeHash=hash(c.guardianCodeHash,'guardianCodeHash');
  c.initialHeight=uint(c.initialHeight,64);
  c.initialBlock=hash(c.initialBlock,'initialBlock');
  c.initialStateRoot=hash(c.initialStateRoot,'initialStateRoot');
  c.initialContextHash=hash(c.initialContextHash,'initialContextHash');
  c.initialTotalDifficulty=uint(c.initialTotalDifficulty,256);
  if(c.ethereumChainId===0n || c.domNetworkMagic===0n || c.initialHeight===0n
      || c.initialHeight===(1n<<64n)-1n || c.firstV4Height!==c.initialHeight+1n
      || c.initialStateRoot!==c.activationEmptyStateRoot || c.verifier===c.guardian
      || c.checkpointInterval===0n || c.checkpointInterval>360n
      || c.confirmationDepth===0n || c.confirmationDepth>c.checkpointInterval
      || c.challengePeriod<86_400n || c.challengePeriod>2_592_000n
      || c.initialTotalDifficulty===0n
      || c.initialHeight+c.checkpointInterval+c.confirmationDepth>(1n<<64n)-1n) {
    throw new Error('invalid checkpoint registry configuration');
  }
  const identityHash=keccak256(abi.encode(
    ['bytes32','uint256','address','bytes32','uint32','bytes32','uint64','bytes32','bytes32',
      'uint32','uint32','uint64','address','bytes32','bytes32'],
    [CHECKPOINT_IDENTITY_TYPEHASH,c.ethereumChainId,c.registry,c.bridgeDomain,c.domNetworkMagic,
      c.domChainId,c.firstV4Height,c.activationEmptyStateRoot,c.activationScheduleCommitment,
      c.checkpointInterval,c.confirmationDepth,c.challengePeriod,
      c.verifier,c.verifierCodeHash,c.verifierConfigHash],
  ));
  const bootstrapHash=keccak256(abi.encode(
    ['bytes32','address','bytes32','uint64','bytes32','bytes32','bytes32','uint256'],
    [CHECKPOINT_BOOTSTRAP_TYPEHASH,c.guardian,c.guardianCodeHash,c.initialHeight,
      c.initialBlock,c.initialStateRoot,c.initialContextHash,c.initialTotalDifficulty],
  ));
  const checkpointConfigHash=keccak256(abi.encode(
    ['bytes32','bytes32','bytes32'],[CHECKPOINT_CONFIG_TYPEHASH,identityHash,bootstrapHash],
  ));
  return {...c,identityHash,bootstrapHash,checkpointConfigHash};
}

/** Hash one exact sequential checkpoint statement for the immutable verifier. */
export function checkpointStatementHash(configuration,input) {
  const c=checkpointRegistryConfigHash(configuration);
  exact(input,checkpointFields,'checkpoint statement');
  const checkpoint={...input};
  checkpoint.previousHeight=uint(checkpoint.previousHeight,64);
  checkpoint.previousBlock=hash(checkpoint.previousBlock,'previousBlock');
  checkpoint.previousStateRoot=hash(checkpoint.previousStateRoot,'previousStateRoot');
  checkpoint.previousContextHash=hash(checkpoint.previousContextHash,'previousContextHash');
  checkpoint.previousTotalDifficulty=uint(checkpoint.previousTotalDifficulty,256);
  checkpoint.height=uint(checkpoint.height,64);
  checkpoint.blockHash=hash(checkpoint.blockHash,'blockHash');
  checkpoint.stateRoot=hash(checkpoint.stateRoot,'stateRoot');
  checkpoint.contextHash=hash(checkpoint.contextHash,'contextHash');
  checkpoint.totalDifficulty=uint(checkpoint.totalDifficulty,256);
  checkpoint.confirmationHeight=uint(checkpoint.confirmationHeight,64);
  checkpoint.confirmationBlock=hash(checkpoint.confirmationBlock,'confirmationBlock');
  checkpoint.confirmationTotalDifficulty=uint(checkpoint.confirmationTotalDifficulty,256);
  checkpoint.confirmationTimestamp=uint(checkpoint.confirmationTimestamp,64);
  if(checkpoint.height!==checkpoint.previousHeight+c.checkpointInterval
      || checkpoint.confirmationHeight!==checkpoint.height+c.confirmationDepth
      || checkpoint.blockHash===checkpoint.previousBlock
      || checkpoint.contextHash===checkpoint.previousContextHash
      || checkpoint.confirmationBlock===checkpoint.blockHash
      || checkpoint.confirmationTimestamp===0n
      || checkpoint.totalDifficulty<=checkpoint.previousTotalDifficulty
      || checkpoint.confirmationTotalDifficulty<=checkpoint.totalDifficulty) {
    throw new Error('checkpoint must be an exact work-increasing round with confirmation suffix');
  }
  return keccak256(abi.encode(
    ['bytes32','bytes32','uint32','uint16','uint16','uint64','bytes32','bytes32','bytes32','uint256','uint64','bytes32',
      'bytes32','bytes32','uint256','uint64','bytes32','uint256','uint64','uint256','address','bytes32','bytes32'],
    [CHECKPOINT_STATEMENT_TYPEHASH,c.bridgeDomain,c.domNetworkMagic,NATIVE_STATE_VERSION,
      TRANSITION_BATCH_VERSION,checkpoint.previousHeight,
      checkpoint.previousBlock,checkpoint.previousStateRoot,checkpoint.previousContextHash,
      checkpoint.previousTotalDifficulty,checkpoint.height,checkpoint.blockHash,checkpoint.stateRoot,
      checkpoint.contextHash,checkpoint.totalDifficulty,
      checkpoint.confirmationHeight,checkpoint.confirmationBlock,checkpoint.confirmationTotalDifficulty,
      checkpoint.confirmationTimestamp,c.ethereumChainId,c.registry,c.activationScheduleCommitment,
      c.checkpointConfigHash],
  ));
}
