import {AbiCoder,getAddress,keccak256,toUtf8Bytes} from 'ethers';

export const ETHEREUM_CHECKPOINT_CONSENSUS_SCHEMA='usdom-ethereum-checkpoint-consensus-v1';
export const PREACTIVATION_POLICY_SCHEMA='usdom-preactivation-policy-v1';
export const DOM_DOMAIN_TYPE='USDOMDomain(uint32 domNetworkMagic,bytes32 domChainId,uint256 ethereumChainId,address reserve,address checkpointRegistry)';
export const DOM_DOMAIN_TYPEHASH=keccak256(toUtf8Bytes(DOM_DOMAIN_TYPE));
const hashPattern=/^0x[0-9a-fA-F]{64}$/;
const addressPattern=/^0x[0-9a-fA-F]{40}$/;
const abi=AbiCoder.defaultAbiCoder();

function exact(value,fields,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||Object.keys(value).length!==fields.length||fields.some(field=>!(field in value))) {
    throw new Error(`${label} must use the exact supported schema`);
  }
}
function decimal(value,bits,label) {
  const maxDigits={8:3,32:10,64:20,128:39,256:78}[bits];
  if(maxDigits===undefined||typeof value!=='string'||value.length>maxDigits
      ||!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${label} must be canonical decimal`);
  const parsed=BigInt(value);
  if(parsed>=(1n<<BigInt(bits))) throw new Error(`${label} exceeds uint${bits}`);
  return parsed;
}
function hash(value,label) {
  if(!hashPattern.test(value??'')||BigInt(value)===0n) throw new Error(`${label} must be nonzero bytes32`);
  return value.toLowerCase();
}
function address(value,label) {
  if(!addressPattern.test(value??'')||BigInt(value)===0n) throw new Error(`${label} must be a nonzero address`);
  return getAddress(value);
}

export function deriveDomDomain({domNetworkMagic,domChainId,ethereumChainId,reserve,checkpointRegistry}) {
  const magic=decimal(domNetworkMagic,32,'domNetworkMagic');
  const chain=hash(domChainId,'domChainId');
  const ethereum=decimal(ethereumChainId,256,'ethereumChainId');
  if(ethereum!==1n) throw new Error('production domain requires Ethereum mainnet');
  return keccak256(abi.encode(['bytes32','uint32','bytes32','uint256','address','address'],
    [DOM_DOMAIN_TYPEHASH,magic,chain,ethereum,address(reserve,'reserve'),
      address(checkpointRegistry,'checkpointRegistry')]));
}

export function materializePreActivationPolicy({releaseConfig,anchor,checkpointConsensus,
  nowUnix=BigInt(Math.floor(Date.now()/1000))}) {
  exact(anchor,['schema','network','networkMagic','chainId','activationPredecessorHeight',
    'activationPredecessorBlock','activationPredecessorContextHash',
    'activationPredecessorTotalDifficulty','checkpointMaxSpan'],'DOM pre-activation anchor');
  exact(checkpointConsensus,['schema','network','checkpointEpoch','checkpointSlot','checkpointRoot',
    'sourceCount','sourceSetCommitment','observedAtUnix'],'Ethereum checkpoint consensus');
  if(anchor.schema!=='usdom-dom-preactivation-anchor-v1'||anchor.network!=='mainnet'
      ||checkpointConsensus.schema!==ETHEREUM_CHECKPOINT_CONSENSUS_SCHEMA
      ||checkpointConsensus.network!=='ethereum-mainnet') throw new Error('pre-activation networks or schemas mismatch');
  const epoch=decimal(checkpointConsensus.checkpointEpoch,64,'checkpointEpoch');
  const slot=decimal(checkpointConsensus.checkpointSlot,64,'checkpointSlot');
  if(slot!==epoch*32n) throw new Error('trusted checkpoint is not an epoch-boundary block');
  if(decimal(checkpointConsensus.sourceCount,8,'sourceCount')<3n) throw new Error('three independent checkpoint sources are required');
  hash(checkpointConsensus.sourceSetCommitment,'sourceSetCommitment');
  const observedAt=decimal(checkpointConsensus.observedAtUnix,64,'observedAtUnix');
  if(typeof nowUnix!=='bigint') throw new Error('nowUnix must be bigint');
  const now=nowUnix;
  // Keep the trusted local clock in the same canonical timestamp domain as
  // the signed/serialized ceremony observations. Without this bound, an
  // observation near uint64::MAX could be accepted against uint64::MAX + 1,
  // even though no Solidity or Rust uint64 timestamp can represent that
  // instant.
  if(now<=0n||now>=(1n<<64n)||observedAt>now+60n||now-observedAt>3600n) {
    throw new Error('Ethereum checkpoint consensus observation is stale or future-dated');
  }
  if(!releaseConfig||releaseConfig.productionReady!==false||releaseConfig.realFundsAuthorized!==false
      ||releaseConfig.ethereumChainId!=='1') throw new Error('unapproved Ethereum mainnet release is required');
  const interval=360n,confirmations=30n,challenge=172800n;
  if(decimal(anchor.checkpointMaxSpan,32,'checkpointMaxSpan')!==interval+confirmations) {
    throw new Error('authenticated DOM context was not built for the fixed production cadence');
  }
  return Object.freeze({schema:PREACTIVATION_POLICY_SCHEMA,
    nativeEthereumTrustedCheckpoint:hash(checkpointConsensus.checkpointRoot,'checkpointRoot'),
    domDomain:deriveDomDomain({domNetworkMagic:anchor.networkMagic,domChainId:anchor.chainId,
      ethereumChainId:releaseConfig.ethereumChainId,reserve:releaseConfig.reserve,
      checkpointRegistry:releaseConfig.checkpointRegistry}),checkpointIntervalBlocks:interval.toString(),
    checkpointConfirmationDepthBlocks:confirmations.toString(),
    checkpointChallengePeriodSeconds:challenge.toString()});
}
