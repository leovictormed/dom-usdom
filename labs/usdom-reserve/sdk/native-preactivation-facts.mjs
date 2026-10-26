export const DOM_PREACTIVATION_ANCHOR_SCHEMA='usdom-dom-preactivation-anchor-v1';
export const PREACTIVATION_POLICY_SCHEMA='usdom-preactivation-policy-v1';
export const NATIVE_PREACTIVATION_FACTS_SCHEMA='usdom-native-preactivation-facts-v1';
const hashPattern=/^0x[0-9a-fA-F]{64}$/;

function exact(value,fields,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||Object.keys(value).length!==fields.length||fields.some(field=>!(field in value))) {
    throw new Error(`${label} must use the exact supported schema`);
  }
}
function hash(value,label) {
  if(!hashPattern.test(value??'')||BigInt(value)===0n) throw new Error(`${label} must be nonzero bytes32`);
  return value.toLowerCase();
}
function decimal(value,bits,label,{nonzero=true}={}) {
  if(typeof value!=='string'||!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed=BigInt(value);
  if((nonzero&&parsed===0n)||parsed>=(1n<<BigInt(bits))) throw new Error(`${label} is outside uint${bits}`);
  return parsed;
}

/** Combine authenticated DOM-chain output with explicitly ratified bridge policy. */
export function assembleNativePreActivationFacts({anchor,policy}) {
  const anchorFields=['schema','network','networkMagic','chainId','activationPredecessorHeight',
    'activationPredecessorBlock','activationPredecessorContextHash',
    'activationPredecessorTotalDifficulty','checkpointMaxSpan'];
  const policyFields=['schema','nativeEthereumTrustedCheckpoint','domDomain','checkpointIntervalBlocks',
    'checkpointConfirmationDepthBlocks','checkpointChallengePeriodSeconds'];
  exact(anchor,anchorFields,'DOM pre-activation anchor');
  exact(policy,policyFields,'pre-activation policy');
  if(anchor.schema!==DOM_PREACTIVATION_ANCHOR_SCHEMA||anchor.network!=='mainnet') {
    throw new Error('production anchor must be the supported DOM mainnet export');
  }
  if(policy.schema!==PREACTIVATION_POLICY_SCHEMA) throw new Error('unsupported pre-activation policy schema');
  const networkMagic=decimal(anchor.networkMagic,32,'networkMagic');
  const height=decimal(anchor.activationPredecessorHeight,64,'activationPredecessorHeight');
  const difficulty=decimal(anchor.activationPredecessorTotalDifficulty,256,
    'activationPredecessorTotalDifficulty');
  const maxSpan=decimal(anchor.checkpointMaxSpan,32,'checkpointMaxSpan');
  const interval=decimal(policy.checkpointIntervalBlocks,32,'checkpointIntervalBlocks');
  const confirmations=decimal(policy.checkpointConfirmationDepthBlocks,32,
    'checkpointConfirmationDepthBlocks');
  const challenge=decimal(policy.checkpointChallengePeriodSeconds,64,
    'checkpointChallengePeriodSeconds');
  if(interval>360n||confirmations>interval||interval+confirmations!==maxSpan) {
    throw new Error('checkpoint cadence does not match the authenticated context span');
  }
  if(challenge<86400n||challenge>2592000n) throw new Error('checkpoint challenge period is outside contract policy');
  if(height===(1n<<64n)-1n) throw new Error('activation predecessor height cannot be incremented');
  return Object.freeze({
    schema:NATIVE_PREACTIVATION_FACTS_SCHEMA,
    nativeEthereumTrustedCheckpoint:hash(policy.nativeEthereumTrustedCheckpoint,
      'nativeEthereumTrustedCheckpoint'),domDomain:hash(policy.domDomain,'domDomain'),
    checkpointDomNetworkMagic:networkMagic.toString(),checkpointDomChainId:hash(anchor.chainId,'chainId'),
    checkpointFirstV4Height:(height+1n).toString(),checkpointIntervalBlocks:interval.toString(),
    checkpointConfirmationDepthBlocks:confirmations.toString(),
    checkpointChallengePeriodSeconds:challenge.toString(),checkpointInitialHeight:height.toString(),
    checkpointInitialBlock:hash(anchor.activationPredecessorBlock,'activationPredecessorBlock'),
    checkpointInitialContextHash:hash(anchor.activationPredecessorContextHash,
      'activationPredecessorContextHash'),checkpointInitialTotalDifficulty:difficulty.toString(),
  });
}
