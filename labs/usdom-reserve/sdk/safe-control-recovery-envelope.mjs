import {getAddress,isAddress} from 'ethers';
import {BoundedMainnetPreflightProvider} from './mainnet-preflight-rpc.mjs';
import {validateRecoverableSafeRecoveryTransactionPackage} from './safe-control-recovery-plan.mjs';
import {_safeControlObservationInternals} from './safe-control-observation.mjs';
import {rpcConsensusEvidence,validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

export const SAFE_RECOVERY_ENVELOPE_SCHEMA='usdom-safe-recovery-envelope/v2';
export const SAFE_RECOVERY_PRIORITY_FEE_PER_GAS=2_000_000_000n;
export const SAFE_RECOVERY_MAX_GAS_LIMIT=500_000n;
export const SAFE_RECOVERY_MAX_BASE_FEE_PER_GAS=120_000_000_000n;
export const SAFE_RECOVERY_MAX_FEE_PER_GAS=500_000_000_000n;
export const SAFE_RECOVERY_INCLUSION_BLOCKS=12;

const HASH=/^0x[0-9a-f]{64}$/;
const DECIMAL=/^(0|[1-9][0-9]*)$/;
const {canonicalJson,documentHash}=_safeControlObservationInternals;

function fail(message) { throw new Error(message); }
function sameAddress(left,right) { return getAddress(left)===getAddress(right); }
function exactKeys(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      || canonicalJson(Object.keys(value).sort())!==canonicalJson([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function isCanonicalDecimal(value) {
  return typeof value==='string'&&DECIMAL.test(value);
}
function asRpcQuantity(value,label) {
  try {
    const parsed=BigInt(value);
    if(parsed<0n) fail(`${label} is negative`);
    return parsed;
  } catch { fail(`${label} is not a canonical RPC quantity`); }
}
function feeAfterMaximumGrowth(baseFee,blocks=SAFE_RECOVERY_INCLUSION_BLOCKS) {
  let result=baseFee;
  for(let index=0;index<blocks;index++) result=(result*9n+7n)/8n;
  return result;
}

/** Produce a bounded EIP-1559 envelope from cataloged read-only Ethereum views. */
export async function prepareRecoverableSafeRecoveryEnvelope({
  plan,transactionPackage,role,relayerOwner,sources,
  providerFactory=(url)=>new BoundedMainnetPreflightProvider(url),
}={}) {
  validateRecoverableSafeRecoveryTransactionPackage(plan,transactionPackage);
  const expected=transactionPackage.transactions.find(value=>value.role===role);
  if(!expected) fail('Safe recovery role is invalid');
  if(!isAddress(relayerOwner)
      || !plan.roles.find(value=>value.role===role).requiredSigners
        .some(owner=>sameAddress(owner,relayerOwner))) {
    fail('Safe recovery relayer must be one of the two surviving owners');
  }
  if(!Array.isArray(sources)||sources.length<2||sources.length>5
      || sources.some(source=>typeof source?.url!=='string'||source.url.length===0)
      || new Set(sources.map(source=>source.url)).size!==sources.length) {
    fail('two to five distinct cataloged Ethereum RPC sources are required');
  }
  const rpcConsensus=rpcConsensusEvidence(sources);
  const observations=[];
  for(const [index,source] of sources.entries()) {
    const provider=providerFactory(source.url);
    try {
      const observe=async()=>{
        const network=await provider.getNetwork();
        if(network.chainId!==1n) fail(`RPC ${index+1} did not report Ethereum chain ID 1`);
        const finalizedBlock=await provider.getBlock('finalized');
        if(!finalizedBlock||!Number.isSafeInteger(finalizedBlock.number)||finalizedBlock.number<0
            ||typeof finalizedBlock.hash!=='string'||!HASH.test(finalizedBlock.hash)
            ||finalizedBlock.baseFeePerGas===null||finalizedBlock.baseFeePerGas===undefined) {
          fail(`RPC ${index+1} did not return a canonical finalized block`);
        }
        provider.pinFinalizedSnapshot?.(finalizedBlock.number,finalizedBlock.hash,{allowPendingNonce:true});
        const finalizedTag=finalizedBlock.number;
        const [finalizedNonce,pendingNonce,estimatedGas,balance,relayerCode]=
          await Promise.all([
            provider.getTransactionCount(relayerOwner,finalizedTag),
            provider.getTransactionCount(relayerOwner,'pending'),
            provider.send('eth_estimateGas',[{
              from:getAddress(relayerOwner),to:expected.to,value:'0x0',data:expected.data,
            },`0x${BigInt(finalizedTag).toString(16)}`]),
            provider.getBalance(relayerOwner,finalizedTag),provider.getCode(relayerOwner,finalizedTag),
          ]);
        if(!Number.isSafeInteger(finalizedNonce)||finalizedNonce<0
            || !Number.isSafeInteger(pendingNonce)||pendingNonce<0
            || relayerCode!=='0x') {
          fail(`RPC ${index+1} returned an invalid recovery envelope observation`);
        }
        const gasEstimate=asRpcQuantity(estimatedGas,`RPC ${index+1} gas estimate`);
        const baseFee=asRpcQuantity(finalizedBlock.baseFeePerGas,`RPC ${index+1} base fee`);
        const observedBalance=asRpcQuantity(balance,`RPC ${index+1} relayer balance`);
        if(gasEstimate===0n||gasEstimate>SAFE_RECOVERY_MAX_GAS_LIMIT) {
          fail(`RPC ${index+1} gas estimate exceeds recovery policy`);
        }
        if(baseFee===0n||baseFee>SAFE_RECOVERY_MAX_BASE_FEE_PER_GAS) {
          fail(`RPC ${index+1} base fee exceeds recovery policy`);
        }
        return {rpc:`rpc${index+1}`,finalizedBlockNumber:String(finalizedBlock.number),
          finalizedBlockHash:finalizedBlock.hash.toLowerCase(),finalizedNonce:String(finalizedNonce),
          pendingNonce:String(pendingNonce),gasEstimate:gasEstimate.toString(),
          baseFeePerGas:baseFee.toString(),relayerBalance:observedBalance.toString()};
      };
      const before=await observe(),after=await observe();
      if(canonicalJson(before)!==canonicalJson(after)) fail(`RPC ${index+1} changed during envelope recheck`);
      observations.push(before);
    } finally { provider.destroy?.(); }
  }
  const nonces=observations.flatMap(value=>[value.finalizedNonce,value.pendingNonce]);
  if(new Set(nonces).size!==1) {
    fail('relayer finalized/pending nonce disagrees across the two RPCs');
  }
  if(observations.some(value=>value.finalizedBlockNumber!==observations[0].finalizedBlockNumber
      ||value.finalizedBlockHash!==observations[0].finalizedBlockHash)) {
    fail('recovery envelope finalized snapshot disagrees across RPCs');
  }
  const maximumEstimate=observations.reduce((maximum,value)=>
    BigInt(value.gasEstimate)>maximum?BigInt(value.gasEstimate):maximum,0n);
  const gasLimit=(maximumEstimate*125n+99n)/100n;
  if(gasLimit>SAFE_RECOVERY_MAX_GAS_LIMIT) fail('buffered gas limit exceeds recovery policy');
  const maximumBaseFee=observations.reduce((maximum,value)=>
    BigInt(value.baseFeePerGas)>maximum?BigInt(value.baseFeePerGas):maximum,0n);
  const maxFeePerGas=feeAfterMaximumGrowth(maximumBaseFee)
    +SAFE_RECOVERY_PRIORITY_FEE_PER_GAS;
  if(maxFeePerGas>SAFE_RECOVERY_MAX_FEE_PER_GAS) {
    fail('derived EIP-1559 max fee exceeds recovery policy');
  }
  const maximumCost=gasLimit*maxFeePerGas;
  if(observations.some(value=>BigInt(value.relayerBalance)<maximumCost)) {
    fail('relayer balance cannot cover the bounded recovery transaction');
  }
  const envelope={
    schema:SAFE_RECOVERY_ENVELOPE_SCHEMA,
    ethereumChainId:'1',
    planHash:plan.planHash,
    transactionPackageHash:transactionPackage.transactionPackageHash,
    role,
    relayerOwner:getAddress(relayerOwner),
    to:getAddress(expected.to),
    value:'0',
    dataHash:expected.dataHash,
    nonce:nonces[0],
    gasLimit:gasLimit.toString(),
    maxFeePerGas:maxFeePerGas.toString(),
    maxPriorityFeePerGas:SAFE_RECOVERY_PRIORITY_FEE_PER_GAS.toString(),
    maximumCost:maximumCost.toString(),
    rpcConsensus,
    rpcObservations:observations,
  };
  const complete={...envelope,envelopeHash:documentHash(envelope)};
  validateRecoverableSafeRecoveryEnvelope(plan,transactionPackage,complete);
  return complete;
}

export function validateRecoverableSafeRecoveryEnvelope(plan,transactionPackage,envelope) {
  validateRecoverableSafeRecoveryTransactionPackage(plan,transactionPackage);
  exactKeys(envelope,['schema','ethereumChainId','planHash','transactionPackageHash','role',
    'relayerOwner','to','value','dataHash','nonce','gasLimit','maxFeePerGas',
    'maxPriorityFeePerGas','maximumCost','rpcConsensus','rpcObservations','envelopeHash'],
  'Safe recovery envelope');
  validateRpcConsensusEvidence(envelope.rpcConsensus);
  const expected=transactionPackage.transactions.find(value=>value.role===envelope.role);
  if(envelope.schema!==SAFE_RECOVERY_ENVELOPE_SCHEMA||envelope.ethereumChainId!=='1'
      || envelope.planHash!==plan.planHash
      || envelope.transactionPackageHash!==transactionPackage.transactionPackageHash
      || !expected||!isAddress(envelope.relayerOwner)||!isAddress(envelope.to)
      || getAddress(envelope.relayerOwner)!==envelope.relayerOwner
      || getAddress(envelope.to)!==envelope.to
      || !plan.roles.find(value=>value.role===envelope.role).requiredSigners
        .some(owner=>sameAddress(owner,envelope.relayerOwner))
      || !sameAddress(envelope.to,expected.to)||envelope.value!=='0'
      || envelope.dataHash!==expected.dataHash||!HASH.test(envelope.envelopeHash)
      || ![envelope.nonce,envelope.gasLimit,envelope.maxFeePerGas,
        envelope.maxPriorityFeePerGas,envelope.maximumCost].every(isCanonicalDecimal)) {
    fail('Safe recovery envelope identity is invalid');
  }
  const unsigned={...envelope}; delete unsigned.envelopeHash;
  if(documentHash(unsigned)!==envelope.envelopeHash) fail('Safe recovery envelope hash mismatch');
  const gasLimit=BigInt(envelope.gasLimit);
  const maxFee=BigInt(envelope.maxFeePerGas);
  const priority=BigInt(envelope.maxPriorityFeePerGas);
  if(BigInt(envelope.nonce)>BigInt(Number.MAX_SAFE_INTEGER)
      || gasLimit===0n||gasLimit>SAFE_RECOVERY_MAX_GAS_LIMIT
      || maxFee===0n||maxFee>SAFE_RECOVERY_MAX_FEE_PER_GAS
      || priority!==SAFE_RECOVERY_PRIORITY_FEE_PER_GAS||priority>maxFee
      || BigInt(envelope.maximumCost)!==gasLimit*maxFee) {
    fail('Safe recovery envelope bounds are invalid');
  }
  if(!Array.isArray(envelope.rpcObservations)||envelope.rpcObservations.length<2
      ||envelope.rpcObservations.length>5
      ||envelope.rpcObservations.length!==Number(envelope.rpcConsensus.sourceCount)) {
    fail('Safe recovery envelope RPC observations are invalid');
  }
  for(const [index,observation] of envelope.rpcObservations.entries()) {
    exactKeys(observation,['rpc','finalizedBlockNumber','finalizedBlockHash','finalizedNonce','pendingNonce','gasEstimate',
      'baseFeePerGas','relayerBalance'],
    `Safe recovery envelope RPC observation ${index}`);
    if(observation.rpc!==`rpc${index+1}`||!HASH.test(observation.finalizedBlockHash)
        || ![observation.finalizedNonce,observation.pendingNonce,observation.gasEstimate,
          observation.finalizedBlockNumber,observation.baseFeePerGas,
          observation.relayerBalance].every(isCanonicalDecimal)
        || observation.finalizedNonce!==envelope.nonce
        || observation.pendingNonce!==envelope.nonce
        || BigInt(observation.gasEstimate)===0n
        || BigInt(observation.gasEstimate)>SAFE_RECOVERY_MAX_GAS_LIMIT
        || BigInt(observation.baseFeePerGas)>SAFE_RECOVERY_MAX_BASE_FEE_PER_GAS
        || BigInt(observation.relayerBalance)<BigInt(envelope.maximumCost)) {
      fail(`Safe recovery envelope RPC observation ${index} violates policy`);
    }
  }
  if(envelope.rpcObservations.some(value=>
    value.finalizedBlockNumber!==envelope.rpcObservations[0].finalizedBlockNumber
      ||value.finalizedBlockHash!==envelope.rpcObservations[0].finalizedBlockHash)) {
    fail('Safe recovery envelope finalized snapshots disagree');
  }
  const maximumEstimate=envelope.rpcObservations.reduce((maximum,value)=>
    BigInt(value.gasEstimate)>maximum?BigInt(value.gasEstimate):maximum,0n);
  const maximumBaseFee=envelope.rpcObservations.reduce((maximum,value)=>
    BigInt(value.baseFeePerGas)>maximum?BigInt(value.baseFeePerGas):maximum,0n);
  if(gasLimit!==(maximumEstimate*125n+99n)/100n
      || maxFee!==feeAfterMaximumGrowth(maximumBaseFee)+SAFE_RECOVERY_PRIORITY_FEE_PER_GAS) {
    fail('Safe recovery envelope derivation mismatch');
  }
  return envelope;
}
