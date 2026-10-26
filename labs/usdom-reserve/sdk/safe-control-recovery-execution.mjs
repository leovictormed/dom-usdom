import {Interface,JsonRpcProvider,Transaction,getAddress,isAddress,keccak256} from 'ethers';
import {BoundedMainnetPreflightProvider} from './mainnet-preflight-rpc.mjs';
import {
  validateRecoverableSafeRecoveryPlan,
  validateRecoverableSafeRecoveryTransactionPackage,
} from './safe-control-recovery-plan.mjs';
import {validateRecoverableSafeRecoveryEnvelope} from './safe-control-recovery-envelope.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

export const SAFE_RECOVERY_EXECUTION_SCHEMA='usdom-safe-recovery-finalized-execution/v2';

const safeInterface=new Interface([
  'event ExecutionSuccess(bytes32 indexed txHash,uint256 payment)',
]);

function fail(message) { throw new Error(message); }
function sameAddress(left,right) { return getAddress(left)===getAddress(right); }
function exactKeys(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function uint64Decimal(value,label) {
  if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value)
      ||BigInt(value)>2n**64n-1n) fail(`${label} is not canonical uint64`);
  return BigInt(value);
}

export function validateFinalizedSafeRecoveryExecution({plan,transactionPackage,execution,
  requireRpcConsensus=true}={}) {
  validateRecoverableSafeRecoveryPlan(plan);
  validateRecoverableSafeRecoveryTransactionPackage(plan,transactionPackage);
  const keys=['schema','role','safe','safeTxHash','transactionHash','blockNumber','blockHash',
    'finalizedObservationBlockNumber','finalizedObservationBlockHash'];
  if(requireRpcConsensus) keys.push('rpcConsensus');
  exactKeys(execution,keys,'finalized Safe recovery execution');
  const rolePlan=plan.roles.find(value=>value.role===execution.role);
  const expected=transactionPackage.transactions.find(value=>value.role===execution.role);
  if(execution.schema!==SAFE_RECOVERY_EXECUTION_SCHEMA||!rolePlan||!expected
      ||execution.safe!==rolePlan.safe||execution.safe!==expected.to
      ||execution.safeTxHash!==rolePlan.safeTxHash
      ||!/^0x[0-9a-f]{64}$/.test(execution.transactionHash??'')
      ||!/^0x[0-9a-f]{64}$/.test(execution.blockHash??'')
      ||!/^0x[0-9a-f]{64}$/.test(execution.finalizedObservationBlockHash??'')) {
    fail('finalized Safe recovery execution identity is invalid');
  }
  const block=uint64Decimal(execution.blockNumber,'execution block number');
  const finalized=uint64Decimal(execution.finalizedObservationBlockNumber,
    'finalized observation block number');
  if(block>finalized) fail('execution block is newer than finalized observation');
  if(requireRpcConsensus) validateRpcConsensusEvidence(execution.rpcConsensus);
  return execution;
}

/**
 * Validate the exact signed Ethereum envelope persisted before publication.
 * This closes the crash-resume boundary: a locally substituted journal cannot
 * change chain, sender, Safe, ETH value or calldata while retaining a matching
 * self-computed hash file.
 */
export function validateRecoverableSafeRecoveryRawTransaction({
  plan,transactionPackage,envelopePlan,role,rawTransaction,relayerOwner,
}={}) {
  validateRecoverableSafeRecoveryPlan(plan);
  validateRecoverableSafeRecoveryTransactionPackage(plan,transactionPackage);
  validateRecoverableSafeRecoveryEnvelope(plan,transactionPackage,envelopePlan);
  const expected=transactionPackage.transactions.find(value=>value.role===role);
  if(!expected||envelopePlan.role!==role) fail('Safe recovery role is invalid');
  if(!isAddress(relayerOwner)
      || !plan.roles.find(value=>value.role===role).requiredSigners
        .some(owner=>sameAddress(owner,relayerOwner))
      || !sameAddress(envelopePlan.relayerOwner,relayerOwner)) {
    fail('Safe recovery relayer must be one of the two surviving owners');
  }
  if(typeof rawTransaction!=='string'||rawTransaction.length>128*1024
      || !/^0x[0-9a-f]+$/.test(rawTransaction)||rawTransaction.length%2!==0) {
    fail(`${role} raw recovery transaction encoding is invalid`);
  }
  let parsed;
  try { parsed=Transaction.from(rawTransaction); }
  catch { fail(`${role} raw recovery transaction cannot be decoded`); }
  if(!parsed.isSigned()||parsed.hash!==keccak256(rawTransaction)
      || parsed.type!==2||parsed.chainId!==1n
      || !parsed.to||!sameAddress(parsed.to,expected.to)
      || !parsed.from||!sameAddress(parsed.from,relayerOwner)
      || parsed.value!==0n||parsed.data.toLowerCase()!==expected.data
      || parsed.nonce!==Number(envelopePlan.nonce)
      || parsed.gasLimit!==BigInt(envelopePlan.gasLimit)
      || parsed.maxFeePerGas!==BigInt(envelopePlan.maxFeePerGas)
      || parsed.maxPriorityFeePerGas!==BigInt(envelopePlan.maxPriorityFeePerGas)
      || parsed.gasLimit<=0n||parsed.maxFeePerGas===null
      || parsed.maxPriorityFeePerGas===null
      || parsed.maxPriorityFeePerGas>parsed.maxFeePerGas
      || (parsed.accessList?.length??0)!==0
      || parsed.authorizationList!==null||parsed.blobVersionedHashes!==null) {
    fail(`${role} signed recovery transaction envelope mismatch`);
  }
  const execution={
    role,
    transactionHash:parsed.hash,
    from:getAddress(parsed.from),
    to:getAddress(parsed.to),
    nonce:String(parsed.nonce),
    gasLimit:parsed.gasLimit.toString(),
    maxFeePerGas:parsed.maxFeePerGas.toString(),
    maxPriorityFeePerGas:parsed.maxPriorityFeePerGas.toString(),
  };
  return execution;
}

export class SafeRecoveryNotFinalizedError extends Error {
  constructor(message) {
    super(message);
    this.name='SafeRecoveryNotFinalizedError';
    this.code='SAFE_RECOVERY_NOT_FINALIZED';
  }
}

/** Recover one exact Safe execution from canonical finalized logs for crash-safe resume. */
export async function observeFinalizedSafeRecoveryExecution({
  plan,transactionPackage,role,rpcUrl,
  providerFactory=(url)=>new BoundedMainnetPreflightProvider(url),
}={}) {
  validateRecoverableSafeRecoveryPlan(plan);
  validateRecoverableSafeRecoveryTransactionPackage(plan,transactionPackage);
  const rolePlan=plan.roles.find(value=>value.role===role);
  const expected=transactionPackage.transactions.find(value=>value.role===role);
  if(!rolePlan||!expected) fail('Safe recovery role is invalid');
  if(typeof rpcUrl!=='string'||rpcUrl.length===0) fail('rpcUrl is required');
  const provider=providerFactory(rpcUrl);
  try {
  const network=await provider.getNetwork();
  if(network.chainId!==1n) fail(`expected Ethereum chain ID 1, got ${network.chainId}`);
  const finalized=await provider.getBlock('finalized');
  if(!finalized||!Number.isSafeInteger(finalized.number)||finalized.number<0
      || typeof finalized.hash!=='string') fail('RPC did not return a valid finalized block');
  const fromBlock=Number(plan.finalizedBlockNumber)+1;
  if(finalized.number<fromBlock) {
    throw new SafeRecoveryNotFinalizedError(`${role} recovery is not finalized`);
  }
  const event=safeInterface.getEvent('ExecutionSuccess');
  const logs=await provider.getLogs({
    address:rolePlan.safe,
    topics:[event.topicHash,rolePlan.safeTxHash],
    fromBlock,
    toBlock:finalized.number,
  });
  if(logs.length===0) throw new SafeRecoveryNotFinalizedError(`${role} recovery is not finalized`);
  if(logs.length!==1) fail(`${role} recovery has an ambiguous finalized event history`);
  const log=logs[0];
  const parsed=safeInterface.parseLog(log);
  if(!parsed||parsed.name!=='ExecutionSuccess'||parsed.args.txHash.toLowerCase()!==rolePlan.safeTxHash
      || parsed.args.payment!==0n) fail(`${role} finalized execution event mismatch`);
  const [transaction,receipt,canonicalBlock]=await Promise.all([
    provider.getTransaction(log.transactionHash),
    provider.getTransactionReceipt(log.transactionHash),
    provider.getBlock(log.blockNumber),
  ]);
  if(!transaction||!receipt||!canonicalBlock||receipt.status!==1
      || transaction.hash!==log.transactionHash||receipt.hash!==log.transactionHash
      || transaction.blockHash!==log.blockHash||receipt.blockHash!==log.blockHash
      || transaction.blockNumber!==log.blockNumber||receipt.blockNumber!==log.blockNumber
      || canonicalBlock.hash!==log.blockHash||log.blockNumber>finalized.number
      || log.removed===true
      || !sameAddress(transaction.to,expected.to)||!sameAddress(receipt.to,expected.to)
      || transaction.value!==0n||transaction.data.toLowerCase()!==expected.data) {
    fail(`${role} finalized transaction or receipt mismatch`);
  }
  const matchingReceiptLogs=receipt.logs.filter(receiptLog=>
    sameAddress(receiptLog.address,rolePlan.safe)
      && receiptLog.topics?.[0]?.toLowerCase()===event.topicHash
      && receiptLog.topics?.[1]?.toLowerCase()===rolePlan.safeTxHash);
  if(matchingReceiptLogs.length!==1) fail(`${role} receipt does not contain one exact execution`);
  const receiptLog=matchingReceiptLogs[0];
  let receiptEvent;
  try { receiptEvent=safeInterface.parseLog(receiptLog); }
  catch { fail(`${role} receipt execution event cannot be decoded`); }
  if(!receiptEvent||receiptEvent.args.payment!==0n
      || receiptLog.transactionHash!==log.transactionHash
      || receiptLog.blockHash!==log.blockHash||receiptLog.blockNumber!==log.blockNumber
      || receiptLog.index!==log.index) {
    fail(`${role} receipt execution event mismatch`);
  }
  return {
    schema:SAFE_RECOVERY_EXECUTION_SCHEMA,
    role,
    safe:rolePlan.safe,
    safeTxHash:rolePlan.safeTxHash,
    transactionHash:log.transactionHash,
    blockNumber:String(log.blockNumber),
    blockHash:log.blockHash,
    finalizedObservationBlockNumber:String(finalized.number),
    finalizedObservationBlockHash:finalized.hash,
  };
  } finally {
    if(typeof provider?.destroy==='function') await provider.destroy();
  }
}
