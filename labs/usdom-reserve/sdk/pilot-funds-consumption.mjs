import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {validateClosedMainnetDepositPackage} from './closed-mainnet-deposit.mjs';

const sha=/^[0-9a-f]{64}$/;
const bytes32=/^0x[0-9a-f]{64}$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
export const pilotFundsConsumptionSha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const executionKeys=['schema','packageSha256','chainId','steps','amountBaseUnits',
  'financialBaselineSha256','funderBalanceBefore','funderBalanceAfter','reserveBalanceBefore',
  'reserveBalanceAfter','totalDepositedBefore','totalDepositedAfter','outstandingBefore',
  'outstandingAfter','allowanceBefore','allowanceAfter','outputLast','transactionHashes',
  'depositFinalitySha256','snapshotBlockNumber','snapshotBlockHash'];
const finalityKeys=['schema','transactionHash','blockNumber','blockHash','transactionIndex','finalizedRpcCount',
  'gasUsed','effectiveGasPrice','actualCost','maximumCost'];
const quantity=/^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const decimal=/^(0|[1-9][0-9]*)$/;
const gateKeys=['schema','transactionHash','safeTxHash','blockNumber','blockHash','transactionIndex',
  'finalizedBlockNumber','finalizedBlockHash','snapshotCommitment','expectedAuthorization','generation'];

function parseBoundEvidence(packageBytes,gateBytes,executionBytes,finalityBytes) {
  const gate=parseStrictJsonBytes(gateBytes,{label:'pilot deposit gate finality'});
  if(!exact(gate,gateKeys)||gate.schema!=='usdom-pilot-deposit-gate-finalized/v2'
      ||!bytes32.test(gate.transactionHash??'')||!bytes32.test(gate.blockHash??'')
      ||!bytes32.test(gate.finalizedBlockHash??'')||!decimal.test(gate.blockNumber??'')
      ||!decimal.test(gate.transactionIndex??'')||!decimal.test(gate.finalizedBlockNumber??'')
      ||BigInt(gate.finalizedBlockNumber)<BigInt(gate.blockNumber)
      ||BigInt(gate.finalizedBlockNumber)===BigInt(gate.blockNumber)
        &&gate.finalizedBlockHash!==gate.blockHash) {
    throw new Error('pilot deposit gate finality is stale or divergent');
  }
  const execution=parseStrictJsonBytes(executionBytes,{label:'pilot deposit execution'});
  if(!exact(execution,executionKeys)||execution.schema!=='usdom-closed-mainnet-deposit-execution-v3'
      ||execution.chainId!=='1'||execution.steps!==3||execution.amountBaseUnits!=='1000000'
      ||execution.packageSha256!==pilotFundsConsumptionSha256(packageBytes)
      ||execution.allowanceBefore!=='0'||execution.allowanceAfter!=='0'||execution.outputLast!==true
      ||!Array.isArray(execution.transactionHashes)||execution.transactionHashes.length!==3
      ||execution.transactionHashes.some(value=>!bytes32.test(value))) {
    throw new Error('pilot deposit execution is stale or divergent');
  }
  const transactions=finalityBytes.map((bytes,index)=>{
    const value=parseStrictJsonBytes(bytes,{label:`pilot deposit finality ${index}`});
    if(!exact(value,finalityKeys)||value.schema!=='usdom-closed-mainnet-deposit-finality-v2'
        ||!bytes32.test(value.transactionHash??'')||!bytes32.test(value.blockHash??'')
        ||!quantity.test(value.blockNumber??'')||!quantity.test(value.transactionIndex??'')
        ||value.finalizedRpcCount!==2) {
      throw new Error('pilot deposit finality evidence is stale or divergent');
    }
    return {transactionHash:value.transactionHash,blockNumber:value.blockNumber,
      blockHash:value.blockHash,transactionIndex:value.transactionIndex};
  });
  if(new Set(transactions.map(value=>value.transactionHash)).size!==3) {
    throw new Error('pilot deposit finality transactions are not unique');
  }
  if(transactions.some((value,index)=>value.transactionHash!==execution.transactionHashes[index])) {
    throw new Error('pilot deposit finality order differs from executed transaction order');
  }
  if(execution.depositFinalitySha256!==pilotFundsConsumptionSha256(finalityBytes[2])
      ||!decimal.test(execution.snapshotBlockNumber??'')||!bytes32.test(execution.snapshotBlockHash??'')
      ||BigInt(execution.snapshotBlockNumber)<BigInt(transactions[2].blockNumber)
      ||BigInt(execution.snapshotBlockNumber)===BigInt(transactions[2].blockNumber)
        &&execution.snapshotBlockHash!==transactions[2].blockHash) {
    throw new Error('pilot deposit terminal snapshot differs from finality authority');
  }
  const first=transactions[0],gateBlock=BigInt(gate.blockNumber),firstBlock=BigInt(first.blockNumber);
  if(firstBlock<gateBlock||firstBlock===gateBlock
      &&BigInt(first.transactionIndex)<=BigInt(gate.transactionIndex)) {
    throw new Error('pilot deposit starts before its authorization gate in canonical order');
  }
  for(let index=1;index<transactions.length;index++) {
    const previous=transactions[index-1],current=transactions[index];
    const previousBlock=BigInt(previous.blockNumber),currentBlock=BigInt(current.blockNumber);
    if(currentBlock<previousBlock||currentBlock===previousBlock
        &&BigInt(current.transactionIndex)<=BigInt(previous.transactionIndex)) {
      throw new Error('pilot deposit finality is not in strict canonical transaction order');
    }
  }
  return transactions;
}

export function buildPilotFundsConsumption({packageValue,packageBytes,gateBytes,executionBytes,finalityBytes}) {
  if(packageValue?.schema!=='usdom-closed-mainnet-deposit-v1'||!bytes32.test(packageValue.depositId??'')
      ||!bytes32.test(packageValue.pilotFundsAuthorizationDigest??'')||!Buffer.isBuffer(packageBytes)
      ||!Buffer.isBuffer(gateBytes)||!Buffer.isBuffer(executionBytes)||!Array.isArray(finalityBytes)||finalityBytes.length!==3
      ||finalityBytes.some(value=>!Buffer.isBuffer(value)||value.length<2)) {
    throw new Error('pilot authorization consumption inputs are invalid');
  }
  const parsedPackage=parseStrictJsonBytes(packageBytes,{label:'closed mainnet deposit package'});
  validateClosedMainnetDepositPackage(parsedPackage);
  if(JSON.stringify(parsedPackage)!==JSON.stringify(packageValue)) {
    throw new Error('pilot authorization consumption package bytes differ from parsed authority');
  }
  const finalizedTransactions=parseBoundEvidence(packageBytes,gateBytes,executionBytes,finalityBytes);
  return Object.freeze({schema:'usdom-pilot-funds-authorization-consumption/v3',
    authorizationDigest:packageValue.pilotFundsAuthorizationDigest,
    depositId:packageValue.depositId,packageSha256:pilotFundsConsumptionSha256(packageBytes),
    gateSha256:pilotFundsConsumptionSha256(gateBytes),
    executionSha256:pilotFundsConsumptionSha256(executionBytes),
    finalitySha256:finalityBytes.map(pilotFundsConsumptionSha256),finalizedTransactions});
}

export function validatePilotFundsConsumption(value,inputs) {
  const keys=['schema','authorizationDigest','depositId','packageSha256','gateSha256','executionSha256','finalitySha256',
    'finalizedTransactions'];
  const expected=buildPilotFundsConsumption(inputs);
  if(!exact(value,keys)||value.schema!=='usdom-pilot-funds-authorization-consumption/v3'
      ||!sha.test(value.packageSha256??'')||!sha.test(value.gateSha256??'')||!sha.test(value.executionSha256??'')
      ||!Array.isArray(value.finalitySha256)||value.finalitySha256.length!==3
      ||value.finalitySha256.some(item=>!sha.test(item))
      ||JSON.stringify(value)!==JSON.stringify(expected)) {
    throw new Error('pilot authorization consumption marker is divergent or stale');
  }
  return value;
}
