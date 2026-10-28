import {Interface,Transaction,getAddress,keccak256} from 'ethers';
import {validateAuthenticatedFinalizedBurnSubmission} from './finalized-burn-submission.mjs';

export const CLOSED_REDEMPTION_AMOUNT=1_000_000n;
export const CLOSED_REDEMPTION_MAX_GAS_LIMIT=2_500_000n;
export const CLOSED_REDEMPTION_MAX_FEE_PER_GAS=100_000_000_000n;
export const CLOSED_REDEMPTION_PRIORITY_FEE_PER_GAS=2_000_000_000n;
export const CLOSED_REDEMPTION_MAX_TRANSACTION_COST=100_000_000_000_000_000n;
const tuple='(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil)';
const reserveInterface=new Interface([`function executeWithdrawal(${tuple} burn)`]);
const MAINNET_USDT=getAddress('0xdAC17F958D2ee523a2206206994597C13D831ec7');

export function buildClosedMainnetRedemptionPackage(submission) {
  const {burn}=validateAuthenticatedFinalizedBurnSubmission(submission);
  if(submission.ethereumChainId!=='1'||BigInt(burn.amount)!==CLOSED_REDEMPTION_AMOUNT) {
    throw new Error('closed mainnet redemption requires chain 1 and exactly one USDOM');
  }
  const executeData=reserveInterface.encodeFunctionData('executeWithdrawal',[burn]);
  return Object.freeze({
    schema:'usdom-closed-mainnet-redemption-v2',ethereumChainId:'1',reserve:submission.to,
    token:MAINNET_USDT,recipient:burn.recipient,amountBaseUnits:CLOSED_REDEMPTION_AMOUNT.toString(),
    burnId:burn.burnId,requestId:burn.requestId,statementHash:submission.statementHash,
    submissionDataKeccak256:submission.dataKeccak256,broadcastAuthorized:false,
    transactions:[
      {name:'queue-withdrawal',to:submission.to,value:'0',data:submission.data,
        dataKeccak256:submission.dataKeccak256},
      {name:'execute-withdrawal',to:submission.to,value:'0',data:executeData,
        dataKeccak256:keccak256(executeData)},
    ],
  });
}

export function validateClosedMainnetRedemptionPackage(value,submission) {
  const expected=buildClosedMainnetRedemptionPackage(submission);
  if(JSON.stringify(value)!==JSON.stringify(expected)) throw new Error('closed redemption package is not canonical');
  return value;
}

export function validateClosedMainnetRedemptionRawTransaction({raw,packageValue,submission,index,nonce}) {
  // The signed transaction must never choose its own plan by supplying a
  // self-consistent detached package. Rebuild the complete package from the
  // authenticated finalized-burn submission before reading any transaction
  // field from it.
  validateClosedMainnetRedemptionPackage(packageValue,submission);
  if(index!==0&&index!==1) throw new Error('closed redemption transaction index is invalid');
  if(typeof nonce!=='string'||nonce.length>20||!/^(0|[1-9][0-9]*)$/.test(nonce)
      ||BigInt(nonce)>2n**64n-1n) {
    throw new Error('closed redemption nonce is invalid');
  }
  let transaction;
  try { transaction=Transaction.from(raw); } catch { throw new Error('closed redemption raw transaction cannot be decoded'); }
  const expected=packageValue.transactions[index],fee=transaction.maxFeePerGas;
  const priority=transaction.maxPriorityFeePerGas,gas=transaction.gasLimit;
  if(packageValue.schema!=='usdom-closed-mainnet-redemption-v2'||packageValue.broadcastAuthorized!==false
      ||packageValue.ethereumChainId!=='1'||packageValue.amountBaseUnits!=='1000000'
      ||transaction.serialized!==raw||transaction.signature===null||transaction.hash===null
      ||transaction.from===null||getAddress(transaction.from)!==getAddress(packageValue.recipient)
      ||transaction.type!==2||transaction.chainId!==1n||BigInt(transaction.nonce)!==BigInt(nonce)
      ||transaction.to===null||getAddress(transaction.to)!==getAddress(expected.to)||transaction.value!==0n
      ||transaction.data!==expected.data.toLowerCase()||keccak256(transaction.data)!==expected.dataKeccak256
      ||transaction.accessList.length!==0||gas===0n||gas>CLOSED_REDEMPTION_MAX_GAS_LIMIT
      ||fee===null||fee===0n||fee>CLOSED_REDEMPTION_MAX_FEE_PER_GAS||priority===null
      ||priority!==CLOSED_REDEMPTION_PRIORITY_FEE_PER_GAS||priority>fee
      ||gas*fee>CLOSED_REDEMPTION_MAX_TRANSACTION_COST||transaction.hash!==keccak256(raw)) {
    throw new Error('signed transaction differs from the exact closed redemption plan');
  }
  return {schema:'usdom-closed-mainnet-redemption-raw-validation-v1',index:String(index),
    name:expected.name,chainId:'1',from:getAddress(transaction.from),nonce,to:expected.to,value:'0',
    dataKeccak256:expected.dataKeccak256,transactionHash:transaction.hash,
    gasLimit:gas.toString(),maxFeePerGas:fee.toString(),maxPriorityFeePerGas:priority.toString(),
    maximumCost:(gas*fee).toString()};
}
