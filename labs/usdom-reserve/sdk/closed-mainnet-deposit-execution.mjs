import {createHash} from 'node:crypto';
import {Transaction,getAddress,keccak256} from 'ethers';
import {buildClosedMainnetDepositPackage} from './closed-mainnet-deposit.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

export const CLOSED_DEPOSIT_MAX_GAS_LIMIT=500_000n;
export const CLOSED_DEPOSIT_MAX_FEE_PER_GAS=100_000_000_000n;
export const CLOSED_DEPOSIT_PRIORITY_FEE_PER_GAS=2_000_000_000n;
export const CLOSED_DEPOSIT_MAX_TRANSACTION_COST=50_000_000_000_000_000n;

const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
function bindAuthority(value,bytes,digest,label,maximum) {
  if(!Buffer.isBuffer(bytes)||typeof digest!=='string'||!/^[0-9a-f]{64}$/.test(digest)
      ||sha256(bytes)!==digest
      ||JSON.stringify(parseStrictJsonBytes(bytes,{label,maxBytes:maximum,maxDepth:64,
        maxNodes:100_000,maxStringBytes:maximum,maxObjectEntries:10_000,
        maxArrayEntries:10_000}))!==JSON.stringify(value)) {
    throw new Error(`${label} bytes or digest differ from authority`);
  }
}

export function validateClosedMainnetDepositAuthority({packageValue,
  release,releaseBytes,releaseSha256,wallet,walletBytes,walletSha256,
  pilotFundsSnapshot,pilotFundsSnapshotBytes,pilotFundsSnapshotSha256,
  pilotFundsAuthorizationState,pilotFundsAuthorizationStateBytes,
  pilotFundsAuthorizationStateSha256,expectedPrivacyPolicyHash}){
  bindAuthority(release,releaseBytes,releaseSha256,'closed deposit release',256*1024);
  bindAuthority(wallet,walletBytes,walletSha256,'closed deposit wallet',64*1024);
  bindAuthority(pilotFundsSnapshot,pilotFundsSnapshotBytes,pilotFundsSnapshotSha256,
    'closed deposit pilot snapshot',256*1024);
  bindAuthority(pilotFundsAuthorizationState,pilotFundsAuthorizationStateBytes,
    pilotFundsAuthorizationStateSha256,'closed deposit pilot authorization state',256*1024);
  const canonical=buildClosedMainnetDepositPackage({release,wallet,
    funder:pilotFundsSnapshot?.funder,salt:pilotFundsSnapshot?.salt,
    releaseConfigSha256:releaseSha256,walletIdentitySha256:walletSha256,
    expectedPrivacyPolicyHash,pilotFundsSnapshot,pilotFundsAuthorizationState});
  if(JSON.stringify(canonical)!==JSON.stringify(packageValue)) {
    throw new Error('closed deposit package differs from authenticated upstream authority');
  }
  return canonical;
}

export function validateClosedMainnetDepositRawTransaction({raw,packageValue,index,nonce,
  release,releaseBytes,releaseSha256,wallet,walletBytes,walletSha256,
  pilotFundsSnapshot,pilotFundsSnapshotBytes,pilotFundsSnapshotSha256,
  pilotFundsAuthorizationState,pilotFundsAuthorizationStateBytes,
  pilotFundsAuthorizationStateSha256,expectedPrivacyPolicyHash}){
  validateClosedMainnetDepositAuthority({packageValue,release,releaseBytes,releaseSha256,
    wallet,walletBytes,walletSha256,pilotFundsSnapshot,pilotFundsSnapshotBytes,
    pilotFundsSnapshotSha256,pilotFundsAuthorizationState,pilotFundsAuthorizationStateBytes,
    pilotFundsAuthorizationStateSha256,expectedPrivacyPolicyHash});
  if(!Number.isInteger(index)||index<0||index>2||typeof nonce!=='string'||nonce.length>20
      ||!/^(0|[1-9][0-9]*)$/.test(nonce)) {
    throw new Error('closed deposit execution index or nonce is invalid');
  }
  const expectedNonce=BigInt(nonce);
  if(expectedNonce>2n**64n-1n) throw new Error('closed deposit nonce exceeds uint64');
  let transaction;
  try { transaction=Transaction.from(raw); } catch { throw new Error('closed deposit raw transaction cannot be decoded'); }
  const expected=packageValue.transactions[index];
  const gas=transaction.gasLimit,fee=transaction.maxFeePerGas,priority=transaction.maxPriorityFeePerGas;
  if(transaction.serialized!==raw||transaction.signature===null||transaction.hash===null
      ||transaction.type!==2||transaction.chainId!==1n||BigInt(transaction.nonce)!==expectedNonce
      ||getAddress(transaction.from)!==packageValue.funder||transaction.to===null
      ||getAddress(transaction.to)!==expected.to||transaction.value!==0n
      ||transaction.data!==expected.data.toLowerCase()||keccak256(transaction.data)!==expected.dataKeccak256
      ||transaction.accessList.length!==0||gas===0n||gas>CLOSED_DEPOSIT_MAX_GAS_LIMIT
      ||fee===null||fee===0n||fee>CLOSED_DEPOSIT_MAX_FEE_PER_GAS||priority===null
      ||priority!==CLOSED_DEPOSIT_PRIORITY_FEE_PER_GAS||priority>fee
      ||gas*fee>CLOSED_DEPOSIT_MAX_TRANSACTION_COST||transaction.hash!==keccak256(raw)) {
    throw new Error('signed transaction differs from the exact closed deposit plan');
  }
  return {schema:'usdom-closed-mainnet-deposit-raw-validation-v1',index:String(index),
    name:expected.name,chainId:'1',from:packageValue.funder,nonce,token:packageValue.token,
    reserve:packageValue.reserve,to:expected.to,value:'0',dataKeccak256:expected.dataKeccak256,
    transactionHash:transaction.hash,gasLimit:gas.toString(),maxFeePerGas:fee.toString(),
    maxPriorityFeePerGas:priority.toString(),maximumCost:(gas*fee).toString()};
}
