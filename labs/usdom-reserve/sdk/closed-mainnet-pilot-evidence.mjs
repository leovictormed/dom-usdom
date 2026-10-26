import {getAddress} from 'ethers';

export function validatePilotTransactionEvidence({kind,index,receipt,validation,finality,transaction,signer}) {
  if(kind!=='deposit'&&kind!=='redemption') throw new Error('pilot transaction kind is invalid');
  const schema=`usdom-closed-mainnet-${kind}-raw-validation-v1`;
  if(validation?.schema!==schema||validation.index!==String(index)||validation.chainId!=='1'
      ||validation.name!==transaction.name||validation.value!=='0'
      ||getAddress(validation.from)!==getAddress(signer)||getAddress(validation.to)!==getAddress(transaction.to)
      ||validation.dataKeccak256!==transaction.dataKeccak256
      ||typeof validation.transactionHash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(validation.transactionHash)
      ||receipt?.status!=='0x1'||receipt.transactionHash?.toLowerCase()!==validation.transactionHash.toLowerCase()
      ||getAddress(receipt.from)!==getAddress(signer)||getAddress(receipt.to)!==getAddress(transaction.to)
      ||typeof receipt.blockNumber!=='string'||!/^0x[0-9a-fA-F]+$/.test(receipt.blockNumber)
      ||typeof receipt.blockHash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(receipt.blockHash)) {
    throw new Error(`${kind} transaction evidence is stale or belongs to another chain/plan/signer`);
  }
  if(finality&&(finality.schema!==`usdom-closed-mainnet-${kind}-finality-v1`
      ||finality.transactionHash?.toLowerCase()!==validation.transactionHash.toLowerCase()
      ||finality.blockNumber!==receipt.blockNumber
      ||finality.blockHash?.toLowerCase()!==receipt.blockHash.toLowerCase()
      ||finality.finalizedRpcCount!==2)) {
    throw new Error(`${kind} finality evidence is stale or foreign`);
  }
  return true;
}
