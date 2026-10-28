import {getAddress} from 'ethers';
import {validatePilotReceiptCost} from './pilot-receipt-cost.mjs';

const decimal=value=>typeof value==='string'&&value.length<=78&&/^(0|[1-9][0-9]*)$/.test(value)
  &&BigInt(value)<(1n<<256n);
const nonce=value=>typeof value==='string'&&value.length<=20&&/^(0|[1-9][0-9]*)$/.test(value)
  &&BigInt(value)<(1n<<64n);
const blockQuantity=value=>typeof value==='string'&&value.length<=18
  &&/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value)&&BigInt(value)<(1n<<64n);
const fields={
  deposit:['schema','index','name','chainId','from','nonce','token','reserve','to','value',
    'dataKeccak256','transactionHash','gasLimit','maxFeePerGas','maxPriorityFeePerGas','maximumCost'],
  redemption:['schema','index','name','chainId','from','nonce','to','value','dataKeccak256',
    'transactionHash','gasLimit','maxFeePerGas','maxPriorityFeePerGas','maximumCost'],
};
const limits={
  deposit:{gas:500_000n,fee:100_000_000_000n,cost:50_000_000_000_000_000n},
  redemption:{gas:2_500_000n,fee:100_000_000_000n,cost:100_000_000_000_000_000n},
};
const finalityFields=['schema','transactionHash','blockNumber','blockHash','finalizedRpcCount',
  'gasUsed','effectiveGasPrice','actualCost','maximumCost'];
const positionedFinalityFields=[...finalityFields,'transactionIndex'];
function exact(value,expected) {
  return value&&typeof value==='object'&&!Array.isArray(value)
    &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...expected].sort());
}

export function validatePilotTransactionOrder(receipts,label='pilot transaction sequence') {
  if(!Array.isArray(receipts)||receipts.length===0) throw new Error(`${label} is incomplete`);
  for(let index=0;index<receipts.length;index++) {
    if(!blockQuantity(receipts[index]?.blockNumber)||!blockQuantity(receipts[index]?.transactionIndex)) {
      throw new Error(`${label} position is invalid`);
    }
    if(index===0) continue;
    const previous=receipts[index-1],current=receipts[index];
    const previousBlock=BigInt(previous.blockNumber),currentBlock=BigInt(current.blockNumber);
    if(currentBlock<previousBlock||currentBlock===previousBlock
        &&BigInt(current.transactionIndex)<=BigInt(previous.transactionIndex)) {
      throw new Error(`${label} is not in strict canonical transaction order`);
    }
  }
  return receipts;
}

export function validatePilotTransactionEvidence({
  kind,index,receipt,validation,finality,transaction,signer,packageValue,
}) {
  if(kind!=='deposit'&&kind!=='redemption') throw new Error('pilot transaction kind is invalid');
  const schema=`usdom-closed-mainnet-${kind}-raw-validation-v1`;
  if(!exact(validation,fields[kind])||validation.schema!==schema||validation.index!==String(index)
      ||validation.chainId!=='1'
      ||validation.name!==transaction.name||validation.value!=='0'
      ||getAddress(validation.from)!==getAddress(signer)||getAddress(validation.to)!==getAddress(transaction.to)
      ||validation.dataKeccak256!==transaction.dataKeccak256
      ||typeof validation.transactionHash!=='string'||!/^0x[0-9a-f]{64}$/.test(validation.transactionHash)
      ||receipt?.status!=='0x1'||receipt.transactionHash?.toLowerCase()!==validation.transactionHash.toLowerCase()
      ||getAddress(receipt.from)!==getAddress(signer)||getAddress(receipt.to)!==getAddress(transaction.to)
      ||!blockQuantity(receipt.blockNumber)
      ||typeof receipt.transactionHash!=='string'||!/^0x[0-9a-f]{64}$/.test(receipt.transactionHash)
      ||typeof receipt.blockHash!=='string'||!/^0x[0-9a-f]{64}$/.test(receipt.blockHash)) {
    throw new Error(`${kind} transaction evidence is stale or belongs to another chain/plan/signer`);
  }
  if(!nonce(validation.nonce)||!decimal(validation.gasLimit)||!decimal(validation.maxFeePerGas)
      ||!decimal(validation.maxPriorityFeePerGas)||!decimal(validation.maximumCost)) {
    throw new Error(`${kind} transaction validation quantities are not canonical and bounded`);
  }
  const gas=BigInt(validation.gasLimit),fee=BigInt(validation.maxFeePerGas);
  const priority=BigInt(validation.maxPriorityFeePerGas),maximum=BigInt(validation.maximumCost);
  const limit=limits[kind];
  if(gas===0n||gas>limit.gas||fee===0n||fee>limit.fee||priority>fee
      ||gas*fee!==maximum||maximum>limit.cost) {
    throw new Error(`${kind} transaction validation cost envelope is invalid`);
  }
  if(kind==='deposit'&&(!packageValue
      ||getAddress(validation.token)!==getAddress(packageValue.token)
      ||getAddress(validation.reserve)!==getAddress(packageValue.reserve))) {
    throw new Error('deposit transaction validation is stale or belongs to another package');
  }
  if(!finality||!exact(finality,positionedFinalityFields)
      ||finality.schema!==`usdom-closed-mainnet-${kind}-finality-v2`
      ||!/^0x[0-9a-f]{64}$/.test(finality.transactionHash??'')
      ||!/^0x[0-9a-f]{64}$/.test(finality.blockHash??'')
      ||finality.transactionHash?.toLowerCase()!==validation.transactionHash.toLowerCase()
      ||finality.blockNumber!==receipt.blockNumber
      ||finality.blockHash?.toLowerCase()!==receipt.blockHash.toLowerCase()
      ||!blockQuantity(receipt.transactionIndex)
      ||finality.transactionIndex!==receipt.transactionIndex
      ||finality.finalizedRpcCount!==2) {
    throw new Error(`${kind} finality evidence is stale or foreign`);
  }
  const cost=validatePilotReceiptCost({gasUsed:receipt.gasUsed,
    effectiveGasPrice:receipt.effectiveGasPrice,maximumCost:validation.maximumCost});
  if(Object.entries(cost).some(([key,value])=>finality[key]!==value)) {
    throw new Error(`${kind} finality cost evidence is stale or forged`);
  }
  return true;
}
