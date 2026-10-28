import {Signature,Transaction,getAddress,recoverAddress} from 'ethers';
const UINT=/^(?:0|[1-9][0-9]*)$/,HEX=/^0x(?:[0-9a-fA-F]{2})+$/;
const SCHEMA='usdom-ledger-eip1559-create-signing/v1',MAX_DATA_BYTES=8*1024*1024;
const fail=message=>{throw new Error(message);};
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function validate(transaction,maxGas) {
  if(transaction.type!==2||transaction.chainId!==1n||transaction.to!==null||transaction.value!==0n
    ||transaction.signature!==null||transaction.accessList.length!==0||transaction.data.length<=2
    ||transaction.data.length>2+MAX_DATA_BYTES*2||transaction.gasLimit<=0n
    ||transaction.gasLimit>maxGas||transaction.maxFeePerGas===null
    ||transaction.maxPriorityFeePerGas!==2000000000n
    ||transaction.maxFeePerGas>100000000000n||transaction.maxPriorityFeePerGas>transaction.maxFeePerGas
    ||!Number.isSafeInteger(transaction.nonce)||transaction.nonce<0) fail('unsigned CREATE policy mismatch');
  return transaction;
}
export function prepareLedgerEip1559CreateTransaction({from,data,nonce,gasLimit,maxFeePerGas,
  maxPriorityFeePerGas='2000000000'}={}) {
  if(![nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas].every(value=>typeof value==='string'&&UINT.test(value))
    ||!HEX.test(data??'')) fail('CREATE transaction input invalid');
  const transaction=validate(Transaction.from({type:2,chainId:1n,to:null,data,value:0n,
    nonce:BigInt(nonce),gasLimit:BigInt(gasLimit),maxFeePerGas:BigInt(maxFeePerGas),
    maxPriorityFeePerGas:BigInt(maxPriorityFeePerGas),accessList:[]}),20000000n);
  return Object.freeze({schema:SCHEMA,from:getAddress(from),unsignedHash:transaction.unsignedHash,
    unsignedSerialized:transaction.unsignedSerialized});
}
export function assembleLedgerEip1559CreateTransaction(prepared,signature) {
  if(!exact(prepared,['schema','from','unsignedHash','unsignedSerialized'])||prepared.schema!==SCHEMA
    ||!/^0x[0-9a-f]{64}$/.test(prepared.unsignedHash??'')
    ||!/^0x[0-9a-f]+$/.test(prepared.unsignedSerialized??'')) fail('prepared CREATE invalid');
  const transaction=validate(Transaction.from(prepared.unsignedSerialized),20000000n);
  if(transaction.unsignedHash.toLowerCase()!==prepared.unsignedHash.toLowerCase()
    ||transaction.unsignedSerialized.toLowerCase()!==prepared.unsignedSerialized.toLowerCase()) {
    fail('prepared CREATE hash mismatch');
  }
  const parsed=Signature.from(signature);
  if(![27,28].includes(parsed.v)||parsed.serialized!==signature
    ||getAddress(recoverAddress(transaction.unsignedHash,parsed))!==getAddress(prepared.from)) {
    fail('CREATE signature invalid');
  }
  transaction.signature=parsed;
  const raw=transaction.serialized,reparsed=Transaction.from(raw);
  if(reparsed.to!==null||reparsed.from!==getAddress(prepared.from)||reparsed.serialized!==raw
    ||reparsed.unsignedHash!==prepared.unsignedHash) fail('signed CREATE round trip mismatch');
  return raw;
}
