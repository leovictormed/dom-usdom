import {Signature,Transaction,getAddress,getCreateAddress,recoverAddress} from 'ethers';
const UINT=/^(?:0|[1-9][0-9]*)$/,HEX=/^0x(?:[0-9a-fA-F]{2})*$/;
const SCHEMA='usdom-onekey-eip1559-signing/v1',MAX_GAS=500000n,MAX_FEE=100000000000n,PRIORITY=2000000000n,MAX_DATA_BYTES=256*1024;
const CREATE_SCHEMA='usdom-onekey-eip1559-create-signing/v1',MAX_CREATE_DATA_BYTES=8*1024*1024;
const fail=m=>{throw new Error(m);};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
function validateUnsigned(transaction,maxGas=MAX_GAS,{create=false,maxDataBytes=MAX_DATA_BYTES}={}){
 if(transaction.type!==2||transaction.chainId!==1n||transaction.value!==0n||transaction.signature!==null
   ||(create?transaction.to!==null:transaction.to===null)||transaction.accessList.length!==0
   ||(create&&transaction.data.length<=2)||transaction.data.length>2+maxDataBytes*2
   ||transaction.gasLimit<=0n||transaction.gasLimit>maxGas||transaction.maxFeePerGas===null
   ||transaction.maxPriorityFeePerGas===null||transaction.maxFeePerGas>MAX_FEE
   ||transaction.maxPriorityFeePerGas!==PRIORITY||transaction.maxPriorityFeePerGas>transaction.maxFeePerGas
   ||!Number.isSafeInteger(transaction.nonce)||transaction.nonce<0)fail('unsigned transaction policy mismatch');
 return transaction;
}
export function prepareOneKeyEip1559CreateTransaction({from,data,nonce,gasLimit,maxFeePerGas,
 maxPriorityFeePerGas='2000000000',expectedContract}={}){
 if(![nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas].every(v=>typeof v==='string'&&UINT.test(v))
   ||!/^0x(?:[0-9a-fA-F]{2})+$/.test(data??'')||(data.length-2)/2>MAX_CREATE_DATA_BYTES)fail('CREATE transaction input invalid');
 const signer=getAddress(from),transaction=validateUnsigned(Transaction.from({type:2,chainId:1n,to:null,data,value:0n,
   nonce:BigInt(nonce),gasLimit:BigInt(gasLimit),maxFeePerGas:BigInt(maxFeePerGas),
   maxPriorityFeePerGas:BigInt(maxPriorityFeePerGas),accessList:[]}),20000000n,{create:true,maxDataBytes:MAX_CREATE_DATA_BYTES});
 const contract=getAddress(expectedContract);
 if(getCreateAddress({from:signer,nonce:transaction.nonce})!==contract)fail('expected CREATE address mismatch');
 return Object.freeze({schema:CREATE_SCHEMA,from:signer,expectedContract:contract,maxGasLimit:'20000000',
   unsignedHash:transaction.unsignedHash,unsignedSerialized:transaction.unsignedSerialized});
}
export function prepareOneKeyEip1559Transaction({chainId='1',from,to,data,nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas,maxGasLimit='500000'}={}){
 if(![chainId,nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas].every(v=>typeof v==='string'&&UINT.test(v))||chainId!=='1')fail('transaction integer invalid');
 if(!HEX.test(data??'')||(data.length-2)/2>MAX_DATA_BYTES)fail('transaction data invalid');
 if(!UINT.test(maxGasLimit)||BigInt(maxGasLimit)>2500000n)fail('maximum gas policy invalid');
 const transaction=validateUnsigned(Transaction.from({type:2,chainId:1n,to:getAddress(to),data,value:0n,nonce:BigInt(nonce),gasLimit:BigInt(gasLimit),maxFeePerGas:BigInt(maxFeePerGas),maxPriorityFeePerGas:BigInt(maxPriorityFeePerGas),accessList:[]}),BigInt(maxGasLimit));
 return Object.freeze({schema:SCHEMA,from:getAddress(from),maxGasLimit,unsignedHash:transaction.unsignedHash,unsignedSerialized:transaction.unsignedSerialized});
}
export function validatePreparedOneKeyEip1559Transaction(prepared){
 const create=prepared?.schema===CREATE_SCHEMA,keys=create
   ?['schema','from','expectedContract','maxGasLimit','unsignedHash','unsignedSerialized']
   :['schema','from','maxGasLimit','unsignedHash','unsignedSerialized'];
 if(!exact(prepared,keys)||(!create&&prepared.schema!==SCHEMA)
   ||!UINT.test(prepared.maxGasLimit??'')||BigInt(prepared.maxGasLimit)>(create?20000000n:2500000n)
   ||!/^0x[0-9a-f]{64}$/.test(prepared.unsignedHash??'')||!/^0x[0-9a-f]+$/.test(prepared.unsignedSerialized??''))fail('prepared transaction invalid');
 const transaction=validateUnsigned(Transaction.from(prepared.unsignedSerialized),BigInt(prepared.maxGasLimit),
   {create,maxDataBytes:create?MAX_CREATE_DATA_BYTES:MAX_DATA_BYTES});
 if(transaction.unsignedSerialized!==prepared.unsignedSerialized
   ||transaction.unsignedHash!==prepared.unsignedHash)fail('prepared transaction hash mismatch');
 if(getAddress(prepared.from)!==prepared.from)fail('prepared transaction signer is noncanonical');
 if(create&&(getAddress(prepared.expectedContract)!==prepared.expectedContract
   ||getCreateAddress({from:prepared.from,nonce:transaction.nonce})!==prepared.expectedContract))fail('expected CREATE address mismatch');
 return Object.freeze({...prepared});
}
export function assembleOneKeyEip1559Transaction(prepared,signature){
 prepared=validatePreparedOneKeyEip1559Transaction(prepared);
 const create=prepared.schema===CREATE_SCHEMA;
 const transaction=validateUnsigned(Transaction.from(prepared.unsignedSerialized),BigInt(prepared.maxGasLimit),
   {create,maxDataBytes:create?MAX_CREATE_DATA_BYTES:MAX_DATA_BYTES});
 if(transaction.unsignedSerialized.toLowerCase()!==prepared.unsignedSerialized.toLowerCase()
   ||transaction.unsignedHash.toLowerCase()!==prepared.unsignedHash.toLowerCase())fail('prepared transaction hash mismatch');
 const parsed=Signature.from(signature);
 if(![27,28].includes(parsed.v)||parsed.serialized!==signature)fail('OneKey signature is noncanonical');
 if(getAddress(recoverAddress(transaction.unsignedHash,parsed))!==getAddress(prepared.from))fail('OneKey transaction signer mismatch');
 transaction.signature=parsed;const raw=transaction.serialized,reparsed=Transaction.from(raw);
 if(reparsed.chainId!==1n||reparsed.type!==2||reparsed.from!==getAddress(prepared.from)
   ||reparsed.unsignedHash!==transaction.unsignedHash||reparsed.serialized!==raw)fail('signed transaction round trip mismatch');
 return raw;
}
