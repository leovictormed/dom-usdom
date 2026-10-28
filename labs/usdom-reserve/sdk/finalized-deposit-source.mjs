import {encodeRlp,getAddress,keccak256,toBeHex} from 'ethers';
import {finalizedDepositSourceSetCommitment,validateFinalizedDepositSourceCatalog}
  from './finalized-deposit-source-catalog.mjs';

export const FINALIZED_DEPOSIT_SOURCE_SCHEMA='usdom-finalized-deposit-source-v2';
export const DEPOSITED_TOPIC=keccak256(Buffer.from('Deposited(bytes32,address,uint64,bytes32)'));
const BN254_SCALAR_FIELD=BigInt(
  '0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001',
);
const sourceFields=[
  'schema','releaseConfigSha256','nativeManifestSha256','transactionHash','chainId','reserve',
  'depositId','funder','amountBaseUnits','receivingCommitment','transactionIndex',
  'receiptLogIndex','depositBlockNumber','depositBlockHash','bootstrap','updates','finality',
  'headers','rawTransactions','receipts','reserveAccount','runtimeBytecode','sourceCatalog','sourceCount',
  'sourceSetCommitment',
];
const accountFields=['address','balance','codeHash','nonce','storageHash','accountProof'];

function exact(value,fields,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...fields].sort())) {
    throw new Error(`exact ${label} fields required`);
  }
}
function hash(value,label) {
  if(typeof value!=='string' || !/^0x[0-9a-f]{64}$/.test(value)
      || value==='0x'+'00'.repeat(32)) throw new Error(`${label} must be canonical nonzero bytes32`);
  return value;
}
function rawHash(value,label) {
  if(typeof value!=='string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a canonical SHA-256 digest`);
  }
  return value;
}
function quantity(value,label,{bits=256}={}) {
  const maximumDigits=Math.ceil(bits/4);
  if(typeof value!=='string' || value.length>2+maximumDigits
      || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical Ethereum quantity`);
  }
  const parsed=BigInt(value);
  if(parsed>=(1n<<BigInt(bits))) throw new Error(`${label} is outside uint${bits}`);
  return parsed;
}
function decimal(value,label,{nonzero=true,bits=256}={}) {
  const maximumDigits=Math.ceil(bits*Math.LOG10E*Math.LN2);
  if(typeof value!=='string' || value.length>maximumDigits
      || !/^(?:0|[1-9][0-9]*)$/.test(value)
      || (nonzero&&value==='0')) throw new Error(`${label} must be canonical decimal`);
  const parsed=BigInt(value);
  if(parsed>=(1n<<BigInt(bits))) throw new Error(`${label} is outside uint${bits}`);
  return parsed;
}
function bytes(value,label,{maximum=1024*1024,nonempty=true}={}) {
  if(typeof value!=='string' || !/^0x(?:[0-9a-f]{2})*$/.test(value)
      || (nonempty&&value==='0x') || (value.length-2)/2>maximum) {
    throw new Error(`${label} must be canonical bounded bytes`);
  }
  return value;
}
function safeIndex(value,label,maximum) {
  if(!Number.isSafeInteger(value)||value<0||value>maximum) throw new Error(`${label} is invalid`);
  return value;
}

/** Bound and canonicalize a full-transaction-hash block response before it is
 * allowed to drive the per-receipt fallback.  The bound must be applied before
 * issuing requests, rather than only after the receipt set has been built. */
export function boundedTransactionHashes(value,label='execution block') {
  if(!value||typeof value!=='object'||!Array.isArray(value.transactions)
      ||value.transactions.length===0||value.transactions.length>4096) {
    throw new Error(`${label} transaction count exceeds policy`);
  }
  const result=value.transactions.map((transaction,index)=>hash(
    typeof transaction==='string'?transaction.toLowerCase():transaction,
    `${label} transaction ${index}`,
  ));
  if(new Set(result).size!==result.length) throw new Error(`${label} contains duplicate transactions`);
  return result;
}

export function encodeRpcReceipt(receipt) {
  if(!receipt || typeof receipt!=='object' || !Array.isArray(receipt.logs)) {
    throw new Error('Ethereum receipt is malformed');
  }
  const status=quantity(receipt.status,'receipt status');
  if(status>1n) throw new Error('receipt status is invalid');
  const cumulative=quantity(receipt.cumulativeGasUsed,'cumulative gas');
  const bloom=bytes(receipt.logsBloom,'receipt logs bloom',{maximum:256});
  if((bloom.length-2)/2!==256) throw new Error('receipt logs bloom width is invalid');
  if(receipt.logs.length>4096) throw new Error('receipt log count exceeds policy');
  const logs=receipt.logs.map((log,index)=>{
    if(!log||typeof log!=='object'||!Array.isArray(log.topics)||log.topics.length>4) {
      throw new Error(`receipt log ${index} is malformed`);
    }
    const address=getAddress(log.address).toLowerCase();
    const topics=log.topics.map((topic,topicIndex)=>hash(topic.toLowerCase(),
      `receipt log ${index} topic ${topicIndex}`));
    const data=bytes(log.data,`receipt log ${index} data`,{maximum:65536,nonempty:false});
    return [address,topics,data];
  });
  const body=encodeRlp([
    status===0n?'0x':toBeHex(status),cumulative===0n?'0x':toBeHex(cumulative),bloom,logs,
  ]);
  const type=quantity(receipt.type??'0x0','receipt type');
  if(type>4n) throw new Error('unsupported receipt type');
  return type===0n?body:`0x${type.toString(16).padStart(2,'0')}${body.slice(2)}`;
}

export function validateFinalizedDepositSource(value) {
  exact(value,sourceFields,'finalized-deposit source');
  if(value.schema!==FINALIZED_DEPOSIT_SOURCE_SCHEMA||value.chainId!=='1') {
    throw new Error('finalized-deposit source identity is invalid');
  }
  rawHash(value.releaseConfigSha256,'releaseConfigSha256');
  rawHash(value.nativeManifestSha256,'nativeManifestSha256');
  hash(value.transactionHash,'transactionHash');
  hash(value.depositBlockHash,'depositBlockHash');
  hash(value.depositId,'depositId');
  hash(value.receivingCommitment,'receivingCommitment');
  if(BigInt(value.receivingCommitment)>=BN254_SCALAR_FIELD) {
    throw new Error('receivingCommitment must be a canonical nonzero BN254 scalar');
  }
  validateFinalizedDepositSourceCatalog(value.sourceCatalog);
  decimal(value.sourceCount,'sourceCount',{bits:64});
  if(value.sourceCount!==String(value.sourceCatalog.sources.length)
      ||value.sourceSetCommitment!==finalizedDepositSourceSetCommitment(value.sourceCatalog)) {
    throw new Error('finalized-deposit source catalog commitment mismatch');
  }
  if(value.reserve!==getAddress(value.reserve)||value.funder!==getAddress(value.funder)) {
    throw new Error('finalized-deposit addresses are not canonical');
  }
  decimal(value.amountBaseUnits,'amountBaseUnits',{bits:64});
  decimal(value.depositBlockNumber,'depositBlockNumber',{bits:64});
  const transactionIndex=safeIndex(value.transactionIndex,'transactionIndex',4095);
  safeIndex(value.receiptLogIndex,'receiptLogIndex',4095);
  if(!value.bootstrap||typeof value.bootstrap!=='object'||Array.isArray(value.bootstrap)
      ||!Array.isArray(value.updates)||value.updates.length>128
      ||!value.finality||typeof value.finality!=='object'||Array.isArray(value.finality)
      ||!Array.isArray(value.headers)||value.headers.length===0||value.headers.length>256
      ||!Array.isArray(value.rawTransactions)||value.rawTransactions.length===0
      ||value.rawTransactions.length>4096
      ||!Array.isArray(value.receipts)||value.receipts.length===0||value.receipts.length>4096
      ||value.rawTransactions.length!==value.receipts.length
      ||transactionIndex>=value.receipts.length) {
    throw new Error('finalized-deposit proof collections are invalid');
  }
  value.rawTransactions.forEach((transaction,index)=>
    bytes(transaction,`raw transaction ${index}`,{maximum:256*1024}));
  if(keccak256(value.rawTransactions[transactionIndex])!==value.transactionHash) {
    throw new Error('deposit transaction hash is not bound to its raw block transaction');
  }
  value.receipts.forEach((receipt,index)=>bytes(receipt,`receipt ${index}`,{maximum:256*1024}));
  let prior;
  for(const [index,header] of value.headers.entries()) {
    if(!header||typeof header!=='object'||Array.isArray(header)) throw new Error('header is invalid');
    const number=quantity(header.number,`header ${index} number`,{bits:64});
    const blockHash=hash(header.hash,`header ${index} hash`);
    const parent=hash(header.parentHash,`header ${index} parentHash`);
    hash(header.receiptsRoot,`header ${index} receiptsRoot`);
    hash(header.stateRoot,`header ${index} stateRoot`);
    if(prior&&(number!==prior.number+1n||parent!==prior.hash)) {
      throw new Error('execution header sequence is discontinuous');
    }
    prior={number,hash:blockHash};
  }
  const finalized=value.finality.finalized_header?.execution;
  const first=value.headers[0];
  const last=value.headers.at(-1);
  if(quantity(first.number,'deposit execution block number',{bits:64})!==BigInt(value.depositBlockNumber)
      ||first.hash!==value.depositBlockHash
      ||!finalized||decimal(finalized.block_number,'finalized execution block number',{bits:64})
      !==quantity(last.number,'last execution block number',{bits:64})
      ||hash(finalized.block_hash,'finalized execution block hash')!==last.hash) {
    throw new Error('execution ancestry does not end at the Beacon-finalized block');
  }
  exact(value.reserveAccount,accountFields,'reserve account proof');
  if(value.reserveAccount.address!==value.reserve.toLowerCase()) {
    throw new Error('reserve account proof belongs to another address');
  }
  quantity(value.reserveAccount.balance,'reserve balance');
  quantity(value.reserveAccount.nonce,'reserve nonce',{bits:64});
  hash(value.reserveAccount.codeHash,'reserve codeHash');
  hash(value.reserveAccount.storageHash,'reserve storageHash');
  if(!Array.isArray(value.reserveAccount.accountProof)||value.reserveAccount.accountProof.length===0
      ||value.reserveAccount.accountProof.length>32) throw new Error('reserve account proof is invalid');
  value.reserveAccount.accountProof.forEach((node,index)=>
    bytes(node,`reserve account proof node ${index}`,{maximum:256*1024}));
  bytes(value.runtimeBytecode,'reserve runtime bytecode',{maximum:24576});
  if(keccak256(value.runtimeBytecode)!==value.reserveAccount.codeHash) {
    throw new Error('reserve runtime bytecode does not match account codeHash');
  }
  return value;
}
