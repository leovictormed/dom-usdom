import test from 'node:test';
import assert from 'node:assert/strict';
import {keccak256} from 'ethers';
import {
  boundedTransactionHashes,FINALIZED_DEPOSIT_SOURCE_SCHEMA,encodeRpcReceipt,
  validateFinalizedDepositSource,
} from '../../sdk/finalized-deposit-source.mjs';
import {FINALIZED_DEPOSIT_SOURCE_CATALOG_SCHEMA,finalizedDepositSourceSetCommitment}
  from '../../sdk/finalized-deposit-source-catalog.mjs';

const hash=byte=>'0x'+byte.toString(16).padStart(2,'0').repeat(32);
const raw=byte=>byte.toString(16).padStart(2,'0').repeat(32);
const bloom='0x'+'00'.repeat(256);
const reserve='0xdAC17F958D2ee523a2206206994597C13D831ec7';
const funder='0x0000000000000000000000000000000000000040';

function fixture() {
  const runtimeBytecode='0x6001600055';
  const sourceCatalog={schema:FINALIZED_DEPOSIT_SOURCE_CATALOG_SCHEMA,sources:[
    {operatorId:'alpha',executionOriginKeccak256:hash(30),beaconOriginKeccak256:hash(31)},
    {operatorId:'bravo',executionOriginKeccak256:hash(32),beaconOriginKeccak256:hash(33)},
  ]};
  return {
    schema:FINALIZED_DEPOSIT_SOURCE_SCHEMA,releaseConfigSha256:raw(1),
    nativeManifestSha256:raw(2),transactionHash:hash(3),chainId:'1',reserve,
    depositId:hash(4),funder,amountBaseUnits:'1000000',receivingCommitment:hash(5),
    transactionIndex:0,receiptLogIndex:1,depositBlockNumber:'100',depositBlockHash:hash(6),
    sourceCatalog,sourceCount:'2',sourceSetCommitment:finalizedDepositSourceSetCommitment(sourceCatalog),
    bootstrap:{header:{beacon:{slot:'1000'}}},updates:[],
    finality:{finalized_header:{beacon:{slot:'1100'},execution:{block_number:'101',block_hash:hash(7)}}},
    headers:[
      {number:'0x64',hash:hash(6),parentHash:hash(8),receiptsRoot:hash(9),stateRoot:hash(10)},
      {number:'0x65',hash:hash(7),parentHash:hash(6),receiptsRoot:hash(11),stateRoot:hash(12)},
    ],
    rawTransactions:['0x01'],transactionHash:keccak256('0x01'),
    receipts:['0x01'],reserveAccount:{address:reserve.toLowerCase(),balance:'0x1',codeHash:keccak256(runtimeBytecode),
      nonce:'0x1',storageHash:hash(13),accountProof:['0x01']},runtimeBytecode,
  };
}

test('RPC receipt encoder reproduces typed canonical EIP-658 framing',()=>{
  const encoded=encodeRpcReceipt({status:'0x1',cumulativeGasUsed:'0x5208',logsBloom:bloom,type:'0x2',
    logs:[{address:reserve,topics:[hash(14)],data:'0x1234'}]});
  assert.match(encoded,/^0x02f9/);
  assert(encoded.length>2+2+512);
  assert.throws(()=>encodeRpcReceipt({status:'0x2',cumulativeGasUsed:'0x1',logsBloom:bloom,
    type:'0x2',logs:[]}));
  assert.throws(()=>encodeRpcReceipt({status:'0x1',cumulativeGasUsed:'0x1',logsBloom:'0x00',
    type:'0x2',logs:[]}));
});

test('receipt fallback bounds and canonicalizes its transaction worklist before requests',()=>{
 const first=hash(40),second=hash(41);
 assert.deepEqual(boundedTransactionHashes({transactions:[first.toUpperCase().replace('0X','0x'),second]}),
  [first,second]);
 for(const transactions of [[],[first,first],[null],Array(4097).fill(first)]) {
  assert.throws(()=>boundedTransactionHashes({transactions}));
 }
});

test('finalized deposit source validates one bounded cross-layer identity',()=>{
  const source=fixture();
  assert.equal(validateFinalizedDepositSource(source),source);
});

test('finalized deposit source rejects ancestry, policy and proof substitutions',()=>{
  for(const mutate of [
    value=>{value.extra=true;},
    value=>{value.chainId='31337';},
    value=>{value.reserve=value.reserve.toLowerCase();},
    value=>{value.amountBaseUnits='01';},
    value=>{value.receivingCommitment=hash(255);},
    value=>{value.depositBlockHash=hash(20);},
    value=>{value.sourceSetCommitment=hash(20);},
    value=>{value.sourceCatalog.sources[0].executionOriginKeccak256=hash(20);},
    value=>{value.headers[1].parentHash=hash(21);},
    value=>{value.headers[1].number='0x66';},
    value=>{value.finality.finalized_header.execution.block_hash=hash(22);},
    value=>{value.receipts=[];},
    value=>{value.rawTransactions=[];},
    value=>{value.rawTransactions[0]='0x02';},
    value=>{value.transactionIndex=2;},
    value=>{value.reserveAccount.address=funder.toLowerCase();},
    value=>{value.reserveAccount.codeHash=hash(23);},
    value=>{value.reserveAccount.accountProof=[];},
    value=>{value.runtimeBytecode='0x';},
  ]) {
    const value=structuredClone(fixture()); mutate(value);
    assert.throws(()=>validateFinalizedDepositSource(value));
  }
});

test('finalized deposit source bounds integers before conversion',()=>{
  const outsideDecimal=(1n<<64n).toString(),outsideQuantity=`0x${(1n<<64n).toString(16)}`;
  for(const mutate of [
    value=>{value.amountBaseUnits='9'.repeat(100_000);},
    value=>{value.depositBlockNumber='9'.repeat(100_000);},
    value=>{value.headers[0].number=`0x${'f'.repeat(100_000)}`;},
    value=>{value.reserveAccount.balance=`0x${'f'.repeat(100_000)}`;},
    value=>{value.amountBaseUnits=outsideDecimal;},
    value=>{value.depositBlockNumber=outsideDecimal;},
    value=>{value.headers[0].number=outsideQuantity;},
    value=>{value.finality.finalized_header.execution.block_number=outsideDecimal;},
    value=>{value.reserveAccount.nonce=outsideQuantity;},
  ]) {
    const value=structuredClone(fixture()); mutate(value);
    assert.throws(()=>validateFinalizedDepositSource(value),/(canonical|outside uint64)/);
  }
});
