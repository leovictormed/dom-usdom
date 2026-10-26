import test from 'node:test';
import assert from 'node:assert/strict';
import {Interface,keccak256} from 'ethers';
import {buildCheckpointFinalizedEventReport} from '../../sdk/checkpoint-finalized-event-report.mjs';
import {buildCheckpointFinalizedEventRpcCatalog,collectCheckpointFinalizedEventObservation}
  from '../../sdk/checkpoint-finalized-event-collector.mjs';

const h=byte=>'0x'+byte.repeat(64),tx=h('7'),blockHash=h('8');
const registryAddress='0x1000000000000000000000000000000000000001';
const runtime='0x6001600055';
const releaseEvidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1'};
const releaseConfig={ethereumChainId:'1',checkpointRegistry:registryAddress,
 checkpointRegistryRuntimeCodeHash:keccak256(runtime),checkpointRegistryConfigHash:h('2'),domDomain:h('3'),
 checkpointDomNetworkMagic:'1146047821'};
const iface=new Interface([
 'event Checkpoint(bytes32 indexed bridgeDomain,uint32 indexed domNetworkMagic,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 checkpointConfigHash)',
 'function checkpointConfigHash() view returns (bytes32)','function halted() view returns (bool)',
 'function gracefullyShutdown() view returns (bool)','function latestIssuanceClosed() view returns (bool)',
 'function latestHeight() view returns (uint64)','function latestBlock() view returns (bytes32)',
 'function latestStateRoot() view returns (bytes32)','function latestContextHash() view returns (bytes32)',
 'function latestTotalDifficulty() view returns (uint256)','function latestTotalIssued() view returns (uint128)',
 'function latestTotalBurned() view returns (uint128)','function checkpointCount() view returns (uint64)',
 'function candidate() view returns (bytes32,uint64,uint64,bytes32,bytes32,bytes32,uint256,uint64,bytes32,uint256,uint64)',
]);
const event=iface.encodeEventLog(iface.getEvent('Checkpoint'),[releaseConfig.domDomain,
 releaseConfig.checkpointDomNetworkMagic,'1001',h('4'),h('5'),releaseConfig.checkpointRegistryConfigHash]);
const log={address:registryAddress,logIndex:'0x2',topics:event.topics,data:event.data};
const receipt={transactionHash:tx,status:'0x1',blockNumber:'0x1312d00',blockHash,logs:[log]};
const calls={checkpointConfigHash:[h('2')],halted:[false],gracefullyShutdown:[false],
 latestIssuanceClosed:[false],latestHeight:[1001n],latestBlock:[h('4')],
 latestStateRoot:[h('5')],latestContextHash:[h('6')],latestTotalDifficulty:[1000000n],
 latestTotalIssued:[100n],latestTotalBurned:[20n],checkpointCount:[1n],
 candidate:['0x'+'00'.repeat(32),0n,0n,'0x'+'00'.repeat(32),'0x'+'00'.repeat(32),
  '0x'+'00'.repeat(32),0n,0n,'0x'+'00'.repeat(32),0n,0n]};
const sources=[{operatorId:'operator-a',url:'https://rpc-a.example/'},
 {operatorId:'operator-b',url:'https://rpc-b.example/'}];
const catalog=buildCheckpointFinalizedEventRpcCatalog(sources);

function fetchMock({receiptAfterHash=blockHash,extraLog=false,stateRoot=h('5')}={}) {
 const receiptCounts=new Map();
 return async(url,init)=>{
  const request=JSON.parse(init.body),origin=new URL(url).origin;
  let result;
  if(request.method==='eth_chainId') result='0x1';
  else if(request.method==='eth_getTransactionReceipt') {
   const count=(receiptCounts.get(origin)??0)+1; receiptCounts.set(origin,count);
   result={...receipt,blockHash:count>1?receiptAfterHash:blockHash,
    logs:extraLog?[log,{...log,logIndex:'0x3'}]:[log]};
  } else if(request.method==='eth_getBlockByNumber') {
   result=request.params[0]==='0x0'
    ?{number:'0x0',hash:'0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3',timestamp:'0x0'}
    :request.params[0]==='finalized'
    ?{number:'0x1312d0a',hash:h('9'),timestamp:'0x6b49d200'}
    :{number:'0x1312d00',hash:blockHash,timestamp:'0x6b49d200'};
  } else if(request.method==='eth_getCode') result=runtime;
  else if(request.method==='eth_call') {
   const fragment=iface.getFunction(request.params[0].data.slice(0,10));
   const values=fragment.name==='latestStateRoot'?[stateRoot]:calls[fragment.name];
   result=iface.encodeFunctionResult(fragment,values);
  } else throw new Error(`unexpected method ${request.method}`);
  return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,result}),{status:200});
 };
}

test('collects and canonically validates one finalized checkpoint receipt and state',async()=>{
 const observation=await collectCheckpointFinalizedEventObservation({catalog,rpcSources:sources,
  transactionHash:tx,releaseEvidence,releaseConfig,fetchImpl:fetchMock()});
 assert.equal(observation.observations.length,2);
 assert.equal(observation.blockHash,blockHash);
 assert.equal(observation.observations[0].checkpointEventCount,'1');
 assert.equal(observation.observations[0].state.latestHeight,'1001');
 assert(!JSON.stringify(observation).includes('/secret'));
 assert.equal(buildCheckpointFinalizedEventReport({releaseEvidence,releaseConfig,observation}).status,'finalized');
});

test('fails closed on catalog substitution, receipt reorg, duplicate event and state mismatch',async()=>{
 await assert.rejects(()=>collectCheckpointFinalizedEventObservation({catalog,
  rpcSources:[{...sources[0],url:'https://attacker.example/'},sources[1]],transactionHash:tx,
  releaseEvidence,releaseConfig,fetchImpl:fetchMock()}),/catalog/);
 await assert.rejects(()=>collectCheckpointFinalizedEventObservation({catalog,rpcSources:sources,
  transactionHash:tx,releaseEvidence,releaseConfig,fetchImpl:fetchMock({receiptAfterHash:h('a')})}),
  /changed during collection/);
 await assert.rejects(()=>collectCheckpointFinalizedEventObservation({catalog,rpcSources:sources,
  transactionHash:tx,releaseEvidence,releaseConfig,fetchImpl:fetchMock({extraLog:true})}),
  /exactly one Checkpoint/);
 await assert.rejects(()=>collectCheckpointFinalizedEventObservation({catalog,rpcSources:sources,
  transactionHash:tx,releaseEvidence,releaseConfig,fetchImpl:fetchMock({stateRoot:h('a')})}),
  /differs from release or registry state/);
});

test('rejects credential-bearing, routed and local RPC endpoint substitutions',()=>{
 for(const url of ['https://rpc-a.example/secret','https://rpc-a.example/?key=secret',
  'https://user:secret@rpc-a.example/','https://127.0.0.1/']) {
  assert.throws(()=>buildCheckpointFinalizedEventRpcCatalog([
   {operatorId:'operator-a',url},{operatorId:'operator-b',url:'https://rpc-b.example/'},
  ]),/canonical public root HTTPS origin/);
 }
});

test('launchers use only owner-only RPC input files and create-once installers',async()=>{
 const {readFile}=await import('node:fs/promises');
 const files=await Promise.all([
  '../../scripts/collect-checkpoint-finalized-event-observation.mjs',
  '../../scripts/write-checkpoint-finalized-event-rpc-catalog.sh',
  '../../scripts/write-checkpoint-finalized-event-observation.sh',
  '../../scripts/prepare-checkpoint-finalized-transaction-reference.mjs',
  '../../scripts/write-checkpoint-finalized-transaction-reference.sh',
 ].map(file=>readFile(new URL(file,import.meta.url),'utf8')));
 const all=files.join('\n');
 assert.match(files[0],/checkpoint finalized-event inputs changed during collection/);
 assert.match(files[0],/parseStrictJsonBytes/);
 assert.match(files[3],/parseStrictJsonBytes/);
 assert.match(all,/USDOM_CHECKPOINT_FINALIZED_RPC_SOURCES/);
 assert.match(all,/USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH/);
 assert.doesNotMatch(files[0],/USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH/);
 assert.match(files[0],/transaction-reference\.sha256/);
 assert.match(files[0],/submissionDocumentSha256/);
 assert.match(files[4],/Existing checkpoint transaction-reference hash differs from rebuilt output/);
 assert.match(files[4],/cmp -s "\$TEMPORARY\/reference\.sha256" "\$REFERENCE_SHA"/);
 assert.match(files[4],/cmp -s "\$TEMPORARY\/reference\.json" "\$REFERENCE"/);
 assert.ok(files[4].indexOf('install-private-file-immutable-stdin.mjs" "$REFERENCE_SHA"')
   <files[4].indexOf('install-private-file-immutable-stdin.mjs" "$REFERENCE"'));
 assert.match(all,/install-public-file-create-once-stdin\.mjs/);
 assert.match(all,/install-private-file-immutable-stdin\.mjs/);
 assert.doesNotMatch(all,/rpc-a\.example|curl|wget|git push|cast send/);
});
