import test from 'node:test';
import assert from 'node:assert/strict';
import {AbiCoder,keccak256} from 'ethers';
import {checkpointBootstrapRatificationDigest} from '../../sdk/checkpoint-bootstrap-ratification-report.mjs';
import {buildCheckpointBootstrapRpcCatalog,collectCheckpointBootstrapRatificationObservation,
  createBoundedJsonRpcProvider} from '../../sdk/checkpoint-bootstrap-ratification-collector.mjs';
import {buildCheckpointBootstrapRatificationSigningRequest,
  validateCheckpointBootstrapRatificationSigningRequest}
  from '../../sdk/checkpoint-bootstrap-ratification-request.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';

const h=byte=>'0x'+byte.repeat(64);
const releaseEvidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1'};
const runtime='0x6001600055';
const releaseConfig={ethereumChainId:'1',governance:'0x1000000000000000000000000000000000000001',
 governanceCodeHash:keccak256(runtime),reserveConfigHash:h('2'),checkpointRegistryConfigHash:h('3'),
 activationScheduleCommitment:h('4'),nativeEthereumTrustedCheckpoint:h('5'),domDomain:h('6'),
 checkpointDomNetworkMagic:'1146047821',checkpointDomChainId:h('7'),checkpointFirstV4Height:'1001',
 checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
 checkpointChallengePeriodSeconds:'172800',checkpointInitialHeight:'1000',checkpointInitialBlock:h('8'),
 checkpointInitialContextHash:h('9'),checkpointInitialTotalDifficulty:'100000'};
const checkpointConsensus={schema:'usdom-ethereum-checkpoint-consensus-v1',network:'ethereum-mainnet',
 checkpointEpoch:'500000',checkpointSlot:'16000000',checkpointRoot:h('5'),sourceCount:'3',
 sourceSetCommitment:h('a'),observedAtUnix:'1000'};
const nativeFacts={schema:'usdom-native-preactivation-facts-v1',nativeEthereumTrustedCheckpoint:h('5'),
 domDomain:h('6'),checkpointDomNetworkMagic:'1146047821',checkpointDomChainId:h('7'),
 checkpointFirstV4Height:'1001',checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
 checkpointChallengePeriodSeconds:'172800',checkpointInitialHeight:'1000',checkpointInitialBlock:h('8'),
 checkpointInitialContextHash:h('9'),checkpointInitialTotalDifficulty:'100000'};
const rpcSources=[{operatorId:'operator-a',url:'https://rpc-a.example/'},
 {operatorId:'operator-b',url:'https://rpc-b.example/'}];
const catalog=buildCheckpointBootstrapRpcCatalog(rpcSources);
const signature='0x1234';
const magic=AbiCoder.defaultAbiCoder().encode(['bytes4'],['0x1626ba7e']);

function rpcFetch({secondHash=h('b')}={}) {
 const counts=new Map();
 return async(url,init)=>{
  const request=JSON.parse(init.body),key=`${new URL(url).origin}:${request.method}`;
  counts.set(key,(counts.get(key)??0)+1);
  let result;
  if(request.method==='eth_chainId') result='0x1';
  else if(request.method==='eth_getCode') result=runtime;
  else if(request.method==='eth_call') result=magic;
  else if(request.method==='eth_getBlockByNumber') {
   if(request.params[0]==='0x0') result={number:'0x0',
    hash:'0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3',timestamp:'0x0'};
   else { const after=request.params[0]!=='finalized';
    result={number:'0x1312d00',hash:after?secondHash:h('b'),timestamp:'0x44c'}; }
  } else throw new Error(`unexpected ${request.method}`);
  return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,result}),
   {status:200,headers:{'content-type':'application/json'}});
 };
}

test('collects one stable finalized EIP-1271 snapshot from catalog-matched RPCs',async()=>{
 const observation=await collectCheckpointBootstrapRatificationObservation({catalog,rpcSources,
  releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,signature,fetchImpl:rpcFetch(),now:()=>1200});
 assert.equal(observation.approvals.length,2);
 assert.equal(observation.snapshotBlockHash,h('b'));
 assert.equal(observation.ratificationDigest,checkpointBootstrapRatificationDigest({releaseEvidence,
  releaseConfig,checkpointConsensus,nativeFacts}));
 assert(!JSON.stringify(observation).includes('secret-key'));
 assert.deepEqual(observation.approvals.map(value=>value.operatorId),['operator-a','operator-b']);
});

test('fails closed on catalog substitution, unstable snapshot and rejected EIP-1271',async()=>{
 await assert.rejects(()=>collectCheckpointBootstrapRatificationObservation({catalog,
  rpcSources:[{...rpcSources[0],url:'https://attacker.example/'},rpcSources[1]],releaseEvidence,
  releaseConfig,checkpointConsensus,nativeFacts,signature,fetchImpl:rpcFetch(),now:()=>1200}),/catalog/);
 await assert.rejects(()=>collectCheckpointBootstrapRatificationObservation({catalog,rpcSources,
  releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,signature,
  fetchImpl:rpcFetch({secondHash:h('c')}),now:()=>1200}),/stable/);
 const rejected=async(url,init)=>{
  const request=JSON.parse(init.body);
  if(request.method==='eth_call') return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,
   result:AbiCoder.defaultAbiCoder().encode(['bytes4'],['0xffffffff'])}),{status:200});
  return rpcFetch()(url,init);
 };
 await assert.rejects(()=>collectCheckpointBootstrapRatificationObservation({catalog,rpcSources,
  releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,signature,fetchImpl:rejected,
  now:()=>1200}),/valid finalized/);
});

test('bounded JSON-RPC rejects duplicate keys, oversized bodies and identity mismatch',async()=>{
 const send=fetchImpl=>createBoundedJsonRpcProvider('https://rpc.example/',{fetchImpl,maxBytes:128})
  .send('eth_chainId',[]);
 await assert.rejects(()=>send(async()=>new Response('{"jsonrpc":"2.0","id":1,"id":1,"result":"0x1"}')),
  /duplicate object key/);
 await assert.rejects(()=>send(async()=>new Response(JSON.stringify({jsonrpc:'2.0',id:1,
  result:'x'.repeat(200)}))),/size limit/);
 await assert.rejects(()=>send(async()=>new Response(JSON.stringify({jsonrpc:'2.0',id:999,result:'0x1'}))),
  /identity differs/);
});

test('bootstrap catalog rejects credential-bearing, routed and local endpoints',()=>{
 for(const url of ['https://rpc-a.example/secret','https://rpc-a.example/?key=secret',
  'https://user:secret@rpc-a.example/','https://127.0.0.1/']) {
  assert.throws(()=>buildCheckpointBootstrapRpcCatalog([
   {operatorId:'operator-a',url},{operatorId:'operator-b',url:'https://rpc-b.example/'},
  ]),/canonical public root HTTPS origin/);
 }
});

test('launchers keep RPC URLs behind owner-only file paths and require hash-addressed create-once signatures',async()=>{
 const {readFile}=await import('node:fs/promises');
 const files=await Promise.all(['../../scripts/collect-checkpoint-bootstrap-ratification-observation.mjs',
  '../../scripts/write-checkpoint-bootstrap-rpc-catalog.sh',
  '../../scripts/write-checkpoint-bootstrap-ratification-observation.sh',
  '../../scripts/write-checkpoint-bootstrap-ratification-request.sh',
  '../../scripts/sign-checkpoint-bootstrap-ratification.sh'].map(file=>
   readFile(new URL(file,import.meta.url),'utf8')));
 const all=files.join('\n');
 assert.match(files[0],/checkpoint bootstrap ratification inputs changed during collection/);
 assert.match(all,/USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES/);
 assert.doesNotMatch(all,/USDOM_CHECKPOINT_RATIFICATION_SIGNATURE/);
 assert.match(files[0],/ratification-signature\.sha256/);
 assert.match(all,/ASSINO CHECKPOINT BOOTSTRAP USDOM SEM TRANSMITIR/);
 assert.match(all,/check-release-signing-network\.mjs/);
 assert.match(all,/"\$cast_bin" wallet sign --no-hash "\$DIGEST" --ledger/);
 assert.doesNotMatch(all,/(?:^|\n)\s*cast wallet sign/m);
 assert.match(files[4],/sort_by\(ascii_downcase\)/);
 assert.match(files[4],/Existing ratification-signature hash differs from rebuilt signature/);
 assert.match(files[4],/signature-sha\.installed\.txt/);
 assert.match(files[4],/signature\.installed\.hex/);
 assert.ok(files[4].lastIndexOf('install-private-file-immutable-stdin.mjs" "$SIGNATURE_SHA"')
   <files[4].lastIndexOf('install-private-file-immutable-stdin.mjs" "$SIGNATURE"'));
 assert.match(files[4],/release-config\.current\.json/);
 assert.match(files[4],/set \+x/);
 assert.match(files[4],/ulimit -c 0/);
 assert.match(all,/install-public-file-create-once-stdin\.mjs/);
 assert.match(all,/install-private-file-immutable-stdin\.mjs/);
 assert.match(files[3],/install-private-file-immutable-stdin\.mjs" --json "\$REQUEST"/);
 assert.match(files[3],/Existing ratification-request hash differs from rebuilt output/);
 assert.match(files[3],/cmp -s "\$TEMPORARY\/request\.sha256" "\$SHA"/);
 assert.match(files[3],/cmp -s "\$TEMPORARY\/request\.json" "\$REQUEST"/);
 assert.ok(files[3].indexOf('install-private-file-immutable-stdin.mjs" "$SHA"')
   <files[3].indexOf('install-private-file-immutable-stdin.mjs" --json "$REQUEST"'));
 assert.doesNotMatch(all,/https:\/\/rpc-[ab]\.example|curl|wget|git push|cast send/);
});

test('canonical signing request binds exact inputs, finalized governance and RPC identities',()=>{
 const finalizedAnchor={blockNumber:'20000000',blockHash:h('b'),blockTimestamp:'1100',
  governance:releaseConfig.governance,governanceCodeHash:releaseConfig.governanceCodeHash,
  rpcConsensus:rpcConsensusEvidence([
   {sourceId:'operator-a',originKeccak256:h('d')},
   {sourceId:'operator-b',originKeccak256:h('e')},
  ])};
 const inputDocuments={releaseEvidenceSha256:'1'.repeat(64),releaseConfigSha256:'2'.repeat(64),
  checkpointConsensusSha256:'3'.repeat(64),nativeFactsSha256:'4'.repeat(64)};
 const args={releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,finalizedAnchor,inputDocuments};
 const request=buildCheckpointBootstrapRatificationSigningRequest(args);
 assert.equal(validateCheckpointBootstrapRatificationSigningRequest({...args,request}).digest,
  checkpointBootstrapRatificationDigest(args));
 for(const changed of [
  {...request,ratificationDigest:h('f')},
  {...request,inputDocuments:{...request.inputDocuments,nativeFactsSha256:'5'.repeat(64)}},
  {...request,finalizedAnchor:{...request.finalizedAnchor,governanceCodeHash:h('f')}},
 ]) assert.throws(()=>validateCheckpointBootstrapRatificationSigningRequest({...args,request:changed}));
});
