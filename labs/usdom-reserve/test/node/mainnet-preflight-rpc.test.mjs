import test from 'node:test';
import assert from 'node:assert/strict';
import {buildMainnetPreflightRpcCatalog,BoundedMainnetPreflightProvider,
  mainnetPreflightRpcSourceSet,matchMainnetPreflightRpcSources,
  validateMainnetPreflightClientIdentity,requireOperationalTlsClock,
  validateMainnetPreflightTimeConsensus}
  from '../../sdk/mainnet-preflight-rpc.mjs';

const source=(operatorId,providerId,infrastructureId,url)=>({operatorId,providerId,infrastructureId,url,
 tlsPolicy:'node-default-ca-hostname-expiry-origin-pinned-v1',clockPolicy:'utc-wall-clock-sane-v1',
 clientPolicy:'ethereum-execution-client-stable-v1'});
const sources=[source('operator-a','provider-a','infra-a','https://rpc-a.example/'),
 source('operator-b','provider-b','infra-b','https://rpc-b.example/')];

test('catalog binds independent operators to origins without persisting endpoint paths',()=>{
 const catalog=buildMainnetPreflightRpcCatalog(sources);
 assert.equal(catalog.sources.length,2);
 assert(!JSON.stringify(catalog).includes('secret'));
 assert.deepEqual(matchMainnetPreflightRpcSources(catalog,sources).map(value=>value.sourceId),
  ['operator-a','operator-b']);
 const sourceSet=mainnetPreflightRpcSourceSet(catalog);
 assert.equal(sourceSet.sourceCount,'2');
 assert.match(sourceSet.sourceSetCommitment,/^0x[0-9a-f]{64}$/);
 assert.deepEqual(sourceSet.sources,catalog.sources);
 assert.notEqual(mainnetPreflightRpcSourceSet(buildMainnetPreflightRpcCatalog([
  sources[0],{...sources[1],url:'https://rpc-c.example/'},
 ])).sourceSetCommitment,sourceSet.sourceSetCommitment);
 assert.throws(()=>matchMainnetPreflightRpcSources(catalog,
  [{...sources[0],url:'https://attacker.example/'},sources[1]]),/differs from catalog/);
 assert.throws(()=>buildMainnetPreflightRpcCatalog([
  sources[0],{...sources[1],url:'https://rpc-a.example:8443/'},
 ]),/hostnames must be distinct/);
 for(const url of ['http://rpc-a.example/','https://user@rpc-a.example/',
  'https://rpc-a.example/key','https://rpc-a.example/?key=secret','https://rpc-a.example/#fragment',
  'https://localhost/','https://node.local/','https://127.0.0.1/','https://[::1]/',
  'https://rpc-a.example./','https://intranet/']) {
  assert.throws(()=>buildMainnetPreflightRpcCatalog([{...sources[0],url},sources[1]]),
   /HTTPS|credentials|fragments|public DNS/);
 }
 for(const mutate of [
  value=>{value[1].providerId=value[0].providerId;},
  value=>{value[1].infrastructureId=value[0].infrastructureId;},
  value=>{value[1].tlsPolicy='unverified';},value=>{value[1].clockPolicy='unchecked';},
  value=>{value[1].clientPolicy='any';},
 ]) { const changed=structuredClone(sources); mutate(changed);
  assert.throws(()=>buildMainnetPreflightRpcCatalog(changed),/distinct|invalid/); }
});

test('bounded ethers provider rejects duplicate JSON keys, oversized bodies and wrong IDs',async()=>{
 const attempt=async fetchImpl=>{
  const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',
   {fetchImpl,maxBytes:128,timeoutMs:1000});
  try { return await provider.send('eth_chainId',[]); } finally { provider.destroy(); }
 };
 await assert.rejects(()=>attempt(async(_url,init)=>new Response(
  `{"jsonrpc":"2.0","id":${JSON.parse(init.body).id},"id":1,"result":"0x1"}`)),/duplicate object key/);
 await assert.rejects(()=>attempt(async()=>new Response(JSON.stringify({jsonrpc:'2.0',id:1,
  result:'x'.repeat(200)}))),/size limit/);
 await assert.rejects(()=>attempt(async()=>new Response(JSON.stringify({jsonrpc:'2.0',id:999,result:'0x1'}))),
  /envelope is invalid/);
});

test('bounded ethers provider fixes redirect policy and validates resource bounds',async()=>{
 let request;
 const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{
  timeoutMs:1000,maxBytes:1024,fetchImpl:async(url,init)=>{
   request={url,init};
   const id=JSON.parse(init.body).id;
   return new Response(JSON.stringify({jsonrpc:'2.0',id,result:'0x1'}));
  },
 });
 try { assert.equal(await provider.send('eth_chainId',[]),'0x1'); } finally { provider.destroy(); }
 assert.equal(request.url,'https://rpc.example/');
 assert.equal(request.init.redirect,'error');
 assert.equal(request.init.headers.accept,'application/json');
 for(const options of [
  {timeoutMs:0},{timeoutMs:120_001},{timeoutMs:NaN},{maxBytes:0},{maxBytes:64*1024*1024+1},
  {maxRequests:0},{maxRequests:1025},{maxRequests:NaN},
 ]) assert.throws(()=>new BoundedMainnetPreflightProvider('https://rpc.example/',options),/outside its bound/);
 const hugeLength=new BoundedMainnetPreflightProvider('https://rpc.example/',{
  timeoutMs:1000,maxBytes:1024,fetchImpl:async(_url,init)=>new Response(
   JSON.stringify({jsonrpc:'2.0',id:JSON.parse(init.body).id,result:'0x1'}),
   {headers:{'content-length':'9'.repeat(400)}},
  ),
 });
 try { await assert.rejects(()=>hugeLength.send('eth_chainId',[]),/size limit/); }
 finally { hugeLength.destroy(); }
});

test('bounded provider caps total requests without retrying failed calls',async()=>{
 let attempts=0;
 const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{
  timeoutMs:1000,maxBytes:1024,maxRequests:2,fetchImpl:async(_url,init)=>{
   attempts+=1; const request=JSON.parse(init.body);
   return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,result:'0x1'}));
  },
 });
 try {
  assert.equal(await provider.send('eth_chainId',[]),'0x1');
  assert.equal(await provider.send('eth_chainId',[]),'0x1');
  await assert.rejects(()=>provider.send('eth_chainId',[]),/request count limit/);
  assert.equal(attempts,2);
 } finally { provider.destroy(); }
});

test('RPC error envelopes are exact, bounded and redact remote text and data',async()=>{
 const attempt=async error=>{
  const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{
   timeoutMs:1000,maxBytes:4096,fetchImpl:async(_url,init)=>new Response(JSON.stringify({
    jsonrpc:'2.0',id:JSON.parse(init.body).id,error,
   })),
  });
  try { return await provider.send('eth_chainId',[]); } finally { provider.destroy(); }
 };
 await assert.rejects(()=>attempt({code:-32000,message:'secret https://rpc.example/',
  data:{token:'secret'}}),error=>{
   assert.doesNotMatch(String(error?.message),/secret|rpc\.example/);
   return true;
 });
 await assert.rejects(()=>attempt({code:-32000,message:'rejected',extra:true}),/error envelope is invalid/);
 await assert.rejects(()=>attempt({code:1.5,message:'rejected'}),/error envelope is invalid/);
 await assert.rejects(()=>attempt({code:-32000,message:'x'.repeat(1025)}),/error envelope is invalid/);
});

test('HTTPS transport rejects proxy/CA overrides and redacts fetch failures',async()=>{
 for(const environment of [
  {HTTPS_PROXY:'https://proxy.example'},
  {http_proxy:'http://proxy.example'},
  {ALL_PROXY:'socks5://proxy.example'},
  {NODE_EXTRA_CA_CERTS:'/tmp/ca.pem'},
  {SSL_CERT_FILE:'/tmp/ca.pem'},
  {NODE_TLS_REJECT_UNAUTHORIZED:'0'},
  {NODE_OPTIONS:'--use-env-proxy'},
  {NODE_OPTIONS:'--use-system-ca'},
  {NODE_OPTIONS:'--openssl-config=/tmp/openssl.cnf'},
  {NODE_OPTIONS:'--require=/tmp/hook.cjs'},
  {OPENSSL_CONF:'/tmp/openssl.cnf'},
  {OPENSSL_ENGINES:'/tmp/engines'},
  {SSLKEYLOGFILE:'/tmp/tls.keys'},
  {NODE_PATH:'/tmp/node-modules'},
  {NODE_DEBUG:'tls,net'},
  {RES_OPTIONS:'ndots:15'},
  {LOCALDOMAIN:'attacker.example'},
  {HOSTALIASES:'/tmp/hosts.aliases'},
  {LD_PRELOAD:'/tmp/hook.so'},
  {DYLD_INSERT_LIBRARIES:'/tmp/hook.dylib'},
 ]) assert.throws(()=>new BoundedMainnetPreflightProvider('https://rpc.example/',
  {environment}),/unsafe HTTPS transport/);
 const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{
  environment:{},fetchImpl:async()=>{throw new Error('secret?token=private');},
 });
 try {
  await assert.rejects(()=>provider.send('eth_chainId',[]),error=>{
   assert.match(String(error?.message),/transport failed/);
   assert.doesNotMatch(String(error?.message),/secret|private|rpc\.example/);
   return true;
  });
 } finally { provider.destroy(); }
});

test('TLS operational clock rejects invalid, stale and implausible wall time',()=>{
 assert.equal(requireOperationalTlsClock(Date.UTC(2026,9,26)),Date.UTC(2026,9,26));
 for(const value of [NaN,Infinity,Date.UTC(2024,11,31),Date.UTC(2100,0,2)]) {
  assert.throws(()=>requireOperationalTlsClock(value),/system clock/);
 }
});

test('state RPC cannot escape or change the pinned finalized snapshot',async()=>{
 const requests=[];
 const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{
  timeoutMs:1000,maxBytes:1024,fetchImpl:async(_url,init)=>{
   const request=JSON.parse(init.body); requests.push(request);
   return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,result:'0x'}));
  },
 });
 try {
  await assert.rejects(()=>provider.send('eth_getCode',['0x'+'11'.repeat(20),'latest']),/precedes/);
  assert.deepEqual(provider.pinFinalizedSnapshot('0x10','0x'+'22'.repeat(32)),
   {tag:'0x10',hash:'0x'+'22'.repeat(32),allowPendingNonce:false});
  for(const number of ['9'.repeat(100000),'0x10000000000000000']) {
   assert.throws(()=>provider.pinFinalizedSnapshot(number,'0x'+'22'.repeat(32)),/number is invalid/);
  }
  await assert.rejects(()=>provider.send('eth_getCode',['0x'+'11'.repeat(20),'0xf']),/not pinned/);
  assert.throws(()=>provider.pinFinalizedSnapshot('0x11','0x'+'33'.repeat(32)),/repinned/);
  assert.equal(await provider.send('eth_getCode',['0x'+'11'.repeat(20),'0x10']),'0x');
  assert.equal(requests.at(-1).params[1],'0x10');
 } finally { provider.destroy(); }
});

test('transport binds mainnet chain and pinned/finalized block identities',async()=>{
 const pinnedHash='0x'+'22'.repeat(32);
 let result='0x1';
 const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{
  environment:{},fetchImpl:async(_url,init)=>{
   const request=JSON.parse(init.body);
   return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,result}));
  },
 });
 try {
  assert.equal(await provider.send('eth_chainId',[]),'0x1');
  result={number:'0x0',hash:'0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3'};
  assert.equal((await provider.send('eth_getBlockByNumber',['0x0',false])).number,'0x0');
  result={number:'0x0',hash:'0x'+'66'.repeat(32)};
  await assert.rejects(()=>provider.send('eth_getBlockByNumber',['0x0',false]),/genesis block/);
  result='0x5';
  await assert.rejects(()=>provider.send('eth_chainId',[]),/not Ethereum mainnet/);
  provider.pinFinalizedSnapshot('0x10',pinnedHash);
  result={number:'0x10',hash:pinnedHash,timestamp:'0x65000000'};
  assert.equal((await provider.send('eth_getBlockByNumber',['0x10',false])).hash,pinnedHash);
  result={number:'0x10',timestamp:'0x65000000'};
  await assert.rejects(()=>provider.send('eth_getBlockByNumber',['0x10',false]),/identity is invalid/);
  result={number:'0x10',hash:'0x'+'33'.repeat(32),timestamp:'0x65000000'};
  await assert.rejects(()=>provider.send('eth_getBlockByNumber',['0x10',false]),/changed/);
  result={number:'0xf',hash:'0x'+'44'.repeat(32),timestamp:'0x65000000'};
  await assert.rejects(()=>provider.send('eth_getBlockByNumber',['finalized',false]),/regressed/);
  result={number:'0x11',hash:'0x'+'55'.repeat(32),timestamp:'0x6500000c'};
  assert.equal((await provider.send('eth_getBlockByNumber',['finalized',false])).number,'0x11');
  result={number:'0x10000000000000000',hash:pinnedHash,timestamp:'0x6500000c'};
  await assert.rejects(()=>provider.send('eth_getBlockByNumber',['finalized',false]),/identity is invalid/);
 } finally { provider.destroy(); }
});

test('execution client identity policy is bounded and recognizes stable client families',()=>{
 assert.equal(validateMainnetPreflightClientIdentity(
  'Geth/v1.15.0-stable/linux-amd64/go1.24','ethereum-execution-client-stable-v1'),
 'Geth/v1.15.0-stable/linux-amd64/go1.24');
 for(const value of ['',123,'unknown-proxy/1.0','Geth/ok\nforged','Geth/'+('x'.repeat(260))]) {
  assert.throws(()=>validateMainnetPreflightClientIdentity(
   value,'ethereum-execution-client-stable-v1'),/client identity/);
 }
 assert.throws(()=>validateMainnetPreflightClientIdentity('Geth/v1','any'),/policy/);
});

test('multisource finalized time is monotonic, bounded and only a plausibility check',()=>{
 const now=Date.UTC(2026,9,26,12,0,0),timestamp=`0x${Math.floor((now-12*60*1000)/1000).toString(16)}`;
 const samples=['operator-a','operator-b'].map((sourceId,index)=>({sourceId,finalizedTimestamp:timestamp,
  collectedBeforeMs:now-1000+index,collectedAfterMs:now-500+index}));
 assert.equal(validateMainnetPreflightTimeConsensus(samples,{nowMs:now}),true);
 const mutate=callback=>{const values=structuredClone(samples);callback(values);return values;};
 assert.throws(()=>validateMainnetPreflightTimeConsensus(
  mutate(v=>{v[1].finalizedTimestamp=`0x${(BigInt(timestamp)+16n).toString(16)}`;}),{nowMs:now}),/source skew/);
 assert.throws(()=>validateMainnetPreflightTimeConsensus(
  mutate(v=>{v[1].collectedAfterMs=v[1].collectedBeforeMs-1;}),{nowMs:now}),/sample 2/);
 assert.throws(()=>validateMainnetPreflightTimeConsensus(samples,{nowMs:now+31*60*1000}),/implausible/);
 assert.throws(()=>validateMainnetPreflightTimeConsensus(samples,{nowMs:now-15*60*1000}),/implausible/);
 assert.throws(()=>validateMainnetPreflightTimeConsensus(
  mutate(v=>{v[0].finalizedTimestamp=`0x${'f'.repeat(100000)}`;}),{nowMs:now}),/sample 1/);
});

test('bounded provider aborts when wall clock regresses or diverges from monotonic time',async()=>{
 let wall=Date.UTC(2026,9,26),monotonic=100;
 const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{environment:{},nowMs:wall,
  wallClock:()=>wall,monotonicClock:()=>monotonic,fetchImpl:async(_url,init)=>{
   wall-=1; monotonic+=1;
   return new Response(JSON.stringify({jsonrpc:'2.0',id:JSON.parse(init.body).id,result:'0x1'}));
  }});
 try { await assert.rejects(()=>provider.send('eth_chainId',[]),/clock regressed or diverged/); }
 finally { provider.destroy(); }
});

test('pending nonce is an explicit pinned-snapshot exception only for deployment identity',async()=>{
 const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{
  timeoutMs:1000,maxBytes:1024,fetchImpl:async(_url,init)=>{
   const request=JSON.parse(init.body);
   return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,result:'0x7'}));
  },
 });
 try {
  provider.pinFinalizedSnapshot('0x10','0x'+'22'.repeat(32),{allowPendingNonce:true});
  assert.equal(await provider.send('eth_getTransactionCount',['0x'+'11'.repeat(20),'pending']),'0x7');
  await assert.rejects(()=>provider.send('eth_getCode',['0x'+'11'.repeat(20),'pending']),/not pinned/);
 } finally { provider.destroy(); }
});

test('capacity and release RPC transports refuse redirects and invalid UTF-8',async()=>{
 const {readFile}=await import('node:fs/promises');
 for(const relative of [
  '../../scripts/run-checkpoint-capacity-e2e.mjs',
  '../../scripts/run-finalized-burn-capacity-e2e.mjs',
  '../../scripts/run-finalized-burn-release-e2e.mjs',
 ]) {
  const script=await readFile(new URL(relative,import.meta.url),'utf8');
  assert.match(script,/redirect:'error'/);
  assert.match(script,/TextDecoder\('utf-8',\{fatal:true\}\)/);
  assert.match(script,/AbortSignal\.timeout\(20_000\)/);
  assert.match(script,/length>262144/);
 }
});

test('preflight collector has no embedded RPC and catalog is public create-once',async()=>{
 const {readFile}=await import('node:fs/promises');
 const [collector,writer]=await Promise.all([
  readFile(new URL('../../scripts/check-mainnet-preflight.mjs',import.meta.url),'utf8'),
  readFile(new URL('../../scripts/write-mainnet-preflight-rpc-catalog.sh',import.meta.url),'utf8'),
 ]);
 assert.match(collector,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES/);
 assert.match(collector,/web3_clientVersion/);
 assert.match(collector,/RPC execution client identity changed during observation/);
 assert.doesNotMatch(collector,/eth\.drpc\.org|ethereum-rpc\.publicnode\.com/);
 assert.match(writer,/install-public-file-create-once-stdin\.mjs/);
 assert.doesNotMatch(`${collector}\n${writer}`,/curl|wget|git push|cast send/);
});
