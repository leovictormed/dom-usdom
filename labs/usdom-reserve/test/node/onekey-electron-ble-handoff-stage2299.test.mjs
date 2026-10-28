import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync,linkSync,mkdtempSync,readFileSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Transaction,TypedDataEncoder,Wallet} from 'ethers';
import {BLE_EVENT_CHANNEL,BLE_HANDOFF_SCHEMA,BLE_IPC_CHANNEL,assertElectronWindowOptions,assertLocalRendererUrl,
 createBleHandoffRequest,createBleHandoffRequestForTest,createNobleBlePreloadBridge,readBleHandoffResponse,
 registerNobleBleMainHandler,sha256,writeBleHandoffResponse} from '../../sdk/onekey-electron-ble-handoff.mjs';
import {createOneKeyEthereumMainnetBoundary} from '../../sdk/onekey-ethereum-mainnet.mjs';

const sessionNonce='11'.repeat(16),nonce='11'.repeat(32),ceremonyId='22'.repeat(32);
const entropy={nonce,ceremonyId};
const makeDir=prefix=>join(mkdtempSync(`/dev/shm/${prefix}.`),'ceremony');

test('private create-once handoff binds nonce, request hash and response hash',()=>{
 const directory=makeDir('usdom-onekey-ble-test');
 const request=createBleHandoffRequestForTest({directory,action:'evmSignTransaction',
  payload:{chainId:1,unsignedTransaction:'0x02'}},entropy);
 const stored=JSON.parse(readFileSync(request.path));
 assert.equal(stored.requestSha256,request.requestSha256);
 assert.throws(()=>createBleHandoffRequest({directory,action:'evmSignTransaction',payload:{}}),/EEXIST/);
 const response={schema:BLE_HANDOFF_SCHEMA,nonce,ceremonyId,requestSha256:request.requestSha256,action:'evmSignTransaction',
  resultType:'transactionSignature',result:{v:'0x1',r:`0x${'22'.repeat(32)}`,s:`0x${'33'.repeat(32)}`}};
 response.responseSha256=sha256(response);
 writeFileSync(join(directory,'response.json'),`${JSON.stringify(response)}\n`,{mode:0o600,flag:'wx'});
 const verified=readBleHandoffResponse(request);
 assert.equal(verified.result.r,response.result.r);
 assert.equal(verified.result.s,response.result.s);
 assert.throws(()=>readBleHandoffResponse(request),/replay/);
 response.requestSha256='44'.repeat(32);
 writeFileSync(join(directory,'bad.json'),JSON.stringify(response),{mode:0o600});
});

test('handoff rejects secrets, RPC material and paths outside private shared memory',()=>{
 assert.throws(()=>createBleHandoffRequest({directory:join(tmpdir(),'bad'),action:'evmGetAddress',payload:{}}),/\/dev\/shm/);
 const directory=makeDir('usdom-onekey-ble-secret');
 assert.throws(()=>createBleHandoffRequest({directory,action:'evmSignTransaction',payload:{rpcUrl:'https://x'}}),/forbidden/);
});

test('production requests generate independent 256-bit nonce and ceremony id in unique directories',()=>{
 const first=createBleHandoffRequest({directory:makeDir('usdom-onekey-random-a'),action:'evmGetAddress',payload:{}});
 const second=createBleHandoffRequest({directory:makeDir('usdom-onekey-random-b'),action:'evmGetAddress',payload:{}});
 assert.match(first.nonce,/^[0-9a-f]{64}$/);assert.match(first.ceremonyId,/^[0-9a-f]{64}$/);
 assert.notEqual(first.nonce,second.nonce);assert.notEqual(first.ceremonyId,second.ceremonyId);
});

test('typed-data response preserves official address and unprefixed signature schema',()=>{
 const directory=makeDir('usdom-onekey-typed');
 const request=createBleHandoffRequestForTest({directory,action:'evmSignTypedData',payload:{digest:`0x${'22'.repeat(32)}`}},entropy);
 const response={schema:BLE_HANDOFF_SCHEMA,nonce,ceremonyId,requestSha256:request.requestSha256,action:'evmSignTypedData',
  resultType:'typedDataSignature',result:{address:`0x${'11'.repeat(20)}`,signature:'33'.repeat(65)}};
 response.responseSha256=sha256(response);
 writeFileSync(join(directory,'response.json'),JSON.stringify(response),{mode:0o600});
 assert.equal(readBleHandoffResponse(request).result.signature,response.result.signature);
});

test('handoff result schemas integrate with transaction and typed-data mainnet boundary',async()=>{
 const wallet=new Wallet(`0x${'42'.repeat(32)}`),connectId='ble-live',deviceId='classic-1s';
 const roundtrip=(action,payload,result)=>{const request=createBleHandoffRequest({directory:makeDir('usdom-onekey-integration'),action,payload});
  writeBleHandoffResponse({directory:request.directory,request,result});return readBleHandoffResponse(request).result;};
 const device={
  async evmGetAddress(_connect,_device,payload){return {success:true,payload:roundtrip('evmGetAddress',payload,{address:wallet.address})};},
  async evmSignTransaction(_connect,_device,payload){const tx=Transaction.from(payload.transaction);
   const signature=wallet.signingKey.sign(tx.unsignedHash);return {success:true,payload:roundtrip('evmSignTransaction',payload,
    {v:`0x${signature.yParity}`,r:signature.r,s:signature.s})};},
  async evmSignTypedData(_connect,_device,payload){const types=Object.fromEntries(Object.entries(payload.data.types).filter(([name])=>name!=='EIP712Domain'));
   const signature=wallet.signingKey.sign(TypedDataEncoder.hash(payload.data.domain,types,payload.data.message));
   return {success:true,payload:roundtrip('evmSignTypedData',payload,{address:wallet.address,signature:signature.serialized.slice(2)})};},
 };
 const boundary=createOneKeyEthereumMainnetBoundary({device,connectId,deviceId,derivationPath:"m/44'/60'/0'/0/0",expectedAddress:wallet.address});
 const tx=Transaction.from({type:2,chainId:1,to:'0x1111111111111111111111111111111111111111',nonce:0,
  gasLimit:21000,maxFeePerGas:2n,maxPriorityFeePerGas:1n,value:1n,data:'0x'});
 const signed=await boundary.signTransaction({unsignedSerialized:tx.unsignedSerialized,unsignedHash:tx.unsignedHash});
 assert.equal(Transaction.from(signed.rawTransaction).from,wallet.address);
 const domain={name:'USDΩ',version:'1',chainId:1,verifyingContract:'0x1111111111111111111111111111111111111111'};
 const types={EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},{name:'chainId',type:'uint256'},
  {name:'verifyingContract',type:'address'}],Approval:[{name:'value',type:'uint256'}]};const value={value:7};
 const typed=await boundary.signTypedData({domain,types,value,digest:TypedDataEncoder.hash(domain,{Approval:types.Approval},value)});
 assert.match(typed.signature,/^0x[0-9a-f]{130}$/);
});

test('response reader rejects duplicate keys, hard links, oversize and action confusion',()=>{
 const makeRequest=()=>createBleHandoffRequestForTest({directory:makeDir('usdom-onekey-ble-reader'),
  action:'evmGetAddress',payload:{derivationPath:"m/44'/60'/0'/0/0"}},entropy);
 let request=makeRequest();
 writeFileSync(join(request.directory,'response.json'),'{"schema":1,"schema":2}',{mode:0o600});
 assert.throws(()=>readBleHandoffResponse(request),/duplicate|schema/);
 request=makeRequest();
 writeFileSync(join(request.directory,'response.json'),'{}',{mode:0o600});
 linkSync(join(request.directory,'response.json'),join(request.directory,'alias.json'));
 assert.throws(()=>readBleHandoffResponse(request),/single-link/);
 request=makeRequest();
 writeFileSync(join(request.directory,'response.json'),'x'.repeat(65*1024),{mode:0o600});
 assert.throws(()=>readBleHandoffResponse(request),/bounded/);
 request=makeRequest();
 const response={schema:BLE_HANDOFF_SCHEMA,nonce,ceremonyId,requestSha256:request.requestSha256,
  action:'evmSignTransaction',resultType:'address',result:{address:`0x${'11'.repeat(20)}`}};
 response.responseSha256=sha256(response);
 writeFileSync(join(request.directory,'response.json'),JSON.stringify(response),{mode:0o600});
 assert.throws(()=>readBleHandoffResponse(request),/authority mismatch/);
});

test('preload exposes fixed methods through one nonce-bound IPC channel',async()=>{
 const calls=[]; let eventListener;
 const ipcRenderer={invoke:(channel,envelope)=>{calls.push({channel,envelope});return 'ok';},
  on:(channel,listener)=>{assert.equal(channel,BLE_EVENT_CHANNEL);eventListener=listener;},removeListener:()=>{eventListener=undefined;}};
 const bridge=createNobleBlePreloadBridge({sessionNonce,ipcRenderer});
 assert.equal(await bridge.enumerate(),'ok');
 assert.equal(calls[0].channel,BLE_IPC_CHANNEL);
 assert.equal(calls[0].envelope.sessionNonce,sessionNonce);
 assert.equal('rpc' in bridge,false);
 let notification;
 const unsubscribe=bridge.onNotification((id,data)=>{notification={id,data};});
 const eventArgs=['dev','aabb'];
 eventListener({}, {schema:BLE_HANDOFF_SCHEMA,sessionNonce,event:'notification',args:eventArgs,argsSha256:sha256({event:'notification',args:eventArgs})});
 assert.deepEqual(notification,{id:'dev',data:'aabb'}); unsubscribe(); bridge.closeBridge();
});

test('main handler authenticates sender, serializes calls and removes handler',async()=>{
 let installed; let removed=false; let release; const sent=[]; const cleanups=[];
 const ipcMain={handle:(channel,fn)=>{assert.equal(channel,BLE_IPC_CHANNEL);installed=fn;},removeHandler:()=>{removed=true;}};
 const adapter={enumerate:()=>new Promise(resolve=>{release=resolve;}),
  onNotification:callback=>{adapter.notify=callback;return ()=>cleanups.push('notification');},
  onMtuChanged:()=>()=>cleanups.push('mtu'),onDeviceDisconnected:()=>()=>cleanups.push('disconnect')};
 const webContents={id:7,send:(...args)=>sent.push(args)};
 const cleanup=registerNobleBleMainHandler({ipcMain,webContents,sessionNonce,adapter});
 const envelope={schema:BLE_HANDOFF_SCHEMA,sessionNonce,requestId:'55'.repeat(16),method:'enumerate',args:[],argsSha256:sha256({method:'enumerate',args:[]})};
 assert.rejects(installed({sender:{id:8}},envelope),/sender rejected/);
 const pending=installed({sender:{id:7}},envelope);
 await assert.rejects(installed({sender:{id:7}},{...envelope,requestId:'66'.repeat(16)}),/already in flight/);
 release([]); assert.deepEqual(await pending,[]);
 adapter.notify('dev','aabb');assert.equal(sent[0][0],BLE_EVENT_CHANNEL);
 await assert.rejects(installed({sender:{id:7}},envelope),/replay/);
 cleanup(); assert.equal(removed,true);assert.deepEqual(cleanups,['notification','mtu','disconnect']);
});

test('closing a handoff rejects a late operation result',async()=>{
 let installed,release;
 const ipcMain={handle:(_channel,fn)=>{installed=fn;},removeHandler:()=>{}};
 const adapter={enumerate:()=>new Promise(resolve=>{release=resolve;}),
  onNotification:()=>()=>{},onMtuChanged:()=>()=>{},onDeviceDisconnected:()=>()=>{}};
 const cleanup=registerNobleBleMainHandler({ipcMain,webContents:{id:3,send:()=>{}},sessionNonce,adapter});
 const args=[];const envelope={schema:BLE_HANDOFF_SCHEMA,sessionNonce,requestId:'77'.repeat(16),
  method:'enumerate',args,argsSha256:sha256({method:'enumerate',args})};
 const pending=installed({sender:{id:3}},envelope);cleanup();release([]);
 await assert.rejects(pending,/completed after handoff closed/);
});

test('Electron window and renderer are fail-closed',()=>{
 assertElectronWindowOptions({webPreferences:{nodeIntegration:false,contextIsolation:true,sandbox:true,
  webSecurity:true,allowRunningInsecureContent:false,preload:'/opt/usdom/pinned-preload.cjs'}});
 assert.throws(()=>assertElectronWindowOptions({webPreferences:{nodeIntegration:true}}),/unsafe/);
 assertLocalRendererUrl('file:///opt/usdom/index.html');
 assert.throws(()=>assertLocalRendererUrl('https://wallet.invalid/'),/remote/);
});
