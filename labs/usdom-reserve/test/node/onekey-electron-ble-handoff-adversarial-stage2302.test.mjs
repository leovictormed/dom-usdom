import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {chmodSync,linkSync,mkdirSync,mkdtempSync,symlinkSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {BLE_EVENT_CHANNEL,BLE_HANDOFF_SCHEMA,createBleHandoffRequest,
 createBleHandoffRequestForTest,createNobleBlePreloadBridge,readBleHandoffRequest,
 readBleHandoffResponse,registerNobleBleMainHandler,
 sha256} from '../../sdk/onekey-electron-ble-handoff.mjs';

const nonce='a1'.repeat(16);
const privateDir=prefix=>{const value=mkdtempSync(`/dev/shm/${prefix}.`);chmodSync(value,0o700);return value;};
const freshPath=prefix=>join(privateDir(`${prefix}-parent`),'ceremony');
const request=(action='evmGetAddress')=>createBleHandoffRequest({
 directory:freshPath('usdom-ble-adv-run'),action,payload:{derivationPath:"m/44'/60'/0'/0/0"}});
const response=(authority,overrides={})=>{
 const value={schema:BLE_HANDOFF_SCHEMA,nonce:authority.nonce,
  ceremonyId:authority.ceremonyId,requestSha256:authority.requestSha256,
  action:authority.action,resultType:'address',
  result:{address:`0x${'11'.repeat(20)}`},...overrides};
 value.responseSha256=sha256(value);return value;
};

test('special, indirect, linked, oversized and duplicate response files fail closed',()=>{
 for(const kind of ['symlink','hardlink','fifo','directory','oversize','duplicate']) {
  const authority=request(),path=join(authority.directory,'response.json');
  if(kind==='symlink') symlinkSync('/dev/null',path);
  else if(kind==='hardlink') {writeFileSync(path,'{}',{mode:0o600});linkSync(path,join(authority.directory,'alias'));}
  else if(kind==='fifo') {execFileSync('mkfifo',[path]);chmodSync(path,0o600);}
  else if(kind==='directory') mkdirSync(path,{mode:0o600});
  else if(kind==='oversize') writeFileSync(path,'x'.repeat(64*1024+1),{mode:0o600});
  else writeFileSync(path,'{"schema":1,"schema":2}',{mode:0o600});
  assert.throws(()=>readBleHandoffResponse(authority));
 }
});

test('response cannot be swapped across operations and is consumed durably',()=>{
 const authority=request();
 writeFileSync(join(authority.directory,'response.json'),JSON.stringify(response(authority,{
  action:'evmSignTransaction'})),{mode:0o600});
 assert.throws(()=>readBleHandoffResponse(authority),/authority mismatch/u);
 const valid=request();
 writeFileSync(join(valid.directory,'response.json'),JSON.stringify(response(valid)),{mode:0o600});
 assert.equal(readBleHandoffResponse(valid).resultType,'address');
 assert.throws(()=>readBleHandoffResponse(valid),/replay/u);
});

test('IPC digest binds method, rejects extra fields, replay and concurrent operations',async()=>{
 let handler,release;
 const ipcMain={handle:(_channel,value)=>{handler=value;},removeHandler:()=>{}};
 const adapter={enumerate:()=>new Promise(resolve=>{release=resolve;}),disconnect:()=>true,
  onNotification:()=>()=>{},onMtuChanged:()=>()=>{},onDeviceDisconnected:()=>()=>{}};
 registerNobleBleMainHandler({ipcMain,webContents:{id:9,send:()=>{}},sessionNonce:nonce,adapter});
 const args=[],envelope={schema:BLE_HANDOFF_SCHEMA,sessionNonce:nonce,requestId:'b2'.repeat(16),
  method:'enumerate',args,argsSha256:sha256({method:'enumerate',args})};
 const swapped={...envelope,requestId:'b3'.repeat(16),method:'disconnect'};
 await assert.rejects(handler({sender:{id:9}},swapped),/invalid/u);
 await assert.rejects(handler({sender:{id:9}},{...envelope,debug:true}),/schema/u);
 const pending=handler({sender:{id:9}},envelope);
 await assert.rejects(handler({sender:{id:9}},{...envelope,requestId:'b4'.repeat(16),
  argsSha256:sha256({method:'enumerate',args})}),/already in flight/u);
 release([]);await pending;
 await assert.rejects(handler({sender:{id:9}},envelope),/replay/u);
});

test('close rejects late operation and suppresses late callbacks or swapped events',async()=>{
 let handler,release,eventListener,notification=0,sent=0;
 const ipcRenderer={invoke:()=>{},on:(_channel,value)=>{eventListener=value;},removeListener:()=>{}};
 const bridge=createNobleBlePreloadBridge({ipcRenderer,sessionNonce:nonce});
 bridge.onNotification(()=>{notification++;});
 const ipcMain={handle:(_channel,value)=>{handler=value;},removeHandler:()=>{}};
 const adapter={enumerate:()=>new Promise(resolve=>{release=resolve;}),
  onNotification:callback=>{adapter.emit=callback;return ()=>{};},
  onMtuChanged:()=>()=>{},onDeviceDisconnected:()=>()=>{}};
 const cleanup=registerNobleBleMainHandler({ipcMain,webContents:{id:4,send:()=>{sent++;}},
  sessionNonce:nonce,adapter});
 const args=[],envelope={schema:BLE_HANDOFF_SCHEMA,sessionNonce:nonce,requestId:'c5'.repeat(16),
  method:'enumerate',args,argsSha256:sha256({method:'enumerate',args})};
 const pending=handler({sender:{id:4}},envelope);cleanup();adapter.emit('late');release([]);
 await assert.rejects(pending,/closed/u);assert.equal(sent,0);
 const eventArgs=['device'];
 eventListener({}, {schema:BLE_HANDOFF_SCHEMA,sessionNonce:nonce,event:'notification',args:eventArgs,
  argsSha256:sha256({event:'deviceDisconnected',args:eventArgs})});
 assert.equal(notification,0);bridge.closeBridge();
});

test('each ceremony has 256-bit independent entropy and a unique create-once directory',()=>{
 const first=createBleHandoffRequest({directory:freshPath('usdom-ble-entropy-a'),action:'evmGetAddress',payload:{}});
 const second=createBleHandoffRequest({directory:freshPath('usdom-ble-entropy-b'),action:'evmGetAddress',payload:{}});
 for(const value of [first.nonce,first.ceremonyId,second.nonce,second.ceremonyId]) {
  assert.match(value,/^[0-9a-f]{64}$/u);
 }
 assert.equal(new Set([first.nonce,first.ceremonyId,second.nonce,second.ceremonyId]).size,4);
 const stored=readBleHandoffRequest(first.path);
 assert.equal(stored.nonce,first.nonce);assert.equal(stored.ceremonyId,first.ceremonyId);
 assert.throws(()=>createBleHandoffRequest({directory:first.directory,action:'evmGetAddress',payload:{}}),/EEXIST/u);
 assert.throws(()=>createBleHandoffRequestForTest({directory:freshPath('usdom-ble-test-entropy'),
  action:'evmGetAddress',payload:{}},{nonce:'aa',ceremonyId:'bb'}),/entropy/u);
 assert.throws(()=>createBleHandoffRequestForTest({directory:freshPath('usdom-ble-equal-entropy'),
  action:'evmGetAddress',payload:{}},{nonce:'aa'.repeat(32),ceremonyId:'aa'.repeat(32)}),/entropy/u);
});
