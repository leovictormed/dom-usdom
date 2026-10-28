import {createHash,randomBytes} from 'node:crypto';
import {closeSync,constants,fstatSync,fsyncSync,lstatSync,mkdirSync,openSync,readFileSync,
 writeFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {parseStrictJson} from './strict-json.mjs';

export const BLE_HANDOFF_SCHEMA='usdom-onekey-electron-ble-handoff-v1';
export const BLE_IPC_CHANNEL='usdom:onekey-ble:v1';
export const BLE_EVENT_CHANNEL='usdom:onekey-ble:event:v1';
export const BLE_METHODS=Object.freeze([
 'enumerate','stopScan','getDevice','connect','release','disconnect','subscribe',
 'unsubscribe','write','cancelPairing','checkAvailability',
]);
export const BLE_EVENTS=Object.freeze(['notification','mtuChanged','deviceDisconnected']);
export const ELECTRON_SECURITY_PROFILE=Object.freeze({
 nodeIntegration:false,contextIsolation:true,sandbox:true,webSecurity:true,
 allowRunningInsecureContent:false,remoteContent:false,rpcOrBroadcast:false,
});

const hex64=/^[0-9a-f]{64}$/u;
const hex32=/^[0-9a-f]{32}$/u;
const dangerousKey=/(?:private.?key|mnemonic|seed|password|secret|rpc|broadcast|endpoint|url)/iu;
const MAX_HANDOFF_BYTES=64*1024;

function canonical(value) {
 if(value===null||typeof value==='boolean'||typeof value==='string') return JSON.stringify(value);
 if(typeof value==='number'&&Number.isSafeInteger(value)) return JSON.stringify(value);
 if(Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
 if(value&&(Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null)) {
  return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
 }
 throw new Error('handoff contains a non-canonical value');
}

export const sha256=value=>createHash('sha256').update(typeof value==='string'?value:canonical(value)).digest('hex');

function rejectSecrets(value,path='$') {
 if(Array.isArray(value)) return value.forEach((item,index)=>rejectSecrets(item,`${path}[${index}]`));
 if(!value||typeof value!=='object') return;
 for(const [key,item] of Object.entries(value)) {
  if(dangerousKey.test(key)) throw new Error(`forbidden handoff field ${path}.${key}`);
  rejectSecrets(item,`${path}.${key}`);
 }
}

function assertPrivate(path,expectedMode,type) {
 const stat=lstatSync(path,{throwIfNoEntry:false});
 if(!stat) throw new Error(`missing private path ${path}`);
 if(stat.isSymbolicLink()) throw new Error(`private path is a symlink: ${path}`);
 if((stat.mode&0o777)!==expectedMode) throw new Error(`private path mode is not ${expectedMode.toString(8)}: ${path}`);
 if(stat.uid!==process.getuid()) throw new Error(`private path owner differs from current uid: ${path}`);
 if(type==='directory'&&!stat.isDirectory()) throw new Error(`private path is not a directory: ${path}`);
 if(type==='file'&&(!stat.isFile()||stat.nlink!==1||stat.size>MAX_HANDOFF_BYTES)) {
  throw new Error(`private handoff is not a bounded single-link regular file: ${path}`);
 }
 return stat;
}

function readPrivateJson(path,label) {
 const before=assertPrivate(path,0o600,'file');
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
 try {
  const opened=fstatSync(fd);
  if(opened.dev!==before.dev||opened.ino!==before.ino||!opened.isFile()||opened.nlink!==1
    ||opened.size>MAX_HANDOFF_BYTES) throw new Error(`${label} identity changed while opening`);
  const source=readFileSync(fd,'utf8');
  const after=fstatSync(fd),installed=lstatSync(path);
  if(after.dev!==opened.dev||after.ino!==opened.ino||after.size!==opened.size
    ||installed.dev!==opened.dev||installed.ino!==opened.ino) throw new Error(`${label} changed while reading`);
  return {value:parseStrictJson(source,{label,maxBytes:MAX_HANDOFF_BYTES}),identity:`${opened.dev}:${opened.ino}:${sha256(source)}`};
 } finally { closeSync(fd); }
}

function exactKeys(value,expected,label) {
 if(!value||![Object.prototype,null].includes(Object.getPrototypeOf(value))
   ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...expected].sort())) {
  throw new Error(`invalid ${label} schema`);
 }
}

function validateResponseResult(action,resultType,result) {
 const expectedType={evmGetAddress:'address',evmSignTransaction:'transactionSignature',
  evmSignTypedData:'typedDataSignature'}[action];
 if(resultType==='cancelled') {if(result!==null) throw new Error('invalid cancelled BLE response');return;}
 if(resultType!==expectedType) throw new Error('invalid BLE response type for action');
 if(resultType==='address') {
  exactKeys(result,['address'],'BLE address result');
  if(!/^0x[0-9a-fA-F]{40}$/u.test(result.address)) throw new Error('invalid BLE address result');
 }
 if(resultType==='transactionSignature') {
  exactKeys(result,['v','r','s'],'BLE signature result');
  if(!['0x0','0x1'].includes(result.v)||!/^0x[0-9a-fA-F]{64}$/u.test(result.r)
    ||!/^0x[0-9a-fA-F]{64}$/u.test(result.s)) throw new Error('invalid BLE signature result');
 }
 if(resultType==='typedDataSignature') {
  exactKeys(result,['address','signature'],'BLE typed-data result');
  if(!/^0x[0-9a-fA-F]{40}$/u.test(result.address)||!/^[0-9a-f]{130}$/u.test(result.signature)) {
   throw new Error('invalid BLE typed-data result');
  }
 }
}

function openPrivateDirectory(path) {
 const before=assertPrivate(path,0o700,'directory');
 const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
 const opened=fstatSync(fd);
 if(before.dev!==opened.dev||before.ino!==opened.ino) {closeSync(fd);throw new Error('private directory changed while opening');}
 return {fd,opened};
}

function createOnceAt(directoryFd,name,serialized) {
 if(!/^[a-z0-9.-]+$/u.test(name)||Buffer.byteLength(serialized)>MAX_HANDOFF_BYTES) throw new Error('invalid private artifact');
 const procPath=`/proc/self/fd/${directoryFd}/${name}`;
 const fd=openSync(procPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
 const opened=fstatSync(fd);
 try {writeFileSync(fd,serialized);fsyncSync(fd);} finally {closeSync(fd);}
 return opened;
}

function createBleHandoffRequestInternal({directory,action,payload,nonce,ceremonyId}={}) {
 const privateDirectory=resolve(directory);
 if(!privateDirectory.startsWith('/dev/shm/')) throw new Error('BLE handoff must use a private /dev/shm directory');
 if(!['evmGetAddress','evmSignTransaction','evmSignTypedData'].includes(action)) throw new Error('unsupported BLE action');
 if(!hex64.test(nonce)||!hex64.test(ceremonyId)||nonce===ceremonyId) throw new Error('invalid handoff entropy');
 rejectSecrets(payload);
 mkdirSync(privateDirectory,{mode:0o700});
 const body={schema:BLE_HANDOFF_SCHEMA,nonce,ceremonyId,action,payload};
 const requestSha256=sha256(body);
 const document={...body,requestSha256};
 const serialized=`${canonical(document)}\n`;
 if(Buffer.byteLength(serialized)>MAX_HANDOFF_BYTES) throw new Error('BLE request exceeds byte limit');
 const path=resolve(privateDirectory,'request.json');
 if(dirname(path)!==privateDirectory) throw new Error('BLE request escaped private directory');
 const {fd:directoryFd,opened:directoryOpened}=openPrivateDirectory(privateDirectory);
 let opened;
 try {opened=createOnceAt(directoryFd,'request.json',serialized);} finally {closeSync(directoryFd);}
 const installed=assertPrivate(path,0o600,'file');
 const directoryAfter=assertPrivate(privateDirectory,0o700,'directory');
 if(installed.dev!==opened.dev||installed.ino!==opened.ino||directoryAfter.dev!==directoryOpened.dev
   ||directoryAfter.ino!==directoryOpened.ino) throw new Error('BLE request authority changed after creation');
 return {directory:privateDirectory,path,nonce,ceremonyId,requestSha256,action};
}

export function createBleHandoffRequest(options={}) {
 return createBleHandoffRequestInternal({...options,nonce:randomBytes(32).toString('hex'),
  ceremonyId:randomBytes(32).toString('hex')});
}

export function createBleHandoffRequestForTest(options,{nonce,ceremonyId}={}) {
 return createBleHandoffRequestInternal({...options,nonce,ceremonyId});
}

export function readBleHandoffRequest(path) {
 const {value:request}=readPrivateJson(resolve(path),'OneKey BLE request');
 exactKeys(request,['schema','nonce','ceremonyId','action','payload','requestSha256'],'BLE request');
 const unsigned={...request};delete unsigned.requestSha256;
 if(request.schema!==BLE_HANDOFF_SCHEMA||!hex64.test(request.nonce)||!hex64.test(request.ceremonyId)
   ||request.nonce===request.ceremonyId
   ||!['evmGetAddress','evmSignTransaction','evmSignTypedData'].includes(request.action)
   ||request.requestSha256!==sha256(unsigned)) throw new Error('BLE request authority mismatch');
 rejectSecrets(request.payload);
 return request;
}

export function writeBleHandoffResponse({directory,request,result}={}) {
 const resultType={evmGetAddress:'address',evmSignTransaction:'transactionSignature',
  evmSignTypedData:'typedDataSignature'}[request?.action];
 if(!resultType) throw new Error('unsupported BLE response action');
 validateResponseResult(request.action,resultType,result);
 const response={schema:BLE_HANDOFF_SCHEMA,nonce:request.nonce,requestSha256:request.requestSha256,
  ceremonyId:request.ceremonyId,action:request.action,resultType,result};
 response.responseSha256=sha256(response);
 const privateDirectory=resolve(directory),{fd,opened}=openPrivateDirectory(privateDirectory);
 try {createOnceAt(fd,'response.json',`${canonical(response)}\n`);} finally {closeSync(fd);}
 const after=assertPrivate(privateDirectory,0o700,'directory');
 if(after.dev!==opened.dev||after.ino!==opened.ino) throw new Error('BLE response directory changed after installation');
 return response;
}

export function readBleHandoffResponse({directory,nonce,ceremonyId,requestSha256,action}={}) {
 const privateDirectory=resolve(directory);
 const {fd:directoryFd,opened:directoryOpened}=openPrivateDirectory(privateDirectory);
 let response;
 try {
 const path=`/proc/self/fd/${directoryFd}/response.json`;
 ({value:response}=readPrivateJson(path,'OneKey BLE response'));
 exactKeys(response,['schema','nonce','ceremonyId','requestSha256','action','resultType','result','responseSha256'],'BLE response');
 if(response?.schema!==BLE_HANDOFF_SCHEMA||response?.nonce!==nonce||response?.ceremonyId!==ceremonyId
   ||response?.requestSha256!==requestSha256||response?.action!==action||!hex64.test(requestSha256)) {
  throw new Error('BLE response authority mismatch');
 }
 rejectSecrets(response);
 validateResponseResult(action,response.resultType,response.result);
 const unsigned={...response}; delete unsigned.responseSha256;
 if(response.responseSha256!==sha256(unsigned)) throw new Error('BLE response hash mismatch');
 try {createOnceAt(directoryFd,'response.consumed.json',`${canonical({schema:BLE_HANDOFF_SCHEMA,nonce,ceremonyId,
  requestSha256,responseSha256:response.responseSha256})}\n`);}
 catch(error) {if(error?.code==='EEXIST') throw new Error('BLE response replay rejected');throw error;}
 } finally {closeSync(directoryFd);}
 const directoryAfter=assertPrivate(privateDirectory,0o700,'directory');
 if(directoryAfter.dev!==directoryOpened.dev||directoryAfter.ino!==directoryOpened.ino) {
  throw new Error('BLE response directory changed while consuming');
 }
 return response;
}

function validateIpcEnvelope(envelope,sessionNonce) {
 exactKeys(envelope,['schema','sessionNonce','requestId','method','args','argsSha256'],'BLE IPC envelope');
 if(!envelope||envelope.schema!==BLE_HANDOFF_SCHEMA||envelope.sessionNonce!==sessionNonce
   ||!hex32.test(envelope.sessionNonce)||!hex32.test(envelope.requestId)
   ||!BLE_METHODS.includes(envelope.method)||!Array.isArray(envelope.args)
   ||envelope.argsSha256!==sha256({method:envelope.method,args:envelope.args})) {
  throw new Error('invalid BLE IPC envelope');
 }
 rejectSecrets(envelope.args);
}

export function createNobleBlePreloadBridge({ipcRenderer,sessionNonce}={}) {
 if(!ipcRenderer||!hex32.test(sessionNonce)) throw new Error('invalid preload authority');
 const invoke=method=>(...args)=>ipcRenderer.invoke(BLE_IPC_CHANNEL,{schema:BLE_HANDOFF_SCHEMA,
  sessionNonce,requestId:randomBytes(16).toString('hex'),method,args,argsSha256:sha256({method,args})});
 const subscriptions=new Map(BLE_EVENTS.map(name=>[name,new Set()]));
 const listener=(_event,envelope)=>{
  try { exactKeys(envelope,['schema','sessionNonce','event','args','argsSha256'],'BLE event envelope'); }
  catch { return; }
  if(envelope.schema!==BLE_HANDOFF_SCHEMA||envelope.sessionNonce!==sessionNonce
    ||!BLE_EVENTS.includes(envelope.event)||!Array.isArray(envelope.args)
    ||envelope.argsSha256!==sha256({event:envelope.event,args:envelope.args})) return;
  for(const callback of subscriptions.get(envelope.event)) callback(...envelope.args);
 };
 ipcRenderer.on(BLE_EVENT_CHANNEL,listener);
 const subscribe=event=>callback=>{
  if(typeof callback!=='function') throw new Error('BLE event callback must be a function');
  const callbacks=subscriptions.get(event); callbacks.add(callback);
  return ()=>callbacks.delete(callback);
 };
 return Object.freeze({...Object.fromEntries(BLE_METHODS.map(method=>[method,invoke(method)])),
  onNotification:subscribe('notification'),onMtuChanged:subscribe('mtuChanged'),
  onDeviceDisconnected:subscribe('deviceDisconnected'),
  closeBridge:()=>{ipcRenderer.removeListener(BLE_EVENT_CHANNEL,listener);subscriptions.forEach(set=>set.clear());},
 });
}

export function registerNobleBleMainHandler({ipcMain,webContents,sessionNonce,adapter}={}) {
 if(!ipcMain||!Number.isSafeInteger(webContents?.id)||typeof webContents?.send!=='function'
   ||!hex32.test(sessionNonce)||!adapter) {
  throw new Error('invalid main-process BLE authority');
 }
 let active=false,closed=false;
 const seenRequestIds=new Set();
 const handler=async(event,envelope)=>{
  if(event?.sender?.id!==webContents.id) throw new Error('BLE IPC sender rejected');
  validateIpcEnvelope(envelope,sessionNonce);
  if(closed) throw new Error('BLE IPC handoff is closed');
  if(seenRequestIds.has(envelope.requestId)) throw new Error('BLE IPC replay rejected');
  seenRequestIds.add(envelope.requestId);
  if(active) throw new Error('BLE operation already in flight');
  const method=adapter[envelope.method];
  if(typeof method!=='function') throw new Error('BLE host method unavailable');
  active=true;
  try { const result=await method(...envelope.args);if(closed) throw new Error('BLE operation completed after handoff closed');return result; }
  finally { active=false; }
 };
 ipcMain.handle(BLE_IPC_CHANNEL,handler);
 const eventCleanups=[];
 for(const [hostEvent,wireEvent] of [['onNotification','notification'],['onMtuChanged','mtuChanged'],
  ['onDeviceDisconnected','deviceDisconnected']]) {
  if(typeof adapter[hostEvent]!=='function') throw new Error(`BLE host event unavailable: ${hostEvent}`);
  const cleanup=adapter[hostEvent]((...args)=>{if(!closed) webContents.send(BLE_EVENT_CHANNEL,{schema:BLE_HANDOFF_SCHEMA,
   sessionNonce,event:wireEvent,args,argsSha256:sha256({event:wireEvent,args})});});
  if(typeof cleanup!=='function') throw new Error(`BLE host event cleanup unavailable: ${hostEvent}`);
  eventCleanups.push(cleanup);
 }
 return ()=>{closed=true;ipcMain.removeHandler(BLE_IPC_CHANNEL);for(const cleanup of eventCleanups) cleanup();};
}

export function assertElectronWindowOptions(options) {
 const preferences=options?.webPreferences;
 for(const [key,expected] of Object.entries(ELECTRON_SECURITY_PROFILE)) {
  if(key==='remoteContent'||key==='rpcOrBroadcast') continue;
  if(preferences?.[key]!==expected) throw new Error(`unsafe Electron option ${key}`);
 }
 if(typeof preferences?.preload!=='string'||!preferences.preload.startsWith('/')) {
  throw new Error('Electron preload must be an absolute pinned path');
 }
 return true;
}

export function assertLocalRendererUrl(url) {
 const parsed=new URL(url);
 if(parsed.protocol!=='file:'||parsed.hostname) throw new Error('remote Electron renderer is forbidden');
 return true;
}
