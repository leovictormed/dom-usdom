import {randomBytes} from 'node:crypto';
import {resolve} from 'node:path';
import {app,BrowserWindow,ipcMain,session} from 'electron';
import {dirname} from 'node:path';
import {assertElectronWindowOptions,assertLocalRendererUrl,readBleHandoffRequest,
 registerNobleBleMainHandler,writeBleHandoffResponse} from '../../sdk/onekey-electron-ble-handoff.mjs';
import {nativeBleAdapterApproved,openNativeBleAdapter} from './native-adapter.mjs';

if(!nativeBleAdapterApproved) throw new Error('OneKey BLE native adapter gate is closed');
const sessionNonce=randomBytes(16).toString('hex');
const requestPath=process.env.USDOM_ONEKEY_BLE_REQUEST;
if(typeof requestPath!=='string'||!requestPath.startsWith('/dev/shm/')) throw new Error('private request path missing');
const request=readBleHandoffRequest(requestPath);
let window,cleanup,adapter,closed=false;
await app.whenReady();
const ceremonySession=session.fromPartition(`usdom-onekey-${sessionNonce}`,{cache:false});
const options={show:true,webPreferences:{preload:resolve(import.meta.dirname,'preload.mjs'),
 nodeIntegration:false,contextIsolation:true,sandbox:true,webSecurity:true,allowRunningInsecureContent:false,
 devTools:false,partition:`usdom-onekey-${sessionNonce}`}};
assertElectronWindowOptions(options);
window=new BrowserWindow(options);
window.webContents.setWindowOpenHandler(()=>({action:'deny'}));
window.webContents.on('will-navigate',event=>event.preventDefault());
window.webContents.on('devtools-opened',()=>window.webContents.closeDevTools());
ceremonySession.webRequest.onBeforeRequest((_details,callback)=>callback({cancel:true}));
ipcMain.on('usdom:onekey-ble:bootstrap:v1',event=>{
 if(event.sender.id!==window.webContents.id) {event.returnValue=null;return;}
 event.returnValue={sessionNonce,request};
});
adapter=await openNativeBleAdapter();
cleanup=registerNobleBleMainHandler({ipcMain,webContents:window.webContents,sessionNonce,adapter});
const close=async()=>{if(closed)return;closed=true;cleanup?.();await adapter?.close?.();};
ipcMain.handle('usdom:onekey-ble:cancel:v1',async event=>{if(event.sender.id!==window.webContents.id)throw new Error('sender rejected');await adapter.cancelPairing();});
ipcMain.handle('usdom:onekey-ble:complete:v1',async(event,completion)=>{
 if(event.sender.id!==window.webContents.id||completion?.action!==request.action
   ||completion?.status!=='success'||Object.keys(completion).sort().join(',')!=='action,result,status') throw new Error('completion rejected');
 writeBleHandoffResponse({directory:dirname(requestPath),request,result:completion.result});
 await close();app.quit();
});
ipcMain.handle('usdom:onekey-ble:failure:v1',async(event,failure)=>{
 if(event.sender.id!==window.webContents.id||failure?.action!==request.action
   ||!['cancelled','failed'].includes(failure?.status)
   ||Object.keys(failure).sort().join(',')!=='action,status') throw new Error('failure rejected');
 await close();app.exit(failure.status==='cancelled'?80:1);
});
app.on('before-quit',event=>{if(!closed){event.preventDefault();void close().finally(()=>app.quit());}});
const renderer=resolve(import.meta.dirname,'index.html');assertLocalRendererUrl(new URL(`file://${renderer}`).href);
await window.loadFile(renderer);
