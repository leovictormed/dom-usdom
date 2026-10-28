import {contextBridge,ipcRenderer} from 'electron';
import {createNobleBlePreloadBridge} from '../../sdk/onekey-electron-ble-handoff.mjs';

const bootstrap=ipcRenderer.sendSync('usdom:onekey-ble:bootstrap:v1');
if(!bootstrap||typeof bootstrap.sessionNonce!=='string') throw new Error('BLE preload bootstrap rejected');
const nobleBle=createNobleBlePreloadBridge({ipcRenderer,sessionNonce:bootstrap.sessionNonce});
contextBridge.exposeInMainWorld('desktopApi',Object.freeze({nobleBle}));
contextBridge.exposeInMainWorld('usdomOneKeyCeremony',Object.freeze({
 request:bootstrap.request,
 complete:result=>ipcRenderer.invoke('usdom:onekey-ble:complete:v1',result),
 fail:result=>ipcRenderer.invoke('usdom:onekey-ble:failure:v1',result),
 cancel:()=>ipcRenderer.invoke('usdom:onekey-ble:cancel:v1'),
}));
