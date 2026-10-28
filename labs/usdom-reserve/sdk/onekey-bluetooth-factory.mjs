import {createHash,randomBytes} from 'node:crypto';
import {lstatSync,readFileSync,rmSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {resolve} from 'node:path';
import {createBleHandoffRequest,readBleHandoffResponse} from './onekey-electron-ble-handoff.mjs';
import {parseStrictJson} from './strict-json.mjs';

const root=resolve(import.meta.dirname,'..');
const authorityPath=resolve(root,'config/onekey-electron-ble-app-authority.json');
const devicePattern=/^[A-Za-z0-9._:-]{1,128}$/u;
const firmwarePattern=/^\d+\.\d+\.\d+$/u;

function safeCleanup(directory,identity) {
 const current=lstatSync(directory,{throwIfNoEntry:false});if(!current)return;
 if(!current.isDirectory()||current.isSymbolicLink()||current.uid!==process.getuid()
   ||current.dev!==identity.dev||current.ino!==identity.ino||(current.mode&0o777)!==0o700) {
  throw new Error('BLE handoff cleanup authority mismatch');
 }
 rmSync(directory,{recursive:true,force:false});
}

function spawnCeremony({executable,main,requestPath,timeoutMilliseconds,onChild}) {
 return new Promise((resolvePromise,reject)=>{
  const child=spawn(executable,[main],{stdio:['ignore','ignore','ignore'],env:{
   PATH:'/usr/bin:/bin',HOME:process.env.HOME??'/nonexistent',LANG:'C.UTF-8',
   USDOM_ONEKEY_BLE_REQUEST:requestPath,
  }});onChild(child);let timedOut=false;
  const timer=setTimeout(()=>{timedOut=true;child.kill('SIGTERM');setTimeout(()=>child.kill('SIGKILL'),5000).unref();},timeoutMilliseconds);
  child.once('error',error=>{clearTimeout(timer);reject(error);});
  child.once('exit',(code,signal)=>{clearTimeout(timer);onChild(undefined);
   if(timedOut)return reject(new Error('OneKey Electron ceremony timed out and was terminated'));
   if(code!==0)return reject(new Error(`OneKey Electron ceremony failed (${code??signal})`));resolvePromise();});
 });
}

export async function openApprovedOneKeyBluetooth({expectedDeviceId,approvedFirmwareVersions,
 runtime}={}) {
 if(!devicePattern.test(expectedDeviceId??'')) throw new Error('OneKey expected device identity is invalid');
 const authority=parseStrictJson(readFileSync(authorityPath,'utf8'),{label:'OneKey Electron BLE app authority'});
 let selectedRuntime=runtime;
 if(!selectedRuntime) {
  if(authority.hardwareSigningApproved!==true||authority.gates?.nativeBleAdapterApproved!==true
    ||authority.gates?.electronRuntimeApproved!==true||authority.gates?.rendererBundleApproved!==true
    ||authority.gates?.physicalCeremonyApproved!==true) throw new Error('OneKey authenticated Electron Bluetooth handoff is not approved');
  const launcher=authority.runtimeLauncher;
  if(!launcher||typeof launcher.electronExecutable!=='string'||typeof launcher.electronExecutableSha256!=='string'
    ||launcher.mainPath!=='electron/onekey-ble/main.mjs'||typeof launcher.mainSha256!=='string') {
   throw new Error('OneKey pinned Electron runtime is not configured');
  }
  const executable=resolve(launcher.electronExecutable),main=resolve(root,launcher.mainPath);
  for(const [path,expected,executableFile] of [[executable,launcher.electronExecutableSha256,true],[main,launcher.mainSha256,false]]) {
   const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||(stat.mode&0o022)!==0
     ||(executableFile&&(stat.mode&0o111)===0)||createHash('sha256').update(readFileSync(path)).digest('hex')!==expected) {
    throw new Error('OneKey pinned Electron runtime authority mismatch');
   }
  }
  selectedRuntime=createPinnedElectronRuntime({executable,main});
 }
 const firmware=approvedFirmwareVersions??authority.approvedFirmwareVersions;
 if(!Array.isArray(firmware)||firmware.length===0||!firmware.every(value=>firmwarePattern.test(value))) {
  throw new Error('OneKey firmware allowlist is not approved');
 }
 if(typeof selectedRuntime.launch!=='function'||!Number.isSafeInteger(selectedRuntime.timeoutMilliseconds)
   ||selectedRuntime.timeoutMilliseconds<1||selectedRuntime.timeoutMilliseconds>300_000) throw new Error('invalid OneKey Electron runtime');
 let activeChild,closed=false,busy=false;
 const connectId=randomBytes(16).toString('hex');
 const invoke=async(action,sdkRequest)=>{
  if(closed)throw new Error('OneKey Bluetooth session is closed');if(busy)throw new Error('OneKey Bluetooth session is busy');busy=true;
  const directory=`/dev/shm/usdom-onekey-${randomBytes(16).toString('hex')}`;
  const handoff=createBleHandoffRequest({directory,action,payload:{ceremonyPolicy:{expectedDeviceId,
   approvedFirmwareVersions:firmware},sdkRequest}});
  const identity=lstatSync(directory);
  try {
   await selectedRuntime.launch({requestPath:handoff.path,onChild:value=>{activeChild=value;},timeoutMilliseconds:selectedRuntime.timeoutMilliseconds});
   const response=readBleHandoffResponse(handoff);return {success:true,payload:response.result};
  } finally {busy=false;activeChild=undefined;safeCleanup(directory,identity);}
 };
 const device=Object.freeze({evmGetAddress:(_connectId,deviceId,payload)=>{
  if(deviceId!==expectedDeviceId)throw new Error('OneKey live device identity mismatch');return invoke('evmGetAddress',payload);},
 evmSignTransaction:(_connectId,deviceId,payload)=>{if(deviceId!==expectedDeviceId)throw new Error('OneKey live device identity mismatch');
  return invoke('evmSignTransaction',payload);},
 evmSignTypedData:(_connectId,deviceId,payload)=>{if(deviceId!==expectedDeviceId)throw new Error('OneKey live device identity mismatch');
  return invoke('evmSignTypedData',payload);}});
 return Object.freeze({device,connectId,deviceId:expectedDeviceId,cancel(){activeChild?.kill?.('SIGTERM');},
  async close(){if(closed)return;closed=true;activeChild?.kill?.('SIGTERM');}});
}

export function createPinnedElectronRuntime({executable,main,timeoutMilliseconds=300_000}={}) {
 if(typeof executable!=='string'||typeof main!=='string')throw new Error('pinned Electron paths required');
 return Object.freeze({timeoutMilliseconds,launch:options=>spawnCeremony({executable,main,
  requestPath:options.requestPath,timeoutMilliseconds,onChild:options.onChild})});
}
