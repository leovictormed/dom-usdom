import {isDeepStrictEqual} from 'node:util';
import {readDirectFile} from './direct-project-file.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

export const oneKeyElectronBlePolicyMaximumBytes=32*1024;

export const expectedOneKeyElectronBlePolicy={
 schema:'usdom-onekey-electron-ble-handoff-policy-v1',status:'unconfigured',
 browserWindow:{contextIsolation:true,nodeIntegration:false,sandbox:true,
  sandboxCompatibilityEvidenceRequired:true,productionDevTools:false,navigation:false,popups:false},
 contentSecurityPolicy:"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
 preloadAllowlist:['cancelOneKeyRequest','requestOneKeyAddress',
  'requestOneKeyEip1559Signature','requestOneKeyEip712Signature'],
 ipc:{requestFields:['schema','operation','nonce','payloadSha256','payload'],
  responseFields:['schema','operation','nonce','requestSha256','resultSha256','status','result'],
  exactSchemas:true,nonceRequired:true,payloadHashRequired:true,requestHashRequired:true,
  resultHashRequired:true},
 durableOutput:{mode:'0600',createOnce:true,overwrite:false},
 forbiddenCapabilities:['broadcast','logs','passphrase','pin','rpc','seed'],
 transport:{allowed:['desktop-web-ble'],forbiddenFallbacks:['emulator','http','usb','web']},
 hardwareSigningApproved:false,
};

export function checkOneKeyElectronBlePolicy(policy) {
 const comparable=policy===undefined?undefined:JSON.parse(JSON.stringify(policy));
 if(!isDeepStrictEqual(comparable,expectedOneKeyElectronBlePolicy)) {
  throw new Error('OneKey Electron BLE handoff policy differs from the fail-closed authority');
 }
 return {ok:true,status:policy.status,hardwareSigningApproved:false};
}

export async function readOneKeyElectronBlePolicy(path) {
 const bytes=await readDirectFile(path,{minimum:2,maximum:oneKeyElectronBlePolicyMaximumBytes,
  exactMode:0o600,label:'OneKey Electron BLE handoff policy'});
 return parseStrictJsonBytes(bytes,{label:'OneKey Electron BLE handoff policy',
  maxBytes:oneKeyElectronBlePolicyMaximumBytes,maxDepth:16});
}
