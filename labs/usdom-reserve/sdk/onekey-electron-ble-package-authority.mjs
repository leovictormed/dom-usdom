import {TextDecoder} from 'node:util';
import {readDirectFile} from './direct-project-file.mjs';
import {parseStrictJson} from './strict-json.mjs';

const TOP=['schema','status','hardwareSigningApproved','runtimeTransport','packagePins','gates','forbiddenFallbacks'];
const PINS=['platform','architecture','electronVersion','electronArtifactSha256','applicationArchiveSha256',
 'unpackedInventorySha256','nativeBleHostPackage','nativeBleHostVersion','nativeBleHostIntegrity','lockfileSha256',
 'buildTool','buildToolVersion','buildCommandSha256','sourceCommit','provenanceSha256','codeSigningIdentity'];
const GATES=['packagedArtifactVerified','electronRuntimeArtifactPinned','applicationArchiveVerified',
 'unpackedNativeInventoryVerified','nativeBleHostPinned','reproducibleBuildVerified','provenanceVerified',
 'codeSigningVerified','blePairingAndPermissionsVerified','deviceIdentityAndReconnectVerified',
 'firmwareAllowlistVerified','addressOnDeviceVerified','eip1559PhysicalSigningVerified',
 'eip712PhysicalSigningVerified','rejectionCancellationDisconnectReconnectVerified','physicalCeremonyApproved'];
const FALLBACKS=['usb','http','web','emulator'];

function exactKeys(value,expected,label) {
 if(value===null||typeof value!=='object'||Array.isArray(value)
   ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...expected].sort())) {
  throw new Error(`${label} has an unexpected schema`);
 }
}

export function validateUnconfiguredOneKeyElectronBlePackageAuthority(authority) {
 exactKeys(authority,TOP,'package authority');
 if(authority.schema!=='usdom-onekey-electron-ble-package-authority-v1'||authority.status!=='unconfigured'
   ||authority.hardwareSigningApproved!==false||authority.runtimeTransport!=='desktop-web-ble') {
  throw new Error('package authority is not fail-closed');
 }
 exactKeys(authority.packagePins,PINS,'package pins');
 for(const key of PINS) if(authority.packagePins[key]!==null) {
  throw new Error(`unconfigured package pin must remain null: ${key}`);
 }
 exactKeys(authority.gates,GATES,'package gates');
 for(const key of GATES) if(authority.gates[key]!==false) {
  throw new Error(`unverified package gate must remain false: ${key}`);
 }
 if(JSON.stringify(authority.forbiddenFallbacks)!==JSON.stringify(FALLBACKS)) {
  throw new Error('package authority must prohibit every non-BLE fallback');
 }
 return authority;
}

export async function loadUnconfiguredOneKeyElectronBlePackageAuthority(file) {
 const bytes=await readDirectFile(file,{minimum:2,maximum:32768,exactMode:0o644,label:'OneKey Electron BLE package authority'});
 let text;
 try { text=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
 catch { throw new Error('OneKey Electron BLE package authority is not valid UTF-8'); }
 return validateUnconfiguredOneKeyElectronBlePackageAuthority(parseStrictJson(text,
  {label:'OneKey Electron BLE package authority'}));
}

export const ONEKEY_ELECTRON_BLE_PACKAGE_GATES=Object.freeze([...GATES]);
