import {getAddress} from 'ethers';

const identifiers=/^[A-Za-z0-9._:-]{1,128}$/u;
const firmware=/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const exact=(value,allowed,required=allowed)=>value&&typeof value==='object'&&!Array.isArray(value)
 &&Object.keys(value).every(key=>allowed.includes(key))&&required.every(key=>Object.hasOwn(value,key));
const TOP=['schemaVersion','revision','updatedAt','protocol','protocolVersion','identity','status',
 'settings','versions','securityElements','capabilities','verification'];
const TOP_REQUIRED=['schemaVersion','revision','updatedAt','protocol','protocolVersion','identity',
 'status','settings','versions','capabilities'];
const IDENTITY=['deviceType','firmwareType','model','vendor','deviceId','serialNo','label','bleName'];
const STATUS=['mode','initialized','unlocked','firmwarePresent','backupRequired','noBackup',
 'unfinishedBackup','recoveryMode','passphraseProtection','pinProtection','attachToPinEnabled',
 'unlockedAttachPin'];
const SETTINGS=['language','bleEnabled','sdCardPresent','sdProtection','wipeCodeProtection',
 'passphraseAlwaysOnDevice','safetyChecks','autoLockDelayMs','autoShutdownDelayMs',
 'displayRotation','experimentalFeatures','wallpaperPath','brightness','animationEnabled',
 'tapToWake','hapticFeedback','deviceNameDisplayEnabled','airgapMode','fidoEnabled',
 'usbLockEnabled','randomKeypad'];
const VERSIONS=['firmware','applicationP1','applicationP2','bootloader','board','ble','se','se01',
 'se02','se03','se04','se01Boot','se02Boot','se03Boot','se04Boot'];
const VERSION_REQUIRED=['firmware','bootloader','board','ble'];
const SECURITY_ELEMENTS=['se01','se02','se03','se04'];
const VERIFICATION=['firmwareBuildId','firmwareHash','applicationP1BuildId','applicationP1Hash',
 'applicationP2BuildId','applicationP2Hash','bootloaderBuildId','bootloaderHash','boardBuildId',
 'boardHash','bleBuildId','bleHash','se01BuildId','se01Hash','se02BuildId','se02Hash',
 'se03BuildId','se03Hash','se04BuildId','se04Hash','se01BootBuildId','se01BootHash',
 'se02BootBuildId','se02BootHash','se03BootBuildId','se03BootHash','se04BootBuildId','se04BootHash'];
const fail=message=>{throw new Error(message);};

function statePayload(response,label) {
 if(!exact(response,['success','payload'])||response.success!==true
    ||!exact(response.payload,TOP,TOP_REQUIRED)||response.payload.schemaVersion!==1
    ||response.payload.protocol!=='V1'||response.payload.protocolVersion!==1
    ||!Number.isSafeInteger(response.payload.revision)||response.payload.revision<0
    ||!Number.isSafeInteger(response.payload.updatedAt)||response.payload.updatedAt<0
    ||!exact(response.payload.identity,IDENTITY)||!exact(response.payload.status,STATUS)
    ||!exact(response.payload.settings,SETTINGS)||!exact(response.payload.versions,VERSIONS,VERSION_REQUIRED)
    ||!Array.isArray(response.payload.capabilities)) fail(`${label} is not an exact official getDeviceState V1 response`);
 if(response.payload.securityElements!==undefined
    &&(!exact(response.payload.securityElements,SECURITY_ELEMENTS,[])
      ||Object.values(response.payload.securityElements).some(value=>!exact(value,['type','state'])))) {
  fail(`${label} security elements differ from the official schema`);
 }
 if(response.payload.verification!==undefined
    &&!exact(response.payload.verification,VERIFICATION,[])) {
  fail(`${label} verification differs from the official schema`);
 }
 const identity=response.payload.identity,version=response.payload.versions.firmware;
 if(identity.deviceType!=='classic1s'
    ||typeof identity.deviceId!=='string'||!identifiers.test(identity.deviceId)
    ||typeof version!=='string'||!firmware.test(version)) fail(`${label} device identity is invalid`);
 return {deviceId:identity.deviceId,firmware:version};
}

export function validateOneKeyBleCeremonyIdentity({before,after,expectedDeviceId,
 firmwareAllowlist,addressConfirmation,expectedAddress}={}) {
 if(!Array.isArray(firmwareAllowlist)||firmwareAllowlist.length===0
    ||new Set(firmwareAllowlist).size!==firmwareAllowlist.length
    ||firmwareAllowlist.some(value=>typeof value!=='string'||!firmware.test(value))) {
  fail('OneKey firmware allowlist is invalid or empty');
 }
 if(typeof expectedDeviceId!=='string'||!identifiers.test(expectedDeviceId)
    ||!exact(before,['transport','connectId','state'])
    ||!exact(after,['transport','connectId','state'])
    ||before.transport!=='desktop-web-ble'||after.transport!=='desktop-web-ble'
    ||typeof before.connectId!=='string'||!identifiers.test(before.connectId)
    ||typeof after.connectId!=='string'||!identifiers.test(after.connectId)
    ||before.connectId===after.connectId) fail('OneKey BLE reconnection envelope is invalid');
 const initial=statePayload(before.state,'initial OneKey state');
 const reconnected=statePayload(after.state,'reconnected OneKey state');
 if(initial.deviceId!==expectedDeviceId||reconnected.deviceId!==expectedDeviceId
    ||initial.firmware!==reconnected.firmware||!firmwareAllowlist.includes(reconnected.firmware)) {
  fail('OneKey persistent identity or firmware binding mismatch');
 }
 let address;
 try {address=getAddress(expectedAddress);} catch {fail('expected OneKey address is invalid');}
 if(address!==expectedAddress||!exact(addressConfirmation,
  ['connectId','deviceId','address','showOnOneKey'])
  ||addressConfirmation.connectId!==after.connectId
  ||addressConfirmation.deviceId!==expectedDeviceId
  ||addressConfirmation.showOnOneKey!==true
  ||addressConfirmation.address!==address) fail('OneKey on-device address confirmation is invalid');
 return Object.freeze({deviceId:expectedDeviceId,firmware:reconnected.firmware,
  connectId:after.connectId,address,transport:'desktop-web-ble'});
}
