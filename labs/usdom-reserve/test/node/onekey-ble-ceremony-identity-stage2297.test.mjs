import test from 'node:test';
import assert from 'node:assert/strict';
import {Wallet} from 'ethers';
import {validateOneKeyBleCeremonyIdentity} from '../../sdk/onekey-ble-ceremony-identity.mjs';

const deviceId='classic1s-stable-01',firmware='4.11.0';
const address=new Wallet(`0x${'31'.repeat(32)}`).address;
const status={mode:'normal',initialized:true,unlocked:true,firmwarePresent:true,
 backupRequired:false,noBackup:false,unfinishedBackup:false,recoveryMode:false,
 passphraseProtection:false,pinProtection:true,attachToPinEnabled:false,unlockedAttachPin:false};
const settings={language:'en',bleEnabled:true,sdCardPresent:false,sdProtection:false,
 wipeCodeProtection:false,passphraseAlwaysOnDevice:false,safetyChecks:'Strict',autoLockDelayMs:60000,
 autoShutdownDelayMs:600000,displayRotation:0,experimentalFeatures:false,wallpaperPath:null,
 brightness:100,animationEnabled:true,tapToWake:true,hapticFeedback:true,
 deviceNameDisplayEnabled:true,airgapMode:false,fidoEnabled:false,usbLockEnabled:true,randomKeypad:true};
// Shape copied from @onekeyfe/hd-core 1.2.7 DeviceState/DeviceStateIdentity;
// `model` is deliberately null because deviceType, not a guessed model value, is authoritative.
const identity=id=>({deviceType:'classic1s',firmwareType:'universal',model:null,vendor:'OneKey',
 deviceId:id,serialNo:'serial-redacted',label:null,bleName:'OneKey'});
const state=(id=deviceId,version=firmware)=>({success:true,payload:{schemaVersion:1,revision:1,
 updatedAt:1,protocol:'V1',protocolVersion:1,identity:identity(id),status:{...status},
 settings:{...settings},versions:{firmware:version,bootloader:'1.0.0',board:null,ble:'1.0.0'},
 securityElements:{se01:{type:'certified',state:'ready'}},capabilities:[],
 verification:{firmwareBuildId:'official-build',firmwareHash:'aa'.repeat(32)}}});
const input=()=>({before:{transport:'desktop-web-ble',connectId:'session-old',state:state()},
 after:{transport:'desktop-web-ble',connectId:'session-new',state:state()},expectedDeviceId:deviceId,
 firmwareAllowlist:[firmware],expectedAddress:address,addressConfirmation:{connectId:'session-new',
 deviceId,address,showOnOneKey:true}});
const reject=mutate=>{const value=structuredClone(input());mutate(value);
 assert.throws(()=>validateOneKeyBleCeremonyIdentity(value));};

test('official V1 state binds stable identity, ephemeral reconnect and displayed address',()=>{
 assert.deepEqual(validateOneKeyBleCeremonyIdentity(input()),{deviceId,firmware,
  connectId:'session-new',address,transport:'desktop-web-ble'});
});

test('invented fields, model/protocol downgrade and firmware drift fail closed',()=>{
 for(const mutation of [
  v=>{v.after.state.payload.invented=true;},v=>{v.after.state.payload.identity.bluetoothId='fake';},
  v=>{v.after.state.payload.identity.deviceType='classic';},v=>{v.after.state.payload.protocol='V2';},
  v=>{v.after.state.payload.protocolVersion=0;},v=>{v.after.state.payload.versions.firmware='4.10.0';},
  v=>{v.firmwareAllowlist=[];},v=>{v.firmwareAllowlist=['4.11'];},
 ]) reject(mutation);
});

test('official optional state sections accept only documented 1.2.7 keys',()=>{
 assert.doesNotThrow(()=>validateOneKeyBleCeremonyIdentity(input()));
 for(const mutation of [
  v=>{v.after.state.payload.securityElements.se05={type:'fake',state:'ready'};},
  v=>{v.after.state.payload.securityElements.se01.serial='invented';},
  v=>{v.after.state.payload.verification.deviceCertificate='invented';},
 ]) reject(mutation);
});

test('device replacement, stale session and transport fallbacks fail closed',()=>{
 for(const mutation of [
  v=>{v.after.state=state('foreign-device');},v=>{v.after.connectId=v.before.connectId;},
  v=>{v.after.transport='node-usb';},v=>{v.before.transport='http';},
  v=>{v.after.fallback='usb';},
 ]) reject(mutation);
});

test('address must be confirmed on the reconnected device display',()=>{
 for(const mutation of [
  v=>{v.addressConfirmation.showOnOneKey=false;},v=>{v.addressConfirmation.connectId='session-old';},
  v=>{v.addressConfirmation.deviceId='foreign-device';},v=>{v.addressConfirmation.address=new Wallet(`0x${'32'.repeat(32)}`).address;},
  v=>{v.addressConfirmation.popupApproved=true;},
 ]) reject(mutation);
});
