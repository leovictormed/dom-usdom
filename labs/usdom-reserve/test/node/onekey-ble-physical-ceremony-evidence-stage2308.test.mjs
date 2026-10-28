import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,chmod,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {buildOneKeyBlePhysicalCeremonyEvidence,materializeOneKeyBlePhysicalCeremonyEvidence,
 validateOneKeyBlePhysicalCeremonyAuthority,validateOneKeyBlePhysicalObservation} from '../../sdk/onekey-ble-physical-ceremony-evidence.mjs';

const H=n=>n.repeat(64);
const authority={schema:'usdom-onekey-ble-physical-ceremony-authority-v1',status:'ratified-for-observation',observationCollectionApproved:true,hardwareSigningApproved:false,
 expectedDeviceId:'classic1s-device-A',expectedAddress:'0x1111111111111111111111111111111111111111',firmwareAllowlist:['4.13.0'],
 appAuthoritySha256:H('a'),packageAuthoritySha256:H('b'),appArtifactSha256:H('c'),packageArtifactSha256:H('d')};
const observation={schema:'usdom-onekey-ble-physical-observation-v1',source:{kind:'pinned-electron-app',mock:false,emulator:false},transport:'desktop-web-ble',
 appAuthoritySha256:H('a'),packageAuthoritySha256:H('b'),appArtifactSha256:H('c'),packageArtifactSha256:H('d'),
 discovery:{deviceCount:1,singleDeviceSelected:true},pairing:{permissionGranted:true,pairedOnHost:true},
 initial:{connectId:'ble-session-1',deviceId:'classic1s-device-A',firmware:'4.13.0'},reconnected:{connectId:'ble-session-2',deviceId:'classic1s-device-A',firmware:'4.13.0'},
 addressConfirmation:{connectId:'ble-session-2',deviceId:'classic1s-device-A',address:'0x1111111111111111111111111111111111111111',showOnDevice:true},
 failureExercises:{rejectionObserved:true,timeoutObserved:true,cancelObserved:true,disconnectObserved:true,reconnectObserved:true,lateCompletionRejected:true}};
const clone=v=>structuredClone(v);

test('valid physical observation remains evidence awaiting operator ratification',()=>{
 const evidence=buildOneKeyBlePhysicalCeremonyEvidence(authority,observation);
 assert.equal(evidence.status,'observed-awaiting-operator-ratification'); assert.equal(evidence.hardwareSigningApproved,false);
});

test('synthetic source, drift, stale reconnect, incomplete failures and secret fields fail closed',()=>{
 for(const mutate of [
  v=>{v.source.mock=true;},v=>{v.packageArtifactSha256=H('e');},v=>{v.reconnected.connectId=v.initial.connectId;},
  v=>{v.reconnected.deviceId='other';},v=>{v.reconnected.firmware='4.14.0';},v=>{v.addressConfirmation.showOnDevice=false;},
  v=>{v.failureExercises.timeoutObserved=false;},v=>{v.pin='1234';},v=>{v.extra=true;}
 ]) {const candidate=clone(observation);mutate(candidate);assert.throws(()=>validateOneKeyBlePhysicalObservation(authority,candidate));}
});

test('unconfigured authority cannot authorize evidence',async()=>{
 const value=JSON.parse(await readFile(new URL('../../config/onekey-ble-physical-ceremony-authority.unconfigured.json',import.meta.url),'utf8'));
 assert.doesNotThrow(()=>validateOneKeyBlePhysicalCeremonyAuthority(value));
 assert.throws(()=>validateOneKeyBlePhysicalCeremonyAuthority(value,{requireRatified:true}));
});

test('materializer reads private strict inputs and installs create-once output',async()=>{
 const base=await mkdtemp(join(tmpdir(),'usdom-onekey-physical-')); const directory=join(base,'private');
 try {await mkdir(directory,{mode:0o700});await chmod(directory,0o700);
  const a=join(directory,'authority.json'),o=join(directory,'observation.json'),out=join(directory,'evidence.json');
  await writeFile(a,JSON.stringify(authority),{mode:0o600});await writeFile(o,JSON.stringify(observation),{mode:0o600});await chmod(a,0o600);await chmod(o,0o600);
  await materializeOneKeyBlePhysicalCeremonyEvidence({authorityPath:a,observationPath:o,outputPath:out});
  assert.equal(JSON.parse(await readFile(out,'utf8')).hardwareSigningApproved,false);
  await assert.rejects(materializeOneKeyBlePhysicalCeremonyEvidence({authorityPath:a,observationPath:o,outputPath:out}),/already exists/u);
 } finally {await rm(base,{recursive:true,force:true});}
});
