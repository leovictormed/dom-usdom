import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {buildOneKeyBlePhysicalCeremonyEvidence} from '../../sdk/onekey-ble-physical-ceremony-evidence.mjs';
import {ratifyOneKeyBlePhysicalCeremony,validateOneKeyBlePhysicalReadinessRatification} from '../../sdk/onekey-ble-physical-ceremony-ratification.mjs';
const H=n=>n.repeat(64),hash=b=>createHash('sha256').update(b).digest('hex');
const authority={schema:'usdom-onekey-ble-physical-ceremony-authority-v1',status:'ratified-for-observation',observationCollectionApproved:true,hardwareSigningApproved:false,expectedDeviceId:'classic1s-device-A',expectedAddress:'0x1111111111111111111111111111111111111111',firmwareAllowlist:['4.13.0'],appAuthoritySha256:H('a'),packageAuthoritySha256:H('b'),appArtifactSha256:H('c'),packageArtifactSha256:H('d')};
const observation={schema:'usdom-onekey-ble-physical-observation-v1',source:{kind:'pinned-electron-app',mock:false,emulator:false},transport:'desktop-web-ble',appAuthoritySha256:H('a'),packageAuthoritySha256:H('b'),appArtifactSha256:H('c'),packageArtifactSha256:H('d'),discovery:{deviceCount:1,singleDeviceSelected:true},pairing:{permissionGranted:true,pairedOnHost:true},initial:{connectId:'ble-session-1',deviceId:'classic1s-device-A',firmware:'4.13.0'},reconnected:{connectId:'ble-session-2',deviceId:'classic1s-device-A',firmware:'4.13.0'},addressConfirmation:{connectId:'ble-session-2',deviceId:'classic1s-device-A',address:'0x1111111111111111111111111111111111111111',showOnDevice:true},failureExercises:{rejectionObserved:true,timeoutObserved:true,cancelObserved:true,disconnectObserved:true,reconnectObserved:true,lateCompletionRejected:true}};
const observationBytes=Buffer.from(JSON.stringify(observation));
const evidenceBytes=Buffer.from(JSON.stringify(buildOneKeyBlePhysicalCeremonyEvidence(authority,observation)));
const ratification={schema:'usdom-onekey-ble-physical-ceremony-ratification-v1',decision:'approve-observed-hardware-gates',singleOperator:true,residualRiskAccepted:true,mockEvidenceAccepted:false,observationBytesSha256:hash(observationBytes),evidenceBytesSha256:hash(evidenceBytes),physicalTestTranscriptSha256:H('e'),appArtifactSha256:H('c'),packageArtifactSha256:H('d'),deviceId:'classic1s-device-A',firmware:'4.13.0',address:'0x1111111111111111111111111111111111111111'};

test('single operator may ratify only gates actually observed while signing remains closed',()=>{
 const result=ratifyOneKeyBlePhysicalCeremony({collectionAuthority:authority,observationBytes,evidenceBytes,ratification});
 assert.equal(result.singleOperator,true);assert.match(result.residualRisk,/no independent auditor/u);
 assert.equal(result.hardwareObservationRatified,true);assert.equal(result.hardwareSigningApproved,false);
 assert.equal(result.readinessGates.production_onekey_eip1559_and_eip712_signing_verified,false);
 assert.equal(result.readinessGates.production_onekey_address_verified_on_device,true);
 assert.doesNotThrow(()=>validateOneKeyBlePhysicalReadinessRatification(result));
});

test('bytes, transcript, pins, identity and residual-risk decision are all mandatory',()=>{
 for(const mutate of [v=>{v.singleOperator=false;},v=>{v.residualRiskAccepted=false;},v=>{v.mockEvidenceAccepted=true;},v=>{v.observationBytesSha256=H('f');},v=>{v.evidenceBytesSha256=H('f');},v=>{v.physicalTestTranscriptSha256='';},v=>{v.appArtifactSha256=H('f');},v=>{v.deviceId='other';},v=>{v.firmware='4.14.0';},v=>{v.extra=true;}]) {const candidate=structuredClone(ratification);mutate(candidate);assert.throws(()=>ratifyOneKeyBlePhysicalCeremony({collectionAuthority:authority,observationBytes,evidenceBytes,ratification:candidate}));}
});

test('mutating exact observation or evidence bytes invalidates ratification',()=>{
 assert.throws(()=>ratifyOneKeyBlePhysicalCeremony({collectionAuthority:authority,observationBytes:Buffer.concat([observationBytes,Buffer.from(' ')]),evidenceBytes,ratification}));
 assert.throws(()=>ratifyOneKeyBlePhysicalCeremony({collectionAuthority:authority,observationBytes,evidenceBytes:Buffer.concat([evidenceBytes,Buffer.from(' ')]),ratification}));
});
