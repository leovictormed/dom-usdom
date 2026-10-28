import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {readDirectFile} from './direct-project-file.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';
import {buildOneKeyBlePhysicalCeremonyEvidence,validateOneKeyBlePhysicalObservation} from './onekey-ble-physical-ceremony-evidence.mjs';

const sha=/^[0-9a-f]{64}$/u;
const RAT=['schema','decision','singleOperator','residualRiskAccepted','mockEvidenceAccepted','observationBytesSha256','evidenceBytesSha256','physicalTestTranscriptSha256','appArtifactSha256','packageArtifactSha256','deviceId','firmware','address'];
const EVID=['schema','status','hardwareSigningApproved','authoritySha256','observationSha256','deviceId','firmware','address','appArtifactSha256','packageArtifactSha256','discoveryPairingVerified','reconnectVerified','addressOnDeviceVerified','failureExercisesVerified'];
const RESULT=['schema','status','singleOperator','residualRisk','hardwareObservationRatified','hardwareSigningApproved','observationBytesSha256','evidenceBytesSha256','physicalTestTranscriptSha256','appArtifactSha256','packageArtifactSha256','deviceId','firmware','address','readinessGates'];
const GATE_KEYS=['production_onekey_ble_pairing_and_permissions_verified','production_onekey_ble_device_identity_and_reconnection_verified','production_onekey_address_verified_on_device','production_onekey_reject_cancel_disconnect_reconnect_verified','production_onekey_eip1559_and_eip712_signing_verified'];
const exact=(v,keys,label)=>{if(v===null||typeof v!=='object'||Array.isArray(v)||JSON.stringify(Object.keys(v).sort())!==JSON.stringify([...keys].sort()))throw new Error(`${label} schema is invalid`);};
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

export function ratifyOneKeyBlePhysicalCeremony({collectionAuthority,observationBytes,evidenceBytes,ratification}) {
 const observation=parseStrictJsonBytes(observationBytes,{label:'physical observation',maxBytes:131072,maxDepth:16});
 const evidence=parseStrictJsonBytes(evidenceBytes,{label:'physical evidence',maxBytes:32768,maxDepth:8});
 validateOneKeyBlePhysicalObservation(collectionAuthority,observation); exact(evidence,EVID,'physical evidence'); exact(ratification,RAT,'operator ratification');
 const rebuilt=buildOneKeyBlePhysicalCeremonyEvidence(collectionAuthority,observation);
 if(JSON.stringify(evidence)!==JSON.stringify(rebuilt)) throw new Error('physical evidence differs from the bound observation');
 if(ratification.schema!=='usdom-onekey-ble-physical-ceremony-ratification-v1'
   ||ratification.decision!=='approve-observed-hardware-gates'||ratification.singleOperator!==true
   ||ratification.residualRiskAccepted!==true||ratification.mockEvidenceAccepted!==false
   ||ratification.observationBytesSha256!==digest(observationBytes)||ratification.evidenceBytesSha256!==digest(evidenceBytes)
   ||!sha.test(ratification.physicalTestTranscriptSha256??'')
   ||ratification.appArtifactSha256!==collectionAuthority.appArtifactSha256
   ||ratification.packageArtifactSha256!==collectionAuthority.packageArtifactSha256
   ||ratification.deviceId!==evidence.deviceId||ratification.firmware!==evidence.firmware
   ||ratification.address!==evidence.address) throw new Error('single-operator physical ratification is invalid or unbound');
 return {schema:'usdom-onekey-ble-physical-readiness-ratification-v1',status:'single-operator-ratified',singleOperator:true,
  residualRisk:'one operator collected and ratified the physical evidence; no independent auditor is asserted',hardwareObservationRatified:true,hardwareSigningApproved:false,
  observationBytesSha256:ratification.observationBytesSha256,evidenceBytesSha256:ratification.evidenceBytesSha256,
  physicalTestTranscriptSha256:ratification.physicalTestTranscriptSha256,appArtifactSha256:evidence.appArtifactSha256,
  packageArtifactSha256:evidence.packageArtifactSha256,deviceId:evidence.deviceId,firmware:evidence.firmware,address:evidence.address,
  readinessGates:{production_onekey_ble_pairing_and_permissions_verified:true,
   production_onekey_ble_device_identity_and_reconnection_verified:true,
   production_onekey_address_verified_on_device:true,
   production_onekey_reject_cancel_disconnect_reconnect_verified:true,
   production_onekey_eip1559_and_eip712_signing_verified:false}};
}

export function validateOneKeyBlePhysicalReadinessRatification(value) {
 exact(value,RESULT,'physical readiness ratification'); exact(value.readinessGates,GATE_KEYS,'physical readiness gates');
 if(value.schema!=='usdom-onekey-ble-physical-readiness-ratification-v1'||value.status!=='single-operator-ratified'
   ||value.singleOperator!==true||value.hardwareObservationRatified!==true||value.hardwareSigningApproved!==false
   ||typeof value.residualRisk!=='string'||!value.residualRisk.includes('no independent auditor')
   ||['observationBytesSha256','evidenceBytesSha256','physicalTestTranscriptSha256','appArtifactSha256','packageArtifactSha256'].some(k=>!sha.test(value[k]??''))
   ||GATE_KEYS.slice(0,4).some(k=>value.readinessGates[k]!==true)
   ||value.readinessGates.production_onekey_eip1559_and_eip712_signing_verified!==false) throw new Error('physical readiness ratification overstates or omits observed gates');
 return value;
}

export async function materializeOneKeyBlePhysicalCeremonyRatification({authorityPath,observationPath,evidencePath,ratificationPath,outputPath}) {
 const [a,o,e,r]=await Promise.all([
  readDirectFile(authorityPath,{minimum:2,maximum:32768,exactMode:0o600,label:'collection authority'}),
  readDirectFile(observationPath,{minimum:2,maximum:131072,exactMode:0o600,label:'physical observation'}),
  readDirectFile(evidencePath,{minimum:2,maximum:32768,exactMode:0o600,label:'physical evidence'}),
  readDirectFile(ratificationPath,{minimum:2,maximum:32768,exactMode:0o600,label:'operator ratification'})]);
 const result=ratifyOneKeyBlePhysicalCeremony({collectionAuthority:parseStrictJsonBytes(a,{label:'collection authority'}),observationBytes:o,evidenceBytes:e,ratification:parseStrictJsonBytes(r,{label:'operator ratification'})});
 await writePrivateFileDurableNew(outputPath,`${JSON.stringify(result,null,2)}\n`,{maximum:32768}); return result;
}
