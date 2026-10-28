import {createHash} from 'node:crypto';
import {getAddress} from 'ethers';
import {readDirectFile} from './direct-project-file.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';

const sha=/^[0-9a-f]{64}$/u, id=/^[A-Za-z0-9._:-]{1,128}$/u, fw=/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const AUTH=['schema','status','observationCollectionApproved','hardwareSigningApproved','expectedDeviceId','expectedAddress','firmwareAllowlist','appAuthoritySha256','packageAuthoritySha256','appArtifactSha256','packageArtifactSha256'];
const OBS=['schema','source','transport','appAuthoritySha256','packageAuthoritySha256','appArtifactSha256','packageArtifactSha256','discovery','pairing','initial','reconnected','addressConfirmation','failureExercises'];
const SOURCE=['kind','mock','emulator'];
const DISCOVERY=['deviceCount','singleDeviceSelected'];
const PAIRING=['permissionGranted','pairedOnHost'];
const STATE=['connectId','deviceId','firmware'];
const ADDRESS=['connectId','deviceId','address','showOnDevice'];
const FAILURES=['rejectionObserved','timeoutObserved','cancelObserved','disconnectObserved','reconnectObserved','lateCompletionRejected'];
const secret=/(?:seed|mnemonic|passphrase|\bpin\b|private.?key|secret)/iu;
const exact=(v,keys,label)=>{if(v===null||typeof v!=='object'||Array.isArray(v)||JSON.stringify(Object.keys(v).sort())!==JSON.stringify([...keys].sort()))throw new Error(`${label} schema is invalid`);};
const canonical=value=>{
 if(value===null||typeof value!=='object') return JSON.stringify(value);
 if(Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
 return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
};

export function validateOneKeyBlePhysicalCeremonyAuthority(value,{requireRatified=false}={}) {
 exact(value,AUTH,'physical ceremony authority');
 if(value.schema!=='usdom-onekey-ble-physical-ceremony-authority-v1'||value.hardwareSigningApproved!==false) throw new Error('physical ceremony authority is invalid');
 if(requireRatified) {
  if(value.status!=='ratified-for-observation'||value.observationCollectionApproved!==true
    ||!id.test(value.expectedDeviceId??'')||getAddress(value.expectedAddress)!==value.expectedAddress
    ||!Array.isArray(value.firmwareAllowlist)||value.firmwareAllowlist.length===0
    ||new Set(value.firmwareAllowlist).size!==value.firmwareAllowlist.length
    ||value.firmwareAllowlist.some(x=>!fw.test(x))
    ||['appAuthoritySha256','packageAuthoritySha256','appArtifactSha256','packageArtifactSha256'].some(k=>!sha.test(value[k]??''))) throw new Error('physical ceremony authority is not ratified');
 } else if(value.status!=='unconfigured'||value.observationCollectionApproved!==false
   ||value.expectedDeviceId!==null||value.expectedAddress!==null||value.firmwareAllowlist.length!==0
   ||['appAuthoritySha256','packageAuthoritySha256','appArtifactSha256','packageArtifactSha256'].some(k=>value[k]!==null)) throw new Error('unconfigured physical ceremony authority is not closed');
 return value;
}

function rejectSecrets(value,path='$') {
 if(Array.isArray(value)) return value.forEach((x,i)=>rejectSecrets(x,`${path}[${i}]`));
 if(value&&typeof value==='object') for(const [key,item] of Object.entries(value)) {
  if(secret.test(key)) throw new Error(`secret-bearing observation field rejected: ${path}.${key}`);
  rejectSecrets(item,`${path}.${key}`);
 }
}

export function validateOneKeyBlePhysicalObservation(authority,observation) {
 validateOneKeyBlePhysicalCeremonyAuthority(authority,{requireRatified:true}); exact(observation,OBS,'physical observation');
 exact(observation.source,SOURCE,'observation source'); exact(observation.discovery,DISCOVERY,'discovery'); exact(observation.pairing,PAIRING,'pairing');
 exact(observation.initial,STATE,'initial state'); exact(observation.reconnected,STATE,'reconnected state'); exact(observation.addressConfirmation,ADDRESS,'address confirmation'); exact(observation.failureExercises,FAILURES,'failure exercises'); rejectSecrets(observation);
 if(observation.schema!=='usdom-onekey-ble-physical-observation-v1'||observation.transport!=='desktop-web-ble'
   ||observation.source.kind!=='pinned-electron-app'||observation.source.mock!==false||observation.source.emulator!==false
   ||observation.discovery.deviceCount!==1||observation.discovery.singleDeviceSelected!==true
   ||observation.pairing.permissionGranted!==true||observation.pairing.pairedOnHost!==true
   ||Object.values(observation.failureExercises).some(x=>x!==true)) throw new Error('physical observation is incomplete or synthetic');
 for(const key of ['appAuthoritySha256','packageAuthoritySha256','appArtifactSha256','packageArtifactSha256']) if(observation[key]!==authority[key]) throw new Error(`physical observation ${key} mismatch`);
 const {initial,reconnected,addressConfirmation}=observation;
 if(!id.test(initial.connectId)||!id.test(reconnected.connectId)||initial.connectId===reconnected.connectId
   ||initial.deviceId!==authority.expectedDeviceId||reconnected.deviceId!==authority.expectedDeviceId
   ||initial.firmware!==reconnected.firmware||!authority.firmwareAllowlist.includes(initial.firmware)
   ||addressConfirmation.connectId!==reconnected.connectId||addressConfirmation.deviceId!==authority.expectedDeviceId
   ||addressConfirmation.address!==authority.expectedAddress||addressConfirmation.showOnDevice!==true) throw new Error('physical identity, reconnect, firmware or address binding mismatch');
 return observation;
}

export function buildOneKeyBlePhysicalCeremonyEvidence(authority,observation) {
 validateOneKeyBlePhysicalObservation(authority,observation);
 return {schema:'usdom-onekey-ble-physical-ceremony-evidence-v1',status:'observed-awaiting-operator-ratification',hardwareSigningApproved:false,
  authoritySha256:createHash('sha256').update(canonical(authority)).digest('hex'),observationSha256:createHash('sha256').update(canonical(observation)).digest('hex'),
  deviceId:authority.expectedDeviceId,firmware:observation.reconnected.firmware,address:authority.expectedAddress,
  appArtifactSha256:authority.appArtifactSha256,packageArtifactSha256:authority.packageArtifactSha256,
  discoveryPairingVerified:true,reconnectVerified:true,addressOnDeviceVerified:true,failureExercisesVerified:true};
}

export async function materializeOneKeyBlePhysicalCeremonyEvidence({authorityPath,observationPath,outputPath}) {
 const [a,o]=await Promise.all([readDirectFile(authorityPath,{minimum:2,maximum:32768,exactMode:0o600,label:'physical ceremony authority'}),readDirectFile(observationPath,{minimum:2,maximum:131072,exactMode:0o600,label:'physical ceremony observation'})]);
 const evidence=buildOneKeyBlePhysicalCeremonyEvidence(parseStrictJsonBytes(a,{label:'physical ceremony authority'}),parseStrictJsonBytes(o,{label:'physical ceremony observation'}));
 await writePrivateFileDurableNew(outputPath,`${JSON.stringify(evidence,null,2)}\n`,{maximum:32768}); return evidence;
}
