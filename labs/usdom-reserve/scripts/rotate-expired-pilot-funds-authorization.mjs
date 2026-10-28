#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import fs from 'node:fs'; import path from 'node:path'; import {createHash} from 'node:crypto'; import {fileURLToPath} from 'node:url';
import {readDirectProjectFile,readDirectFile} from '../sdk/direct-project-file.mjs'; import {parseStrictJsonBytes} from '../sdk/strict-json.mjs'; import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {requireOperationalTlsClock} from '../sdk/mainnet-preflight-rpc.mjs';
import {validatePilotGateFinality,validatePilotGateInvalidation,validatePilotGateInvalidationSequence} from '../sdk/pilot-gate-invalidation.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),authorizationDirectory=path.join(root,'evidence/authorization');
const relative=['evidence/authorization/pilot-funds-authorization-request.json','evidence/authorization/pilot-funds-authorization-signature.hex','evidence/authorization/pilot-funds-authorization-state.json'],names=['request.json','signature.hex','state.json'];
const markerPath=path.join(authorizationDirectory,'.pilot-funds-rotation.json'),sha=value=>createHash('sha256').update(value).digest('hex');
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
async function copyOrVerify(source,destination,expectedHash,maximum) {
 let archived;
 if(fs.existsSync(destination)) archived=await readDirectFile(destination,{minimum:2,maximum,exactMode:0o600});
 else { const value=await readDirectFile(source,{minimum:2,maximum,exactMode:0o600}); if(sha(value)!==expectedHash) throw new Error('rotation source differs from authenticated intent'); await writePrivateFileDurableNewOrEqual(destination,value,{maximum}); archived=value; }
 if(sha(archived)!==expectedHash) throw new Error('rotation archive differs from authenticated intent');
 return archived;
}
async function validateArchivedGateGeneration(directory,marker) {
 const inventory=new Map(marker.gateArtifacts.map(item=>[item.name,item]));
 const parse=async name=>parseStrictJsonBytes(await readDirectFile(path.join(directory,name),{minimum:2,maximum:8*1024*1024,exactMode:0o600}),{label:name});
 const plan=await parse('pilot-deposit-gate-plan.json');
 if(!/^0x[0-9a-f]{64}$/.test(plan.snapshotCommitment??'')||!decimalGeneration(plan.generation)) throw new Error('archived pilot gate plan identity is invalid');
 const kind=marker.gateStatus==='cancelled-finalized'?'cancel':marker.gateStatus==='expired-cleared-finalized'?'clear':null;
 if(!kind) {
  if(inventory.has('pilot-deposit-gate-receipt.json')||inventory.has('pilot-deposit-gate-finalized.json')) throw new Error('mined pilot gate cannot be archived as unbroadcast');
  return;
 }
 const terminalName=`pilot-deposit-gate-${kind}-finalized.json`;
 if(!inventory.has(terminalName)) throw new Error('pilot gate invalidation completion is absent from authenticated archive');
 const terminal=await parse(terminalName); validatePilotGateInvalidation(terminal,kind);
 if(terminal.snapshotCommitment!==plan.snapshotCommitment||terminal.generation!==plan.generation) throw new Error('pilot gate invalidation differs from archived plan');
 const bindReceipt=async(prefix,completion)=>{
  const name=`${prefix}-receipt.json`; if(!inventory.has(name)) throw new Error(`${prefix} receipt is absent from authenticated archive`);
  const receipt=await parse(name),quantity=value=>typeof value==='string'&&/^0x(0|[1-9a-f][0-9a-f]*)$/.test(value)?BigInt(value):null;
  if((receipt.transactionHash??'').toLowerCase()!==completion.transactionHash||
    (receipt.blockHash??'').toLowerCase()!==completion.blockHash||quantity(receipt.blockNumber)!==BigInt(completion.blockNumber)||
    quantity(receipt.transactionIndex)!==BigInt(completion.transactionIndex)||quantity(receipt.status)!==1n) throw new Error(`${prefix} receipt differs from finalized completion`);
 };
 await bindReceipt(`pilot-deposit-gate-${kind}`,terminal);
 const mined=inventory.has('pilot-deposit-gate-receipt.json')||inventory.has('pilot-deposit-gate-finalized.json');
 if(mined) {
  if(!inventory.has('pilot-deposit-gate-finalized.json')) throw new Error('mined pilot gate lacks finalized completion');
  const gate=await parse('pilot-deposit-gate-finalized.json'); validatePilotGateFinality(gate);
  if(gate.snapshotCommitment!==plan.snapshotCommitment||gate.generation!==plan.generation||gate.expectedAuthorization!==plan.expectedAuthorization) throw new Error('pilot gate finality differs from archived plan');
  await bindReceipt('pilot-deposit-gate',gate); validatePilotGateInvalidationSequence(gate,terminal,kind);
 }
}
const decimalGeneration=value=>typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value);
async function unlinkEqual(source,destination,expectedHash,maximum) {
 if(!fs.existsSync(source)) return;
 const before=fs.lstatSync(source); if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1) throw new Error('rotation source type changed');
 const [current,archived]=await Promise.all([readDirectFile(source,{minimum:2,maximum,exactMode:0o600}),readDirectFile(destination,{minimum:2,maximum,exactMode:0o600})]);
 if(sha(current)!==expectedHash||!current.equals(archived)) throw new Error('rotation source changed before unlink');
 const after=fs.lstatSync(source); if(before.dev!==after.dev||before.ino!==after.ino||after.nlink!==1) throw new Error('rotation source identity changed before unlink'); fs.unlinkSync(source);
}
try {
 if(process.argv.length!==2) throw new Error('expired authorization rotation accepts no arguments');
 let marker;
 if(fs.existsSync(markerPath)) marker=parseStrictJsonBytes(await readDirectFile(markerPath,{minimum:2,maximum:65536,exactMode:0o600}),{label:'pilot rotation intent'});
 else {
  const paths=relative.map(value=>path.join(root,value)),present=paths.map(value=>fs.existsSync(value)); if(present.every(value=>!value)) process.exit(0); if(present.some(value=>!value)) throw new Error('partial pilot authorization generation without rotation intent');
  const bytes=await Promise.all(relative.map(value=>readDirectProjectFile(root,value,{exactMode:0o600}))),state=parseStrictJsonBytes(bytes[2],{label:'pilot authorization state'});
  if(!/^0x[0-9a-f]{64}$/.test(state.digest??'')||!/^([1-9][0-9]*)$/.test(state.authorization?.validUntil??'')) throw new Error('pilot authorization generation identity is invalid');
  const control=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY??null,gateNames=['pilot-deposit-gate-plan.json','pilot-deposit-gate-signature-1.json','pilot-deposit-gate-signature-2.json','pilot-deposit-gate-onekey-signature-1.hex','pilot-deposit-gate-onekey-signature-2.hex','pilot-deposit-gate-transaction.json','pilot-deposit-gate-relayer-envelope.json','pilot-deposit-gate-raw.txt','pilot-deposit-gate-receipt.json','pilot-deposit-gate-finalized.json','pilot-deposit-gate-clear-transaction.json','pilot-deposit-gate-clear-relayer-envelope.json','pilot-deposit-gate-clear-raw.txt','pilot-deposit-gate-clear-receipt.json','pilot-deposit-gate-clear-finalized.json','pilot-deposit-gate-cancel-plan.json','pilot-deposit-gate-cancel-signature-1.json','pilot-deposit-gate-cancel-signature-2.json','pilot-deposit-gate-cancel-onekey-signature-1.hex','pilot-deposit-gate-cancel-onekey-signature-2.hex','pilot-deposit-gate-cancel-transaction.json','pilot-deposit-gate-cancel-relayer-envelope.json','pilot-deposit-gate-cancel-raw.txt','pilot-deposit-gate-cancel-receipt.json','pilot-deposit-gate-cancel-finalized.json'];
  const existing=control?gateNames.filter(name=>fs.existsSync(path.join(control,name))):[],gateWasMined=existing.includes('pilot-deposit-gate-receipt.json')||existing.includes('pilot-deposit-gate-finalized.json'),cancelled=existing.includes('pilot-deposit-gate-cancel-finalized.json');
  if(!cancelled&&BigInt(state.authorization.validUntil)>=BigInt(Math.floor(requireOperationalTlsClock(Date.now())/1000))) throw new Error('current pilot authorization is still live and cannot be rotated');
  if(existing.length&&existing[0]!=='pilot-deposit-gate-plan.json') throw new Error('partial pilot gate generation cannot be rotated');
  if(gateWasMined&&!existing.includes('pilot-deposit-gate-clear-finalized.json')&&!cancelled) throw new Error('finalized or mined pilot gate requires finalized on-chain generation invalidation before rotation');
  const gateArtifacts=[]; for(const name of existing) { const value=await readDirectFile(path.join(control,name),{minimum:2,maximum:8*1024*1024,exactMode:0o600}); gateArtifacts.push({name,sha256:sha(value)}); }
  marker={schema:'usdom-pilot-funds-rotation-intent/v1',digest:state.digest,validUntil:state.authorization.validUntil,authorizationArtifacts:names.map((name,index)=>({name,sha256:sha(bytes[index])})),controlDirectory:control,gateStatus:cancelled?'cancelled-finalized':gateWasMined?'expired-cleared-finalized':'expired-unbroadcast',gateArtifacts};
  await writePrivateFileDurableNewOrEqual(markerPath,Buffer.from(JSON.stringify(marker,null,2)+'\n'),{maximum:65536});
 }
 if(!exact(marker,['schema','digest','validUntil','authorizationArtifacts','controlDirectory','gateStatus','gateArtifacts'])||marker.schema!=='usdom-pilot-funds-rotation-intent/v1'||!/^0x[0-9a-f]{64}$/.test(marker.digest)||!Array.isArray(marker.authorizationArtifacts)||marker.authorizationArtifacts.length!==3||!Array.isArray(marker.gateArtifacts)) throw new Error('pilot rotation intent schema is invalid');
 if((process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY??null)!==marker.controlDirectory) throw new Error('pilot rotation control directory changed');
 const generation=marker.digest.slice(2),directory=path.join(authorizationDirectory,'pilot-funds-generations',generation); fs.mkdirSync(directory,{recursive:true,mode:0o700});
 for(let i=0;i<3;i++) { const item=marker.authorizationArtifacts[i]; if(!exact(item,['name','sha256'])||item.name!==names[i]||!/^[0-9a-f]{64}$/.test(item.sha256)) throw new Error('pilot rotation authorization inventory is invalid'); await copyOrVerify(path.join(root,relative[i]),path.join(directory,item.name),item.sha256,4*1024*1024); }
 const authReceipt={schema:'usdom-pilot-funds-authorization-generation/v1',digest:marker.digest,validUntil:marker.validUntil,requestSha256:marker.authorizationArtifacts[0].sha256,signatureSha256:marker.authorizationArtifacts[1].sha256,stateSha256:marker.authorizationArtifacts[2].sha256,status:marker.gateStatus==='cancelled-finalized'?'cancelled':'expired'};
 await writePrivateFileDurableNewOrEqual(path.join(directory,'generation.json'),Buffer.from(JSON.stringify(authReceipt,null,2)+'\n'),{maximum:65536});
 let gateDirectory=null;
 if(marker.gateArtifacts.length) { gateDirectory=path.join(marker.controlDirectory,'pilot-gate-generations',generation); fs.mkdirSync(gateDirectory,{recursive:true,mode:0o700}); for(const item of marker.gateArtifacts) { if(!exact(item,['name','sha256'])||!/^pilot-deposit-gate-[a-z0-9-]+\.(json|txt)$/.test(item.name)||!/^[0-9a-f]{64}$/.test(item.sha256)) throw new Error('pilot rotation gate inventory is invalid'); await copyOrVerify(path.join(marker.controlDirectory,item.name),path.join(gateDirectory,item.name),item.sha256,8*1024*1024); }
  await validateArchivedGateGeneration(gateDirectory,marker);
  await writePrivateFileDurableNewOrEqual(path.join(gateDirectory,'generation.json'),Buffer.from(JSON.stringify({schema:'usdom-pilot-deposit-gate-generation/v1',authorizationDigest:marker.digest,status:marker.gateStatus,artifacts:marker.gateArtifacts},null,2)+'\n'),{maximum:65536}); }
 // Completion records and every archive byte exist before the first source is removed.
 for(let i=0;i<3;i++) await unlinkEqual(path.join(root,relative[i]),path.join(directory,names[i]),marker.authorizationArtifacts[i].sha256,4*1024*1024);
 if(gateDirectory) for(const item of marker.gateArtifacts) await unlinkEqual(path.join(marker.controlDirectory,item.name),path.join(gateDirectory,item.name),item.sha256,8*1024*1024);
 const before=fs.lstatSync(markerPath); if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1) throw new Error('pilot rotation intent identity changed'); fs.unlinkSync(markerPath);
} catch(error) { writeReleaseFailure('rotate-expired-pilot-funds-authorization',error); process.exitCode=1; }
