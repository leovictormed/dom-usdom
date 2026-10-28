#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {closeSync,constants,fstatSync,openSync,readFileSync,statSync} from 'node:fs';
import {buildProductionOperationalGasMeasurementJob} from '../sdk/local-operational-gas-evidence.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
if(process.argv.length!==4) throw new Error('usage: prepare-production-operational-gas-job RELEASE LOCAL_EVIDENCE');
const sha=value=>createHash('sha256').update(value).digest('hex');
const openSnapshot=(target,label)=>{
 const descriptor=openSync(target,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
 const before=fstatSync(descriptor,{bigint:true}),named=statSync(target,{bigint:true});
 if(!before.isFile()||before.nlink!==1n||before.uid!==BigInt(process.getuid())||(before.mode&0o777n)!==0o600n
      ||before.size<1n||before.size>1024n*1024n||before.dev!==named.dev||before.ino!==named.ino){closeSync(descriptor);throw new Error(`${label} file policy mismatch`)}
 return{target,label,descriptor,before};
};
const captures=[];try{captures.push(openSnapshot(process.argv[2],'production release'));captures.push(openSnapshot(process.argv[3],'local operational gas evidence'))}catch(error){for(const item of captures)closeSync(item.descriptor);throw error}
let release,local;try{[release,local]=captures.map(item=>{const bytes=readFileSync(item.descriptor),after=fstatSync(item.descriptor,{bigint:true});if(item.before.dev!==after.dev||item.before.ino!==after.ino||item.before.size!==after.size||item.before.mtimeNs!==after.mtimeNs||item.before.ctimeNs!==after.ctimeNs||BigInt(bytes.length)!==item.before.size)throw new Error(`${item.label} changed during read`);return{bytes,value:parseStrictJson(bytes.toString('utf8'),{label:item.label,maxBytes:1024*1024,maxDepth:64}),sha256:sha(bytes)}});for(const item of captures){const after=fstatSync(item.descriptor,{bigint:true}),named=statSync(item.target,{bigint:true});if(item.before.dev!==after.dev||item.before.ino!==after.ino||item.before.size!==after.size||item.before.mtimeNs!==after.mtimeNs||item.before.ctimeNs!==after.ctimeNs||after.dev!==named.dev||after.ino!==named.ino)throw new Error(`${item.label} set changed during capture`)}}finally{for(const item of captures)closeSync(item.descriptor)}
const job=buildProductionOperationalGasMeasurementJob({release:release.value,
 releaseBytes:release.bytes,localEvidence:local.value,localEvidenceBytes:local.bytes,
 releaseSha256:release.sha256,localEvidenceSha256:local.sha256});
process.stdout.write(JSON.stringify(job,null,2)+'\n');
