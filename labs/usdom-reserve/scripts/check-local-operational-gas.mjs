#!/usr/bin/env node
import {closeSync,constants,fstatSync,openSync,readFileSync,statSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateLocalOperationalGasEvidence} from '../sdk/local-operational-gas-evidence.mjs';
if(process.argv.length!==3) throw new Error('usage: check-local-operational-gas REPORT');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
function openDirect(target,label,maximum=64*1024*1024){const absolute=path.resolve(target);const fd=openSync(absolute,constants.O_RDONLY|constants.O_NOFOLLOW),before=fstatSync(fd,{bigint:true}),named=statSync(absolute,{bigint:true});if(!before.isFile()||before.nlink!==1n||before.size<1n||before.size>BigInt(maximum)||before.dev!==named.dev||before.ino!==named.ino){closeSync(fd);throw new Error(`unsafe ${label}`)}return{absolute,fd,before,label}}
function readCaptured(item){const bytes=readFileSync(item.fd),after=fstatSync(item.fd,{bigint:true});if(item.before.dev!==after.dev||item.before.ino!==after.ino||item.before.size!==after.size||item.before.mtimeNs!==after.mtimeNs||item.before.ctimeNs!==after.ctimeNs||BigInt(bytes.length)!==item.before.size)throw new Error(`${item.label} changed during read`);return bytes}
function revalidate(items){for(const item of items){const after=fstatSync(item.fd,{bigint:true}),named=statSync(item.absolute,{bigint:true});if(item.before.dev!==after.dev||item.before.ino!==after.ino||item.before.size!==after.size||item.before.mtimeNs!==after.mtimeNs||item.before.ctimeNs!==after.ctimeNs||after.dev!==named.dev||after.ino!==named.ino)throw new Error(`${item.label} set changed during capture`)}}
function openSet(specifications){const result=[];try{for(const specification of specifications)result.push(openDirect(...specification));return result}catch(error){for(const item of result)closeSync(item.fd);throw error}}
const initial=openDirect(process.argv[2],'local gas report',1024*1024);let reportBytes;try{reportBytes=readCaptured(initial);revalidate([initial])}finally{closeSync(initial.fd)}
const report=JSON.parse(reportBytes),requirementsPath=path.join(root,'config/production-requirements.json');
const expectedPaths={reserve:'out/USDOMProofReserve.sol/USDOMProofReserve.json',verifier:'out/USDOMProofReserve.t.sol/MockFinalizedBurnVerifier.json',token:'out/Mocks.sol/HostileToken.json',governance:'out/Mocks.sol/MockGovernance.json',registry:'out/Mocks.sol/MockGracefulShutdownRegistry.json'};
for(const [key,expected] of Object.entries(expectedPaths))if(report.artifacts?.[key]?.artifactPath!==expected)throw new Error(`operational gas ${key} artifact path differs from canonical allowlist`);
if(report.safeFixture?.path!=='test/fixtures/safe-1.4.1-mainnet.json')throw new Error('operational gas Safe fixture path differs from canonical allowlist');
const artifactPaths=[...Object.values(report.artifacts??{}),report.safeFixture].map(value=>value?.artifactPath??value?.path);
if(artifactPaths.length!==6||new Set(artifactPaths).size!==6||artifactPaths.some(relative=>typeof relative!=='string'||path.resolve(root,relative)===root||!path.resolve(root,relative).startsWith(root+path.sep)))throw new Error('operational gas artifact paths are not one canonical repository allowlist');
const items=openSet([[process.argv[2],'local gas report',1024*1024],[requirementsPath,'production requirements',1024*1024],...artifactPaths.map((relative,index)=>[path.resolve(root,relative),`gas artifact ${index}`])]);
let bytes;try{bytes=items.map(readCaptured);revalidate(items)}finally{for(const item of items)closeSync(item.fd)}
if(!bytes[0].equals(reportBytes))throw new Error('local gas report changed before stable-set capture');
const artifactBytes=new Map(artifactPaths.map((relative,index)=>[relative,bytes[index+2]]));
validateLocalOperationalGasEvidence(report,{root,artifactBytes});
const requirements=JSON.parse(bytes[1]);
for(const key of ['production_queue_withdrawal_worst_case_gas_measured',
 'production_prune_expired_256_worst_case_gas_measured',
 'production_prune_discardable_256_worst_case_gas_measured',
 'production_safe_admin_overhead_gas_measured']) {
  if(requirements[key]!==false) throw new Error(`${key} must remain false for local evidence`);
}
process.stdout.write('ok\n');
