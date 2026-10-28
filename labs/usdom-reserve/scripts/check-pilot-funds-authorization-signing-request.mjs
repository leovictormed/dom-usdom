#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {closeSync,constants,fstatSync,openSync,readFileSync,statSync} from 'node:fs'; import {getAddress} from 'ethers';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs'; import {
  validatePilotFundsAuthorizationRequest,validatePilotFundsSigningDocumentBindings,
} from '../sdk/pilot-funds-authorization.mjs';
try {if(process.argv.length!==6)throw new Error('request, Safe bundle, release and snapshot required');
 const captures=process.argv.slice(2).map((p,index)=>{const fd=openSync(p,constants.O_RDONLY|constants.O_NOFOLLOW),before=fstatSync(fd,{bigint:true}),named=statSync(p,{bigint:true});if(!before.isFile()||before.nlink!==1n||before.size<2n||before.size>16n*1024n*1024n||before.dev!==named.dev||before.ino!==named.ino){closeSync(fd);throw new Error(`unsafe signing input ${index}`)}return{p,fd,before};});
 let bytes;try{bytes=captures.map(({fd,before},index)=>{const value=readFileSync(fd),after=fstatSync(fd,{bigint:true});if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||BigInt(value.length)!==before.size)throw new Error(`signing input ${index} changed during read`);return value});for(const [index,{p,fd,before}] of captures.entries()){const after=fstatSync(fd,{bigint:true}),named=statSync(p,{bigint:true});if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||after.dev!==named.dev||after.ino!==named.ino)throw new Error(`signing input set changed during capture: ${index}`)}}finally{for(const {fd} of captures)closeSync(fd)}
 const [request,bundle,release,snapshot]=bytes.map((value,index)=>
  parseStrictJsonBytes(value,{label:process.argv[index+2]}));
 if(getAddress(request.finalizedAnchor.governance)!==getAddress(release.governance))throw new Error('pilot funds signing request differs from authenticated inputs');
 validatePilotFundsSigningDocumentBindings({snapshot,bundle,bundleBytes:bytes[1],releaseConfig:release,
  releaseConfigBytes:bytes[2]});
 validatePilotFundsAuthorizationRequest({request,snapshot,releaseConfig:release});
 process.stdout.write(request.digest+'\n');
}catch(e){writeReleaseFailure('check-pilot-funds-authorization-signing-request',e);process.exitCode=1;}
