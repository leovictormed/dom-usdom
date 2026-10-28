#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {closeSync,constants,fstatSync,openSync,readFileSync,statSync} from 'node:fs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {auditPilotPublicArtifact,auditPilotPublicArtifactSet} from '../sdk/pilot-publication-privacy.mjs';
try {
  if(process.argv.length===3&&process.argv[2]==='--self-test') {
    auditPilotPublicArtifact({schema:'deposit/v1',depositPhaseCommitment:'11'.repeat(32)});
    for(const forbidden of [{depositId:'0x'+'11'.repeat(32),burnId:'0x'+'22'.repeat(32)},
      {privateWitness:'secret'},{rawTransaction:'0x02'+'ab'.repeat(100)}]) {
      try { auditPilotPublicArtifact(forbidden); throw new Error('privacy self-test accepted forbidden artifact'); }
      catch(error) { if(error.message==='privacy self-test accepted forbidden artifact') throw error; }
    }
    process.stdout.write('PASS: pilot publication privacy self-test\n');
    process.exit(0);
  }
  if(process.argv.length<3) throw new Error('usage: check-pilot-publication-privacy.mjs PUBLIC_JSON...');
  const entries=[];
  const captures=[];try{for(const file of process.argv.slice(2)){const fd=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW),before=fstatSync(fd,{bigint:true}),named=statSync(file,{bigint:true});if(!before.isFile()||before.nlink!==1n||before.size<1n||before.size>1024n*1024n||before.dev!==named.dev||before.ino!==named.ino){closeSync(fd);throw new Error('public pilot artifact must be a direct bounded regular file')}captures.push({file,fd,before})}}catch(error){for(const {fd} of captures)closeSync(fd);throw error}
  try{for(const {file,fd,before} of captures){const bytes=readFileSync(fd),after=fstatSync(fd,{bigint:true});if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||BigInt(bytes.length)!==before.size)throw new Error('public pilot artifact changed during read');const value=parseStrictJson(bytes.toString('utf8'),{label:'public pilot artifact',maxBytes:1024*1024,maxDepth:32});auditPilotPublicArtifact(value);entries.push({label:file,value})}for(const {file,fd,before} of captures){const after=fstatSync(fd,{bigint:true}),named=statSync(file,{bigint:true});if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||after.dev!==named.dev||after.ino!==named.ino)throw new Error('public pilot artifact set changed during audit')}auditPilotPublicArtifactSet(entries)}finally{for(const {fd} of captures)closeSync(fd)}
  process.stdout.write(`PASS: ${process.argv.length-2} public pilot artifacts preserve phase privacy\n`);
} catch(error) { writeReleaseFailure('check-pilot-publication-privacy',error); process.exitCode=1; }
