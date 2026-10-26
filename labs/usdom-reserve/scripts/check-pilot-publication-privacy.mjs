#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readFileSync,lstatSync} from 'node:fs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {auditPilotPublicArtifact} from '../sdk/pilot-publication-privacy.mjs';
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
  for(const file of process.argv.slice(2)) {
    const stat=lstatSync(file);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.size===0||stat.size>1024*1024) {
      throw new Error('public pilot artifact must be a direct bounded regular file');
    }
    auditPilotPublicArtifact(parseStrictJson(readFileSync(file,'utf8'),{label:'public pilot artifact',maxBytes:1024*1024,maxDepth:32}));
  }
  process.stdout.write(`PASS: ${process.argv.length-2} public pilot artifacts preserve phase privacy\n`);
} catch(error) { writeReleaseFailure('check-pilot-publication-privacy',error); process.exitCode=1; }
