#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {closeSync,constants,fstatSync,openSync,readFileSync} from 'node:fs';
import {auditReserveArtifact} from '../sdk/reserve-artifact-safety.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=new URL('../',import.meta.url);
if(process.argv.length!==2) {
  process.stderr.write('usage: check-reserve-artifact-safety.mjs\n');
  process.exit(1);
}
try {
  const artifactPath=new URL('out/USDOMProofReserve.sol/USDOMProofReserve.json',root);
  const descriptor=openSync(artifactPath,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
  let bytes;
  try {
    const stat=fstatSync(descriptor);
    if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o600
        ||stat.size<=0||stat.size>4*1024*1024) throw new Error('reserve artifact file policy mismatch');
    bytes=readFileSync(descriptor);
  } finally { closeSync(descriptor); }
  const artifact=parseStrictJson(bytes.toString('utf8'),{
    label:'reserve artifact',maxBytes:4*1024*1024,maxDepth:128,
  });
  process.stdout.write(`${JSON.stringify(auditReserveArtifact(artifact,{root:new URL('.',root).pathname}))}\n`);
} catch(error) {
  writeReleaseFailure('check-reserve-artifact-safety',error);
  process.exit(1);
}
