#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateReleaseAuthorizationSigningRequest} from '../sdk/release-authorization.mjs';

function fail(message) { throw new Error(message); }
const readBytes=(path,label)=>readDirectFile(path,{
  minimum:1,maximum:4*1024*1024,exactMode:0o600,label,
});
const parse=(bytes,label)=>parseStrictJsonBytes(bytes,{
  label,maxBytes:4*1024*1024,maxDepth:64,
});

try {
  if(process.argv.length!==6) {
    fail('usage: check-release-authorization-signing-request REQUEST BUNDLE RELEASE EVIDENCE');
  }
  const labels=['release authorization request','Safe evidence bundle',
    'release configuration snapshot','release evidence snapshot'];
  const bytes=await Promise.all([
    readBytes(process.argv[2],labels[0]),readBytes(process.argv[3],labels[1]),
    readBytes(process.argv[4],labels[2]),readBytes(process.argv[5],labels[3]),
  ]);
  const [request,bundle,releaseConfig,releaseEvidence]=bytes.map((value,index)=>
    parse(value,labels[index]));
  const {digest}=validateReleaseAuthorizationSigningRequest({
    request,bundle,bundleSha256:createHash('sha256').update(bytes[1]).digest('hex'),
    releaseConfig,releaseEvidence,
  });
  process.stdout.write(`PASS: release authorization ${digest} is bound to release, evidence and Safe owners\n`);
} catch(error) {
  writeReleaseFailure('check-release-authorization-signing-request',error);
  process.exitCode=1;
}
