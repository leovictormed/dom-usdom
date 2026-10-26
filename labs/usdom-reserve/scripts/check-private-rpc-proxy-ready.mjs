#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {validatePrivateRpcProxyReady} from '../sdk/private-rpc-proxy-ready.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

let readinessBytes;
try {
  if(process.argv.length!==4&&process.argv.length!==5) throw new Error('usage: FILE EXPECTED_PID [EXPECTED_SHA256]');
  if(!path.isAbsolute(process.argv[2])||!/^[1-9][0-9]{0,9}$/.test(process.argv[3])) throw new Error('invalid argument');
  const expectedPid=Number(process.argv[3]);
  const expectedSha=process.argv[4];
  if(expectedSha!==undefined&&!/^[0-9a-f]{64}$/.test(expectedSha)) throw new Error('invalid expected digest');
  readinessBytes=await readDirectFile(process.argv[2],{
    minimum:2,maximum:2048,exactMode:0o600,label:'private RPC proxy readiness',
  });
  const digest=createHash('sha256').update(readinessBytes).digest('hex');
  if(expectedSha!==undefined&&digest!==expectedSha) throw new Error('readiness bytes changed');
  const value=validatePrivateRpcProxyReady(parseStrictJsonBytes(readinessBytes,{
    label:'private RPC proxy readiness',maxBytes:2048,maxDepth:4,
  }),{expectedPid});
  process.stdout.write(`${digest}\n${value.urls.join('\n')}\n`);
} catch(error) {
  writeReleaseFailure('check-private-rpc-proxy-ready',error);
  process.exitCode=1;
} finally {
  readinessBytes?.fill(0);
}
