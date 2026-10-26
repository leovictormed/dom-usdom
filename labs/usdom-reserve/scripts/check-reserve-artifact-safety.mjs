#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readFileSync} from 'node:fs';
import {auditReserveArtifact} from '../sdk/reserve-artifact-safety.mjs';

const root=new URL('../',import.meta.url);
if(process.argv.length!==2) {
  process.stderr.write('usage: check-reserve-artifact-safety.mjs\n');
  process.exit(1);
}
try {
  const artifact=JSON.parse(readFileSync(new URL('out/USDOMProofReserve.sol/USDOMProofReserve.json',root)));
  process.stdout.write(`${JSON.stringify(auditReserveArtifact(artifact,{root:new URL('.',root).pathname}))}\n`);
} catch(error) {
  writeReleaseFailure('check-reserve-artifact-safety',error);
  process.exit(1);
}
