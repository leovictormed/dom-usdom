#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {validateDomMainnetIdentity} from '../sdk/finalized-deposit-issuance.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  if(process.argv.length!==3 || !path.isAbsolute(process.argv[2])) {
    throw new Error('usage: check-dom-mainnet-identity-file.mjs ABSOLUTE_IDENTITY_FILE');
  }
  const bytes=await readDirectFile(process.argv[2],{
    minimum:2,maximum:65_536,exactMode:0o600,label:'DOM mainnet identity',
  });
  validateDomMainnetIdentity(parseStrictJsonBytes(bytes,{
    label:'DOM mainnet identity',maxBytes:65_536,maxDepth:8,
  }));
} catch(error) {
  writeReleaseFailure('check-dom-mainnet-identity-file',error);
  process.exitCode=1;
}
