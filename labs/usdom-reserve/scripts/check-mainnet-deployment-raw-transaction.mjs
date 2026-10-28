#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {validateMainnetDeploymentRawTransaction} from '../sdk/mainnet-deployment-execution.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateDeploymentRawEvidence} from '../sdk/deployment-evidence.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {snapshotExecutablePath} from '../sdk/stable-executable.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
function decodeUtf8(bytes,label) {
  try { return new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} contains invalid UTF-8`); }
}

let rawTransactionBytes;
try {
  if(process.argv.length!==3||!(/^[0-3]$/).test(process.argv[2])) {
    throw new Error('usage: check-mainnet-deployment-raw-transaction.mjs INDEX_0_TO_3');
  }
  const rawPath=process.env.USDOM_MAINNET_DEPLOYMENT_RAW_TRANSACTION;
  if(typeof rawPath!=='string'||!path.isAbsolute(rawPath)) {
    throw new Error('USDOM_MAINNET_DEPLOYMENT_RAW_TRANSACTION must be an absolute path');
  }
  rawTransactionBytes=await readDirectFile(rawPath,{minimum:4,maximum:8*1024*1024,
    exactMode:0o600,label:'mainnet deployment raw transaction'});
  const rawText=decodeUtf8(rawTransactionBytes,'mainnet deployment raw transaction');
  const raw=rawText.trim();
  if(!/^0x[0-9a-f]+$/.test(raw)||raw.length%2!==0||rawText!==`${raw}\n`) {
    throw new Error('mainnet deployment raw transaction framing is invalid');
  }
  const node=await snapshotExecutablePath(process.execPath);
  const expectedResult=await runPinnedExecutable(node,
    ['scripts/prepare-mainnet-deployment-transaction.mjs',process.argv[2]],{
      cwd:root,maxBuffer:8*1024*1024,timeout:10*60*1000,env:process.env,
    });
  if(expectedResult.stderr.length!==0) throw new Error('deployment transaction derivation wrote stderr');
  const expected=parseStrictJsonBytes(expectedResult.stdout,
    {label:'derived deployment transaction',maxBytes:8*1024*1024,maxDepth:64});
  if(!expectedResult.stdout.equals(Buffer.from(`${JSON.stringify(expected)}\n`))) {
    throw new Error('derived deployment transaction framing is not canonical');
  }
  if(expected.schema!=='usdom-mainnet-deployment-ledger-handoff-v1') {
    throw new Error('deployment Ledger handoff schema is invalid');
  }
  const packagePath=process.env.USDOM_MAINNET_DEPLOYMENT_PACKAGE;
  const packageSha256=process.env.USDOM_PACKAGE_SHA256;
  if(typeof packagePath!=='string'||!path.isAbsolute(packagePath)
      ||typeof packageSha256!=='string'||!/^[0-9a-f]{64}$/.test(packageSha256)) {
    throw new Error('reviewed deployment package authority is unavailable');
  }
  const packageBytes=await readDirectFile(packagePath,{minimum:2,maximum:8*1024*1024,
    label:'reviewed deployment package'});
  const packageValue=parseStrictJsonBytes(packageBytes,
    {label:'reviewed deployment package',maxBytes:8*1024*1024,maxDepth:64});
  const validated=validateMainnetDeploymentRawTransaction({raw,packageValue,packageBytes,
    packageSha256,handoff:expected,index:process.argv[2]});
  const evidence={...validated,
    chainId:expected.chainId,releaseConfigSha256:expected.releaseConfigSha256,
    packageSha256:expected.packageSha256,
    rpcCatalogSha256:expected.rpcCatalogSha256,
    observationDocumentSha256:expected.observationDocumentSha256,
    observationHash:expected.observationHash,
    rawSha256:createHash('sha256').update(rawTransactionBytes).digest('hex'),
  };
  validateDeploymentRawEvidence(evidence);
  process.stdout.write(`${JSON.stringify(evidence,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('check-mainnet-deployment-raw-transaction',error);
  process.exitCode=1;
} finally {
  rawTransactionBytes?.fill(0);
}
