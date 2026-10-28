#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateMainnetDeploymentLedgerHandoff,validateMainnetDeploymentPackage}
  from '../sdk/deployment-package.mjs';
import {validateMainnetDeploymentIdentityObservation} from '../sdk/mainnet-deployment-identity.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {snapshotExecutablePath} from '../sdk/stable-executable.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
function decodeJson(bytes,label,maximum) {
  let json;
  try { json=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} contains invalid UTF-8`); }
  return parseStrictJson(json,{label,maxBytes:maximum,maxDepth:32});
}
try {
  if(process.argv.length!==3||!(/^[0-3]$/).test(process.argv[2])) {
    throw new Error('usage: prepare-mainnet-deployment-transaction.mjs INDEX_0_TO_3');
  }
  const packagePath=process.env.USDOM_MAINNET_DEPLOYMENT_PACKAGE;
  const expectedSha=process.env.USDOM_PACKAGE_SHA256;
  const observationPath=process.env.USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION;
  if(typeof packagePath!=='string'||!path.isAbsolute(packagePath)
      ||typeof expectedSha!=='string'||!(/^[0-9a-f]{64}$/).test(expectedSha)
      ||typeof observationPath!=='string'||!path.isAbsolute(observationPath)) {
    throw new Error('fixed deployment package path and SHA-256 are required');
  }
  const packageBytes=await readDirectFile(packagePath,{minimum:1,maximum:8*1024*1024,
    exactMode:0o600,label:'reviewed mainnet deployment package'});
  if(createHash('sha256').update(packageBytes).digest('hex')!==expectedSha) {
    throw new Error('reviewed deployment package SHA-256 mismatch');
  }
  const packageValue=validateMainnetDeploymentPackage(
    decodeJson(packageBytes,'reviewed mainnet deployment package',8*1024*1024));
  const catalogPath=path.join(root,'config/mainnet-preflight-rpc-catalog.json');
  const catalogBytes=await readDirectFile(catalogPath,{minimum:1,maximum:1024*1024,
    exactMode:0o644,label:'mainnet preflight RPC catalog'});
  decodeJson(catalogBytes,'mainnet preflight RPC catalog',1024*1024);
  const catalogSha256=createHash('sha256').update(catalogBytes).digest('hex');
  const expectedObservationSha=packageValue.observationDocumentSha256;
  if(typeof expectedObservationSha!=='string'||!(/^[0-9a-f]{64}$/).test(expectedObservationSha)) {
    throw new Error('deployment package observation SHA-256 is invalid');
  }
  const observationBytes=await readDirectFile(observationPath,{minimum:1,maximum:4*1024*1024,
    exactMode:0o600,label:'deployment identity observation'});
  const observationSha=createHash('sha256').update(observationBytes).digest('hex');
  if(observationSha!==expectedObservationSha) throw new Error('deployment identity observation SHA-256 mismatch');
  const observation=validateMainnetDeploymentIdentityObservation({observation:
    decodeJson(observationBytes,'deployment identity observation',4*1024*1024)});
  const node=await snapshotExecutablePath(process.execPath);
  const prepared=await runPinnedExecutable(node,['scripts/prepare-mainnet-deployment.mjs'],{
    cwd:root,maxBuffer:8*1024*1024,timeout:10*60*1000,
    env:{...process.env,USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256:expectedObservationSha},
  });
  if(!Buffer.isBuffer(prepared.stdout)||!prepared.stdout.equals(packageBytes)
      || prepared.stderr.length!==0) {
    throw new Error('reviewed deployment package differs from current source-derived package');
  }
  if(packageValue.observationDocumentSha256!==observationSha
      ||packageValue.observationHash!==observation.observationHash) {
    throw new Error('deployment package identity observation binding mismatch');
  }
  const transaction=packageValue.transactions[Number(process.argv[2])];
  const observationAfter=await readDirectFile(observationPath,{minimum:observationBytes.length,
    maximum:observationBytes.length,exactMode:0o600,label:'deployment identity observation'});
  if(!observationAfter.equals(observationBytes)) throw new Error('deployment identity observation changed during handoff');
  const catalogAfter=await readDirectFile(catalogPath,{minimum:catalogBytes.length,
    maximum:catalogBytes.length,exactMode:0o644,label:'mainnet preflight RPC catalog'});
  if(!catalogAfter.equals(catalogBytes)) throw new Error('mainnet preflight RPC catalog changed during handoff');
  const handoff={schema:'usdom-mainnet-deployment-ledger-handoff-v1',
    chainId:packageValue.chainId,releaseConfigSha256:packageValue.releaseConfigSha256,
    packageSha256:expectedSha,rpcCatalogSha256:catalogSha256,observationDocumentSha256:observationSha,
    observationHash:observation.observationHash,transaction};
  validateMainnetDeploymentLedgerHandoff({handoff,packageValue,packageBytes,index:Number(process.argv[2]),
    packageSha256:expectedSha});
  process.stdout.write(`${JSON.stringify(handoff)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-mainnet-deployment-transaction',error);
  process.exitCode=1;
}
