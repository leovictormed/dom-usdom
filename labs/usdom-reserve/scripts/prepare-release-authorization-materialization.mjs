#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {TypedDataEncoder} from 'ethers';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {
  buildReleaseAuthorization,collectReleaseAuthorizationApproval,releaseAuthorizationTypedData,
  validateReleaseAuthorizationSigningRequest,
} from '../sdk/release-authorization.mjs';
import {collectReleaseAuthorizationApprovalConsensus,resolveReleaseAuthorizationRpcSources,
  withReleaseAuthorizationProviders} from '../sdk/release-authorization-rpc.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const parseJson=(bytes,relative)=>parseStrictJson(bytes.toString('utf8'),{
  label:relative,maxBytes:4*1024*1024,maxDepth:64,
});
const fixedInputs=[
  ['config/mainnet-release-evidence.unconfigured.json',{exactMode:0o644,maximum:4*1024*1024}],
  ['config/proof-reserve.unconfigured.json',{exactMode:0o644,maximum:4*1024*1024}],
  ['config/operator-intent.json',{exactMode:0o600,maximum:4*1024*1024}],
  ['evidence/authorization/release-authorization-request.json',
    {exactMode:0o600,maximum:4*1024*1024}],
  ['evidence/authorization/release-authorization-signature.hex',
    {exactMode:0o600,maximum:4096}],
  ['evidence/control-plane/safe-control-release-evidence-bundle.json',
    {exactMode:0o600,maximum:4*1024*1024}],
  ['config/mainnet-preflight-rpc-catalog.json',{exactMode:0o644,maximum:1024*1024}],
];
const readFixedInputs=()=>Promise.all(fixedInputs.map(([relative,options])=>
  readDirectProjectFile(root,relative,{...options,minimum:1,label:relative})));
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const fixedBytes=await readFixedInputs();
  const [releaseEvidence,releaseConfig,operatorIntent,request]=fixedBytes.slice(0,4).map(
    (bytes,index)=>parseJson(bytes,fixedInputs[index][0]));
  const safeBundle=parseJson(fixedBytes[5],fixedInputs[5][0]);
  const signatureBytes=fixedBytes[4];
  if(!exact(request,['schema','releaseId','sourceCommit','finalizedAnchor','authorization','digest','typedData'])
      || request.schema!=='usdom-release-authorization-request/v2') {
    throw new Error('release-authorization request schema is invalid');
  }
  validateReleaseAuthorizationSigningRequest({request,bundle:safeBundle,
    bundleSha256:createHash('sha256').update(fixedBytes[5]).digest('hex'),
    releaseConfig,releaseEvidence});
  const signature=signatureBytes.toString('ascii').trim();
  if(Buffer.from(`${signature}\n`,'ascii').compare(signatureBytes)!==0) {
    throw new Error('signature file must contain one canonical newline-terminated hex value');
  }
  const built=buildReleaseAuthorization({releaseEvidence,releaseConfig,operatorIntent,
    acceptedAt:request.authorization?.acceptedAt,signature});
  if(built.digest.toLowerCase()!==String(request.digest).toLowerCase()) {
    throw new Error('signed request digest differs from current release');
  }
  const unsigned={...built.authorization,signature:null};
  if(JSON.stringify(unsigned)!==JSON.stringify(request.authorization)) {
    throw new Error('signed request authorization differs from current release');
  }
  const typed=releaseAuthorizationTypedData(built.authorization,releaseConfig);
  if(JSON.stringify(TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message))
      !==JSON.stringify(request.typedData)) throw new Error('typed-data request differs from current release');
  const catalog=parseJson(fixedBytes.at(-1),'mainnet preflight RPC catalog');
  const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
  const observation=await withReleaseAuthorizationProviders(sources,providers=>
    collectReleaseAuthorizationApprovalConsensus({providers,releaseConfig,
      authorization:built.authorization,sources}));
  if(observation.approvals.releaseAuthorization.valid!==true
      || BigInt(built.authorization.acceptedAt)>BigInt(observation.finalizedBlockTimestamp)) {
    throw new Error('governance signature is not valid in finalized Ethereum state');
  }
  const nextIntent=structuredClone(operatorIntent);
  nextIntent.production_approved=true;
  nextIntent.deploy_authorized=true;
  nextIntent.real_funds_authorized=true;
  nextIntent.residual_risk_acceptance=built.authorization;
  const currentFixedBytes=await readFixedInputs();
  if(currentFixedBytes.some((bytes,index)=>!bytes.equals(fixedBytes[index]))) {
    throw new Error('release inputs changed during authorization materialization');
  }
  process.stdout.write(`${JSON.stringify({schema:'usdom-release-authorization-materialization/v1',
    operatorIntent:nextIntent,authorization:built.authorization,observation},null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-release-authorization-materialization',error);
  process.exitCode=1;
}
