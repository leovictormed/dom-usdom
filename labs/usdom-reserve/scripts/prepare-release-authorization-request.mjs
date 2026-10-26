#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {TypedDataEncoder} from 'ethers';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {collectReleaseAuthorizationAnchor,resolveReleaseAuthorizationRpcSources,
  withReleaseAuthorizationProviders} from '../sdk/release-authorization-rpc.mjs';
import {
  buildReleaseAuthorization,releaseAuthorizationTypedData,
} from '../sdk/release-authorization.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const parseJson=(bytes,relative)=>parseStrictJson(bytes.toString('utf8'),{
  label:relative,maxBytes:4*1024*1024,maxDepth:64,
});
const fixedInputs=[
  ['config/mainnet-release-evidence.unconfigured.json',{exactMode:0o644}],
  ['config/proof-reserve.unconfigured.json',{exactMode:0o644}],
  ['config/operator-intent.json',{exactMode:0o600}],
  ['config/mainnet-preflight-rpc-catalog.json',{exactMode:0o644,maximum:1024*1024}],
];
const readFixedInputs=()=>Promise.all(fixedInputs.map(([relative,options])=>
  readDirectProjectFile(root,relative,{...options,minimum:1,maximum:4*1024*1024,label:relative})));

try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const fixedBytes=await readFixedInputs();
  const [releaseEvidence,releaseConfig,operatorIntent]=fixedBytes.slice(0,3).map((bytes,index)=>
    parseJson(bytes,fixedInputs[index][0]));
  const reportDocument=releaseEvidence.residualRiskAcceptanceReport;
  if(typeof reportDocument?.path!=='string'||typeof reportDocument.sha256!=='string') {
    throw new Error('residual-risk report metadata is missing');
  }
  const report=await readDirectProjectFile(root,reportDocument.path,{
    minimum:1,maximum:4*1024*1024,exactMode:0o600,label:'residual-risk report',
  });
  if(createHash('sha256').update(report).digest('hex')!==reportDocument.sha256) {
    throw new Error('residual-risk report hash differs from metadata');
  }
  const catalog=parseJson(fixedBytes.at(-1),'mainnet preflight RPC catalog');
  const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
  const anchor=await withReleaseAuthorizationProviders(sources,providers=>
    collectReleaseAuthorizationAnchor({providers,releaseConfig,sources}));
  const acceptedAt=anchor.blockTimestamp;
  const {authorization,digest}=buildReleaseAuthorization({releaseEvidence,releaseConfig,
    operatorIntent,acceptedAt});
  const typed=releaseAuthorizationTypedData(authorization,releaseConfig);
  const request={schema:'usdom-release-authorization-request/v2',releaseId:releaseEvidence.releaseId,
    sourceCommit:releaseEvidence.sourceCommit,finalizedAnchor:{
      ...anchor,
    },authorization,digest,
    typedData:TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message)};
  const currentFixedBytes=await readFixedInputs();
  const currentReport=await readDirectProjectFile(root,reportDocument.path,{
    minimum:report.length,maximum:report.length,exactMode:0o600,label:'residual-risk report',
  });
  if(currentFixedBytes.some((bytes,index)=>!bytes.equals(fixedBytes[index]))
      ||!currentReport.equals(report)) throw new Error('release inputs changed during request preparation');
  process.stdout.write(`${JSON.stringify(request,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-release-authorization-request',error);
  process.exitCode=1;
}
