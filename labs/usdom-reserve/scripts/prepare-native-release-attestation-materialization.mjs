#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {TypedDataEncoder} from 'ethers';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {
  buildNativeReleaseAttestation,collectNativeAttestationApprovals,
  nativeReleaseAttestationTypedData,
} from '../sdk/native-release-attestation.mjs';
import {collectNativeAttestationApprovalConsensus,resolveReleaseAuthorizationRpcSources,
  withReleaseAuthorizationProviders} from '../sdk/release-authorization-rpc.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const parseJson=(bytes,relative)=>parseStrictJson(bytes.toString('utf8'),{
  label:relative,maxBytes:4*1024*1024,maxDepth:64,
});
const names=['nativePrivacyTrustedSetup','nativeScheduledRuntimeActivation',
  'nativeWalletCustody','nativeWalletRecovery'];
const files={nativePrivacyTrustedSetup:'native-privacy-trusted-setup-signature.hex',
  nativeScheduledRuntimeActivation:'native-scheduled-runtime-activation-signature.hex',
  nativeWalletCustody:'native-wallet-custody-signature.hex',
  nativeWalletRecovery:'native-wallet-recovery-signature.hex'};
const fixedInputs=[
  ['config/mainnet-release-evidence.unconfigured.json',{exactMode:0o644,maximum:4*1024*1024}],
  ['config/proof-reserve.unconfigured.json',{exactMode:0o644,maximum:4*1024*1024}],
  ['evidence/native-attestations/native-release-attestation-requests.json',
    {exactMode:0o600,maximum:4*1024*1024}],
  ...names.map(name=>[path.posix.join('evidence/native-attestations',files[name]),
    {exactMode:0o600,maximum:4096}]),
  ['config/mainnet-preflight-rpc-catalog.json',{exactMode:0o644,maximum:1024*1024}],
];
const readFixedInputs=()=>Promise.all(fixedInputs.map(([relative,options])=>
  readDirectProjectFile(root,relative,{...options,minimum:1,label:relative})));
try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const fixedBytes=await readFixedInputs();
  const [releaseEvidence,releaseConfig,request]=fixedBytes.slice(0,3).map(
    (bytes,index)=>parseJson(bytes,fixedInputs[index][0]));
  if(request.schema!=='usdom-native-release-attestation-requests/v3'
      || JSON.stringify(Object.keys(request.requests??{}).sort())!==JSON.stringify([...names].sort())) {
    throw new Error('native release-attestation request schema or set is invalid');
  }
  const attestations={};
  for(const [index,name] of names.entries()) {
    const bytes=fixedBytes[index+3];
    const signature=bytes.toString('ascii').trim();
    if(!Buffer.from(`${signature}\n`,'ascii').equals(bytes)) {
      throw new Error(`${name} signature file is not canonical`);
    }
    const requested=request.requests[name];
    const built=buildNativeReleaseAttestation({kind:requested.attestation?.kind,
      releaseEvidence,releaseConfig,completedAt:requested.attestation?.completedAt,
      subjectCommitment:requested.attestation?.subjectCommitment,signature});
    if(built.digest.toLowerCase()!==String(requested.digest).toLowerCase()) {
      throw new Error(`${name} digest differs from current release`);
    }
    if(JSON.stringify({...built.attestation,signature:null})!==JSON.stringify(requested.attestation)) {
      throw new Error(`${name} attestation differs from current release`);
    }
    const typed=nativeReleaseAttestationTypedData(built.attestation,releaseConfig);
    if(JSON.stringify(TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message))
        !==JSON.stringify(requested.typedData)) throw new Error(`${name} typed data differs`);
    attestations[name]=built.attestation;
  }
  const catalog=parseJson(fixedBytes.at(-1),'mainnet preflight RPC catalog');
  const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
  const observation=await withReleaseAuthorizationProviders(sources,providers=>
    collectNativeAttestationApprovalConsensus({providers,releaseConfig,attestations,sources}));
  for(const name of names) {
    if(observation.approvals[name].valid!==true
        || BigInt(attestations[name].completedAt)>BigInt(observation.finalizedBlockTimestamp)) {
      throw new Error(`${name} is not valid in finalized Ethereum state`);
    }
  }
  const currentFixedBytes=await readFixedInputs();
  if(currentFixedBytes.some((bytes,index)=>!bytes.equals(fixedBytes[index]))) {
    throw new Error('native release inputs changed during attestation materialization');
  }
  process.stdout.write(`${JSON.stringify({
    schema:'usdom-native-release-attestation-materialization/v1',attestations,observation,
  },null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-native-release-attestation-materialization',error);
  process.exitCode=1;
}
