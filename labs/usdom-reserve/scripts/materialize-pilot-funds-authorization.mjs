#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path'; import {fileURLToPath} from 'node:url'; import {createHash} from 'node:crypto';
import {readDirectProjectFile,readDirectFile} from '../sdk/direct-project-file.mjs'; import {parseStrictJsonBytes} from '../sdk/strict-json.mjs'; import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {resolveReleaseAuthorizationRpcSources,withReleaseAuthorizationProviders,collectPilotFundsAuthorizationApprovalConsensus} from '../sdk/release-authorization-rpc.mjs';
import {pilotFundsAuthorizationDigest,validatePilotFundsAuthorizationRequest,
 validatePilotFundsAuthorizationState,validatePilotFundsReleaseBinding} from '../sdk/pilot-funds-authorization.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
try {const paths=['evidence/authorization/pilot-funds-snapshot.json','evidence/authorization/pilot-funds-authorization-request.json','evidence/authorization/pilot-funds-authorization-signature.hex','config/proof-reserve.unconfigured.json','config/mainnet-preflight-rpc-catalog.json']; const bytes=await Promise.all(paths.map((p,i)=>readDirectProjectFile(root,p,{exactMode:i===3||i===4?0o644:0o600})));
 const snapshot=parseStrictJsonBytes(bytes[0],{label:paths[0]}),request=parseStrictJsonBytes(bytes[1],{label:paths[1]}),release=parseStrictJsonBytes(bytes[3],{label:paths[3]}),catalog=parseStrictJsonBytes(bytes[4],{label:paths[4]}); const signature=bytes[2].toString('ascii').trim(); const authorization={...request.authorization,signature};
 validatePilotFundsReleaseBinding(snapshot,createHash('sha256').update(bytes[3]).digest('hex'));
 validatePilotFundsAuthorizationRequest({request,snapshot,releaseConfig:release});
 if(pilotFundsAuthorizationDigest(authorization,release).toLowerCase()!==request.digest.toLowerCase())throw new Error('pilot signature request digest changed');
 const rpcPath=process.env.USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE;
 const rpcBytes=await readDirectFile(rpcPath,{minimum:2,maximum:1024*1024,exactMode:0o600,label:'RPC sources'});
 const capturedRuntime=parseStrictJsonBytes(rpcBytes,{label:'RPC sources'});
 const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'RPC sources'});
 if(JSON.stringify(runtimeSources)!==JSON.stringify(capturedRuntime))throw new Error('RPC sources changed before provider creation');
 const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources}); const finalizedObservation=await withReleaseAuthorizationProviders(sources,p=>collectPilotFundsAuthorizationApprovalConsensus({providers:p,releaseConfig:release,authorization,sources}));
 const current=await Promise.all(paths.map((p,i)=>readDirectProjectFile(root,p,{exactMode:i===3||i===4?0o644:0o600})));
 if(current.some((value,index)=>!value.equals(bytes[index]))
    ||!(await readDirectFile(rpcPath,{minimum:rpcBytes.length,maximum:rpcBytes.length,exactMode:0o600,label:'RPC sources'})).equals(rpcBytes))throw new Error('pilot authorization materialization inputs changed during finalized observation');
 const state={schema:'usdom-pilot-funds-authorization-state/v1',authorization,digest:request.digest,finalizedObservation,consumed:false}; validatePilotFundsAuthorizationState({state,snapshot,releaseConfig:release,depositAmountBaseUnits:snapshot.pilotDepositBaseUnits});
 await writePrivateFileDurableNewOrEqual(path.join(root,'evidence/authorization/pilot-funds-authorization-state.json'),Buffer.from(JSON.stringify(state,null,2)+'\n'),{maximum:4*1024*1024});
}catch(e){writeReleaseFailure('materialize-pilot-funds-authorization',e);process.exitCode=1;}
