#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path'; import {fileURLToPath} from 'node:url'; import {createHash} from 'node:crypto'; import {TypedDataEncoder} from 'ethers';
import {readDirectProjectFile,readDirectFile} from '../sdk/direct-project-file.mjs'; import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {collectReleaseAuthorizationAnchor,resolveReleaseAuthorizationRpcSources,withReleaseAuthorizationProviders} from '../sdk/release-authorization-rpc.mjs';
import {pilotFundsSnapshotCommitment,pilotFundsAuthorizationTypedData,pilotFundsAuthorizationDigest,
 pilotFundsAuthorizationNonce,pilotFundsReleaseId,validatePilotFundsAuthorizationRequest,
 validatePilotFundsReleaseBinding} from '../sdk/pilot-funds-authorization.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
try {const [snapshotBytes,releaseBytes,catalogBytes]=await Promise.all(['evidence/authorization/pilot-funds-snapshot.json','config/proof-reserve.unconfigured.json','config/mainnet-preflight-rpc-catalog.json'].map(p=>readDirectProjectFile(root,p)));
 const snapshot=parseStrictJsonBytes(snapshotBytes,{label:'pilot snapshot'}),release=parseStrictJsonBytes(releaseBytes,{label:'release'}),catalog=parseStrictJsonBytes(catalogBytes,{label:'RPC catalog'});
 validatePilotFundsReleaseBinding(snapshot,createHash('sha256').update(releaseBytes).digest('hex'));
 const rpcPath=process.env.USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE;
 const rpcBytes=await readDirectFile(rpcPath,{minimum:2,maximum:1024*1024,exactMode:0o600,label:'RPC sources'});
 const capturedRuntime=parseStrictJsonBytes(rpcBytes,{label:'RPC sources'});
 const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'RPC sources'});
 if(JSON.stringify(runtimeSources)!==JSON.stringify(capturedRuntime))throw new Error('RPC sources changed before provider creation');
 const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
 const anchor=await withReleaseAuthorizationProviders(sources,p=>collectReleaseAuthorizationAnchor({providers:p,releaseConfig:release,sources}));
 const current=await Promise.all(['evidence/authorization/pilot-funds-snapshot.json','config/proof-reserve.unconfigured.json','config/mainnet-preflight-rpc-catalog.json'].map(p=>readDirectProjectFile(root,p)));
 if(current.some((value,index)=>!value.equals([snapshotBytes,releaseBytes,catalogBytes][index]))
    ||!(await readDirectFile(rpcPath,{minimum:rpcBytes.length,maximum:rpcBytes.length,exactMode:0o600,label:'RPC sources'})).equals(rpcBytes))throw new Error('pilot authorization request inputs changed during finalized observation');
 const commitment=pilotFundsSnapshotCommitment(snapshot),validAfter=anchor.blockTimestamp,validUntil=(BigInt(validAfter)+3600n).toString();
 const authorization={schema:'usdom-pilot-funds-authorization/v1',snapshotCommitment:commitment,releaseId:pilotFundsReleaseId(commitment),validAfter,validUntil,governance:release.governance,pilotDepositBaseUnits:snapshot.pilotDepositBaseUnits,funder:snapshot.funder,salt:snapshot.salt,receivingCommitment:snapshot.receivingCommitment,nonce:pilotFundsAuthorizationNonce(commitment,anchor.blockHash),signature:null};
 const digest=pilotFundsAuthorizationDigest(authorization,release),typed=pilotFundsAuthorizationTypedData(authorization,release);
 const request={schema:'usdom-pilot-funds-authorization-request/v1',authorization,digest,finalizedAnchor:anchor,typedData:TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message)};
 validatePilotFundsAuthorizationRequest({request,snapshot,releaseConfig:release});
 process.stdout.write(JSON.stringify(request,null,2)+'\n');
}catch(e){writeReleaseFailure('prepare-pilot-funds-authorization-request',e);process.exitCode=1;}
