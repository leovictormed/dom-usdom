#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs'; import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildPilotDepositGatePlan} from '../sdk/pilot-deposit-gate.mjs';
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&JSON.stringify(Object.keys(v).sort())===JSON.stringify([...k].sort());
const keys=['chainId','finalizedBlockNumber','finalizedBlockHash','safeNonce','safeThreshold','safeOwners','pilotRestrictedDeployment','permissionlessDeposits','pilotDepositConsumed','authorizedPilotDeposit','authorizedPilotSnapshot','authorizedPilotValidUntil','pilotAuthorizationGeneration','totalDeposited','derivedAuthorization'];
try {
 if(process.argv.length!==8) throw new Error('usage: prepare-pilot-deposit-gate-plan SNAPSHOT AUTHORIZATION_STATE RELEASE SAFE OBSERVATION_A OBSERVATION_B');
 const inputBytes=await Promise.all(process.argv.slice(2).map(value=>readDirectFile(value,{minimum:2,maximum:8*1024*1024,exactMode:0o600})));
 const [snapshot,authorizationState,releaseConfig,safePackage,a,b]=inputBytes.map((value,index)=>parseStrictJsonBytes(value,{label:`pilot gate input ${index}`}));
 if(!exact(a,keys)||JSON.stringify(a)!==JSON.stringify(b)||a.chainId!=='1'||a.safeThreshold!=='2'||JSON.stringify(a.safeOwners.map(value=>value.toLowerCase()).sort())!==JSON.stringify(safePackage.ownersByRole.governance.map(value=>value.toLowerCase()).sort())||a.pilotRestrictedDeployment!==true||a.permissionlessDeposits!==false||a.pilotDepositConsumed!==false||a.authorizedPilotDeposit!=='0x'+'0'.repeat(64)||a.authorizedPilotSnapshot!=='0x'+'0'.repeat(64)||a.authorizedPilotValidUntil!=='0'||a.totalDeposited!=='0') throw new Error('pilot gate dual-RPC prestate is divergent or already used');
 process.stdout.write(JSON.stringify(buildPilotDepositGatePlan({snapshot,authorizationState,releaseConfig,safePackage,safeNonce:a.safeNonce,pilotAuthorizationGeneration:a.pilotAuthorizationGeneration,finalizedBlockNumber:a.finalizedBlockNumber,finalizedBlockHash:a.finalizedBlockHash,observedAuthorization:a.derivedAuthorization}),null,2)+'\n');
} catch(error) { writeReleaseFailure('prepare-pilot-deposit-gate-plan',error); process.exitCode=1; }
