#!/usr/bin/env node
import {createHash} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import process from 'node:process';
import {validateClosedMainnetDepositEvidence} from '../sdk/closed-mainnet-deposit-evidence.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  if(process.argv.length!==6) throw new Error('usage: check-closed-mainnet-deposit-evidence BASELINE EXECUTION PACKAGE DEPOSIT_FINALITY');
  const paths=process.argv.slice(2);
  const labels=['deposit baseline','deposit execution','deposit package','deposit finality'];
  const bytes=await Promise.all(paths.map((path,index)=>readDirectFile(path,{
    minimum:2,maximum:4*1024*1024,label:labels[index],
  })));
  const values=bytes.map((value,index)=>parseStrictJsonBytes(value,{
    label:labels[index],maxBytes:4*1024*1024,maxDepth:64,maxNodes:100_000,
    maxStringBytes:4*1024*1024,maxObjectEntries:10_000,maxArrayEntries:10_000,
  }));
  const baselineSha256=createHash('sha256').update(bytes[0]).digest('hex');
  const packageSha256=createHash('sha256').update(bytes[2]).digest('hex');
  const depositFinalitySha256=createHash('sha256').update(bytes[3]).digest('hex');
  const walletPath=path.join(os.homedir(),'.local','share','dom-usdom','mainnet-wallet','public-identity.json');
  const [releaseBytes,requirementsBytes,walletBytes,pilotFundsSnapshotBytes,
    pilotFundsAuthorizationStateBytes]=await Promise.all([
    readDirectProjectFile(root,'config/proof-reserve.unconfigured.json'),
    readDirectProjectFile(root,'config/production-requirements.json'),
    readDirectFile(walletPath,{minimum:1,maximum:64*1024,privateMode:true,label:'public wallet identity'}),
    readDirectProjectFile(root,'evidence/authorization/pilot-funds-snapshot.json',{exactMode:0o600}),
    readDirectProjectFile(root,'evidence/authorization/pilot-funds-authorization-state.json',{exactMode:0o600}),
  ]);
  const parse=(value,label)=>parseStrictJsonBytes(value,{label,maxBytes:4*1024*1024,maxDepth:64,
    maxNodes:100_000,maxStringBytes:4*1024*1024,maxObjectEntries:10_000,maxArrayEntries:10_000});
  const release=parse(releaseBytes,'closed deposit release'),wallet=parse(walletBytes,'closed deposit wallet');
  const requirements=parse(requirementsBytes,'production requirements');
  const pilotFundsSnapshot=parse(pilotFundsSnapshotBytes,'closed deposit pilot snapshot');
  const pilotFundsAuthorizationState=parse(pilotFundsAuthorizationStateBytes,'closed deposit authorization state');
  const sha=value=>createHash('sha256').update(value).digest('hex');
  validateClosedMainnetDepositEvidence({baseline:values[0],baselineSha256,packageSha256,
    execution:values[1],packageValue:values[2],baselineBytes:bytes[0],executionBytes:bytes[1],
    packageBytes:bytes[2],depositFinality:values[3],depositFinalityBytes:bytes[3],depositFinalitySha256,
    release,releaseBytes,releaseSha256:sha(releaseBytes),wallet,walletBytes,
    walletSha256:sha(walletBytes),pilotFundsSnapshot,pilotFundsSnapshotBytes,
    pilotFundsSnapshotSha256:sha(pilotFundsSnapshotBytes),pilotFundsAuthorizationState,
    pilotFundsAuthorizationStateBytes,pilotFundsAuthorizationStateSha256:sha(pilotFundsAuthorizationStateBytes),
    expectedPrivacyPolicyHash:`0x${requirements.native_privacy_policy_hash}`});
  process.stdout.write('ok\n');
} catch(error) {
  writePilotFailure('check-closed-mainnet-deposit-evidence',error);
  process.exitCode=1;
}
