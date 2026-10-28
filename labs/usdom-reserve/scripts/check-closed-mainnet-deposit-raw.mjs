#!/usr/bin/env node
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateClosedMainnetDepositRawTransaction} from '../sdk/closed-mainnet-deposit-execution.mjs';
import {readPrivateRawTransaction} from '../sdk/private-raw-transaction.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');

try {
  if(process.argv.length!==5) throw new Error('usage: check-closed-mainnet-deposit-raw.mjs PACKAGE INDEX NONCE');
  const packageBytes=await readDirectFile(process.argv[2],{
    minimum:2,maximum:4*1024*1024,label:'deposit package',
  });
  const packageValue=parseStrictJsonBytes(packageBytes,{label:'deposit package',maxBytes:4*1024*1024,
    maxDepth:64,maxNodes:100_000,maxStringBytes:4*1024*1024,
    maxObjectEntries:10_000,maxArrayEntries:10_000});
  if(process.env.USDOM_CLOSED_MAINNET_DEPOSIT_RAW!==undefined) throw new Error('raw transaction environment values are forbidden');
  const walletPath=path.join(os.homedir(),'.local','share','dom-usdom','mainnet-wallet','public-identity.json');
  const [releaseBytes,requirementsBytes,walletBytes,pilotFundsSnapshotBytes,
    pilotFundsAuthorizationStateBytes]=await Promise.all([
    readDirectProjectFile(root,'config/proof-reserve.unconfigured.json'),
    readDirectProjectFile(root,'config/production-requirements.json'),
    readDirectFile(walletPath,{minimum:1,maximum:64*1024,privateMode:true,
      label:'public wallet identity'}),
    readDirectProjectFile(root,'evidence/authorization/pilot-funds-snapshot.json',{exactMode:0o600}),
    readDirectProjectFile(root,'evidence/authorization/pilot-funds-authorization-state.json',
      {exactMode:0o600}),
  ]);
  const parse=(bytes,label,maximum=256*1024)=>parseStrictJsonBytes(bytes,{label,
    maxBytes:maximum,maxDepth:64,maxNodes:100_000,maxStringBytes:maximum,
    maxObjectEntries:10_000,maxArrayEntries:10_000});
  const release=parse(releaseBytes,'closed deposit release');
  const requirements=parse(requirementsBytes,'production requirements');
  const wallet=parse(walletBytes,'closed deposit wallet',64*1024);
  const pilotFundsSnapshot=parse(pilotFundsSnapshotBytes,'closed deposit pilot snapshot');
  const pilotFundsAuthorizationState=parse(pilotFundsAuthorizationStateBytes,
    'closed deposit pilot authorization state');
  const raw=readPrivateRawTransaction(process.env.USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE);
  const result=validateClosedMainnetDepositRawTransaction({raw,packageValue,
    index:Number(process.argv[3]),nonce:process.argv[4],release,releaseBytes,
    releaseSha256:sha256(releaseBytes),wallet,walletBytes,walletSha256:sha256(walletBytes),
    pilotFundsSnapshot,pilotFundsSnapshotBytes,
    pilotFundsSnapshotSha256:sha256(pilotFundsSnapshotBytes),pilotFundsAuthorizationState,
    pilotFundsAuthorizationStateBytes,
    pilotFundsAuthorizationStateSha256:sha256(pilotFundsAuthorizationStateBytes),
    expectedPrivacyPolicyHash:`0x${requirements.native_privacy_policy_hash}`});
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error){
  writePilotFailure('closed-mainnet-deposit-raw-check',error);
  process.exitCode=1;
}
