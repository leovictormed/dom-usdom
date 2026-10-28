#!/usr/bin/env node
import path from 'node:path';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateNativeFinalizedDepositVector} from '../sdk/native-deposit-vector.mjs';

if(process.argv.length!==2||!process.env.HOME) throw new Error('usage: check-native-finalized-deposit-vector.mjs');
const root=path.resolve(import.meta.dirname,'..');
const wallet=path.join(process.env.HOME,'.local/share/dom-usdom/mainnet-wallet');
const projectInputs=['evidence/native-runtime/native-usdom-v2.json',
  'evidence/native-runtime/native-usdom-v2.manifest.sha256',
  'evidence/finalized-deposit-source/finalized-deposit-source.json',
  'config/proof-reserve.unconfigured.json',
  'evidence/finalized-deposit-witness/finalized-deposit-witness.bin',
  'evidence/finalized-deposit-witness/finalized-deposit-witness-index.json'];
const walletInputs=['registered-state-v1/expected-deposit-registration.json',
  'registered-state-v1/issuance-submission.json','registered-state-v1/issuance-block-production.json',
  'observed-state-v1/canonical-deposit-observation.json'];
const projectBytes=await Promise.all(projectInputs.map(relative=>readDirectProjectFile(root,relative)));
const walletBytes=await Promise.all(walletInputs.map(relative=>readDirectFile(path.join(wallet,relative),
  {minimum:1,maximum:4*1024*1024,privateMode:true,label:path.basename(relative)})));
const [manifest,pinBytes,sourceBytes,releaseConfigBytes,witness,indexBytes]=projectBytes;
const pinText=new TextDecoder('utf-8',{fatal:true}).decode(pinBytes);
if(!/^[0-9a-f]{64}\n$/.test(pinText)) throw new Error('native manifest pin framing is invalid');
const pin=pinText.slice(0,-1);
const parsed=[indexBytes,...walletBytes].map((bytes,index)=>parseStrictJsonBytes(bytes,
  {label:index===0?'finalized-deposit-witness-index.json':path.basename(walletInputs[index-1])}));
const [index,registration,submission,block,observation]=parsed;
const value=validateNativeFinalizedDepositVector({manifestBytes:manifest,manifestPin:pin,
  sourceBytes,releaseConfigBytes,witness,index,registration,submission,block,observation});
const [projectAfter,walletAfter]=await Promise.all([
  Promise.all(projectInputs.map(relative=>readDirectProjectFile(root,relative))),
  Promise.all(walletInputs.map(relative=>readDirectFile(path.join(wallet,relative),
    {minimum:1,maximum:4*1024*1024,privateMode:true,label:path.basename(relative)}))),
]);
if(projectAfter.some((bytes,index)=>!bytes.equals(projectBytes[index]))
    ||walletAfter.some((bytes,index)=>!bytes.equals(walletBytes[index]))) {
  throw new Error('native finalized-deposit vector inputs changed during validation');
}
process.stdout.write(`${JSON.stringify(value,null,2)}\n`);
