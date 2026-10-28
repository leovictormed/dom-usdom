#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {constants,open,readFile,lstat,mkdir} from 'node:fs/promises';
import path from 'node:path';

const fail=message=>{throw new Error(message)};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const canonical=value=>JSON.stringify(value,null,2)+'\n';
async function privateFile(file,label,id=label){
 const info=await lstat(file,{bigint:false});
 if(!info.isFile()||info.isSymbolicLink()||info.mode%512!==0o600||info.nlink!==1||info.uid!==process.getuid()) fail(`${label} is not a private create-once regular file`);
 const bytes=await readFile(file);if(bytes.length<2||bytes.length>16*1024*1024)fail(`${label} size is invalid`);
 return {id,path:path.basename(file),sha256:sha(bytes),bytes};
}
async function assertPrivateDirectory(directory){
 const info=await lstat(directory);
 if(!info.isDirectory()||info.isSymbolicLink()||info.mode%512!==0o700||info.nlink<2||info.uid!==process.getuid())fail(`output directory is not private: ${directory}`);
}
async function privateDirectory(directory){await mkdir(directory,{recursive:true,mode:0o700});await assertPrivateDirectory(directory);}
async function install(directory,document){
 const bytes=Buffer.from(canonical(document)),digest=sha(bytes),file=path.join(directory,`${digest}.json`);
 try{const handle=await open(file,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);try{await handle.writeFile(bytes);await handle.sync();}finally{await handle.close();}}catch(error){if(error.code!=='EEXIST')throw error;const existing=await readFile(file);if(!existing.equals(bytes))fail('content-addressed artifact collision');}
 return {file,sha256:digest};
}
try{
 if(process.argv.length<7||process.argv.length>8||process.argv[7]&&process.argv[7]!=='--verify-only')fail('usage: materialize-onekey-ios-pilot-preparation-plan STATE_DIR RELAYER_DIR SAFE_PACKAGE WALLETCONNECT_CONFIG OUTPUT_DIR [--verify-only]');
 const [stateDir,relayerDir,safePackage,walletConnectConfig,outputDir]=process.argv.slice(2),verifyOnly=process.argv[7]==='--verify-only';
 if(!verifyOnly){await privateDirectory(outputDir);await privateDirectory(path.join(outputDir,'readiness'));await privateDirectory(path.join(outputDir,'plans'));}
 else {await assertPrivateDirectory(outputDir);await assertPrivateDirectory(path.join(outputDir,'readiness'));await assertPrivateDirectory(path.join(outputDir,'plans'));}
 const artifacts=[];
 for(let i=1;i<=3;i++)artifacts.push(await privateFile(path.join(stateDir,`owner-${i}-evidence.json`),`owner ${i} evidence`));
 for(const role of ['deployment','safe-deployment','recovery','reserve-resume','pilot-gate'])artifacts.push(await privateFile(path.join(relayerDir,role,'relayer-public-identity.json'),`${role} relayer identity`,`relayer:${role}`));
 artifacts.push(await privateFile(path.join(stateDir,'safe-owner-identities-v2.json'),'owner identities'));
 artifacts.push(await privateFile(safePackage,'Safe package'));
 artifacts.push(await privateFile(walletConnectConfig,'WalletConnect client configuration'));
 for(let i=0;i<12;i++)artifacts.push(await privateFile(path.join(stateDir,`custody-signature-${i}.json`),`custody signature ${i}`));
 artifacts.push(await privateFile(path.join(stateDir,'safe-owner-hardware-custody-proofs-v1.json'),'custody proof bundle'));
 const evidence=artifacts.map(({id,path,sha256})=>({id,path,sha256}));
 const report={schema:'usdom-onekey-ios-pilot-preparation-readiness/v1',codeReady:true,externalEvidenceReady:false,fundsAuthorized:false,automaticFundsAuthorization:false,externalEvidencePending:['real-mainnet-rpc-observations','deployed-contract-identities-and-codehashes','dual-rpc-finality','operator-risk-ratification','pilot-funds-authorization','closed-deposit-and-redemption-evidence'],evidence};
 const reportBytes=Buffer.from(canonical(report)),reportSha256=sha(reportBytes);
 const plan={schema:'usdom-onekey-ios-pilot-offline-plan/v1',chainId:'1',route:'onekey-classic-1s-iphone-walletconnect-eip712',safeThreshold:2,codeReady:true,fundsAuthorized:false,readinessReportSha256:reportSha256,evidence};
 const planBytes=Buffer.from(canonical(plan)),planSha256=sha(planBytes);
 const marker={schema:'usdom-onekey-ios-pilot-plan-ready/v1',planSha256,readinessReportSha256:reportSha256,codeReady:true,externalEvidenceReady:false,fundsAuthorized:false};
 const markerBytes=Buffer.from(canonical(marker)),markerPath=path.join(outputDir,'plan-ready.json');
 if(verifyOnly){
  for(const [file,expected] of [[path.join(outputDir,'readiness',`${reportSha256}.json`),reportBytes],[path.join(outputDir,'plans',`${planSha256}.json`),planBytes],[markerPath,markerBytes]])if(!(await privateFile(file,'installed preparation artifact')).bytes.equals(expected))fail('installed preparation artifact differs from current evidence');
  process.stdout.write(`${path.join(outputDir,'plans',`${planSha256}.json`)}\n`);process.exit(0);
 }
 const reportInstalled=await install(path.join(outputDir,'readiness'),report),planInstalled=await install(path.join(outputDir,'plans'),plan);
 try{const h=await open(markerPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);try{await h.writeFile(markerBytes);await h.sync();}finally{await h.close();}}catch(error){if(error.code!=='EEXIST')throw error;if(!(await readFile(markerPath)).equals(markerBytes))fail('installed plan-ready marker differs');}
 process.stdout.write(`${planInstalled.file}\n`);
}catch(error){console.error(`PILOT_PREPARATION_PLAN_REJECTED: ${error.message}`);process.exitCode=1;}
