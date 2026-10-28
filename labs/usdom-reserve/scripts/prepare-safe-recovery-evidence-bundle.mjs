#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildSafeRecoveryEvidenceBundle,validateSafeRecoveryEvidenceBundle}
  from '../sdk/safe-recovery-evidence-bundle.mjs';

async function capture(file,label) {
  if(typeof file!=='string'||!path.isAbsolute(file)) throw new Error(`${label} path is invalid`);
  const bytes=await readDirectFile(file,{minimum:2,maximum:4*1024*1024,exactMode:0o600,label});
  return {file,label,bytes,value:parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64})};
}
try {
  if(process.argv.length!==3||!path.isAbsolute(process.argv[2])) throw new Error('report path is required');
  const roles=['governance','reserveGuardian','checkpointGuardian'];
  const directory=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;
  if(typeof directory!=='string'||!path.isAbsolute(directory)) throw new Error('evidence directory is invalid');
  const [pkg,baseline,plan,replacementProofs,transactions,report,...executions]=await Promise.all([
    capture(process.env.USDOM_SAFE_PACKAGE,'Safe package'),capture(process.env.USDOM_SAFE_BASELINE,'Safe baseline'),
    capture(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan'),
    capture(process.env.USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS,'Safe recovery replacement proofs'),
    capture(process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS,'Safe recovery transactions'),
    capture(process.argv[2],'Safe recovery final report'),
    ...roles.map(role=>capture(path.join(directory,`${role}-finalized-execution.json`),`${role} execution`)),
  ]);
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const rpcCatalogBytes=await readDirectProjectFile(root,
    'config/mainnet-preflight-rpc-catalog.json',{minimum:2,maximum:1024*1024,label:'RPC catalog'});
  const inputs={packageBytes:pkg.bytes,baselineBytes:baseline.bytes,planBytes:plan.bytes,
    replacementProofsBytes:replacementProofs.bytes,
    transactionPackageBytes:transactions.bytes,rpcCatalogBytes,executionBytes:executions.map(v=>v.bytes),
    reportBytes:report.bytes,packageDocument:pkg.value,baseline:baseline.value,plan:plan.value,
    replacementProofs:replacementProofs.value,
    transactionPackage:transactions.value,executions:executions.map(v=>v.value),report:report.value};
  const bundle=buildSafeRecoveryEvidenceBundle(inputs);
  validateSafeRecoveryEvidenceBundle(bundle,inputs);
  for(const input of [pkg,baseline,plan,replacementProofs,transactions,report,...executions]) {
    const current=await readDirectFile(input.file,{minimum:input.bytes.length,maximum:input.bytes.length,
      exactMode:0o600,label:input.label});
    if(!current.equals(input.bytes)) throw new Error(`${input.label} changed during bundle creation`);
  }
  const rpcCatalogAfter=await readDirectProjectFile(root,'config/mainnet-preflight-rpc-catalog.json',
    {minimum:rpcCatalogBytes.length,maximum:rpcCatalogBytes.length,label:'RPC catalog'});
  if(!rpcCatalogAfter.equals(rpcCatalogBytes)) throw new Error('RPC catalog changed during bundle creation');
  process.stdout.write(`${JSON.stringify(bundle,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-safe-recovery-evidence-bundle',error);
  process.exitCode=1;
}
