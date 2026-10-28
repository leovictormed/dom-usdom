#!/usr/bin/env node
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateSafeRecoveryEvidenceBundle} from '../sdk/safe-recovery-evidence-bundle.mjs';
import {buildRecoverableSafeControlReleaseEvidence} from '../sdk/safe-control-release-evidence.mjs';
import {validateSafeRecoveryReplacementProofs} from '../sdk/safe-recovery-replacement-proofs.mjs';

async function capture(file,label,maximum=4*1024*1024){
  if(typeof file!=='string'||!path.isAbsolute(file)) throw new Error(`${label} path is invalid`);
  const bytes=await readDirectFile(file,{minimum:2,maximum,exactMode:0o600,label});
  return {file,label,bytes,value:parseStrictJsonBytes(bytes,{label,maxBytes:maximum,maxDepth:64})};
}

try {
  const directory=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;
  if(typeof directory!=='string'||!path.isAbsolute(directory)) throw new Error('evidence directory is invalid');
  const roles=['governance','reserveGuardian','checkpointGuardian'];
  const [pkg,baseline,plan,transactions,replacementProofs,report,bundle,...executions]=await Promise.all([
    capture(process.env.USDOM_SAFE_PACKAGE,'Safe package'),capture(process.env.USDOM_SAFE_BASELINE,'Safe baseline'),
    capture(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan'),
    capture(process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS,'Safe recovery transactions'),
    capture(process.env.USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS,'replacement possession proofs'),
    capture(path.join(directory,'safe-recovery-finalized-report.json'),'Safe recovery final report'),
    capture(path.join(directory,'safe-recovery-finalized-bundle.json'),'Safe recovery final bundle'),
    ...roles.map(role=>capture(path.join(directory,`${role}-finalized-execution.json`),
      `${role} finalized execution`)),
  ]);
  validateSafeRecoveryReplacementProofs(plan.value,replacementProofs.value);
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const rpcCatalogBytes=await readDirectProjectFile(root,'config/mainnet-preflight-rpc-catalog.json',
    {minimum:2,maximum:1024*1024,label:'RPC catalog'});
  validateSafeRecoveryEvidenceBundle(bundle.value,{packageBytes:pkg.bytes,baselineBytes:baseline.bytes,
    planBytes:plan.bytes,replacementProofsBytes:replacementProofs.bytes,
    transactionPackageBytes:transactions.bytes,rpcCatalogBytes,
    executionBytes:executions.map(value=>value.bytes),reportBytes:report.bytes,
    packageDocument:pkg.value,baseline:baseline.value,plan:plan.value,
    replacementProofs:replacementProofs.value,
    transactionPackage:transactions.value,executions:executions.map(value=>value.value),report:report.value});
  const release=buildRecoverableSafeControlReleaseEvidence({packageDocument:pkg.value,
    baselineSnapshot:baseline.value,recoveryReport:report.value});
  for(const [index,role] of roles.entries()) {
    const releaseRole=role==='reserveGuardian'?'guardian':role;
    const roleEvidence=release.roleReports[releaseRole];
    const planned=plan.value.roles.find(entry=>entry?.role===role);
    if(!planned||roleEvidence.replacementOwner.toLowerCase()!==planned.newOwner.toLowerCase()
        ||!roleEvidence.ownersAfter.some(owner=>owner.toLowerCase()===planned.newOwner.toLowerCase())
        ||roleEvidence.ownersAfter.some(owner=>owner.toLowerCase()===roleEvidence.lostOwner.toLowerCase())
        ||roleEvidence.threshold!=='2'||roleEvidence.ownersAfter.length!==3
        ||bundle.value.executions[index].transactionHash!==roleEvidence.recoveryTransactionHash) {
      throw new Error(`${role} owner replacement or post-recovery 2-of-3 liveness is not proven`);
    }
  }
  for(const input of [pkg,baseline,plan,transactions,replacementProofs,report,bundle,...executions]) {
    const current=await readDirectFile(input.file,{minimum:input.bytes.length,maximum:input.bytes.length,
      exactMode:0o600,label:input.label});
    if(!current.equals(input.bytes)) throw new Error(`${input.label} changed during completion validation`);
  }
  const rpcAfter=await readDirectProjectFile(root,'config/mainnet-preflight-rpc-catalog.json',
    {minimum:rpcCatalogBytes.length,maximum:rpcCatalogBytes.length,label:'RPC catalog'});
  if(!rpcAfter.equals(rpcCatalogBytes)) throw new Error('RPC catalog changed during completion validation');
  process.stdout.write(`${JSON.stringify({schema:'usdom-safe-recovery-final-completion/v1',valid:true,
    planHash:plan.value.planHash,recoveryHash:report.value.recoveryHash,replacementProofCount:3,
    finalizedExecutionCount:3,liveness:'2-of-3'})}\n`);
} catch(error) {
  writeReleaseFailure('check-safe-recovery-final-completion',error);
  process.exitCode=1;
}
