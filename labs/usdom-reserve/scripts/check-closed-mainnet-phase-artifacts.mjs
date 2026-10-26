#!/usr/bin/env node
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {getAddress} from 'ethers';
import {validateMainnetDeploymentPackage} from '../sdk/deployment-package.mjs';
import {validateMainnetDeploymentIdentityObservation} from '../sdk/mainnet-deployment-identity.mjs';
import {validateRecoverableSafeControlBaseline} from '../sdk/safe-control-observation.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {reconcileClosedMainnetPilotDag} from '../sdk/closed-mainnet-pilot-dag.mjs';
import {validateClosedMainnetDepositPackage} from '../sdk/closed-mainnet-deposit.mjs';
import {validateClosedMainnetRedemptionPackage} from '../sdk/closed-mainnet-redemption-execution.mjs';
import {validateClosedMainnetPayoutEvidence} from '../sdk/closed-mainnet-payout-evidence.mjs';
import {validateClosedMainnetDepositEvidence} from '../sdk/closed-mainnet-deposit-evidence.mjs';
import {validateClosedMainnetRedemptionRelease} from '../sdk/closed-mainnet-redemption-release.mjs';
import {validatePilotReceiptCost} from '../sdk/pilot-receipt-cost.mjs';
import {validatePilotTransactionEvidence} from '../sdk/closed-mainnet-pilot-evidence.mjs';
import {validateClosedMainnetPilotBudget} from '../sdk/closed-mainnet-pilot-budget.mjs';
import {validateClosedMainnetFinancialConservation} from '../sdk/closed-mainnet-financial-conservation.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const requirement=process.argv[2]??'inventory';
if(!['inventory','require-deposit-complete','require-pilot-complete'].includes(requirement)||process.argv.length>3) {
  process.stderr.write('usage: check-closed-mainnet-phase-artifacts.mjs [require-deposit-complete|require-pilot-complete]\n');
  process.exit(64);
}
const evidence='/home/leonardov/usdom-mainnet-private/control-plane';
const locations={
  owners:path.join(evidence,'safe-owner-identities.json'),
  safePackage:path.join(evidence,'safe-package.json'),
  baseline:path.join(evidence,'safe-baseline-primary.json'),
  identity:path.join(evidence,'mainnet-deployment-identity-observation.json'),
  deployment:path.join(evidence,'mainnet-deployment-package.json'),
  depositPackage:path.join(evidence,'closed-mainnet-deposit-package.json'),
  depositExecution:path.join(evidence,'closed-mainnet-deposit-execution.json'),
  redemptionPackage:path.join(evidence,'closed-mainnet-redemption-package.json'),
  redemptionExecution:path.join(evidence,'closed-mainnet-redemption-execution.json'),
};
const result=[];
const loaded=new Map();
function sha(bytes){return createHash('sha256').update(bytes).digest('hex');}
function exact(value,keys,label){
  if(!value||Array.isArray(value)||typeof value!=='object'
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    throw new Error(`${label} schema is not exact`);
  }
}
function load(name,{mode=0o600}={}){
  const target=locations[name],stat=fs.lstatSync(target,{throwIfNoEntry:false});
  if(!stat){result.push({artifact:name,status:'missing',path:target}); return undefined;}
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||(stat.mode&0o777)!==mode) {
    throw new Error(`${name} must be one regular, nonlinked ${mode.toString(8)} file`);
  }
  const bytes=fs.readFileSync(target);
  if(bytes.length===0||bytes.length>4*1024*1024) throw new Error(`${name} size is invalid`);
  let value;
  try { value=parseStrictJson(bytes.toString('utf8'),{label:name,maxBytes:4*1024*1024,maxDepth:64}); }
  catch { throw new Error(`${name} JSON is invalid`); }
  loaded.set(name,{bytes,value,sha256:sha(bytes)});
  return value;
}
function verified(name,detail={}){result.push({artifact:name,status:'verified',path:locations[name],...detail});}
function evidenceJson(target,label) {
  const stat=fs.lstatSync(target,{throwIfNoEntry:false});
  if(!stat) return undefined;
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||(stat.mode&0o777)!==0o600) {
    throw new Error(`${label} must be one regular, nonlinked 600 file`);
  }
  const bytes=fs.readFileSync(target);
  if(bytes.length===0||bytes.length>4*1024*1024) throw new Error(`${label} size is invalid`);
  return parseStrictJson(bytes.toString('utf8'),{label,maxBytes:4*1024*1024,maxDepth:64});
}

try {
  const owners=load('owners');
  if(owners){
    exact(owners,['schema','ownersByRole'],'owners');
    if(owners.schema!=='usdom-safe-owner-identities/v2') throw new Error('owners schema is invalid');
    const roleNames=['governance','reserveGuardian','checkpointGuardian'];
    exact(owners.ownersByRole,roleNames,'ownersByRole');
    const ownerSet=roleNames.flatMap(role=>{
      const values=owners.ownersByRole[role];
      if(!Array.isArray(values)||values.length!==3) throw new Error(`${role} owners are invalid`);
      return values.map(getAddress).map(value=>value.toLowerCase());
    });
    if(new Set(ownerSet).size!==9) throw new Error('owners are not nine globally distinct addresses');
    verified('owners',{sha256:loaded.get('owners').sha256});
  }
  const safePackage=load('safePackage');
  if(safePackage){
    if(!owners) throw new Error('safePackage exists before owners');
    if(safePackage.schema!=='usdom-safe-controls-recoverable/v2'
        ||safePackage.ethereumChainId!=='1'||safePackage.threshold!=='2'
        ||!Array.isArray(safePackage.controls)||safePackage.controls.length!==3) {
      throw new Error('safePackage header is invalid');
    }
    if(JSON.stringify(safePackage.ownersByRole)!==JSON.stringify(owners.ownersByRole)) {
      throw new Error('safePackage owners are stale/foreign');
    }
    const roles=safePackage.controls.map(value=>value?.role);
    if(JSON.stringify(roles)!==JSON.stringify(['governance','reserveGuardian','checkpointGuardian'])) {
      throw new Error('safePackage role order is invalid');
    }
    result.push({artifact:'safePackage',status:'bound-to-owners-awaiting-baseline',
      path:locations.safePackage,sha256:loaded.get('safePackage').sha256});
  }
  const baseline=load('baseline');
  if(baseline){
    if(!safePackage) throw new Error('baseline exists before safePackage');
    validateRecoverableSafeControlBaseline(baseline,safePackage);
    verified('baseline',{snapshotHash:baseline.snapshotHash});
  }
  const identity=load('identity');
  if(identity){
    const release=parseStrictJson(fs.readFileSync(path.join(root,'config/proof-reserve.unconfigured.json'),'utf8'),
      {label:'release configuration',maxBytes:4*1024*1024,maxDepth:64});
    validateMainnetDeploymentIdentityObservation({observation:identity,releaseConfigAfter:release});
    verified('identity',{sha256:loaded.get('identity').sha256,observationHash:identity.observationHash});
  }
  const deployment=load('deployment');
  if(deployment){
    if(!identity) throw new Error('deployment exists before identity');
    validateMainnetDeploymentPackage(deployment);
    const releaseBytes=fs.readFileSync(path.join(root,'config/proof-reserve.unconfigured.json'));
    if(deployment.observationDocumentSha256!==loaded.get('identity').sha256
        ||deployment.observationHash!==identity.observationHash
        ||deployment.releaseConfigSha256!==sha(releaseBytes)) {
      throw new Error('deployment package is stale/foreign');
    }
    verified('deployment',{sha256:loaded.get('deployment').sha256});
  }
  for(const [artifact,file] of [['predeploymentAttestation','mainnet-predeployment-attestation.json'],
    ['coldStartAttestation','mainnet-cold-start-attestation.json']]) {
    const target=path.join(evidence,file);
    result.push({artifact,status:fs.existsSync(target)?'deferred-to-readiness':'missing',path:target});
  }
  const pilot={};
  let completedDepositPackage,completedDepositExecution,completedRedemptionPackage,completedRedemptionExecution;
  const depositMaximumCosts=[],redemptionMaximumCosts=[];
  const depositPackage=load('depositPackage');
  if(depositPackage) {
    validateClosedMainnetDepositPackage(depositPackage);
    const releasePath=path.join(root,'config/proof-reserve.unconfigured.json');
    const releaseBytes=fs.readFileSync(releasePath);
    const release=parseStrictJson(releaseBytes.toString('utf8'),{label:'current release'});
    if(depositPackage.releaseConfigSha256!==sha(releaseBytes)
        ||depositPackage.reserveConfigHash!==release.reserveConfigHash?.toLowerCase()
        ||getAddress(depositPackage.token)!==getAddress(release.token)
        ||getAddress(depositPackage.reserve)!==getAddress(release.reserve)) {
      throw new Error('deposit package is stale or belongs to another release');
    }
    const receipts=[];
    for(let index=0;index<3;index++) {
      const receiptPath=path.join(evidence,`closed-deposit-${index}-receipt.json`);
      const validationPath=path.join(evidence,`closed-deposit-${index}-validation.json`);
      const finalityPath=path.join(evidence,`closed-deposit-${index}-finality.json`);
      if(!fs.existsSync(receiptPath)&&!fs.existsSync(validationPath)) break;
      if(!fs.existsSync(receiptPath)||!fs.existsSync(validationPath)) throw new Error('deposit crash pair is incomplete');
      const receipt=evidenceJson(receiptPath,'deposit receipt');
      const validation=evidenceJson(validationPath,'deposit validation');
      const finality=evidenceJson(finalityPath,'deposit finality');
      validatePilotTransactionEvidence({kind:'deposit',index,receipt,validation,finality,
        transaction:depositPackage.transactions[index],signer:depositPackage.funder});
      const cost=validatePilotReceiptCost({gasUsed:receipt.gasUsed,effectiveGasPrice:receipt.effectiveGasPrice,
        maximumCost:validation.maximumCost});
      depositMaximumCosts.push(cost.maximumCost);
      if(finality&&(!Object.entries(cost).every(([key,value])=>finality[key]===value))) throw new Error('deposit finality gas cost is invalid');
      receipts.push({nonce:validation.nonce,finalizedRpcCount:finality?.finalizedRpcCount??0,
        canonical:receipt.status!=='0x1'?false:!finality?null:finality.transactionHash?.toLowerCase()===validation.transactionHash?.toLowerCase()
          &&finality?.blockNumber===receipt.blockNumber&&finality?.blockHash?.toLowerCase()===receipt.blockHash?.toLowerCase()});
    }
    const execution=evidenceJson(locations.depositExecution,'deposit execution')??null;
    if(execution&&execution.packageSha256!==loaded.get('depositPackage').sha256) throw new Error('deposit execution references foreign package');
    if(execution) {
      const baselinePath=path.join(evidence,'closed-mainnet-deposit-financial-baseline.json');
      const baseline=evidenceJson(baselinePath,'deposit financial baseline');
      validateClosedMainnetDepositEvidence({baseline,baselineSha256:sha(fs.readFileSync(baselinePath)),
        execution,packageValue:depositPackage});
      completedDepositPackage=depositPackage; completedDepositExecution=execution;
    }
    const baseNonce=receipts[0]?.nonce??'0';
    pilot.deposit={packageSha256:loaded.get('depositPackage').sha256,
      amountBaseUnits:depositPackage.amountBaseUnits,broadcastAuthorized:depositPackage.broadcastAuthorized,
      baseNonce,receipts,pendingNonce:(BigInt(baseNonce)+BigInt(receipts.length)).toString(),
      allowanceAfter:execution?.allowanceAfter??'0'};
  }
  const redemptionPackage=load('redemptionPackage');
  if(redemptionPackage) {
    const submissionPath=path.join(root,'evidence/finalized-burn-submission/finalized-burn-submission.json');
    if(!fs.existsSync(submissionPath)) throw new Error('redemption package exists before authenticated submission');
    const submission=parseStrictJson(fs.readFileSync(submissionPath,'utf8'),{label:'finalized burn submission'});
    validateClosedMainnetRedemptionPackage(redemptionPackage,submission);
    const releasePath=path.join(root,'config/proof-reserve.unconfigured.json');
    const verifierPath=path.join(root,'config/finalized-burn-verifier.unconfigured.json');
    const releaseBytes=fs.readFileSync(releasePath),verifierBytes=fs.readFileSync(verifierPath);
    const release=parseStrictJson(releaseBytes.toString('utf8'),{label:'current release'});
    validateClosedMainnetRedemptionRelease({submission,packageValue:redemptionPackage,release,
      releaseConfigSha256:sha(releaseBytes),verifierManifestSha256:sha(verifierBytes)});
    const receipts=[];
    for(let index=0;index<2;index++) {
      const receiptPath=path.join(evidence,`closed-redemption-${index}-receipt.json`);
      const validationPath=path.join(evidence,`closed-redemption-${index}-validation.json`);
      const finalityPath=path.join(evidence,`closed-redemption-${index}-finality.json`);
      if(!fs.existsSync(receiptPath)&&!fs.existsSync(validationPath)) break;
      if(!fs.existsSync(receiptPath)||!fs.existsSync(validationPath)) throw new Error('redemption crash pair is incomplete');
      const receipt=evidenceJson(receiptPath,'redemption receipt');
      const validation=evidenceJson(validationPath,'redemption validation');
      const finality=evidenceJson(finalityPath,'redemption finality');
      validatePilotTransactionEvidence({kind:'redemption',index,receipt,validation,finality,
        transaction:redemptionPackage.transactions[index],signer:redemptionPackage.recipient});
      const cost=validatePilotReceiptCost({gasUsed:receipt.gasUsed,effectiveGasPrice:receipt.effectiveGasPrice,
        maximumCost:validation.maximumCost});
      redemptionMaximumCosts.push(cost.maximumCost);
      if(finality&&(!Object.entries(cost).every(([key,value])=>finality[key]===value))) throw new Error('redemption finality gas cost is invalid');
      receipts.push({nonce:validation.nonce,finalizedRpcCount:finality?.finalizedRpcCount??0,
        canonical:receipt.status!=='0x1'?false:!finality?null:finality.transactionHash?.toLowerCase()===validation.transactionHash?.toLowerCase()
          &&finality?.blockNumber===receipt.blockNumber&&finality?.blockHash?.toLowerCase()===receipt.blockHash?.toLowerCase()});
    }
    const execution=evidenceJson(locations.redemptionExecution,'redemption execution')??null;
    if(execution&&execution.packageSha256!==loaded.get('redemptionPackage').sha256) throw new Error('redemption execution references foreign package');
    if(execution) {
      const baselinePath=path.join(evidence,'closed-mainnet-redemption-payout-baseline.json');
      const baseline=evidenceJson(baselinePath,'redemption payout baseline');
      const baselineBytes=fs.readFileSync(baselinePath);
      validateClosedMainnetPayoutEvidence({baseline,baselineSha256:sha(baselineBytes),
        execution,packageValue:redemptionPackage});
      completedRedemptionPackage=redemptionPackage; completedRedemptionExecution=execution;
    }
    const baseNonce=receipts[0]?.nonce??'0';
    pilot.redemption={packageSha256:loaded.get('redemptionPackage').sha256,
      amountBaseUnits:redemptionPackage.amountBaseUnits,broadcastAuthorized:redemptionPackage.broadcastAuthorized,
      burnId:redemptionPackage.burnId,requestId:redemptionPackage.requestId,baseNonce,receipts,
      pendingNonce:(BigInt(baseNonce)+BigInt(receipts.length)).toString(),
      paidBurn:execution?true:false,paidRequest:execution?true:false};
  }
  if(completedDepositExecution||completedRedemptionExecution) {
    if(!completedDepositExecution||!completedRedemptionExecution) {
      if(requirement==='require-pilot-complete') throw new Error('financial conservation requires both terminal executions');
    } else {
      const issuanceIndexPath=path.join(root,'evidence/finalized-deposit-witness/finalized-deposit-witness-index.json');
      const issuanceIndex=evidenceJson(issuanceIndexPath,'finalized deposit issuance index');
      if(!issuanceIndex) throw new Error('terminal pilot lacks finalized deposit issuance evidence');
      const conservation=validateClosedMainnetFinancialConservation({depositPackage:completedDepositPackage,
        depositExecution:completedDepositExecution,issuanceIndex,
        redemptionPackage:completedRedemptionPackage,redemptionExecution:completedRedemptionExecution});
      result.push({artifact:'financialConservation',status:'verified',
        amountBaseUnits:conservation.amountBaseUnits,conserved:conservation.conserved});
    }
  }
  const pilotDag=reconcileClosedMainnetPilotDag(pilot);
  const pilotBudget=validateClosedMainnetPilotBudget({depositMaximumCosts,redemptionMaximumCosts});
  const phaseStatus=Object.fromEntries(pilotDag.phases.map(phase=>[phase.phase,phase.status]));
  if(requirement==='require-deposit-complete'&&phaseStatus.deposit!=='complete') {
    throw new Error(`deposit phase is ${phaseStatus.deposit??'absent'}, not complete`);
  }
  if(requirement==='require-pilot-complete'
      &&(phaseStatus.deposit!=='complete'||phaseStatus.redemption!=='complete')) {
    throw new Error(`pilot phases are deposit=${phaseStatus.deposit??'absent'}, redemption=${phaseStatus.redemption??'absent'}`);
  }
  result.push({artifact:'pilot',status:'reconciled',detail:pilotDag,budget:pilotBudget});
  process.stdout.write(`${JSON.stringify({schema:'usdom-closed-mainnet-phase-checklist/v1',artifacts:result},null,2)}\n`);
} catch(error) {
  writePilotFailure('closed-mainnet-phase-check',error);
  process.exitCode=1;
}
