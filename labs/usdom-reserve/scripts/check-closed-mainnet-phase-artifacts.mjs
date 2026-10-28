#!/usr/bin/env node
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
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
import {validatePilotTransactionEvidence,validatePilotTransactionOrder} from '../sdk/closed-mainnet-pilot-evidence.mjs';
import {validateClosedMainnetPilotBudget} from '../sdk/closed-mainnet-pilot-budget.mjs';
import {validateClosedMainnetFinancialConservation} from '../sdk/closed-mainnet-financial-conservation.mjs';
import {canonicalOwnersByRole} from '../sdk/safe-control-deployment.mjs';

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
const localSnapshots=new Map();
const allSnapshots=new Map();
function sha(bytes){return createHash('sha256').update(bytes).digest('hex');}
function exact(value,keys,label){
  if(!value||Array.isArray(value)||typeof value!=='object'
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    throw new Error(`${label} schema is not exact`);
  }
}
function directSnapshot(target,label,{mode=0o600,missing=false}={}) {
  let fd;
  try { fd=fs.openSync(target,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW); }
  catch(error) {
    if(missing&&error?.code==='ENOENT') return undefined;
    throw new Error(`${label} is not a safe direct file: ${error?.code??'open failed'}`);
  }
  try {
    const before=fs.fstatSync(fd,{bigint:true});
    const expectedUid=typeof process.getuid==='function'?BigInt(process.getuid()):before.uid;
    if(!before.isFile()||before.uid!==expectedUid||before.nlink!==1n
        ||(before.mode&0o777n)!==BigInt(mode)) {
      throw new Error(`${label} must be one regular, nonlinked ${mode.toString(8)} file`);
    }
    if(fs.realpathSync(`/proc/self/fd/${fd}`)!==path.resolve(target)) throw new Error(`${label} path changed before read`);
    const bytes=fs.readFileSync(fd),after=fs.fstatSync(fd,{bigint:true});
    const named=fs.lstatSync(target,{throwIfNoEntry:false});
    if(!named||named.isSymbolicLink()||BigInt(named.dev)!==before.dev||BigInt(named.ino)!==before.ino
        ||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size
        ||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||BigInt(bytes.length)!==before.size) {
      throw new Error(`${label} changed while it was read`);
    }
    if(bytes.length===0||bytes.length>4*1024*1024) throw new Error(`${label} size is invalid`);
    const snapshot={bytes,value:parseStrictJson(bytes.toString('utf8'),{
      label,maxBytes:4*1024*1024,maxDepth:64,
    }),sha256:sha(bytes),mode};
    allSnapshots.set(target,snapshot);
    return snapshot;
  } finally { fs.closeSync(fd); }
}
function load(name,{mode=0o600}={}){
  const target=locations[name],snapshot=directSnapshot(target,name,{mode,missing:true});
  if(!snapshot){result.push({artifact:name,status:'missing',path:target}); return undefined;}
  const {bytes,value}=snapshot;
  loaded.set(name,{bytes,value,sha256:sha(bytes)});
  return value;
}
function verified(name,detail={}){result.push({artifact:name,status:'verified',path:locations[name],...detail});}
function evidenceSnapshot(target,label) {
  return directSnapshot(target,label,{missing:true});
}
const evidenceJson=(target,label)=>evidenceSnapshot(target,label)?.value;
function localJsonSnapshot(target,label) {
  const existing=localSnapshots.get(target);
  if(existing) return existing;
  const snapshot=directSnapshot(target,label);
  localSnapshots.set(target,snapshot);
  return snapshot;
}
function assertSnapshotsUnchanged() {
  for(const [target,expected] of allSnapshots) {
    const actual=directSnapshot(target,'terminal evidence recheck',{mode:expected.mode});
    if(!actual.bytes.equals(expected.bytes)) throw new Error('terminal evidence changed during readiness decision');
  }
}

try {
  const owners=load('owners');
  if(owners){
    exact(owners,['schema','threshold','singleOperator','singleOperatorResidualRisk','ownersByRole',
      'evidenceSha256ByOwner','custodySignaturesStatus'],'owners');
    if(owners.schema!=='usdom-safe-owner-identities/v2'||owners.threshold!==2
        ||owners.singleOperator!==true||owners.singleOperatorResidualRisk!==true
        ||owners.custodySignaturesStatus!=='awaiting-safe-package-for-12-custody-signatures') {
      throw new Error('owners schema or single-operator policy is invalid');
    }
    exact(owners.evidenceSha256ByOwner,['owner-1','owner-2','owner-3'],'owner evidence hashes');
    if(Object.values(owners.evidenceSha256ByOwner).some(value=>
      typeof value!=='string'||!/^[0-9a-f]{64}$/u.test(value))) {
      throw new Error('owner evidence hashes are invalid');
    }
    const canonical=canonicalOwnersByRole(owners.ownersByRole);
    if(JSON.stringify(canonical)!==JSON.stringify(owners.ownersByRole)) {
      throw new Error('owners are not canonical');
    }
    verified('owners',{sha256:loaded.get('owners').sha256});
  }
  const safePackage=load('safePackage');
  if(safePackage){
    if(!owners) throw new Error('safePackage exists before owners');
    if(safePackage.schema!=='usdom-safe-controls-recoverable/v2'
        ||safePackage.ethereumChainId!=='1'||safePackage.threshold!=='2'
        ||!Array.isArray(safePackage.controls)||safePackage.controls.length!==4) {
      throw new Error('safePackage header is invalid');
    }
    if(JSON.stringify(safePackage.ownersByRole)!==JSON.stringify(owners.ownersByRole)) {
      throw new Error('safePackage owners are stale/foreign');
    }
    const roles=safePackage.controls.map(value=>value?.role);
    if(JSON.stringify(roles)!==JSON.stringify(['governance','reserveGuardian','checkpointGuardian','usdtCustody'])) {
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
    const releaseSnapshot=localJsonSnapshot(path.join(root,'config/proof-reserve.unconfigured.json'),
      'release configuration');
    validateMainnetDeploymentIdentityObservation({observation:identity,releaseConfigAfter:releaseSnapshot.value});
    verified('identity',{sha256:loaded.get('identity').sha256,observationHash:identity.observationHash});
  }
  const deployment=load('deployment');
  if(deployment){
    if(!identity) throw new Error('deployment exists before identity');
    validateMainnetDeploymentPackage(deployment);
    const releaseSnapshot=localJsonSnapshot(path.join(root,'config/proof-reserve.unconfigured.json'),
      'release configuration');
    if(deployment.observationDocumentSha256!==loaded.get('identity').sha256
        ||deployment.observationHash!==identity.observationHash
        ||deployment.releaseConfigSha256!==releaseSnapshot.sha256) {
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
    const releaseSnapshot=localJsonSnapshot(path.join(root,'config/proof-reserve.unconfigured.json'),
      'current release');
    if(depositPackage.releaseConfigSha256!==releaseSnapshot.sha256
        ||depositPackage.reserveConfigHash!==releaseSnapshot.value.reserveConfigHash?.toLowerCase()
        ||getAddress(depositPackage.token)!==getAddress(releaseSnapshot.value.token)
        ||getAddress(depositPackage.reserve)!==getAddress(releaseSnapshot.value.reserve)) {
      throw new Error('deposit package is stale or belongs to another release');
    }
    const receipts=[];
    let depositGap=false;
    let depositFinalitySnapshot=null;
    for(let index=0;index<3;index++) {
      const receiptPath=path.join(evidence,`closed-deposit-${index}-receipt.json`);
      const validationPath=path.join(evidence,`closed-deposit-${index}-validation.json`);
      const finalityPath=path.join(evidence,`closed-deposit-${index}-finality.json`);
      const receipt=evidenceJson(receiptPath,'deposit receipt');
      const validation=evidenceJson(validationPath,'deposit validation');
      const finalitySnapshot=evidenceSnapshot(finalityPath,'deposit finality');
      const finality=finalitySnapshot?.value??null;
      if(!receipt&&!validation&&!finality){depositGap=true;continue;}
      if(depositGap) throw new Error('deposit receipt prefix has a hole');
      if(!receipt||!validation||!finality) throw new Error('deposit receipt/validation/finality set is incomplete');
      if(index===2) depositFinalitySnapshot=finalitySnapshot;
      validatePilotTransactionEvidence({kind:'deposit',index,receipt,validation,finality,
        transaction:depositPackage.transactions[index],signer:depositPackage.funder,
        packageValue:depositPackage});
      const cost=validatePilotReceiptCost({gasUsed:receipt.gasUsed,effectiveGasPrice:receipt.effectiveGasPrice,
        maximumCost:validation.maximumCost});
      depositMaximumCosts.push(cost.maximumCost);
      if(!Object.entries(cost).every(([key,value])=>finality[key]===value)) throw new Error('deposit finality gas cost is invalid');
      receipts.push({nonce:validation.nonce,finalizedRpcCount:finality.finalizedRpcCount,
        canonical:receipt.status!=='0x1'?false:finality.transactionHash?.toLowerCase()===validation.transactionHash?.toLowerCase()
          &&finality?.blockNumber===receipt.blockNumber&&finality?.blockHash?.toLowerCase()===receipt.blockHash?.toLowerCase()});
    }
    const executionSnapshot=evidenceSnapshot(locations.depositExecution,'deposit execution');
    const execution=executionSnapshot?.value??null;
    if(execution&&execution.packageSha256!==loaded.get('depositPackage').sha256) throw new Error('deposit execution references foreign package');
    if(execution) {
      const baselinePath=path.join(evidence,'closed-mainnet-deposit-financial-baseline.json');
      const baselineSnapshot=evidenceSnapshot(baselinePath,'deposit financial baseline');
      if(!baselineSnapshot) throw new Error('deposit financial baseline is missing');
      if(!depositFinalitySnapshot) throw new Error('deposit finality is missing');
      const releaseSnapshot=localJsonSnapshot(path.join(root,'config/proof-reserve.unconfigured.json'),'deposit release');
      const requirementsSnapshot=localJsonSnapshot(path.join(root,'config/production-requirements.json'),'production requirements');
      const walletSnapshot=localJsonSnapshot(path.join(os.homedir(),'.local','share','dom-usdom','mainnet-wallet','public-identity.json'),'deposit wallet');
      const pilotSnapshot=localJsonSnapshot(path.join(root,'evidence/authorization/pilot-funds-snapshot.json'),'pilot funds snapshot');
      const authorizationSnapshot=localJsonSnapshot(path.join(root,'evidence/authorization/pilot-funds-authorization-state.json'),'pilot funds authorization state');
      validateClosedMainnetDepositEvidence({baseline:baselineSnapshot.value,
        baselineSha256:baselineSnapshot.sha256,packageSha256:loaded.get('depositPackage').sha256,
        execution,packageValue:depositPackage,baselineBytes:baselineSnapshot.bytes,
        executionBytes:executionSnapshot.bytes,packageBytes:loaded.get('depositPackage').bytes,
        depositFinality:depositFinalitySnapshot.value,depositFinalityBytes:depositFinalitySnapshot.bytes,
        depositFinalitySha256:depositFinalitySnapshot.sha256,
        release:releaseSnapshot.value,releaseBytes:releaseSnapshot.bytes,releaseSha256:releaseSnapshot.sha256,
        wallet:walletSnapshot.value,walletBytes:walletSnapshot.bytes,walletSha256:walletSnapshot.sha256,
        pilotFundsSnapshot:pilotSnapshot.value,pilotFundsSnapshotBytes:pilotSnapshot.bytes,
        pilotFundsSnapshotSha256:pilotSnapshot.sha256,pilotFundsAuthorizationState:authorizationSnapshot.value,
        pilotFundsAuthorizationStateBytes:authorizationSnapshot.bytes,
        pilotFundsAuthorizationStateSha256:authorizationSnapshot.sha256,
        expectedPrivacyPolicyHash:`0x${requirementsSnapshot.value.native_privacy_policy_hash}`});
      completedDepositPackage=depositPackage; completedDepositExecution=execution;
    }
    const baseNonce=receipts[0]?.nonce??'0';
    pilot.deposit={packageSha256:loaded.get('depositPackage').sha256,
      amountBaseUnits:depositPackage.amountBaseUnits,broadcastAuthorized:depositPackage.broadcastAuthorized,
      baseNonce,receipts,pendingNonce:(BigInt(baseNonce)+BigInt(receipts.length)).toString(),
      allowanceAfter:execution?.allowanceAfter??'0'};
    verified('depositPackage',{sha256:loaded.get('depositPackage').sha256});
    if(execution) verified('depositExecution',{packageSha256:execution.packageSha256});
  }
  const redemptionPackage=load('redemptionPackage');
  if(redemptionPackage) {
    const submissionPath=path.join(root,'evidence/finalized-burn-submission/finalized-burn-submission.json');
    const submissionSnapshot=evidenceSnapshot(submissionPath,'finalized burn submission');
    if(!submissionSnapshot) throw new Error('redemption package exists before authenticated submission');
    const submission=submissionSnapshot.value;
    validateClosedMainnetRedemptionPackage(redemptionPackage,submission);
    const releaseSnapshot=localJsonSnapshot(path.join(root,'config/proof-reserve.unconfigured.json'),
      'current release');
    const verifierSnapshot=localJsonSnapshot(path.join(root,'config/finalized-burn-verifier.unconfigured.json'),
      'finalized burn verifier manifest');
    validateClosedMainnetRedemptionRelease({submission,packageValue:redemptionPackage,
      submissionBytes:submissionSnapshot.bytes,packageBytes:loaded.get('redemptionPackage').bytes,
      release:releaseSnapshot.value,releaseBytes:releaseSnapshot.bytes,
      releaseConfigSha256:releaseSnapshot.sha256,
      verifierManifestSha256:verifierSnapshot.sha256});
    const receipts=[];
    let redemptionGap=false;
    const redemptionReceiptOrder=[];
    let executeFinalitySnapshot=null;
    for(let index=0;index<2;index++) {
      const receiptPath=path.join(evidence,`closed-redemption-${index}-receipt.json`);
      const validationPath=path.join(evidence,`closed-redemption-${index}-validation.json`);
      const finalityPath=path.join(evidence,`closed-redemption-${index}-finality.json`);
      const receipt=evidenceJson(receiptPath,'redemption receipt');
      const validation=evidenceJson(validationPath,'redemption validation');
      const finalitySnapshot=evidenceSnapshot(finalityPath,'redemption finality');
      const finality=finalitySnapshot?.value??null;
      if(!receipt&&!validation&&!finality){redemptionGap=true;continue;}
      if(redemptionGap) throw new Error('redemption receipt prefix has a hole');
      if(!receipt||!validation||!finality) throw new Error('redemption receipt/validation/finality set is incomplete');
      if(index===1) executeFinalitySnapshot=finalitySnapshot;
      validatePilotTransactionEvidence({kind:'redemption',index,receipt,validation,finality,
        transaction:redemptionPackage.transactions[index],signer:redemptionPackage.recipient,
        packageValue:redemptionPackage});
      redemptionReceiptOrder.push(receipt);
      const cost=validatePilotReceiptCost({gasUsed:receipt.gasUsed,effectiveGasPrice:receipt.effectiveGasPrice,
        maximumCost:validation.maximumCost});
      redemptionMaximumCosts.push(cost.maximumCost);
      if(!Object.entries(cost).every(([key,value])=>finality[key]===value)) throw new Error('redemption finality gas cost is invalid');
      receipts.push({nonce:validation.nonce,finalizedRpcCount:finality.finalizedRpcCount,
        canonical:receipt.status!=='0x1'?false:finality.transactionHash?.toLowerCase()===validation.transactionHash?.toLowerCase()
          &&finality?.blockNumber===receipt.blockNumber&&finality?.blockHash?.toLowerCase()===receipt.blockHash?.toLowerCase()});
    }
    if(redemptionReceiptOrder.length>0) validatePilotTransactionOrder(
      redemptionReceiptOrder,'redemption receipts');
    const executionSnapshot=evidenceSnapshot(locations.redemptionExecution,'redemption execution');
    const execution=executionSnapshot?.value??null;
    if(execution&&execution.packageSha256!==loaded.get('redemptionPackage').sha256) throw new Error('redemption execution references foreign package');
    if(execution) {
      const baselinePath=path.join(evidence,'closed-mainnet-redemption-payout-baseline.json');
      const baselineSnapshot=evidenceSnapshot(baselinePath,'redemption payout baseline');
      if(!baselineSnapshot) throw new Error('redemption payout baseline is missing');
      if(!executeFinalitySnapshot) throw new Error('redemption execute finality is missing');
      validateClosedMainnetPayoutEvidence({baseline:baselineSnapshot.value,
        baselineSha256:baselineSnapshot.sha256,packageSha256:loaded.get('redemptionPackage').sha256,
        execution,packageValue:redemptionPackage,baselineBytes:baselineSnapshot.bytes,
        executionBytes:executionSnapshot.bytes,packageBytes:loaded.get('redemptionPackage').bytes,
        executeFinality:executeFinalitySnapshot.value,executeFinalityBytes:executeFinalitySnapshot.bytes,
        executeFinalitySha256:executeFinalitySnapshot.sha256,
        submission,submissionBytes:submissionSnapshot.bytes,release:releaseSnapshot.value,
        releaseBytes:releaseSnapshot.bytes,releaseConfigSha256:releaseSnapshot.sha256,
        verifierManifestBytes:verifierSnapshot.bytes,verifierManifestSha256:verifierSnapshot.sha256});
      completedRedemptionPackage=redemptionPackage; completedRedemptionExecution=execution;
    }
    const baseNonce=receipts[0]?.nonce??'0';
    pilot.redemption={packageSha256:loaded.get('redemptionPackage').sha256,
      amountBaseUnits:redemptionPackage.amountBaseUnits,broadcastAuthorized:redemptionPackage.broadcastAuthorized,
      burnId:redemptionPackage.burnId,requestId:redemptionPackage.requestId,baseNonce,receipts,
      pendingNonce:(BigInt(baseNonce)+BigInt(receipts.length)).toString(),
      paidBurn:execution?true:false,paidRequest:execution?true:false};
    verified('redemptionPackage',{sha256:loaded.get('redemptionPackage').sha256});
    if(execution) verified('redemptionExecution',{packageSha256:execution.packageSha256});
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
  for(const phase of ['deposit','redemption']) {
    const receipts=pilot[phase]?.receipts??[];
    for(let index=1;index<receipts.length;index++) {
      if(BigInt(receipts[index].nonce)!==BigInt(receipts[index-1].nonce)+1n) {
        throw new Error(`${phase} receipt nonce sequence regressed or skipped`);
      }
    }
  }
  const pilotBudget=validateClosedMainnetPilotBudget({depositMaximumCosts,redemptionMaximumCosts});
  const phaseStatus=Object.fromEntries(pilotDag.phases.map(phase=>[phase.phase,phase.status]));
  if(requirement==='require-deposit-complete'&&phaseStatus.deposit!=='complete') {
    throw new Error(`deposit phase is ${phaseStatus.deposit??'absent'}, not complete`);
  }
  if(requirement==='require-pilot-complete'
      &&(phaseStatus.deposit!=='complete'||phaseStatus.redemption!=='complete')) {
    throw new Error(`pilot phases are deposit=${phaseStatus.deposit??'absent'}, redemption=${phaseStatus.redemption??'absent'}`);
  }
  assertSnapshotsUnchanged();
  result.push({artifact:'pilot',status:'reconciled',detail:pilotDag,budget:pilotBudget});
  process.stdout.write(`${JSON.stringify({schema:'usdom-closed-mainnet-phase-checklist/v1',artifacts:result},null,2)}\n`);
} catch(error) {
  writePilotFailure('closed-mainnet-phase-check',error);
  process.exitCode=1;
}
