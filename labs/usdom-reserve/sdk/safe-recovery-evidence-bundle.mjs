import {createHash} from 'node:crypto';
import {validateRecoverableSafeControlRecoveryReport} from './safe-control-observation.mjs';
import {validateRecoverableSafeRecoveryPlan,
  validateRecoverableSafeRecoveryTransactionPackage} from './safe-control-recovery-plan.mjs';
import {validateFinalizedSafeRecoveryExecution} from './safe-control-recovery-execution.mjs';
import {validateSafeRecoveryReplacementProofs} from './safe-recovery-replacement-proofs.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {mainnetPreflightRpcSourceSet} from './mainnet-preflight-rpc.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

const SHA=/^[0-9a-f]{64}$/;
const ZERO_SHA='0'.repeat(64);
const ZERO_HASH='0x'+ZERO_SHA;
const ROLES=['governance','reserveGuardian','checkpointGuardian','usdtCustody'];
const KEYS=['schema','ethereumChainId','packageDocumentSha256','packageHash',
  'baselineDocumentSha256','planDocumentSha256','replacementProofsDocumentSha256',
  'transactionPackageDocumentSha256',
  'rpcCatalogSha256','executions','reportDocumentSha256','recoveryHash'];
function exact(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    throw new Error(`${label} schema is invalid`);
  }
}
export const documentSha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const bindJson=(value,bytes,label)=>{
  if(!Buffer.isBuffer(bytes)
      ||JSON.stringify(parseStrictJsonBytes(bytes,{label,maxDepth:64}))!==JSON.stringify(value)) {
    throw new Error(`${label} bytes differ from parsed authority`);
  }
};
const bindRpcCatalog=(bytes,rpcConsensus)=>{
  if(!Buffer.isBuffer(bytes)) throw new Error('Safe recovery RPC catalog bytes are missing');
  const catalog=parseStrictJsonBytes(bytes,{label:'Safe recovery RPC catalog',maxBytes:1024*1024,
    maxDepth:16});
  const sourceSet=mainnetPreflightRpcSourceSet(catalog);
  validateRpcConsensusEvidence(rpcConsensus);
  const expected=sourceSet.sources.map(source=>({operatorId:source.operatorId,
    originKeccak256:source.originKeccak256}));
  if(sourceSet.sourceCount!==rpcConsensus.sourceCount
      ||JSON.stringify(expected)!==JSON.stringify(rpcConsensus.sources)) {
    throw new Error('Safe recovery RPC catalog differs from recovery consensus');
  }
  return catalog;
};
const canonicalAddress=value=>String(value).toLowerCase();
const bindRecoverySourceGraph=({packageDocument,baseline,plan,transactionPackage,
  executions,report})=>{
  if(plan.packageHash!==report.packageHash
      ||plan.packageHash!==baseline.packageHash
      ||plan.baselineSnapshotHash!==baseline.snapshotHash
      ||plan.baselineSnapshotHash!==report.baselineSnapshotHash
      ||transactionPackage.planHash!==plan.planHash
      ||JSON.stringify(plan.transitionsByRole)!==JSON.stringify(report.transitionsByRole)
      ||JSON.stringify(plan.rpcConsensus)!==JSON.stringify(baseline.rpcConsensus)
      ||JSON.stringify(plan.rpcConsensus)!==JSON.stringify(report.rpcConsensus)) {
    throw new Error('Safe recovery source graph has stale or mixed authorities');
  }
  const packageRoles=new Map(packageDocument.controls.map(value=>[value.role,value]));
  const baselineRoles=new Map(baseline.roles.map(value=>[value.role,value]));
  const reportRecoveries=new Map(report.recoveries.map(value=>[value.role,value]));
  const reportAfterRoles=new Map(report.afterSnapshot.roles.map(value=>[value.role,value]));
  if(BigInt(plan.finalizedBlockNumber)<BigInt(baseline.finalizedBlockNumber)
      ||BigInt(report.afterSnapshot.finalizedBlockNumber)<BigInt(plan.finalizedBlockNumber)) {
    throw new Error('Safe recovery source graph has a non-monotonic finalized timeline');
  }
  for(const rolePlan of plan.roles) {
    const role=rolePlan.role,control=packageRoles.get(role),before=baselineRoles.get(role);
    const recovery=reportRecoveries.get(role),after=reportAfterRoles.get(role);
    const execution=executions.find(value=>value.role===role);
    const transition=report.transitionsByRole[role];
    if(!control||!before||!recovery||!after||!execution||!transition) {
      throw new Error(`${role} Safe recovery source graph is incomplete`);
    }
    const lostIndex=before.owners.findIndex(owner=>canonicalAddress(owner)
      ===canonicalAddress(transition.lostOwner));
    const previousOwner=lostIndex===0?'0x0000000000000000000000000000000000000001'
      :before.owners[lostIndex-1];
    const expectedSigners=before.owners.filter(owner=>canonicalAddress(owner)
      !==canonicalAddress(transition.lostOwner)).sort((left,right)=>
      BigInt(left)<BigInt(right)?-1:1);
    if(lostIndex<0||canonicalAddress(control.safe)!==canonicalAddress(before.address)
        ||canonicalAddress(rolePlan.safe)!==canonicalAddress(before.address)
        ||canonicalAddress(rolePlan.oldOwner)!==canonicalAddress(transition.lostOwner)
        ||canonicalAddress(rolePlan.newOwner)!==canonicalAddress(transition.replacementOwner)
        ||canonicalAddress(rolePlan.previousOwner)!==canonicalAddress(previousOwner)
        ||JSON.stringify(rolePlan.requiredSigners.map(canonicalAddress))
          !==JSON.stringify(expectedSigners.map(canonicalAddress))
        ||rolePlan.safeTransaction.nonce!==before.nonce
        ||canonicalAddress(after.address)!==canonicalAddress(before.address)
        ||recovery.safeTxHash!==rolePlan.safeTxHash
        ||execution.safeTxHash!==rolePlan.safeTxHash
        ||execution.transactionHash!==recovery.transactionHash
        ||BigInt(recovery.blockNumber)<=BigInt(plan.finalizedBlockNumber)) {
      throw new Error(`${role} Safe recovery source graph is cross-inconsistent`);
    }
  }
  for(let index=1;index<executions.length;index++) {
    const previous=executions[index-1],current=executions[index];
    const previousBlock=BigInt(previous.blockNumber),currentBlock=BigInt(current.blockNumber);
    if(currentBlock<previousBlock
        || currentBlock===previousBlock
          && BigInt(current.transactionIndex)<=BigInt(previous.transactionIndex)
        || BigInt(current.finalizedObservationBlockNumber)
          <BigInt(previous.finalizedObservationBlockNumber)) {
      throw new Error('Safe recovery executions have a non-monotonic canonical timeline');
    }
  }
};
export const _safeRecoveryEvidenceBundleInternals=Object.freeze({
  bindJson,bindRpcCatalog,bindRecoverySourceGraph,
});

export function validateSafeRecoveryEvidenceBundleShape(bundle) {
  exact(bundle,KEYS,'Safe recovery evidence bundle');
  if(bundle.schema!=='usdom-safe-recovery-evidence-bundle/v2'||bundle.ethereumChainId!=='1'
      ||[bundle.packageDocumentSha256,bundle.baselineDocumentSha256,bundle.planDocumentSha256,
        bundle.replacementProofsDocumentSha256,bundle.transactionPackageDocumentSha256,
        bundle.rpcCatalogSha256,
        bundle.reportDocumentSha256].some(value=>!SHA.test(value??'')||value===ZERO_SHA)
      ||typeof bundle.packageHash!=='string'||!/^0x[0-9a-f]{64}$/.test(bundle.packageHash)
      ||typeof bundle.recoveryHash!=='string'||!/^0x[0-9a-f]{64}$/.test(bundle.recoveryHash)
      ||bundle.packageHash===ZERO_HASH||bundle.recoveryHash===ZERO_HASH
      ||!Array.isArray(bundle.executions)||bundle.executions.length!==ROLES.length) {
    throw new Error('Safe recovery evidence bundle identity is invalid');
  }
  for(const [index,binding] of bundle.executions.entries()) {
    exact(binding,['role','documentSha256','transactionHash'],`execution binding ${index}`);
    if(binding.role!==ROLES[index]||!SHA.test(binding.documentSha256??'')
        ||binding.documentSha256===ZERO_SHA
        ||!/^0x[0-9a-f]{64}$/.test(binding.transactionHash??'')
        ||binding.transactionHash===ZERO_HASH) {
      throw new Error(`execution binding ${index} is invalid`);
    }
  }
  return bundle;
}

export function buildSafeRecoveryEvidenceBundle({packageBytes,baselineBytes,planBytes,
  replacementProofsBytes,
  transactionPackageBytes,rpcCatalogBytes,executionBytes,reportBytes,packageDocument,
  baseline,plan,replacementProofs,transactionPackage,executions,report}) {
  bindJson(packageDocument,packageBytes,'Safe recovery package');
  bindJson(baseline,baselineBytes,'Safe recovery baseline');
  bindJson(plan,planBytes,'Safe recovery plan');
  bindJson(replacementProofs,replacementProofsBytes,'Safe recovery replacement proofs');
  bindJson(transactionPackage,transactionPackageBytes,'Safe recovery transaction package');
  bindJson(report,reportBytes,'Safe recovery report');
  validateRecoverableSafeRecoveryPlan(plan);
  validateSafeRecoveryReplacementProofs(plan,replacementProofs);
  validateRecoverableSafeRecoveryTransactionPackage(plan,transactionPackage);
  validateRecoverableSafeControlRecoveryReport(report,baseline,packageDocument);
  bindRpcCatalog(rpcCatalogBytes,report.rpcConsensus);
  if(!Array.isArray(executions)||executions.length!==ROLES.length
      ||!Array.isArray(executionBytes)||executionBytes.length!==ROLES.length) {
    throw new Error('Safe recovery executions are incomplete');
  }
  bindRecoverySourceGraph({packageDocument,baseline,plan,transactionPackage,executions,report});
  const bindings=executions.map((execution,index)=>{
    bindJson(execution,executionBytes[index],`${ROLES[index]} recovery execution`);
    validateFinalizedSafeRecoveryExecution({plan,transactionPackage,execution});
    const recovery=report.recoveries[index];
    if(execution.role!==ROLES[index]||recovery.role!==ROLES[index]
        ||execution.transactionHash!==recovery.transactionHash
        ||execution.safeTxHash!==recovery.safeTxHash
        ||execution.blockNumber!==recovery.blockNumber||execution.blockHash!==recovery.blockHash
        ||execution.transactionIndex!==recovery.transactionIndex
        ||JSON.stringify(execution.rpcConsensus)!==JSON.stringify(report.rpcConsensus)) {
      throw new Error(`${ROLES[index]} execution does not match the final report`);
    }
    return {role:ROLES[index],documentSha256:documentSha256(executionBytes[index]),
      transactionHash:execution.transactionHash};
  });
  return {schema:'usdom-safe-recovery-evidence-bundle/v2',ethereumChainId:'1',
    packageDocumentSha256:documentSha256(packageBytes),packageHash:report.packageHash,
    baselineDocumentSha256:documentSha256(baselineBytes),planDocumentSha256:documentSha256(planBytes),
    replacementProofsDocumentSha256:documentSha256(replacementProofsBytes),
    transactionPackageDocumentSha256:documentSha256(transactionPackageBytes),
    rpcCatalogSha256:documentSha256(rpcCatalogBytes),executions:bindings,
    reportDocumentSha256:documentSha256(reportBytes),recoveryHash:report.recoveryHash};
}

export function validateSafeRecoveryEvidenceBundle(bundle,inputs) {
  validateSafeRecoveryEvidenceBundleShape(bundle);
  const expected=buildSafeRecoveryEvidenceBundle(inputs);
  if(JSON.stringify(bundle)!==JSON.stringify(expected)) {
    throw new Error('Safe recovery evidence bundle differs from its source graph');
  }
  return bundle;
}
