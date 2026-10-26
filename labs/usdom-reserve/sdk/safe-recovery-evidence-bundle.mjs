import {createHash} from 'node:crypto';
import {validateRecoverableSafeControlRecoveryReport} from './safe-control-observation.mjs';
import {validateRecoverableSafeRecoveryPlan,
  validateRecoverableSafeRecoveryTransactionPackage} from './safe-control-recovery-plan.mjs';
import {validateFinalizedSafeRecoveryExecution} from './safe-control-recovery-execution.mjs';

const SHA=/^[0-9a-f]{64}$/;
const ROLES=['governance','reserveGuardian','checkpointGuardian'];
const KEYS=['schema','ethereumChainId','packageDocumentSha256','packageHash',
  'baselineDocumentSha256','planDocumentSha256','transactionPackageDocumentSha256',
  'rpcCatalogSha256','executions','reportDocumentSha256','recoveryHash'];
function exact(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    throw new Error(`${label} schema is invalid`);
  }
}
export const documentSha256=bytes=>createHash('sha256').update(bytes).digest('hex');

export function validateSafeRecoveryEvidenceBundleShape(bundle) {
  exact(bundle,KEYS,'Safe recovery evidence bundle');
  if(bundle.schema!=='usdom-safe-recovery-evidence-bundle/v1'||bundle.ethereumChainId!=='1'
      ||[bundle.packageDocumentSha256,bundle.baselineDocumentSha256,bundle.planDocumentSha256,
        bundle.transactionPackageDocumentSha256,bundle.rpcCatalogSha256,
        bundle.reportDocumentSha256].some(value=>!SHA.test(value??''))
      ||typeof bundle.packageHash!=='string'||!/^0x[0-9a-f]{64}$/.test(bundle.packageHash)
      ||typeof bundle.recoveryHash!=='string'||!/^0x[0-9a-f]{64}$/.test(bundle.recoveryHash)
      ||!Array.isArray(bundle.executions)||bundle.executions.length!==ROLES.length) {
    throw new Error('Safe recovery evidence bundle identity is invalid');
  }
  for(const [index,binding] of bundle.executions.entries()) {
    exact(binding,['role','documentSha256','transactionHash'],`execution binding ${index}`);
    if(binding.role!==ROLES[index]||!SHA.test(binding.documentSha256??'')
        ||!/^0x[0-9a-f]{64}$/.test(binding.transactionHash??'')) {
      throw new Error(`execution binding ${index} is invalid`);
    }
  }
  return bundle;
}

export function buildSafeRecoveryEvidenceBundle({packageBytes,baselineBytes,planBytes,
  transactionPackageBytes,rpcCatalogBytes,executionBytes,reportBytes,packageDocument,
  baseline,plan,transactionPackage,executions,report}) {
  validateRecoverableSafeRecoveryPlan(plan);
  validateRecoverableSafeRecoveryTransactionPackage(plan,transactionPackage);
  validateRecoverableSafeControlRecoveryReport(report,baseline,packageDocument);
  if(!Array.isArray(executions)||executions.length!==ROLES.length
      ||!Array.isArray(executionBytes)||executionBytes.length!==ROLES.length) {
    throw new Error('Safe recovery executions are incomplete');
  }
  const bindings=executions.map((execution,index)=>{
    validateFinalizedSafeRecoveryExecution({plan,transactionPackage,execution});
    const recovery=report.recoveries[index];
    if(execution.role!==ROLES[index]||recovery.role!==ROLES[index]
        ||execution.transactionHash!==recovery.transactionHash
        ||execution.safeTxHash!==recovery.safeTxHash
        ||execution.blockNumber!==recovery.blockNumber||execution.blockHash!==recovery.blockHash
        ||JSON.stringify(execution.rpcConsensus)!==JSON.stringify(report.rpcConsensus)) {
      throw new Error(`${ROLES[index]} execution does not match the final report`);
    }
    return {role:ROLES[index],documentSha256:documentSha256(executionBytes[index]),
      transactionHash:execution.transactionHash};
  });
  return {schema:'usdom-safe-recovery-evidence-bundle/v1',ethereumChainId:'1',
    packageDocumentSha256:documentSha256(packageBytes),packageHash:report.packageHash,
    baselineDocumentSha256:documentSha256(baselineBytes),planDocumentSha256:documentSha256(planBytes),
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
