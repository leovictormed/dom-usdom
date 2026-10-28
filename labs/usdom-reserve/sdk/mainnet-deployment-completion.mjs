import {createHash} from 'node:crypto';
import {validateMainnetDeploymentPackage} from './deployment-package.mjs';
import {validateDeploymentStageLink} from './deployment-evidence.mjs';
import {validateMainnetDeploymentRawTransaction} from './mainnet-deployment-execution.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {validateOrderedDeploymentChronology} from './mainnet-deployment-identity.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const SHA=/^[0-9a-f]{64}$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
const bindJson=(value,bytes,label)=>{
  if(!Buffer.isBuffer(bytes)
      ||JSON.stringify(parseStrictJsonBytes(bytes,{label,maxDepth:32}))!==JSON.stringify(value)) {
    throw new Error(`${label} bytes differ from parsed authority`);
  }
};
function validateDeploymentChronology(deployments) {
  const names=['finalizedBurnVerifier','checkpointVerifier','checkpointRegistry','reserve'];
  validateOrderedDeploymentChronology(deployments.map((value,index)=>({...value,name:names[index]})),
    {requireReceiptOrder:true});
}
export const _mainnetDeploymentCompletionInternals=Object.freeze({bindJson,validateDeploymentChronology});

export function buildMainnetDeploymentCompletion({packageValue,packageBytes,stages}){
  bindJson(packageValue,packageBytes,'deployment package');
  validateMainnetDeploymentPackage(packageValue);
  if(!Array.isArray(stages)||stages.length!==4) throw new Error('four deployment stages are required');
  const deployments=stages.map((stage,index)=>{
    bindJson(stage.raw,stage.rawBytes,`deployment stage ${index} raw validation`);
    bindJson(stage.receipt,stage.receiptBytes,`deployment stage ${index} receipt`);
    bindJson(stage.completion,stage.completionBytes,`deployment stage ${index} evidence`);
    bindJson(stage.anchor,stage.anchorBytes,`deployment stage ${index} finalized anchor`);
    validateDeploymentStageLink(stage);
    const planned=packageValue.transactions[index];
    const rawText=stage.rawTransactionBytes.toString('utf8');
    if(`${rawText.trim()}\n`!==rawText) throw new Error(`deployment stage ${index} raw framing is invalid`);
    const handoff={schema:'usdom-mainnet-deployment-ledger-handoff-v1',chainId:'1',
      releaseConfigSha256:stage.raw.releaseConfigSha256,
      packageSha256:stage.raw.packageSha256,rpcCatalogSha256:stage.raw.rpcCatalogSha256,
      observationDocumentSha256:stage.raw.observationDocumentSha256,
      observationHash:stage.raw.observationHash,transaction:planned};
    const decoded=validateMainnetDeploymentRawTransaction({raw:rawText.trim(),packageValue,
      packageBytes,packageSha256:sha(packageBytes),handoff,index:String(index)});
    if(stage.raw.index!==String(index)||stage.raw.name!==planned.name
        ||stage.raw.from!==planned.from||stage.raw.nonce!==planned.nonce
        ||stage.raw.expectedContract!==planned.expectedContract
        ||stage.completion.initcodeHash!==planned.initcodeHash
        ||stage.completion.runtimeCodeHash!==planned.expectedRuntimeCodeHash
        ||stage.completion.packageSha256!==sha(packageBytes)
        ||stage.raw.rawSha256!==sha(stage.rawTransactionBytes)
        ||decoded.transactionHash!==stage.raw.transactionHash
        ||decoded.gasLimit!==stage.raw.gasLimit||decoded.maxFeePerGas!==stage.raw.maxFeePerGas
        ||decoded.maximumCost!==stage.raw.maximumCost) {
      throw new Error(`deployment stage ${index} differs from ordered CREATE package`);
    }
    return {index:String(index),name:planned.name,nonce:planned.nonce,
      expectedContract:planned.expectedContract,transactionHash:stage.raw.transactionHash,
      receiptBlockNumber:stage.receipt.blockNumber,receiptBlockHash:stage.receipt.blockHash,
      receiptTransactionIndex:stage.receipt.transactionIndex,
      finalizedBlockNumber:stage.completion.finalizedBlockNumber,
      finalizedBlockHash:stage.completion.finalizedBlockHash,
      rawTransactionSha256:sha(stage.rawTransactionBytes),rawValidationSha256:sha(stage.rawBytes),
      receiptSha256:sha(stage.receiptBytes),stageEvidenceSha256:sha(stage.completionBytes),
      finalizedAnchorSha256:sha(stage.anchorBytes)};
  });
  validateDeploymentChronology(deployments);
  return {schema:'usdom-mainnet-deployment-completion/v1',chainId:'1',
    packageSha256:sha(packageBytes),releaseConfigSha256:packageValue.releaseConfigSha256,
    observationDocumentSha256:packageValue.observationDocumentSha256,
    observationHash:packageValue.observationHash,deployments};
}

export function validateMainnetDeploymentCompletion(value,inputs){
  if(!exact(value,['schema','chainId','packageSha256','releaseConfigSha256',
    'observationDocumentSha256','observationHash','deployments'])
      ||value.schema!=='usdom-mainnet-deployment-completion/v1'||value.chainId!=='1'
      ||![value.packageSha256,value.releaseConfigSha256,value.observationDocumentSha256]
        .every(item=>SHA.test(item??''))) throw new Error('mainnet deployment completion identity is invalid');
  const expected=buildMainnetDeploymentCompletion(inputs);
  if(JSON.stringify(value)!==JSON.stringify(expected)) throw new Error('mainnet deployment completion differs from source graph');
  return value;
}
