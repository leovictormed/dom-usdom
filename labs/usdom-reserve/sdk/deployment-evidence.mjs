import {getAddress} from 'ethers';
import {canonicalEthereumQuantity,canonicalUnsignedDecimal} from './ethereum-quantity.mjs';
import {MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS,MAINNET_DEPLOYMENT_MAX_GAS_LIMIT,
  MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST,MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS}
  from './mainnet-deployment-execution.mjs';

const names=['finalizedBurnVerifier','checkpointVerifier','checkpointRegistry','reserve'];
const keys=['schema','index','name','chainId','releaseConfigSha256','packageSha256','rpcCatalogSha256',
  'observationDocumentSha256','observationHash','transactionHash','from','nonce','rawSha256',
  'initcodeHash','expectedContract','runtimeCodeHash','receiptBlockNumber','receiptBlockHash',
  'finalizedBlockNumber','finalizedBlockHash'];
const sha=/^[0-9a-f]{64}$/;
const bytes32=/^0x[0-9a-f]{64}$/;

export function validateDeploymentEvidence(value) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    throw new Error('deployment evidence must use the exact supported schema');
  }
  if(value.schema!=='usdom-mainnet-deployment-evidence-v1'||value.chainId!=='1'
      ||typeof value.index!=='string'||!(/^[0-3]$/).test(value.index)
      ||value.name!==names[Number(value.index)]) throw new Error('deployment evidence identity is invalid');
  for(const field of ['releaseConfigSha256','packageSha256','rpcCatalogSha256',
    'observationDocumentSha256','rawSha256']) {
    if(typeof value[field]!=='string'||!sha.test(value[field])
        ||BigInt(`0x${value[field]}`)===0n) throw new Error(`${field} is invalid`);
  }
  for(const field of ['observationHash','transactionHash','initcodeHash','runtimeCodeHash',
    'receiptBlockHash','finalizedBlockHash']) {
    if(typeof value[field]!=='string'||!bytes32.test(value[field])||BigInt(value[field])===0n) {
      throw new Error(`${field} is invalid`);
    }
  }
  for(const field of ['from','expectedContract']) {
    if(typeof value[field]!=='string'||getAddress(value[field])!==value[field]
        ||BigInt(value[field])===0n) throw new Error(`${field} is invalid`);
  }
  canonicalUnsignedDecimal(value.nonce,{maximum:(1n<<64n)-1n});
  const receipt=canonicalEthereumQuantity(value.receiptBlockNumber);
  const finalized=canonicalEthereumQuantity(value.finalizedBlockNumber);
  if(BigInt(receipt)>BigInt(finalized)) throw new Error('receipt is above finalized evidence');
  return value;
}

const rawKeys=['schema','index','name','from','nonce','expectedContract','transactionHash','gasLimit',
  'maxFeePerGas','maxPriorityFeePerGas','maximumCost','chainId','releaseConfigSha256','packageSha256',
  'rpcCatalogSha256','observationDocumentSha256','observationHash','rawSha256'];

export function validateDeploymentRawEvidence(value) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...rawKeys].sort())) {
    throw new Error('deployment raw evidence must use the exact supported schema');
  }
  if(value.schema!=='usdom-mainnet-deployment-raw-validation-v1'||value.chainId!=='1'
      ||typeof value.index!=='string'||!(/^[0-3]$/).test(value.index)
      ||value.name!==names[Number(value.index)]) throw new Error('deployment raw evidence identity is invalid');
  for(const field of ['releaseConfigSha256','packageSha256','rpcCatalogSha256',
    'observationDocumentSha256','rawSha256']) {
    if(typeof value[field]!=='string'||!sha.test(value[field])
        ||BigInt(`0x${value[field]}`)===0n) throw new Error(`${field} is invalid`);
  }
  for(const field of ['observationHash','transactionHash']) {
    if(typeof value[field]!=='string'||!bytes32.test(value[field])||BigInt(value[field])===0n) {
      throw new Error(`${field} is invalid`);
    }
  }
  for(const field of ['from','expectedContract']) {
    if(typeof value[field]!=='string'||getAddress(value[field])!==value[field]
        ||BigInt(value[field])===0n) throw new Error(`${field} is invalid`);
  }
  canonicalUnsignedDecimal(value.nonce,{maximum:(1n<<64n)-1n});
  const gas=canonicalUnsignedDecimal(value.gasLimit,{maximum:MAINNET_DEPLOYMENT_MAX_GAS_LIMIT});
  const fee=canonicalUnsignedDecimal(value.maxFeePerGas,{maximum:MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS});
  const priority=canonicalUnsignedDecimal(value.maxPriorityFeePerGas,
    {maximum:MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS});
  const cost=canonicalUnsignedDecimal(value.maximumCost);
  if(BigInt(gas)===0n||BigInt(fee)===0n
      ||BigInt(priority)!==MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS||BigInt(priority)>BigInt(fee)
      ||BigInt(cost)!==BigInt(gas)*BigInt(fee)) throw new Error('deployment raw evidence fee relation is invalid');
  return value;
}

const receiptKeys=['schema','transactionHash','blockNumber','blockHash','transactionIndex','status','from','to','contractAddress',
  'gasUsed','effectiveGasPrice','actualCost'];
export function validateDeploymentReceiptEvidence(value) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...receiptKeys].sort())) {
    throw new Error('deployment receipt evidence must use the exact supported schema');
  }
  if(value.schema!=='usdom-mainnet-deployment-receipt-v1'||value.status!=='0x1'||value.to!==null) {
    throw new Error('deployment receipt status or destination is invalid');
  }
  canonicalEthereumQuantity(value.blockNumber);
  canonicalEthereumQuantity(value.transactionIndex);
  for(const field of ['transactionHash','blockHash']) {
    if(typeof value[field]!=='string'||!bytes32.test(value[field])||BigInt(value[field])===0n) {
      throw new Error(`${field} is invalid`);
    }
  }
  for(const field of ['from','contractAddress']) {
    if(typeof value[field]!=='string'||getAddress(value[field])!==value[field]
        ||BigInt(value[field])===0n) throw new Error(`${field} is invalid`);
  }
  const gas=canonicalEthereumQuantity(value.gasUsed),fee=canonicalEthereumQuantity(value.effectiveGasPrice);
  const actual=canonicalUnsignedDecimal(value.actualCost,{maximum:MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST});
  if(BigInt(gas)===0n||BigInt(gas)>MAINNET_DEPLOYMENT_MAX_GAS_LIMIT||BigInt(fee)===0n
      ||BigInt(fee)>MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS||BigInt(actual)!==BigInt(gas)*BigInt(fee)) {
    throw new Error('deployment receipt cost relation is invalid');
  }
  return value;
}

export function projectDeploymentReceipt(receipt) {
  if(!receipt||typeof receipt!=='object'||Array.isArray(receipt)) throw new Error('RPC receipt is invalid');
  const gasUsed=canonicalEthereumQuantity(receipt.gasUsed,{maximum:MAINNET_DEPLOYMENT_MAX_GAS_LIMIT});
  const effectiveGasPrice=canonicalEthereumQuantity(receipt.effectiveGasPrice,
    {maximum:MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS});
  const status=receipt.status==='0x01'?'0x1':receipt.status;
  const projected={schema:'usdom-mainnet-deployment-receipt-v1',
    transactionHash:typeof receipt.transactionHash==='string'?receipt.transactionHash.toLowerCase():receipt.transactionHash,
    blockNumber:receipt.blockNumber,
    blockHash:typeof receipt.blockHash==='string'?receipt.blockHash.toLowerCase():receipt.blockHash,
    transactionIndex:receipt.transactionIndex,
    status,from:typeof receipt.from==='string'?getAddress(receipt.from):receipt.from,to:receipt.to,
    contractAddress:typeof receipt.contractAddress==='string'?getAddress(receipt.contractAddress):receipt.contractAddress,
    gasUsed:receipt.gasUsed,effectiveGasPrice:receipt.effectiveGasPrice,
    actualCost:(BigInt(gasUsed)*BigInt(effectiveGasPrice)).toString()};
  return validateDeploymentReceiptEvidence(projected);
}

const anchorKeys=['schema','index','name','chainId','packageSha256','observationDocumentSha256',
  'observationHash','finalizedBlockNumber','finalizedBlockHash','maximumBaseFeePerGas','gasLimit',
  'maxFeePerGas'];
export function validateDeploymentFeeAnchor(value) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...anchorKeys].sort())) {
    throw new Error('deployment fee anchor must use the exact supported schema');
  }
  if(value.schema!=='usdom-mainnet-deployment-fee-anchor-v1'||value.chainId!=='1'
      ||typeof value.index!=='string'||!(/^[0-3]$/).test(value.index)
      ||value.name!==names[Number(value.index)]) throw new Error('deployment fee anchor identity is invalid');
  for(const field of ['packageSha256','observationDocumentSha256']) {
    if(typeof value[field]!=='string'||!sha.test(value[field])
        ||BigInt(`0x${value[field]}`)===0n) throw new Error(`${field} is invalid`);
  }
  for(const field of ['observationHash','finalizedBlockHash']) {
    if(typeof value[field]!=='string'||!bytes32.test(value[field])||BigInt(value[field])===0n) {
      throw new Error(`${field} is invalid`);
    }
  }
  canonicalEthereumQuantity(value.finalizedBlockNumber);
  const base=canonicalUnsignedDecimal(value.maximumBaseFeePerGas,{maximum:120_000_000_000n});
  const gas=canonicalUnsignedDecimal(value.gasLimit,{maximum:MAINNET_DEPLOYMENT_MAX_GAS_LIMIT});
  const fee=canonicalUnsignedDecimal(value.maxFeePerGas,{maximum:MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS});
  if(BigInt(base)===0n||BigInt(gas)===0n) throw new Error('deployment fee anchor contains zero policy value');
  let projected=BigInt(base);
  for(let index=0;index<12;index++) projected=(projected*9n+7n)/8n;
  projected+=MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS;
  if(BigInt(fee)!==projected) throw new Error('deployment fee projection mismatch');
  return value;
}

export function validateDeploymentStageLink({raw,receipt,completion,anchor}) {
  validateDeploymentRawEvidence(raw); validateDeploymentReceiptEvidence(receipt);
  validateDeploymentEvidence(completion); validateDeploymentFeeAnchor(anchor);
  for(const field of ['index','name','chainId','packageSha256','observationDocumentSha256','observationHash']) {
    if(anchor[field]!==raw[field]||completion[field]!==raw[field]) {
      throw new Error(`deployment stage ${field} link is invalid`);
    }
  }
  for(const field of ['releaseConfigSha256','rpcCatalogSha256','transactionHash','from','nonce',
    'expectedContract','rawSha256']) {
    if(completion[field]!==raw[field]) throw new Error(`deployment stage ${field} link is invalid`);
  }
  const receiptHeight=BigInt(receipt.blockNumber);
  const anchorHeight=BigInt(anchor.finalizedBlockNumber);
  const completionHeight=BigInt(completion.finalizedBlockNumber);
  if(receipt.transactionHash!==raw.transactionHash||receipt.from!==raw.from
      ||receipt.contractAddress!==raw.expectedContract
      ||completion.receiptBlockNumber!==receipt.blockNumber
      ||completion.receiptBlockHash!==receipt.blockHash
      ||anchor.gasLimit!==raw.gasLimit||anchor.maxFeePerGas!==raw.maxFeePerGas
      ||BigInt(receipt.gasUsed)>BigInt(raw.gasLimit)
      ||BigInt(receipt.effectiveGasPrice)>BigInt(raw.maxFeePerGas)
      ||BigInt(receipt.actualCost)>BigInt(raw.maximumCost)
      ||anchorHeight>completionHeight
      ||(receiptHeight===anchorHeight&&receipt.blockHash!==anchor.finalizedBlockHash)
      ||(receiptHeight===completionHeight&&receipt.blockHash!==completion.finalizedBlockHash)
      ||(anchorHeight===completionHeight&&anchor.finalizedBlockHash!==completion.finalizedBlockHash)) {
    throw new Error('deployment stage receipt, cost or finality link is invalid');
  }
  return true;
}
