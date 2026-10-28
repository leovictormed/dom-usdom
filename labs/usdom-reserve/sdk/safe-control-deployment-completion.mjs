import {createHash} from 'node:crypto';
import {Transaction,getAddress,keccak256} from 'ethers';
import {validateRecoverableSafeControlBaseline} from './safe-control-observation.mjs';
import {validateRecoverableSafeControlPackage} from './safe-control-deployment.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {canonicalEthereumQuantity} from './ethereum-quantity.mjs';

const ROLES=['governance','reserveGuardian','checkpointGuardian','usdtCustody'];
const SHA=/^[0-9a-f]{64}$/;
const HASH=/^0x[0-9a-f]{64}$/;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
const bindJson=(value,bytes,label)=>{
  if(!Buffer.isBuffer(bytes)
      ||JSON.stringify(parseStrictJsonBytes(bytes,{label,maxDepth:64}))!==JSON.stringify(value)) {
    throw new Error(`${label} bytes differ from parsed authority`);
  }
};
function validateSafeDeploymentSequence(authorities,baseline) {
  if(authorities.length!==ROLES.length) throw new Error('Safe deployment sequence is incomplete');
  const deployer=getAddress(authorities[0].from),baseNonce=BigInt(authorities[0].nonce);
  for(let index=0;index<authorities.length;index++) {
    const authority=authorities[index];
    const receiptHeight=BigInt(canonicalEthereumQuantity(authority.receiptBlockNumber));
    const receiptIndex=BigInt(canonicalEthereumQuantity(authority.receiptTransactionIndex));
    if(getAddress(authority.from)!==deployer||BigInt(authority.nonce)!==baseNonce+BigInt(index)) {
      throw new Error('Safe deployments must use one deployer and consecutive role-ordered nonces');
    }
    if(receiptHeight===BigInt(baseline.finalizedBlockNumber)
        &&authority.receiptBlockHash!==baseline.finalizedBlockHash) {
      throw new Error('Safe receipt conflicts with the finalized baseline block identity');
    }
    if(index>0) {
      const previous=authorities[index-1];
      const previousHeight=BigInt(canonicalEthereumQuantity(previous.receiptBlockNumber));
      const previousIndex=BigInt(canonicalEthereumQuantity(previous.receiptTransactionIndex));
      const currentHeight=receiptHeight;
      if(currentHeight<previousHeight
          ||(currentHeight===previousHeight
            &&(authority.receiptBlockHash!==previous.receiptBlockHash
              ||receiptIndex<=previousIndex))) {
        throw new Error('Safe receipt chronology conflicts with consecutive deployer nonces');
      }
    }
  }
}
export const _safeControlDeploymentCompletionInternals=Object.freeze({
  bindJson,validateSafeDeploymentSequence,
});

export function buildSafeControlDeploymentCompletion({packageDocument,packageBytes,baseline,
  baselineBytes,roles}) {
  bindJson(packageDocument,packageBytes,'Safe deployment package');
  bindJson(baseline,baselineBytes,'Safe deployment baseline');
  validateRecoverableSafeControlPackage(packageDocument);
  validateRecoverableSafeControlBaseline(baseline,packageDocument);
  if(!Array.isArray(roles)||roles.length!==4) throw new Error('deployment role evidence is incomplete');
  const authorities=[];
  const bindings=roles.map((entry,index)=>{
    const role=ROLES[index],control=packageDocument.controls.find(value=>value.role===role);
    if(entry.role!==role||!control) throw new Error(`${role} deployment role mismatch`);
    const {journal,rawBytes,validation,receipt}=entry;
    bindJson(journal,entry.journalBytes,`${role} deployment journal`);
    bindJson(validation,entry.validationBytes,`${role} deployment validation`);
    bindJson(receipt,entry.receiptBytes,`${role} deployment receipt`);
    const raw=rawBytes.toString('utf8').trim();
    if(!exact(journal,['schema','role','raw','validation'])
        ||journal.schema!=='usdom-safe-deployment-journal/v1'||journal.role!==role
        ||journal.raw!==raw||JSON.stringify(journal.validation)!==JSON.stringify(validation)) {
      throw new Error(`${role} deployment journal mismatch`);
    }
    const tx=Transaction.from(raw);
    if(tx.serialized!==raw||tx.chainId!==1n||tx.hash?.toLowerCase()!==validation.transactionHash
        ||getAddress(tx.from)!==getAddress(validation.from)||getAddress(tx.to)!==getAddress(control.to)
        ||keccak256(tx.data)!==validation.dataHash||keccak256(raw)!==validation.rawHash
        ||validation.role!==role||getAddress(validation.safe)!==getAddress(control.safe)
        ||receipt.role!==role||receipt.transactionHash!==validation.transactionHash
        ||receipt.status!=='0x1'||getAddress(receipt.from)!==getAddress(validation.from)
        ||getAddress(receipt.to)!==getAddress(control.to)||!HASH.test(receipt.blockHash)
        ||BigInt(receipt.blockHash)===0n
        ||BigInt(receipt.blockNumber)>BigInt(baseline.finalizedBlockNumber)) {
      throw new Error(`${role} transaction, receipt or finalized baseline mismatch`);
    }
    const observed=baseline.roles[index];
    if(observed.role!==role||getAddress(observed.address)!==getAddress(control.safe)
        ||observed.threshold!=='2'||observed.nonce!=='0'||observed.owners.length!==3) {
      throw new Error(`${role} finalized Safe configuration mismatch`);
    }
    authorities.push({from:validation.from,nonce:validation.nonce,
      receiptBlockNumber:receipt.blockNumber,receiptBlockHash:receipt.blockHash,
      receiptTransactionIndex:receipt.transactionIndex});
    return {role,transactionHash:validation.transactionHash,receiptBlockNumber:receipt.blockNumber,
      receiptBlockHash:receipt.blockHash,receiptTransactionIndex:receipt.transactionIndex,
      journalSha256:sha(entry.journalBytes),
      rawTransactionSha256:sha(rawBytes),validationSha256:sha(entry.validationBytes),
      receiptSha256:sha(entry.receiptBytes),configurationHash:observed.configurationHash};
  });
  validateSafeDeploymentSequence(authorities,baseline);
  return {schema:'usdom-safe-control-deployment-completion/v1',ethereumChainId:'1',
    packageDocumentSha256:sha(packageBytes),packageHash:baseline.packageHash,
    baselineDocumentSha256:sha(baselineBytes),baselineSnapshotHash:baseline.snapshotHash,
    finalizedBlockNumber:baseline.finalizedBlockNumber,finalizedBlockHash:baseline.finalizedBlockHash,
    deployments:bindings};
}

export function validateSafeControlDeploymentCompletion(value,inputs){
  if(!exact(value,['schema','ethereumChainId','packageDocumentSha256','packageHash',
    'baselineDocumentSha256','baselineSnapshotHash','finalizedBlockNumber','finalizedBlockHash',
    'deployments'])||value.schema!=='usdom-safe-control-deployment-completion/v1'
      ||value.ethereumChainId!=='1'||![value.packageDocumentSha256,value.baselineDocumentSha256]
        .every(item=>SHA.test(item??''))) throw new Error('deployment completion identity is invalid');
  const expected=buildSafeControlDeploymentCompletion(inputs);
  if(JSON.stringify(value)!==JSON.stringify(expected)) throw new Error('deployment completion differs from its exact source graph');
  return value;
}
