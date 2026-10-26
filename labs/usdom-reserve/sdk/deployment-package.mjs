import {getAddress,getCreateAddress,keccak256} from 'ethers';
import {uint} from './reserve.mjs';
import {auditedDeploymentGasLimit,MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT,
} from './mainnet-deployment-execution.mjs';

const sha256Pattern=/^[0-9a-f]{64}$/;
const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const names=['finalizedBurnVerifier','checkpointVerifier','checkpointRegistry','reserve'];

function exactObject(value,keys,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || Object.keys(value).length!==keys.length || keys.some(key=>!(key in value))) {
    throw new Error(`${label} must use the exact supported schema`);
  }
}

function canonicalPlan(value,name) {
  exactObject(value,['data','expectedContract','expectedInitcodeHash','expectedRuntimeCodeHash','from','nonce'],
    `${name} plan`);
  const from=getAddress(value.from);
  if(BigInt(from)===0n) throw new Error(`${name} deployer must not be zero`);
  const nonce=uint(value.nonce,64);
  const expectedContract=getAddress(value.expectedContract);
  if(BigInt(expectedContract)===0n) throw new Error(`${name} contract must not be zero`);
  if(typeof value.data!=='string' || !/^0x[0-9a-fA-F]+$/.test(value.data)
      || value.data.length%2!==0) throw new Error(`${name} initcode is malformed`);
  if(!bytes32Pattern.test(value.expectedRuntimeCodeHash??'')
      || value.expectedRuntimeCodeHash.toLowerCase()==='0x'+'00'.repeat(32)) {
    throw new Error(`${name} runtime code hash must be nonzero bytes32`);
  }
  if(!bytes32Pattern.test(value.expectedInitcodeHash??'')
      || value.expectedInitcodeHash.toLowerCase()==='0x'+'00'.repeat(32)) {
    throw new Error(`${name} approved initcode hash must be nonzero bytes32`);
  }
  const initcodeHash=keccak256(value.data);
  if(initcodeHash.toLowerCase()!==value.expectedInitcodeHash.toLowerCase()) {
    throw new Error(`${name} initcode does not match the exact release`);
  }
  const predicted=getCreateAddress({from,nonce});
  if(predicted!==expectedContract) throw new Error(`${name} CREATE address does not match the release`);
  return {name,from,nonce:nonce.toString(),to:null,value:'0',expectedContract,
    initcodeHash,expectedRuntimeCodeHash:value.expectedRuntimeCodeHash.toLowerCase(),
    data:value.data.toLowerCase()};
}

function canonicalApprovedArtifact(value,name) {
  exactObject(value,['expectedContract','expectedInitcodeHash','expectedRuntimeCodeHash'],
    `${name} approved artifact`);
  const expectedContract=getAddress(value.expectedContract);
  if(BigInt(expectedContract)===0n) throw new Error(`${name} approved contract must not be zero`);
  for(const [field,label] of [
    ['expectedInitcodeHash','initcode'],['expectedRuntimeCodeHash','runtime code'],
  ]) {
    if(!bytes32Pattern.test(value[field]??'')||value[field].toLowerCase()==='0x'+'00'.repeat(32)) {
      throw new Error(`${name} approved ${label} hash must be nonzero bytes32`);
    }
  }
  return {expectedContract,expectedInitcodeHash:value.expectedInitcodeHash.toLowerCase(),
    expectedRuntimeCodeHash:value.expectedRuntimeCodeHash.toLowerCase()};
}

/** Build a deterministic unsigned package. This function neither accepts a
 * signing key nor has an RPC transport, so it cannot broadcast a transaction. */
export function buildMainnetDeploymentPackage({releaseConfigSha256,observationDocumentSha256,
  observationHash,plans,approvedArtifacts}) {
  if(!sha256Pattern.test(releaseConfigSha256??'')) {
    throw new Error('release configuration SHA-256 must be canonical lowercase hex');
  }
  if(!sha256Pattern.test(observationDocumentSha256??'')
      ||!bytes32Pattern.test(observationHash??'')) {
    throw new Error('deployment identity observation commitments are invalid');
  }
  exactObject(plans,names,'deployment plans');
  exactObject(approvedArtifacts,names,'approved deployment artifacts');
  const approved=Object.fromEntries(names.map(name=>[
    name,canonicalApprovedArtifact(approvedArtifacts[name],name),
  ]));
  const transactions=names.map(name=>canonicalPlan(plans[name],name));
  const sequentialGas=transactions.reduce((total,transaction)=>
    total+auditedDeploymentGasLimit(transaction.name,transaction.data),0n);
  if(sequentialGas>MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT) {
    throw new Error('deployment sequence exceeds the audited aggregate gas policy');
  }
  for(const tx of transactions) {
    const artifact=approved[tx.name];
    if(tx.expectedContract!==artifact.expectedContract
        ||tx.initcodeHash!==artifact.expectedInitcodeHash
        ||tx.expectedRuntimeCodeHash!==artifact.expectedRuntimeCodeHash) {
      throw new Error(`${tx.name} plan does not match its approved release artifact`);
    }
  }
  if(new Set(transactions.map(tx=>tx.expectedContract)).size!==transactions.length) {
    throw new Error('deployment contract addresses must be distinct');
  }
  const deployer=transactions[0].from,baseNonce=BigInt(transactions[0].nonce);
  for(let index=0;index<transactions.length;index++) {
    const tx=transactions[index];
    if(tx.from!==deployer||BigInt(tx.nonce)!==baseNonce+BigInt(index)) {
      throw new Error('deployment plans must use one deployer and four consecutive role-ordered nonces');
    }
  }
  return {schema:'usdom-mainnet-deployment-package-v1',chainId:'1',releaseConfigSha256,
    observationDocumentSha256,observationHash:observationHash.toLowerCase(),transactions};
}

export function validateMainnetDeploymentPackage(value) {
  exactObject(value,['schema','chainId','releaseConfigSha256','observationDocumentSha256',
    'observationHash','transactions'],'deployment package');
  if(value.schema!=='usdom-mainnet-deployment-package-v1'||value.chainId!=='1'
      ||!Array.isArray(value.transactions)||value.transactions.length!==names.length) {
    throw new Error('deployment package header is invalid');
  }
  const plans={};
  const approvedArtifacts={};
  for(let index=0;index<names.length;index++) {
    const name=names[index],transaction=value.transactions[index];
    exactObject(transaction,['name','from','nonce','to','value','expectedContract','initcodeHash',
      'expectedRuntimeCodeHash','data'],`${name} transaction`);
    if(transaction.name!==name||transaction.to!==null||transaction.value!=='0') {
      throw new Error(`${name} transaction role or CREATE fields are invalid`);
    }
    plans[name]={from:transaction.from,nonce:transaction.nonce,data:transaction.data,
      expectedContract:transaction.expectedContract,expectedInitcodeHash:transaction.initcodeHash,
      expectedRuntimeCodeHash:transaction.expectedRuntimeCodeHash};
    approvedArtifacts[name]={expectedContract:transaction.expectedContract,
      expectedInitcodeHash:transaction.initcodeHash,
      expectedRuntimeCodeHash:transaction.expectedRuntimeCodeHash};
  }
  const canonical=buildMainnetDeploymentPackage({
    releaseConfigSha256:value.releaseConfigSha256,
    observationDocumentSha256:value.observationDocumentSha256,
    observationHash:value.observationHash,plans,approvedArtifacts,
  });
  if(JSON.stringify(canonical)!==JSON.stringify(value)) {
    throw new Error('deployment package is not canonical');
  }
  return canonical;
}

export function validateMainnetDeploymentLedgerHandoff({handoff,packageValue,index,packageSha256}) {
  validateMainnetDeploymentPackage(packageValue);
  exactObject(handoff,['schema','chainId','releaseConfigSha256','packageSha256','rpcCatalogSha256',
    'observationDocumentSha256','observationHash','transaction'],'deployment Ledger handoff');
  if(!Number.isInteger(index)||index<0||index>=names.length
      ||handoff.schema!=='usdom-mainnet-deployment-ledger-handoff-v1'
      ||handoff.chainId!=='1'||!sha256Pattern.test(packageSha256??'')
      ||handoff.packageSha256!==packageSha256
      ||handoff.releaseConfigSha256!==packageValue.releaseConfigSha256
      ||handoff.observationDocumentSha256!==packageValue.observationDocumentSha256
      ||handoff.observationHash!==packageValue.observationHash
      ||!sha256Pattern.test(handoff.rpcCatalogSha256??'')
      ||JSON.stringify(handoff.transaction)!==JSON.stringify(packageValue.transactions[index])) {
    throw new Error('deployment Ledger handoff differs from the reviewed package');
  }
  return handoff;
}
