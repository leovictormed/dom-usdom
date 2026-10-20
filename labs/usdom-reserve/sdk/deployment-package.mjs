import {getAddress,getCreateAddress,keccak256} from 'ethers';
import {uint} from './reserve.mjs';

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

/** Build a deterministic unsigned package. This function neither accepts a
 * signing key nor has an RPC transport, so it cannot broadcast a transaction. */
export function buildMainnetDeploymentPackage({releaseConfigSha256,plans}) {
  if(!sha256Pattern.test(releaseConfigSha256??'')) {
    throw new Error('release configuration SHA-256 must be canonical lowercase hex');
  }
  exactObject(plans,names,'deployment plans');
  const transactions=names.map(name=>canonicalPlan(plans[name],name));
  if(new Set(transactions.map(tx=>tx.expectedContract)).size!==transactions.length) {
    throw new Error('deployment contract addresses must be distinct');
  }
  const identities=new Set();
  for(const tx of transactions) {
    const identity=`${tx.from}:${tx.nonce}`;
    if(identities.has(identity)) throw new Error('deployment nonce pair is reused');
    identities.add(identity);
  }
  const byName=Object.fromEntries(transactions.map(tx=>[tx.name,tx]));
  for(const [dependency,dependent] of [
    ['finalizedBurnVerifier','reserve'],['checkpointVerifier','checkpointRegistry'],
  ]) {
    if(byName[dependency].from===byName[dependent].from
        && BigInt(byName[dependency].nonce)>=BigInt(byName[dependent].nonce)) {
      throw new Error(`${dependency} must be deployed before ${dependent} for a shared deployer`);
    }
  }
  return {schema:'usdom-mainnet-deployment-package-v1',chainId:'1',releaseConfigSha256,transactions};
}
