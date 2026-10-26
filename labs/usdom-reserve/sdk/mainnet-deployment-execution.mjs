import {Transaction,getAddress,getCreateAddress,keccak256} from 'ethers';

export const MAINNET_DEPLOYMENT_MAX_GAS_LIMIT=20_000_000n;
export const MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT=12_500_000n;
export const MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS=100_000_000_000n;
export const MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS=2_000_000_000n;
export const MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST=600_000_000_000_000_000n;
export const MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST=1_000_000_000_000_000_000n;
const deploymentNames=['finalizedBurnVerifier','checkpointVerifier','checkpointRegistry','reserve'];
// Conservative constructor/code-deposit ceilings. Live multi-RPC estimates are
// still required and must fit below these values. The publication gate proves
// each ceiling remains above the rebuilt runtime's unavoidable 200 gas/byte
// code-deposit cost; a larger rebuild therefore fails closed before signing.
// Fresh pinned-Anvil solc-0.8.37/via-IR transactions measured 2,545,275 gas
// for Registry CREATE and 4,707,900 for Reserve CREATE at the current 20,100 B
// Reserve runtime. These ceilings round upward before the
// planner independently adds calldata/EIP-3860 charges and a further 25%.
const auditedCreateGas={finalizedBurnVerifier:750_000n,checkpointVerifier:750_000n,
  checkpointRegistry:2_600_000n,reserve:4_800_000n};

export function auditedDeploymentCreateGasCeiling(name) {
  if(!(name in auditedCreateGas)) throw new Error('unknown deployment gas policy');
  return auditedCreateGas[name];
}

function canonicalInitcode(data) {
  if(typeof data!=='string'||!/^0x[0-9a-f]+$/.test(data)||data.length%2!==0) {
    throw new Error('deployment initcode must be canonical lowercase hex');
  }
  return Buffer.from(data.slice(2),'hex');
}

/** Conservative offline floor: measured Cancun CREATE execution/code-deposit
 * plus full transaction calldata and EIP-3860 word charges, then 25% margin. */
export function auditedDeploymentGasLimit(name,data) {
  if(!(name in auditedCreateGas)) throw new Error('unknown deployment gas policy');
  const bytes=canonicalInitcode(data);
  if(bytes.length>49_152-8_192) {
    throw new Error('deployment initcode lacks the required EIP-3860 safety margin');
  }
  let calldata=21_000n+2n*BigInt(Math.ceil(bytes.length/32));
  for(const byte of bytes) calldata+=byte===0?4n:16n;
  const measuredMaximum=auditedCreateGas[name]+calldata;
  return (measuredMaximum*125n+99n)/100n;
}

export function planMainnetDeploymentGas({name,data,maximumEstimate}) {
  let estimate;
  try { estimate=BigInt(maximumEstimate); }
  catch { throw new Error('deployment gas estimate is malformed'); }
  if(estimate<=0n) throw new Error('deployment gas estimate is malformed');
  const limit=auditedDeploymentGasLimit(name,data);
  if(estimate>(limit*100n)/125n) {
    throw new Error('deployment gas estimate exceeds the audited constructor policy');
  }
  if(limit>MAINNET_DEPLOYMENT_MAX_GAS_LIMIT) {
    throw new Error('audited deployment gas limit exceeds the per-transaction policy');
  }
  return limit;
}

export function validateMainnetDeploymentRawTransaction({raw,expected,index}) {
  if(typeof index!=='string'||!(/^[0-3]$/).test(index)) throw new Error('invalid deployment index');
  if(typeof raw!=='string'||!/^0x[0-9a-f]+$/.test(raw)||raw.length%2!==0) {
    throw new Error('deployment raw transaction must be canonical lowercase hex');
  }
  if(!expected||typeof expected!=='object'||Array.isArray(expected)
      ||typeof expected.from!=='string'||typeof expected.nonce!=='string'
      ||typeof expected.data!=='string'||typeof expected.expectedContract!=='string'
      ||typeof expected.initcodeHash!=='string'||expected.name!==deploymentNames[Number(index)]) {
    throw new Error('deployment plan is malformed');
  }
  let expectedFrom;
  let expectedContract;
  let expectedNonce;
  try {
    expectedFrom=getAddress(expected.from);
    expectedContract=getAddress(expected.expectedContract);
    expectedNonce=BigInt(expected.nonce);
  } catch {
    throw new Error('deployment plan is malformed');
  }
  if(!/^(0|[1-9][0-9]*)$/.test(expected.nonce)||expectedNonce>2n**64n-1n
      ||BigInt(expectedFrom)===0n||BigInt(expectedContract)===0n
      ||!/^0x[0-9a-f]+$/.test(expected.data)||expected.data.length%2!==0
      ||!/^0x[0-9a-f]{64}$/.test(expected.initcodeHash)
      ||keccak256(expected.data)!==expected.initcodeHash
      ||getCreateAddress({from:expectedFrom,nonce:expectedNonce})!==expectedContract) {
    throw new Error('deployment plan is malformed');
  }
  let transaction;
  try { transaction=Transaction.from(raw); }
  catch { throw new Error('deployment raw transaction cannot be decoded'); }
  if(transaction.unsignedHash===null||transaction.signature===null||transaction.hash===null) {
    throw new Error('deployment transaction is not signed');
  }
  const gasLimit=transaction.gasLimit;
  const maxFee=transaction.maxFeePerGas;
  const priorityFee=transaction.maxPriorityFeePerGas;
  if(transaction.serialized!==raw||transaction.type!==2||transaction.chainId!==1n
      ||BigInt(transaction.nonce)!==expectedNonce
      ||getAddress(transaction.from)!==expectedFrom||transaction.to!==null
      ||transaction.value!==0n||transaction.data!==expected.data.toLowerCase()
      ||transaction.accessList.length!==0||gasLimit!==auditedDeploymentGasLimit(expected.name,expected.data)
      ||gasLimit>MAINNET_DEPLOYMENT_MAX_GAS_LIMIT||maxFee===null||maxFee===0n
      ||maxFee>MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS||priorityFee===null
      ||priorityFee!==MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS||priorityFee>maxFee
      ||gasLimit*maxFee>MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST
      ||transaction.hash!==keccak256(raw)) {
    throw new Error('signed transaction differs from the bounded mainnet deployment plan');
  }
  return {
    schema:'usdom-mainnet-deployment-raw-validation-v1',index,name:expected.name,
    from:expectedFrom,nonce:expected.nonce,
    expectedContract,transactionHash:transaction.hash,
    gasLimit:gasLimit.toString(),maxFeePerGas:maxFee.toString(),
    maxPriorityFeePerGas:priorityFee.toString(),maximumCost:(gasLimit*maxFee).toString(),
  };
}
