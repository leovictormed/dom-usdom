import {getAddress,Signature,verifyTypedData} from 'ethers';

const ROLES=['governance','reserveGuardian','checkpointGuardian','usdtCustody'];
const DOMAIN_TYPES=[
  {name:'name',type:'string'},{name:'version',type:'string'},
  {name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'},
];
const PROOF_TYPES=[
  {name:'role',type:'string'},{name:'replacementOwner',type:'address'},
  {name:'planHash',type:'bytes32'},
];
function fail(message){ throw new Error(message); }
function exactKeys(value,keys,label){
  if(value===null||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} has unexpected or missing fields`);
  }
}
function address(value,label){
  if(typeof value!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(value)) fail(`${label} is not an address`);
  try { return getAddress(value); } catch { fail(`${label} is not a valid address`); }
}
function equalAddress(left,right,label){
  if(address(left,`${label} left`).toLowerCase()!==address(right,`${label} right`).toLowerCase()) {
    fail(`${label} mismatch`);
  }
}

export function validateSafeRecoveryReplacementProofs(plan,bundle){
  if(typeof plan?.planHash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(plan.planHash)) fail('planHash is invalid');
  if(!Array.isArray(plan.roles)||plan.roles.length!==ROLES.length) fail('plan roles must contain exactly four entries');
  exactKeys(bundle,['schema','ethereumChainId','planHash','proofs'],'proof bundle');
  if(bundle.schema!=='usdom-safe-recovery-replacement-proofs/v2'||bundle.ethereumChainId!=='1') fail('proof bundle identity is invalid');
  if(bundle.planHash!==plan.planHash) fail('proof bundle planHash mismatch');
  if(!Array.isArray(bundle.proofs)||bundle.proofs.length!==ROLES.length) fail('proof bundle must contain exactly four proofs');
  const replacements=new Set();
  for(let index=0;index<ROLES.length;index++){
    const role=ROLES[index],planned=plan.roles.find(entry=>entry?.role===role),proof=bundle.proofs[index];
    if(!planned) fail(`plan is missing ${role}`);
    exactKeys(proof,['role','replacementOwner','safe','typedData','signature'],`${role} proof`);
    if(proof.role!==role) fail(`${role} proof order or role mismatch`);
    equalAddress(proof.replacementOwner,planned.newOwner,`${role} replacement owner`);
    equalAddress(proof.safe,planned.safe,`${role} Safe`);
    const replacement=address(proof.replacementOwner,`${role} replacement owner`).toLowerCase();
    if(replacements.has(replacement)) fail('replacement owners must be globally distinct');
    replacements.add(replacement);
    exactKeys(proof.typedData,['types','primaryType','domain','message'],`${role} typed data`);
    exactKeys(proof.typedData.types,['EIP712Domain','SafeRecoveryReplacementProof'],`${role} typed types`);
    if(JSON.stringify(proof.typedData.types.EIP712Domain)!==JSON.stringify(DOMAIN_TYPES)
        ||JSON.stringify(proof.typedData.types.SafeRecoveryReplacementProof)!==JSON.stringify(PROOF_TYPES)) fail(`${role} typed data types mismatch`);
    if(proof.typedData.primaryType!=='SafeRecoveryReplacementProof') fail(`${role} primary type mismatch`);
    exactKeys(proof.typedData.domain,['name','version','chainId','verifyingContract'],`${role} domain`);
    if(proof.typedData.domain.name!=='USDOM Safe Recovery Replacement Proof'
        ||proof.typedData.domain.version!=='1'||proof.typedData.domain.chainId!==1) fail(`${role} domain identity mismatch`);
    equalAddress(proof.typedData.domain.verifyingContract,planned.safe,`${role} verifying contract`);
    exactKeys(proof.typedData.message,['role','replacementOwner','planHash'],`${role} message`);
    if(proof.typedData.message.role!==role||proof.typedData.message.planHash!==plan.planHash) fail(`${role} message binding mismatch`);
    equalAddress(proof.typedData.message.replacementOwner,planned.newOwner,`${role} message owner`);
    if(typeof proof.signature!=='string'||!/^0x[0-9a-f]{130}$/.test(proof.signature)) fail(`${role} signature is invalid`);
    let canonicalSignature;
    try { canonicalSignature=Signature.from(proof.signature).serialized; }
    catch { fail(`${role} signature is invalid`); }
    if(canonicalSignature!==proof.signature) fail(`${role} signature is noncanonical`);
    const recovered=verifyTypedData(proof.typedData.domain,
      {SafeRecoveryReplacementProof:PROOF_TYPES},proof.typedData.message,proof.signature);
    equalAddress(recovered,planned.newOwner,`${role} recovered signer`);
  }
  return {schema:'usdom-safe-recovery-replacement-proof-check/v1',valid:true,
    planHash:plan.planHash,proofCount:3};
}
