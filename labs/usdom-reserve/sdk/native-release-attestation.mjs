import {Interface,TypedDataEncoder,getAddress,keccak256} from 'ethers';

export const EIP1271_MAGIC_VALUE='0x1626ba7e';
export const NATIVE_ATTESTATION_DOMAIN_NAME='USDOM Native Release Attestation';
export const NATIVE_ATTESTATION_DOMAIN_VERSION='1';
export const MAX_NATIVE_ATTESTATION_SIGNATURE_BYTES=65_536;

const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const canonicalUintPattern=/^(0|[1-9][0-9]*)$/;
const signaturePattern=/^0x(?:[0-9a-fA-F]{2})+$/;
const eip1271=new Interface(['function isValidSignature(bytes32 digest,bytes signature) view returns (bytes4)']);
const types={NativeReleaseAttestation:[
  {name:'kind',type:'string'},
  {name:'releaseId',type:'string'},
  {name:'sourceCommit',type:'string'},
  {name:'reserveConfigHash',type:'bytes32'},
  {name:'checkpointRegistryConfigHash',type:'bytes32'},
  {name:'completedAt',type:'uint64'},
  {name:'subjectCommitment',type:'bytes32'},
  {name:'approvedBy',type:'address'},
]};

function canonicalChainId(value) {
  if(typeof value!=='string' || !canonicalUintPattern.test(value) || value==='0') {
    throw new Error('ethereumChainId must be a nonzero canonical integer string');
  }
  return BigInt(value);
}

function bytes32(value,name) {
  if(!bytes32Pattern.test(value??'')) throw new Error(`${name} must be bytes32`);
  return value;
}

export function validNativeAttestationSignature(value) {
  return typeof value==='string' && signaturePattern.test(value)
    && (value.length-2)/2<=MAX_NATIVE_ATTESTATION_SIGNATURE_BYTES;
}

export function nativeReleaseAttestationDigest(attestation,releaseConfig) {
  if(!attestation || typeof attestation!=='object' || Array.isArray(attestation)) {
    throw new Error('native release attestation is missing');
  }
  if(typeof attestation.completedAt!=='string' || !/^[1-9][0-9]*$/.test(attestation.completedAt)
      || BigInt(attestation.completedAt)>0xffffffffffffffffn) {
    throw new Error('completedAt must be a nonzero canonical uint64 string');
  }
  const governance=getAddress(releaseConfig?.governance);
  if(getAddress(attestation.approvedBy)!==governance) {
    throw new Error('approvedBy does not match release governance');
  }
  return TypedDataEncoder.hash({
    name:NATIVE_ATTESTATION_DOMAIN_NAME,version:NATIVE_ATTESTATION_DOMAIN_VERSION,
    chainId:canonicalChainId(releaseConfig?.ethereumChainId),verifyingContract:governance,
  },types,{
    kind:attestation.kind,releaseId:attestation.releaseId,sourceCommit:attestation.sourceCommit,
    reserveConfigHash:bytes32(attestation.reserveConfigHash,'reserveConfigHash'),
    checkpointRegistryConfigHash:bytes32(
      attestation.checkpointRegistryConfigHash,'checkpointRegistryConfigHash',
    ),
    completedAt:attestation.completedAt,
    subjectCommitment:bytes32(attestation.subjectCommitment,'subjectCommitment'),
    approvedBy:governance,
  });
}

export async function collectNativeAttestationApprovals({provider,releaseConfig,attestations}) {
  if(!provider || typeof provider.send!=='function') throw new Error('JSON-RPC provider is required');
  if(!attestations || typeof attestations!=='object' || Array.isArray(attestations)
      || Object.keys(attestations).length===0) throw new Error('native attestations are required');
  const [chainIdValue,finalized]=await Promise.all([
    provider.send('eth_chainId',[]),provider.send('eth_getBlockByNumber',['finalized',false]),
  ]);
  if(!finalized?.hash || !/^0x[0-9a-fA-F]+$/.test(finalized.number??'')
      || !/^0x[0-9a-fA-F]+$/.test(finalized.timestamp??'')) {
    throw new Error('RPC did not return a canonical finalized block');
  }
  const finalizedTag=finalized.number;
  const governance=getAddress(releaseConfig?.governance);
  const governanceCode=await provider.send('eth_getCode',[governance,finalizedTag]);
  const approvals=Object.fromEntries(await Promise.all(Object.entries(attestations).map(async([name,attestation])=>{
    if(!validNativeAttestationSignature(attestation?.signature)) {
      throw new Error(`${name} signature is malformed or oversized`);
    }
    const digest=nativeReleaseAttestationDigest(attestation,releaseConfig);
    const data=eip1271.encodeFunctionData('isValidSignature',[digest,attestation.signature]);
    let valid=false;
    try {
      const result=await provider.send('eth_call',[{to:governance,data},finalizedTag]);
      valid=typeof result==='string'
        && new RegExp(`^${EIP1271_MAGIC_VALUE.slice(2)}0{56}$`,'i').test(result.slice(2));
    } catch { /* a rejecting or unavailable governance call is an invalid approval */ }
    return [name,{digest,valid}];
  })));
  const snapshotAfter=await provider.send('eth_getBlockByNumber',[finalizedTag,false]);
  return {approvals,chainId:BigInt(chainIdValue).toString(),
    finalizedBlockHash:finalized.hash,finalizedBlockNumber:BigInt(finalized.number).toString(),
    finalizedBlockTimestamp:BigInt(finalized.timestamp).toString(),
    governance,governanceCodeHash:keccak256(governanceCode),
    snapshotBlockHashAfter:snapshotAfter?.hash??null};
}
