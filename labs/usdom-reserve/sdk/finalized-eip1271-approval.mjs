import {AbiCoder,Interface,getAddress,keccak256} from 'ethers';

export const EIP1271_MAGIC_VALUE='0x1626ba7e';
export const MAX_EIP1271_SIGNATURE_BYTES=65_536;

const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const signaturePattern=/^0x(?:[0-9a-fA-F]{2})+$/;
const eip1271=new Interface([
  'function isValidSignature(bytes32 digest,bytes signature) view returns (bytes4)',
]);
const encodedMagic=AbiCoder.defaultAbiCoder().encode(['bytes4'],[EIP1271_MAGIC_VALUE]);

export function validEip1271Signature(value) {
  return typeof value==='string' && signaturePattern.test(value)
    && (value.length-2)/2<=MAX_EIP1271_SIGNATURE_BYTES;
}

export async function collectFinalizedEip1271Approvals({provider,chainId,governance,requests}) {
  if(!provider || typeof provider.send!=='function') throw new Error('JSON-RPC provider is required');
  if(typeof chainId!=='string'||!/^[1-9][0-9]*$/.test(chainId)) {
    throw new Error('chainId must be a nonzero canonical integer string');
  }
  const authority=getAddress(governance);
  if(!requests || typeof requests!=='object' || Array.isArray(requests)
      || Object.keys(requests).length===0) throw new Error('EIP-1271 approval requests are required');
  for(const [name,request] of Object.entries(requests)) {
    if(!request || typeof request!=='object' || Array.isArray(request)
        || !bytes32Pattern.test(request.digest??'')) throw new Error(`${name} digest is malformed`);
    if(!validEip1271Signature(request.signature)) {
      throw new Error(`${name} signature is malformed or oversized`);
    }
  }
  const [chainIdValue,finalized]=await Promise.all([
    provider.send('eth_chainId',[]),provider.send('eth_getBlockByNumber',['finalized',false]),
  ]);
  if(BigInt(chainIdValue).toString()!==chainId) throw new Error('RPC chain ID differs from release');
  if(!finalized?.hash || !/^0x[0-9a-fA-F]+$/.test(finalized.number??'')
      || !/^0x[0-9a-fA-F]+$/.test(finalized.timestamp??'')) {
    throw new Error('RPC did not return a canonical finalized block');
  }
  const pinned=provider.pinFinalizedSnapshot?.(finalized.number,finalized.hash);
  const finalizedTag=pinned?.tag??finalized.number;
  const governanceCode=await provider.send('eth_getCode',[authority,finalizedTag]);
  if(typeof governanceCode!=='string'||!/^0x(?:[0-9a-fA-F]{2})+$/.test(governanceCode)) {
    throw new Error('governance has no canonical finalized runtime code');
  }
  const approvals=Object.fromEntries(await Promise.all(Object.entries(requests).map(async([name,request])=>{
    const data=eip1271.encodeFunctionData('isValidSignature',[request.digest,request.signature]);
    let valid=false;
    try {
      const result=await provider.send('eth_call',[{to:authority,data},finalizedTag]);
      valid=typeof result==='string' && result.toLowerCase()===encodedMagic.toLowerCase();
    } catch { /* a rejecting or unavailable governance call is an invalid approval */ }
    return [name,{digest:request.digest,valid}];
  })));
  const snapshotAfter=await provider.send('eth_getBlockByNumber',[finalizedTag,false]);
  return {approvals,chainId,
    finalizedBlockHash:finalized.hash,finalizedBlockNumber:BigInt(finalized.number).toString(),
    finalizedBlockTimestamp:BigInt(finalized.timestamp).toString(),
    governance:authority,governanceCodeHash:keccak256(governanceCode),
    snapshotBlockHashAfter:snapshotAfter?.hash??null};
}
