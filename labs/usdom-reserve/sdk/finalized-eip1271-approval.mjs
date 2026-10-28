import {AbiCoder,Interface,getAddress,keccak256} from 'ethers';
import {MAX_UINT256,canonicalEthereumQuantity,canonicalUnsignedDecimal}
  from './ethereum-quantity.mjs';

export const EIP1271_MAGIC_VALUE='0x1626ba7e';
export const MAX_EIP1271_SIGNATURE_BYTES=65_536;

const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const signaturePattern=/^0x(?:[0-9a-f]{2})+$/;
const eip1271=new Interface([
  'function isValidSignature(bytes32 digest,bytes signature) view returns (bytes4)',
]);
const encodedMagic=AbiCoder.defaultAbiCoder().encode(['bytes4'],[EIP1271_MAGIC_VALUE]);

export function validEip1271Signature(value) {
  return typeof value==='string' && signaturePattern.test(value)
    && (value.length-2)/2<=MAX_EIP1271_SIGNATURE_BYTES;
}

export async function collectFinalizedEip1271Approvals({provider,chainId,governance,
  governanceImplementation,governanceImplementationCodeHash,requests}) {
  if(!provider || typeof provider.send!=='function') throw new Error('JSON-RPC provider is required');
  let expectedChainId;
  try { expectedChainId=canonicalUnsignedDecimal(chainId,{maximum:MAX_UINT256}); }
  catch { throw new Error('chainId must be a nonzero canonical integer string'); }
  if(expectedChainId==='0') {
    throw new Error('chainId must be a nonzero canonical integer string');
  }
  const authority=getAddress(governance);
  const implementation=getAddress(governanceImplementation);
  if(BigInt(implementation)===0n || !bytes32Pattern.test(governanceImplementationCodeHash??'')
      || BigInt(governanceImplementationCodeHash)===0n) {
    throw new Error('governance implementation identity is required');
  }
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
  let observedChainId,finalizedNumber,finalizedTimestamp;
  try {
    observedChainId=canonicalEthereumQuantity(chainIdValue,{maximum:MAX_UINT256});
    finalizedNumber=canonicalEthereumQuantity(finalized?.number);
    finalizedTimestamp=canonicalEthereumQuantity(finalized?.timestamp);
  } catch { throw new Error('RPC did not return canonical bounded quantities'); }
  if(observedChainId!==expectedChainId) throw new Error('RPC chain ID differs from release');
  if(!bytes32Pattern.test(finalized?.hash??'')) {
    throw new Error('RPC did not return a canonical finalized block');
  }
  const pinned=provider.pinFinalizedSnapshot?.(finalized.number,finalized.hash);
  const finalizedTag=pinned?.tag??finalized.number;
  const [governanceCode,implementationCode,singletonWord]=await Promise.all([
    provider.send('eth_getCode',[authority,finalizedTag]),
    provider.send('eth_getCode',[implementation,finalizedTag]),
    provider.send('eth_getStorageAt',[authority,'0x0',finalizedTag]),
  ]);
  if(typeof governanceCode!=='string'||!/^0x(?:[0-9a-fA-F]{2})+$/.test(governanceCode)) {
    throw new Error('governance has no canonical finalized runtime code');
  }
  if(typeof implementationCode!=='string'||!/^0x(?:[0-9a-fA-F]{2})+$/.test(implementationCode)
      ||keccak256(implementationCode).toLowerCase()!==governanceImplementationCodeHash.toLowerCase()) {
    throw new Error('governance implementation differs from release');
  }
  if(typeof singletonWord!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(singletonWord)
      ||getAddress(`0x${singletonWord.slice(-40)}`)!==implementation) {
    throw new Error('governance proxy implementation differs from release');
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
  const [snapshotAfter,governanceCodeAfter,implementationCodeAfter,singletonWordAfter]=await Promise.all([
    provider.send('eth_getBlockByNumber',[finalizedTag,false]),
    provider.send('eth_getCode',[authority,finalizedTag]),
    provider.send('eth_getCode',[implementation,finalizedTag]),
    provider.send('eth_getStorageAt',[authority,'0x0',finalizedTag]),
  ]);
  if(String(governanceCodeAfter).toLowerCase()!==governanceCode.toLowerCase()
      ||String(implementationCodeAfter).toLowerCase()!==implementationCode.toLowerCase()
      ||String(singletonWordAfter).toLowerCase()!==singletonWord.toLowerCase()) {
    throw new Error('governance implementation changed during finalized collection');
  }
  return {approvals,chainId:expectedChainId,
    finalizedBlockHash:finalized.hash,finalizedBlockNumber:finalizedNumber,
    finalizedBlockTimestamp:finalizedTimestamp,
    governance:authority,governanceCodeHash:keccak256(governanceCode),
    snapshotBlockHashAfter:snapshotAfter?.hash??null};
}
