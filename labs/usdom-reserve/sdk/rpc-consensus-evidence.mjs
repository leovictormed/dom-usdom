import {keccak256,toUtf8Bytes} from 'ethers';

const HASH=/^0x[0-9a-f]{64}$/;
function canonical(value) {
  if(Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if(value&&typeof value==='object') return `{${Object.keys(value).sort().map(key=>
    `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
export function rpcConsensusEvidence(sources) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) throw new Error('two to five RPC sources required');
  const entries=sources.map(source=>({operatorId:source.sourceId,originKeccak256:source.originKeccak256}));
  if(entries.some(value=>typeof value.operatorId!=='string'||!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value.operatorId)
      ||!HASH.test(value.originKeccak256??'')||BigInt(value.originKeccak256)===0n)
      ||new Set(entries.map(v=>v.operatorId)).size!==entries.length
      ||new Set(entries.map(v=>v.originKeccak256)).size!==entries.length) throw new Error('RPC consensus sources invalid');
  const sorted=[...entries].sort((a,b)=>a.operatorId.localeCompare(b.operatorId));
  if(entries.some((v,i)=>v.operatorId!==sorted[i].operatorId)) throw new Error('RPC consensus sources not ordered');
  return {schema:'usdom-rpc-consensus-evidence-v1',sourceCount:String(entries.length),sources:entries,
    sourceSetCommitment:keccak256(toUtf8Bytes(`USDOM_RPC_CONSENSUS_SOURCES_V1\n${entries.map(v=>
      `${v.operatorId}\u0000${v.originKeccak256}`).join('\n')}`))};
}
export function validateRpcConsensusEvidence(value) {
  if(!value||Object.keys(value).sort().join(',')!=='schema,sourceCount,sourceSetCommitment,sources') throw new Error('RPC consensus evidence schema invalid');
  const rebuilt=rpcConsensusEvidence(value.sources.map(v=>({sourceId:v.operatorId,originKeccak256:v.originKeccak256})));
  if(canonical(value)!==canonical(rebuilt)) throw new Error('RPC consensus evidence commitment mismatch');
  return true;
}
export function bindRpcConsensusEvidence(value,sources,hashField) {
  const result={...value}; if(hashField) delete result[hashField];
  result.rpcConsensus=rpcConsensusEvidence(sources);
  if(hashField) result[hashField]=keccak256(toUtf8Bytes(canonical(result)));
  return result;
}
