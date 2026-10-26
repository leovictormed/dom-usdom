import {keccak256} from 'ethers';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {readDirectProjectFile} from './direct-project-file.mjs';

export async function snapshotArtifactSources(root,artifactBytes,{label='canonical artifact'}={}) {
  const artifact=parseStrictJsonBytes(artifactBytes,{
    label,maxBytes:64*1024*1024,maxDepth:128,
  });
  const sources=artifact?.metadata?.sources;
  if(!sources||typeof sources!=='object'||Array.isArray(sources)||Object.keys(sources).length===0) {
    throw new Error(`${label} source metadata is missing`);
  }
  const snapshot=[];
  for(const relative of Object.keys(sources).sort()) {
    const expected=sources[relative]?.keccak256;
    if(typeof expected!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(expected)) {
      throw new Error(`${label} source hash is invalid: ${relative}`);
    }
    const bytes=await readDirectProjectFile(root,relative,{label:`${label} source`,maximum:16*1024*1024});
    if(keccak256(bytes)!==expected.toLowerCase()) {
      throw new Error(`${label} source differs from compiler metadata: ${relative}`);
    }
    snapshot.push(Object.freeze({relative,bytes}));
  }
  return Object.freeze(snapshot);
}

export async function assertArtifactSourcesUnchanged(root,snapshot,{label='canonical artifact'}={}) {
  if(!Array.isArray(snapshot)||snapshot.length===0) throw new Error(`${label} source snapshot is invalid`);
  for(const entry of snapshot) {
    const current=await readDirectProjectFile(root,entry.relative,{
      label:`${label} source`,maximum:16*1024*1024,
    });
    if(!current.equals(entry.bytes)) throw new Error(`${label} source changed during materialization: ${entry.relative}`);
  }
  return true;
}
