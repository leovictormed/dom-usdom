import {createHash} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {readDirectFile} from './direct-project-file.mjs';

export const RISC0_RECURSION_ARTIFACT_BYTES=59_768_781;
export const RISC0_RECURSION_ARTIFACT_SHA256=
  '744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849';

async function inspectDirectArtifact(target) {
  const bytes=await readDirectFile(target,{
    minimum:RISC0_RECURSION_ARTIFACT_BYTES,maximum:RISC0_RECURSION_ARTIFACT_BYTES,
    privateMode:false,label:'RISC Zero recursion artifact',
  });
  return Object.freeze({bytes:bytes.length,
    sha256:createHash('sha256').update(bytes).digest('hex')});
}

/** Authenticate the pinned local recursion artifact and bind it into a fresh environment. */
export async function requireRisc0RecursionArtifact({
  environment=process.env,home=os.homedir(),inspectArtifact=inspectDirectArtifact,
}={}) {
  if(!environment || typeof environment!=='object' || Array.isArray(environment)) {
    throw new Error('RISC Zero recursion environment must be an object');
  }
  if(typeof inspectArtifact!=='function') throw new Error('recursion artifact inspector must be a function');
  const dataRoot=environment.XDG_DATA_HOME??path.join(home,'.local/share');
  const target=environment.RECURSION_SRC_PATH??
    path.join(dataRoot,'dom-usdom/toolchain/risc0-4.0.5/recursion_zkr.zip');
  if(typeof target!=='string' || !path.isAbsolute(target) || path.normalize(target)!==target
      || target===path.parse(target).root) {
    throw new Error('RISC Zero recursion artifact path must be canonical and absolute');
  }
  let identity;
  try { identity=await inspectArtifact(target); }
  catch(error) {
    throw new Error(`missing or unsafe direct RISC Zero recursion artifact: ${target}`,{cause:error});
  }
  if(!identity || identity.bytes!==RISC0_RECURSION_ARTIFACT_BYTES
      || identity.sha256!==RISC0_RECURSION_ARTIFACT_SHA256) {
    throw new Error('RISC Zero recursion artifact size or SHA-256 mismatch');
  }
  return Object.freeze({path:target,bytes:identity.bytes,sha256:identity.sha256,
    environment:Object.freeze({...environment,RECURSION_SRC_PATH:target})});
}
