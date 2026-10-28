import {createHash} from 'node:crypto';

const hex=/^0x[0-9a-fA-F]*$/;

/**
 * Fingerprint only the artifact fields consumed to construct and interact with
 * a contract. Foundry's surrounding JSON contains build metadata whose byte
 * representation may change when an unrelated concurrent compilation rewrites
 * `out/`, while these three fields remain identical.
 */
export function solidityArtifactExecutableFingerprint(artifact) {
  if(!artifact || typeof artifact!=='object' || Array.isArray(artifact)
      || !Array.isArray(artifact.abi)
      || typeof artifact.bytecode?.object!=='string' || !hex.test(artifact.bytecode.object)
      || artifact.bytecode.object.length<4 || artifact.bytecode.object.length%2!==0
      || typeof artifact.deployedBytecode?.object!=='string'
      || !hex.test(artifact.deployedBytecode.object)
      || artifact.deployedBytecode.object.length<4
      || artifact.deployedBytecode.object.length%2!==0) {
    throw new Error('Solidity artifact lacks canonical executable content');
  }
  const canonical=JSON.stringify({
    abi:artifact.abi,
    creationBytecode:artifact.bytecode.object.toLowerCase(),
    runtimeBytecode:artifact.deployedBytecode.object.toLowerCase(),
  });
  return createHash('sha256').update(canonical).digest('hex');
}
