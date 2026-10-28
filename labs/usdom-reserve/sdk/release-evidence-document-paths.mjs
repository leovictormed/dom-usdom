const rawSha256Pattern=/^[0-9a-f]{64}$/;
const canonicalFoundryArtifactPaths = new Set([
  'out/USDOMProofReserve.sol/USDOMProofReserve.json',
  'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',
  'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
  'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json',
]);

export function isCanonicalReleaseEvidenceDocumentPath(value) {
  if(typeof value!=='string' || value.length===0 || value.length>4095
      || value.startsWith('/') || value.includes('\\') || value.includes('\0')) return false;
  if(canonicalFoundryArtifactPaths.has(value)) return true;
  const parts=value.split('/');
  if(!parts.every(part=>part.length<=255
      && /^[a-z0-9][a-z0-9._-]*$/.test(part))) return false;
  return parts[0]==='evidence' && parts.length>1;
}

function exactDocument(value) {
  return value && typeof value==='object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===JSON.stringify(['path','sha256'])
    && isCanonicalReleaseEvidenceDocumentPath(value.path)
    && typeof value.sha256==='string' && rawSha256Pattern.test(value.sha256)
    && value.sha256!=='0'.repeat(64);
}

/**
 * Enumerate every hash-addressed document in release evidence. Any object that
 * resembles a document must be exact; malformed and overly deep structures
 * fail closed before a materializer writes repository state.
 */
export function collectReleaseEvidenceDocumentPaths(value,{
  skipTopLevelKey=null,maxDepth=8,maxNodes=8192,
}={}) {
  if(!Number.isSafeInteger(maxDepth) || maxDepth<1 || maxDepth>32
      || !Number.isSafeInteger(maxNodes) || maxNodes<1 || maxNodes>65536) {
    throw new Error('invalid release-evidence traversal bounds');
  }
  const paths=[];
  const documents=[];
  let nodes=0;
  const visit=(current,depth,key=null)=>{
    nodes+=1;
    if(nodes>maxNodes) throw new Error('release evidence exceeds its structural node bound');
    if(depth>maxDepth) throw new Error('release evidence exceeds its structural depth bound');
    if(depth===1 && key===skipTopLevelKey) return;
    if(current===null || typeof current!=='object') return;
    const hasPath=Object.prototype.hasOwnProperty.call(current,'path');
    const hasSha256=Object.prototype.hasOwnProperty.call(current,'sha256');
    if(hasPath || hasSha256) {
      if(!exactDocument(current)) throw new Error('release evidence contains a malformed document');
      paths.push(current.path);
      documents.push(current);
      return;
    }
    if(Array.isArray(current)) {
      for(const item of current) visit(item,depth+1);
      return;
    }
    for(const [name,item] of Object.entries(current)) visit(item,depth+1,name);
  };
  visit(value,0);
  const finalizedTranscript=value?.trustedSetup?.transcript;
  const checkpointTranscript=value?.checkpointTrustedSetup?.transcript;
  const finalizedDecision=value?.trustedSetup?.decisionReport;
  const checkpointDecision=value?.checkpointTrustedSetup?.decisionReport;
  const finalizedVerifyingKey=value?.verifyingKeyArtifact;
  const checkpointVerifyingKey=value?.checkpointVerifyingKeyArtifact;
  const sharedTranscriptPath=skipTopLevelKey!=='trustedSetup'
    && skipTopLevelKey!=='checkpointTrustedSetup'
    && exactDocument(finalizedTranscript) && exactDocument(checkpointTranscript)
    && finalizedTranscript.path===checkpointTranscript.path
    && finalizedTranscript.sha256===checkpointTranscript.sha256
    ? finalizedTranscript.path : null;
  const sharedDecisionPath=skipTopLevelKey!=='trustedSetup'
    && skipTopLevelKey!=='checkpointTrustedSetup'
    && exactDocument(finalizedDecision) && exactDocument(checkpointDecision)
    && finalizedDecision.path===checkpointDecision.path
    && finalizedDecision.sha256===checkpointDecision.sha256
    ? finalizedDecision.path : null;
  const sharedVerifyingKeyPath=skipTopLevelKey!=='verifyingKeyArtifact'
    && skipTopLevelKey!=='checkpointVerifyingKeyArtifact'
    && exactDocument(finalizedVerifyingKey) && exactDocument(checkpointVerifyingKey)
    && finalizedVerifyingKey.path===checkpointVerifyingKey.path
    && finalizedVerifyingKey.sha256===checkpointVerifyingKey.sha256
    ? finalizedVerifyingKey.path : null;
  const counts=new Map();
  for(const path of paths) counts.set(path,(counts.get(path)??0)+1);
  for(const [path,count] of counts) {
    if(count!==1 && !((path===sharedTranscriptPath || path===sharedDecisionPath
        || path===sharedVerifyingKeyPath) && count===2)) {
      throw new Error('release evidence contains duplicate document paths');
    }
  }
  const distinctDocuments=new Map();
  for(const document of documents) {
    const previous=distinctDocuments.get(document.path);
    if(previous===undefined) distinctDocuments.set(document.path,document.sha256);
    else if(previous!==document.sha256) {
      throw new Error('release evidence contains one path with conflicting content hashes');
    }
  }
  const contentOwners=new Map();
  for(const [path,sha256] of distinctDocuments) {
    const previous=contentOwners.get(sha256);
    if(previous!==undefined && previous!==path) {
      throw new Error('release evidence contains duplicate document content under different paths');
    }
    contentOwners.set(sha256,path);
  }
  return Object.freeze([...new Set(paths)]);
}
