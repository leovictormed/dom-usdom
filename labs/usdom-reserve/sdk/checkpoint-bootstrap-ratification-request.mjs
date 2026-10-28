import {createHash} from 'node:crypto';
import {getAddress} from 'ethers';
import {checkpointBootstrapRatificationDigest}
  from './checkpoint-bootstrap-ratification-report.mjs';
import {checkpointBootstrapRatificationTypedData}
  from './checkpoint-bootstrap-ratification-report.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

export const CHECKPOINT_BOOTSTRAP_RATIFICATION_REQUEST_SCHEMA=
  'usdom-checkpoint-bootstrap-ratification-signing-request-v1';
const hash=/^0x[0-9a-f]{64}$/;
const sha=/^[0-9a-f]{64}$/;
const uint64=/^[1-9][0-9]{0,19}$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
const fail=message=>{ throw new Error(message); };

const bindDocument=(value,bytes,label)=>{
  if(!Buffer.isBuffer(bytes)) fail(`${label} bytes are required`);
  const parsed=parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64});
  if(JSON.stringify(parsed)!==JSON.stringify(value)) fail(`${label} object differs from fixed bytes`);
  return createHash('sha256').update(bytes).digest('hex');
};

export function buildCheckpointBootstrapRatificationSigningRequest({releaseEvidence,
  releaseEvidenceBytes,releaseConfig,releaseConfigBytes,checkpointConsensus,
  checkpointConsensusBytes,nativeFacts,nativeFactsBytes,finalizedAnchor,inputDocuments}={}) {
  const boundDocuments={
    checkpointConsensusSha256:bindDocument(checkpointConsensus,checkpointConsensusBytes,
      'checkpoint consensus'),
    nativeFactsSha256:bindDocument(nativeFacts,nativeFactsBytes,'native facts'),
    releaseConfigSha256:bindDocument(releaseConfig,releaseConfigBytes,'release configuration'),
    releaseEvidenceSha256:bindDocument(releaseEvidence,releaseEvidenceBytes,'release evidence'),
  };
  const ratificationArgs={releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts};
  const digest=checkpointBootstrapRatificationDigest(ratificationArgs);
  const typedData=checkpointBootstrapRatificationTypedData(ratificationArgs);
  if(!exact(finalizedAnchor,['blockHash','blockNumber','blockTimestamp','governance',
    'governanceCodeHash','rpcConsensus'])) fail('finalized anchor schema is invalid');
  validateRpcConsensusEvidence(finalizedAnchor.rpcConsensus);
  if(!uint64.test(finalizedAnchor.blockNumber??'')
      ||BigInt(finalizedAnchor.blockNumber)>=(1n<<64n)
      ||!uint64.test(finalizedAnchor.blockTimestamp??'')
      ||BigInt(finalizedAnchor.blockTimestamp)>=(1n<<64n)
      ||!hash.test(finalizedAnchor.blockHash??'')||BigInt(finalizedAnchor.blockHash)===0n
      ||getAddress(finalizedAnchor.governance)!==getAddress(releaseConfig.governance)
      ||String(finalizedAnchor.governanceCodeHash).toLowerCase()
        !==String(releaseConfig.governanceCodeHash).toLowerCase()
      ||!hash.test(finalizedAnchor.governanceCodeHash??'')
      ||BigInt(finalizedAnchor.governanceCodeHash)===0n) {
    fail('finalized governance differs from release configuration');
  }
  const checkpointObserved=checkpointConsensus?.observedAtUnix;
  if(!uint64.test(checkpointObserved??'')||BigInt(checkpointObserved)>=(1n<<64n)
      ||BigInt(finalizedAnchor.blockTimestamp)<BigInt(checkpointObserved)
      ||BigInt(finalizedAnchor.blockTimestamp)-BigInt(checkpointObserved)>30n*86400n) {
    fail('finalized signing anchor is outside the checkpoint ratification window');
  }
  if(!exact(inputDocuments,['checkpointConsensusSha256','nativeFactsSha256',
    'releaseConfigSha256','releaseEvidenceSha256'])
      ||Object.values(inputDocuments).some(value=>!sha.test(value))
      ||Object.entries(boundDocuments).some(([key,value])=>inputDocuments[key]!==value)) {
    fail('ratification request input commitments are invalid');
  }
  return {schema:CHECKPOINT_BOOTSTRAP_RATIFICATION_REQUEST_SCHEMA,
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',
    governance:getAddress(releaseConfig.governance),ratificationDigest:digest,typedData,
    finalizedAnchor,inputDocuments};
}

export function validateCheckpointBootstrapRatificationSigningRequest(args={}) {
  const expected=buildCheckpointBootstrapRatificationSigningRequest(args);
  const request=args.request;
  if(!exact(request,Object.keys(expected))||JSON.stringify(request)!==JSON.stringify(expected)) {
    fail('ratification signing request differs from authenticated inputs');
  }
  return {digest:expected.ratificationDigest,
    documentSha256:createHash('sha256').update(`${JSON.stringify(request,null,2)}\n`).digest('hex')};
}
