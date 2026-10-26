import {createHash} from 'node:crypto';
import {getAddress} from 'ethers';
import {checkpointBootstrapRatificationDigest}
  from './checkpoint-bootstrap-ratification-report.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

export const CHECKPOINT_BOOTSTRAP_RATIFICATION_REQUEST_SCHEMA=
  'usdom-checkpoint-bootstrap-ratification-signing-request-v1';
const hash=/^0x[0-9a-f]{64}$/;
const sha=/^[0-9a-f]{64}$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
const fail=message=>{ throw new Error(message); };

export function buildCheckpointBootstrapRatificationSigningRequest({releaseEvidence,releaseConfig,
  checkpointConsensus,nativeFacts,finalizedAnchor,inputDocuments}={}) {
  const digest=checkpointBootstrapRatificationDigest({releaseEvidence,releaseConfig,
    checkpointConsensus,nativeFacts});
  if(!exact(finalizedAnchor,['blockHash','blockNumber','blockTimestamp','governance',
    'governanceCodeHash','rpcConsensus'])) fail('finalized anchor schema is invalid');
  validateRpcConsensusEvidence(finalizedAnchor.rpcConsensus);
  if(getAddress(finalizedAnchor.governance)!==getAddress(releaseConfig.governance)
      ||String(finalizedAnchor.governanceCodeHash).toLowerCase()
        !==String(releaseConfig.governanceCodeHash).toLowerCase()) {
    fail('finalized governance differs from release configuration');
  }
  if(!exact(inputDocuments,['checkpointConsensusSha256','nativeFactsSha256',
    'releaseConfigSha256','releaseEvidenceSha256'])
      ||Object.values(inputDocuments).some(value=>!sha.test(value))) {
    fail('ratification request input commitments are invalid');
  }
  return {schema:CHECKPOINT_BOOTSTRAP_RATIFICATION_REQUEST_SCHEMA,
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',
    governance:getAddress(releaseConfig.governance),ratificationDigest:digest,
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
