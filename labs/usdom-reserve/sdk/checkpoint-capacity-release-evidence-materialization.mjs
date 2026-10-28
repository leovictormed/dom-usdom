import {createHash} from 'node:crypto';
import {validateCheckpointProofCapacityReport} from './checkpoint-proof-capacity-report.mjs';
import {collectReleaseEvidenceDocumentPaths} from './release-evidence-document-paths.mjs';
import {isExactReleaseEvidenceShape} from './release-evidence-schema.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

export const CHECKPOINT_CAPACITY_EVIDENCE_PATH=
  'evidence/checkpoint-capacity/checkpoint-proof-capacity-report.json';
export const CHECKPOINT_CAPACITY_MANIFEST_PATH=
  'evidence/checkpoint-capacity/checkpoint-capacity-artifact-manifest.json';

const bindJson=(value,bytes,label)=>{
  if(!Buffer.isBuffer(bytes)
      ||JSON.stringify(parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64}))
        !==JSON.stringify(value)) throw new Error(`${label} bytes differ from parsed authority`);
};

export function validateInstalledCheckpointCapacityReleaseEvidence({
  reportBytes,manifestBytes,evidence,evidenceBytes,releaseConfig,releaseConfigBytes,checkpointVerifierConfig,
  checkpointVerifierConfigBytes,riscZeroReference,
}) {
  bindJson(evidence,evidenceBytes,'release evidence');
  bindJson(releaseConfig,releaseConfigBytes,'proof reserve release configuration');
  bindJson(checkpointVerifierConfig,checkpointVerifierConfigBytes,
    'checkpoint verifier configuration');
  if(!Buffer.isBuffer(reportBytes) || reportBytes.length<2 || reportBytes.length>4*1024*1024) {
    throw new Error('checkpoint capacity evidence bytes are invalid');
  }
  if(!isExactReleaseEvidenceShape(evidence) || evidence.schema!==1) {
    throw new Error('release evidence schema is incompatible');
  }
  const descriptor=evidence.checkpointProofCapacityReport;
  if(!descriptor || typeof descriptor!=='object' || Array.isArray(descriptor)
      || JSON.stringify(Object.keys(descriptor).sort())!==JSON.stringify(['path','sha256'])
      || descriptor.path!==CHECKPOINT_CAPACITY_EVIDENCE_PATH
      || !/^[0-9a-f]{64}$/.test(descriptor.sha256)) {
    throw new Error('checkpoint capacity evidence descriptor is invalid');
  }
  const observedSha256=createHash('sha256').update(reportBytes).digest('hex');
  if(observedSha256!==descriptor.sha256) {
    throw new Error('checkpoint capacity evidence hash mismatch');
  }
  const report=parseStrictJsonBytes(reportBytes,{
    label:'installed checkpoint capacity release report',maxBytes:4*1024*1024,maxDepth:64,
  });
  if(!Buffer.isBuffer(manifestBytes)||createHash('sha256').update(manifestBytes).digest('hex')
      !==report.artifactManifestSha256) throw new Error('checkpoint capacity artifact manifest hash mismatch');
  const manifest=parseStrictJsonBytes(manifestBytes,{label:'checkpoint capacity artifact manifest',maxBytes:16*1024*1024,maxDepth:16});
  if(manifest?.schema!=='usdom-checkpoint-capacity-artifact-manifest/v1'||manifest.runId!==report.runId
      ||!Array.isArray(manifest.files)||manifest.files.length<1) throw new Error('checkpoint capacity artifact manifest identity mismatch');
  const validated=validateCheckpointProofCapacityReport(report,{
    evidence,releaseConfig,checkpointVerifierConfig,riscZeroReference,
  });
  const canonical=Buffer.from(`${JSON.stringify(validated,null,2)}\n`);
  if(!canonical.equals(reportBytes)) {
    throw new Error('checkpoint capacity evidence is not canonical');
  }
  return Object.freeze({report:Object.freeze({...validated}),manifest:Object.freeze(manifest),sha256:observedSha256});
}

/**
 * Revalidate and canonicalize the exact checkpoint capacity report, then
 * prepare its evidence-only metadata update. The caller writes the report
 * first, so interruption cannot create a hash reference to a missing file.
 */
export function prepareCheckpointCapacityReleaseEvidenceMaterialization({
  report,evidence,releaseConfig,checkpointVerifierConfig,riscZeroReference,
}) {
  if(!isExactReleaseEvidenceShape(evidence) || evidence.schema!==1) {
    throw new Error('release evidence schema is incompatible');
  }
  const validated=validateCheckpointProofCapacityReport(report,{
    evidence,releaseConfig,checkpointVerifierConfig,riscZeroReference,
  });
  const paths=collectReleaseEvidenceDocumentPaths(evidence,{
    skipTopLevelKey:'checkpointProofCapacityReport',
  });
  if(paths.includes(CHECKPOINT_CAPACITY_EVIDENCE_PATH)) {
    throw new Error('checkpoint capacity evidence path is already used by another slot');
  }
  const reportContent=JSON.stringify(validated,null,2)+'\n';
  const sha256=createHash('sha256').update(reportContent).digest('hex');
  const document={path:CHECKPOINT_CAPACITY_EVIDENCE_PATH,sha256};
  const current=evidence.checkpointProofCapacityReport;
  if(current!==null && JSON.stringify(current)!==JSON.stringify(document)) {
    throw new Error('release evidence already binds a different checkpoint capacity report');
  }
  const updated={...evidence,checkpointProofCapacityReport:document};
  return Object.freeze({report:Object.freeze({...validated}),reportContent,sha256,
    evidence:Object.freeze(updated),evidenceContent:JSON.stringify(updated,null,2)+'\n'});
}
