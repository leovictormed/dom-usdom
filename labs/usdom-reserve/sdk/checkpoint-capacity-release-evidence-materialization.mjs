import {createHash} from 'node:crypto';
import {validateCheckpointProofCapacityReport} from './checkpoint-proof-capacity-report.mjs';
import {collectReleaseEvidenceDocumentPaths} from './release-evidence-document-paths.mjs';
import {isExactReleaseEvidenceShape} from './release-evidence-schema.mjs';

export const CHECKPOINT_CAPACITY_EVIDENCE_PATH=
  'evidence/checkpoint-capacity/checkpoint-proof-capacity-report.json';

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
  const updated={...evidence,checkpointProofCapacityReport:{
    path:CHECKPOINT_CAPACITY_EVIDENCE_PATH,sha256,
  }};
  return Object.freeze({report:Object.freeze({...validated}),reportContent,sha256,
    evidence:Object.freeze(updated),evidenceContent:JSON.stringify(updated,null,2)+'\n'});
}
