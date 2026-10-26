import {createHash} from 'node:crypto';
import {validateFinalizedBurnE2eReport} from './finalized-burn-e2e-report.mjs';
import {collectReleaseEvidenceDocumentPaths} from './release-evidence-document-paths.mjs';
import {isExactReleaseEvidenceShape} from './release-evidence-schema.mjs';

export const FINALIZED_BURN_E2E_EVIDENCE_PATH=
  'evidence/finalized-burn-e2e/finalized-burn-e2e-report.json';

/**
 * Revalidate and canonicalize the exact release report, then prepare an
 * evidence-only metadata update. The writer publishes the report before this
 * metadata so a crash can leave only an unreferenced file, never a dangling
 * hash-addressed evidence reference.
 */
export function prepareFinalizedBurnReleaseEvidenceMaterialization({
  report,evidence,releaseConfig,verifierConfig,riscZeroReference,
}) {
  if(!isExactReleaseEvidenceShape(evidence) || evidence.schema!==1) {
    throw new Error('release evidence schema is incompatible');
  }
  const validated=validateFinalizedBurnE2eReport(report,{
    evidence,releaseConfig,verifierConfig,riscZeroReference,
  });
  const paths=collectReleaseEvidenceDocumentPaths(evidence,{
    skipTopLevelKey:'realFinalizedEndToEndReport',
  });
  if(paths.includes(FINALIZED_BURN_E2E_EVIDENCE_PATH)) {
    throw new Error('finalized-burn E2E evidence path is already used by another slot');
  }
  const reportContent=JSON.stringify(validated,null,2)+'\n';
  const sha256=createHash('sha256').update(reportContent).digest('hex');
  const updated={...evidence,realFinalizedEndToEndReport:{
    path:FINALIZED_BURN_E2E_EVIDENCE_PATH,sha256,
  }};
  return Object.freeze({report:Object.freeze({...validated}),reportContent,sha256,
    evidence:Object.freeze(updated),evidenceContent:JSON.stringify(updated,null,2)+'\n'});
}
