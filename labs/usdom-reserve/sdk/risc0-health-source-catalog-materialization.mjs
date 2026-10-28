import {createHash} from 'node:crypto';
import {validateRiscZeroHealthSourceCatalog} from './risc0-health-source-catalog.mjs';
import {collectReleaseEvidenceDocumentPaths} from './release-evidence-document-paths.mjs';
import {isExactReleaseEvidenceShape} from './release-evidence-schema.mjs';

export const RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH='evidence/risc0-health-sources.json';

export function prepareRiscZeroHealthSourceCatalogMaterialization({catalog,evidence}) {
  const validated=validateRiscZeroHealthSourceCatalog(catalog);
  if(!isExactReleaseEvidenceShape(evidence) || evidence.schema!==1
      || !Object.prototype.hasOwnProperty.call(evidence,'riscZeroHealthSourceCatalog')) {
    throw new Error('release evidence does not expose the RISC Zero health source catalog slot');
  }
  const catalogContent=JSON.stringify(validated,null,2)+'\n';
  const sha256=createHash('sha256').update(catalogContent).digest('hex');
  const document={path:RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,sha256};
  const paths=collectReleaseEvidenceDocumentPaths(evidence,{skipTopLevelKey:'riscZeroHealthSourceCatalog'});
  if(paths.includes(document.path)) {
    throw new Error('RISC Zero health source catalog path is already used by another slot');
  }
  const current=evidence.riscZeroHealthSourceCatalog;
  if(current!==null && JSON.stringify(current)!==JSON.stringify(document)) {
    throw new Error('release evidence already binds a different RISC Zero health source catalog');
  }
  const nextEvidence={...evidence,riscZeroHealthSourceCatalog:document};
  return {catalog:validated,catalogContent,sha256,nextEvidence,
    evidenceContent:JSON.stringify(nextEvidence,null,2)+'\n'};
}
