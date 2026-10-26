import {createHash} from 'node:crypto';
import {validateRiscZeroHealthSourceCatalog} from './risc0-health-source-catalog.mjs';

export const RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH='evidence/risc0-health-sources.json';

export function prepareRiscZeroHealthSourceCatalogMaterialization({catalog,evidence}) {
  const validated=validateRiscZeroHealthSourceCatalog(catalog);
  if(!evidence || typeof evidence!=='object' || Array.isArray(evidence)
      || !Object.prototype.hasOwnProperty.call(evidence,'riscZeroHealthSourceCatalog')) {
    throw new Error('release evidence does not expose the RISC Zero health source catalog slot');
  }
  const catalogContent=JSON.stringify(validated,null,2)+'\n';
  const sha256=createHash('sha256').update(catalogContent).digest('hex');
  const nextEvidence={...evidence,riscZeroHealthSourceCatalog:{
    path:RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,sha256,
  }};
  return {catalog:validated,catalogContent,sha256,nextEvidence,
    evidenceContent:JSON.stringify(nextEvidence,null,2)+'\n'};
}
