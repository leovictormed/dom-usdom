import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {
  SAFE_CONTROL_EVIDENCE_PATHS,
  validateSafeControlReleaseFragment,
} from '../sdk/safe-control-materialization.mjs';
import {validateRecoverableSafeControlReleaseArtifactSet} from '../sdk/safe-control-release-evidence.mjs';
import {validateSafeControlReleaseArtifactSetV3} from '../sdk/safe-control-release-evidence-v3.mjs';

function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

export function parseSafeControlReleaseArtifactBytes(bytes,path) {
  return parseStrictJsonBytes(bytes,{label:path,maxBytes:4*1024*1024,maxDepth:48});
}

export async function readSafeControlReleaseArtifacts(root) {
  const entries=await Promise.all(Object.entries(SAFE_CONTROL_EVIDENCE_PATHS).map(
    async([name,path])=>{
      const bytes=await readDirectProjectFile(root,path);
      return [name,{bytes,value:parseSafeControlReleaseArtifactBytes(bytes,path)}];
    },
  ));
  const files=Object.fromEntries(entries);
  const artifactSet={
    bundle:files.bundle.value,
    roleReports:{
      governance:files.governance.value,
      guardian:files.guardian.value,
      checkpointGuardian:files.checkpointGuardian.value,
      usdtCustody:files.usdtCustody.value,
    },
    separationReport:files.separation.value,
    recoveryDrillReport:files.recovery.value,
  };
  if(artifactSet.bundle.schema==='usdom-safe-control-release-evidence/v3') validateSafeControlReleaseArtifactSetV3(artifactSet);
  else validateRecoverableSafeControlReleaseArtifactSet(artifactSet);
  const fragment=files.fragment.value;
  validateSafeControlReleaseFragment(fragment,artifactSet.bundle);
  const references={
    bundle:fragment.controlPlaneEvidenceBundle,
    governance:fragment.controlPlane.governance.configurationReport,
    guardian:fragment.controlPlane.guardian.configurationReport,
    checkpointGuardian:fragment.controlPlane.checkpointGuardian.configurationReport,
    usdtCustody:fragment.controlPlane.usdtCustody.configurationReport,
    separation:fragment.controlPlaneSeparationReport,
    recovery:fragment.controlPlaneRecoveryDrillReport,
  };
  for(const [name,reference] of Object.entries(references)) {
    if(reference.sha256!==digest(files[name].bytes)) {
      throw new Error(`${name} Safe release-evidence SHA-256 mismatch`);
    }
  }
  // The fragment commits to each support file, but those files were opened at
  // different instants. Re-read the complete fixed catalog after validation so
  // a concurrent renewal cannot yield a mixed generation that merely happened
  // to be internally valid while it was being assembled.
  const current=await Promise.all(Object.entries(SAFE_CONTROL_EVIDENCE_PATHS).map(
    async([name,path])=>[name,await readDirectProjectFile(root,path)],
  ));
  for(const [name,bytes] of current) {
    if(!bytes.equals(files[name].bytes)) {
      throw new Error('Safe control release artifacts changed during materialization');
    }
  }
  return {artifactSet,fragment};
}
