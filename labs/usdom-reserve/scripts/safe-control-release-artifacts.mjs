import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {
  SAFE_CONTROL_EVIDENCE_PATHS,
  validateSafeControlReleaseFragment,
} from '../sdk/safe-control-materialization.mjs';
import {validateRecoverableSafeControlReleaseArtifactSet} from '../sdk/safe-control-release-evidence.mjs';

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
    },
    separationReport:files.separation.value,
    recoveryDrillReport:files.recovery.value,
  };
  validateRecoverableSafeControlReleaseArtifactSet(artifactSet);
  const fragment=files.fragment.value;
  validateSafeControlReleaseFragment(fragment,artifactSet.bundle);
  const references={
    bundle:fragment.controlPlaneEvidenceBundle,
    governance:fragment.controlPlane.governance.configurationReport,
    guardian:fragment.controlPlane.guardian.configurationReport,
    checkpointGuardian:fragment.controlPlane.checkpointGuardian.configurationReport,
    separation:fragment.controlPlaneSeparationReport,
    recovery:fragment.controlPlaneRecoveryDrillReport,
  };
  for(const [name,reference] of Object.entries(references)) {
    if(reference.sha256!==digest(files[name].bytes)) {
      throw new Error(`${name} Safe release-evidence SHA-256 mismatch`);
    }
  }
  return {artifactSet,fragment};
}
