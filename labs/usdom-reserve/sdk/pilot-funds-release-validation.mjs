import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {isExactReleaseEvidenceShape} from './release-evidence-schema.mjs';
import {validateReleaseValidationReport} from './release-validation-report.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=message=>{throw new Error(message);};

/** Validate the exact long-vector report that a pilot-funds snapshot commits to. */
export function validatePilotFundsReleaseValidation({reportBytes,releaseEvidenceBytes,
  toolchainLockBytes,cargoLockBytes,reportRelativePath}={}) {
  const evidence=parseStrictJsonBytes(releaseEvidenceBytes,{label:'mainnet release evidence',maxDepth:32});
  const lock=parseStrictJsonBytes(toolchainLockBytes,{label:'mainnet toolchain lock',maxDepth:16});
  const report=parseStrictJsonBytes(reportBytes,{label:'release validation report',maxDepth:24});
  if(!isExactReleaseEvidenceShape(evidence)) fail('release evidence schema is incompatible');
  const reference=evidence.releaseValidationReport;
  if(!reference||reference.path!==reportRelativePath||reference.sha256!==sha(reportBytes)) {
    fail('pilot release-validation report differs from the authenticated release-evidence reference');
  }
  const cargoEntry=lock?.files?.find(item=>item?.path==='../../Cargo.lock');
  if(!cargoEntry||cargoEntry.sha256!==sha(cargoLockBytes)) {
    fail('pilot release-validation Cargo.lock differs from the toolchain lock');
  }
  validateReleaseValidationReport(report,{releaseEvidence:evidence,
    toolchainLockSha256:sha(toolchainLockBytes),cargoLockSha256:cargoEntry.sha256});
  return {evidence,reportSha256:reference.sha256};
}
