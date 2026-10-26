import {getAddress} from 'ethers';
import {SAFE_MAINNET_IDENTITY} from './safe-control-deployment.mjs';
import {
  SAFE_CONTROL_RELEASE_ROLE_MAP,
  validateRecoverableSafeControlReleaseArtifactSet,
} from './safe-control-release-evidence.mjs';
import {_safeControlObservationInternals} from './safe-control-observation.mjs';

export const SAFE_CONTROL_RELEASE_FRAGMENT_SCHEMA='usdom-safe-control-release-fragment/v2';
export const SAFE_CONTROL_EVIDENCE_PATHS=Object.freeze({
  governance:'evidence/control-plane/governance-configuration.json',
  guardian:'evidence/control-plane/guardian-configuration.json',
  checkpointGuardian:'evidence/control-plane/checkpoint-guardian-configuration.json',
  separation:'evidence/control-plane/control-plane-separation.json',
  recovery:'evidence/control-plane/control-plane-recovery-drill.json',
  bundle:'evidence/control-plane/safe-control-release-evidence-bundle.json',
  fragment:'evidence/control-plane/release-evidence-fragment.json',
});

const SHA256=/^[0-9a-f]{64}$/;
const {canonicalJson}=_safeControlObservationInternals;

function fail(message) { throw new Error(message); }
function exactKeys(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      || canonicalJson(Object.keys(value).sort())!==canonicalJson([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function document(value,path,label) {
  exactKeys(value,['path','sha256'],label);
  if(value.path!==path||typeof value.sha256!=='string'||!SHA256.test(value.sha256)) {
    fail(`${label} identity is invalid`);
  }
  return value;
}
function assignUnset(target,key,value,label) {
  if(target[key]!==null&&target[key]!==value) fail(`${label}.${key} already contains a different value`);
  target[key]=value;
}

export function validateSafeControlReleaseFragment(fragment,bundle) {
  validateRecoverableSafeControlReleaseArtifactSet({
    bundle,
    roleReports:bundle.roleReports,
    separationReport:bundle.separationReport,
    recoveryDrillReport:bundle.recoveryDrillReport,
  });
  exactKeys(fragment,['schema','bundleHash','controlPlaneEvidenceBundle','controlPlane',
    'controlPlaneSeparationReport','controlPlaneRecoveryDrillReport'],
  'Safe control release fragment');
  if(fragment.schema!==SAFE_CONTROL_RELEASE_FRAGMENT_SCHEMA
      || fragment.bundleHash!==bundle.bundleHash) fail('Safe control release fragment identity mismatch');
  document(fragment.controlPlaneEvidenceBundle,SAFE_CONTROL_EVIDENCE_PATHS.bundle,
    'Safe control bundle document');
  exactKeys(fragment.controlPlane,SAFE_CONTROL_RELEASE_ROLE_MAP.map(value=>value.releaseRole),
    'Safe control release roles');
  for(const {releaseRole} of SAFE_CONTROL_RELEASE_ROLE_MAP) {
    const value=fragment.controlPlane[releaseRole];
    exactKeys(value,['address','runtimeCodeHash','configurationHash','configurationReport'],
      `${releaseRole} fragment`);
    const expected=bundle.roleReports[releaseRole];
    if(getAddress(value.address)!==getAddress(expected.address)
        || value.runtimeCodeHash!==expected.runtimeCodeHash
        || value.configurationHash!==expected.configurationHash) {
      fail(`${releaseRole} fragment disagrees with the Safe evidence bundle`);
    }
    document(value.configurationReport,SAFE_CONTROL_EVIDENCE_PATHS[releaseRole],
      `${releaseRole} configuration document`);
  }
  document(fragment.controlPlaneSeparationReport,SAFE_CONTROL_EVIDENCE_PATHS.separation,
    'Safe separation document');
  document(fragment.controlPlaneRecoveryDrillReport,SAFE_CONTROL_EVIDENCE_PATHS.recovery,
    'Safe recovery document');
  return fragment;
}

/** Populate source-release identities only; readiness and authorization remain false. */
export function materializeSafeControlReleaseConfig({releaseConfig,artifactSet}={}) {
  const bundle=validateRecoverableSafeControlReleaseArtifactSet(artifactSet);
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)) {
    fail('proof-reserve release config is missing');
  }
  if(releaseConfig.productionReady!==false||releaseConfig.realFundsAuthorized!==false) {
    fail('Safe materialization cannot preserve a readiness or real-funds claim');
  }
  const result=structuredClone(releaseConfig);
  const allOwners=[];
  for(const {releaseRole} of SAFE_CONTROL_RELEASE_ROLE_MAP) {
    const key=`${releaseRole}Owners`;
    if(!Object.prototype.hasOwnProperty.call(result,key)) fail(`proof-reserve release config lacks ${key}`);
    const approvedOwners=bundle.roleReports[releaseRole].ownersAfter.map(getAddress);
    if(result[key]!==null&&canonicalJson(result[key].map(getAddress))!==canonicalJson(approvedOwners)) {
      fail(`proof-reserve release config.${key} already contains a different value`);
    }
    result[key]=approvedOwners; allOwners.push(...approvedOwners);
  }
  if(new Set(allOwners).size!==9) fail('Safe role owners must be globally distinct');
  for(const {releaseRole} of SAFE_CONTROL_RELEASE_ROLE_MAP) {
    const observed=bundle.roleReports[releaseRole];
    const addressKey=releaseRole;
    const codeHashKey=`${releaseRole}CodeHash`;
    const implementationKey=`${releaseRole}Implementation`;
    const implementationCodeHashKey=`${releaseRole}ImplementationCodeHash`;
    if(!Object.prototype.hasOwnProperty.call(result,addressKey)
        || !Object.prototype.hasOwnProperty.call(result,codeHashKey)
        || !Object.prototype.hasOwnProperty.call(result,implementationKey)
        || !Object.prototype.hasOwnProperty.call(result,implementationCodeHashKey)) {
      fail(`proof-reserve release config lacks ${releaseRole} identity fields`);
    }
    assignUnset(result,addressKey,observed.address,'proof-reserve release config');
    assignUnset(result,codeHashKey,observed.runtimeCodeHash,'proof-reserve release config');
    assignUnset(result,implementationKey,observed.singleton,'proof-reserve release config');
    assignUnset(result,implementationCodeHashKey,SAFE_MAINNET_IDENTITY.singletonCodeHash,
      'proof-reserve release config');
  }
  return result;
}

/** Populate evidence-commit metadata only; all unrelated slots remain untouched. */
export function materializeSafeControlReleaseMetadata({
  releaseEvidence,fragment,artifactSet,
}={}) {
  const bundle=validateRecoverableSafeControlReleaseArtifactSet(artifactSet);
  validateSafeControlReleaseFragment(fragment,bundle);
  if(!releaseEvidence||typeof releaseEvidence!=='object'||Array.isArray(releaseEvidence)
      || releaseEvidence.schema!==1) fail('mainnet release evidence config is invalid');
  const result=structuredClone(releaseEvidence);
  for(const key of ['controlPlaneEvidenceBundle','controlPlane','controlPlaneSeparationReport',
    'controlPlaneRecoveryDrillReport']) {
    if(!Object.prototype.hasOwnProperty.call(result,key)) {
      fail(`mainnet release evidence lacks ${key}`);
    }
    const next=fragment[key];
    const emptyControlPlane=key==='controlPlane'
      && result[key]&&typeof result[key]==='object'&&!Array.isArray(result[key])
      && Object.keys(result[key]).sort().join(',')==='checkpointGuardian,governance,guardian'
      && Object.values(result[key]).every(value=>value===null);
    if(result[key]!==null&&!emptyControlPlane
        && canonicalJson(result[key])!==canonicalJson(next)) {
      fail(`mainnet release evidence ${key} already contains a different value`);
    }
    result[key]=structuredClone(next);
  }
  return result;
}
