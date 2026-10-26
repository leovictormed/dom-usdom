import {isCanonicalGitSigningKeyFingerprint,isCanonicalReleaseTag} from './git-signature.mjs';

const COMMIT=/^[0-9a-f]{40}$/;
const VERSION=/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;

function fail(message) { throw new Error(message); }
function assignUnset(target,key,value,label) {
  if(target[key]!==null&&target[key]!==value) fail(`${label}.${key} already contains a different value`);
  target[key]=value;
}

export function deriveReleaseProvenanceIdentity({packageVersion,sourceCommit,signingFingerprint}={}) {
  if(typeof packageVersion!=='string'||!VERSION.test(packageVersion)) {
    fail('package version cannot derive a canonical release identity');
  }
  if(typeof sourceCommit!=='string'||!COMMIT.test(sourceCommit)) {
    fail('source commit must be an exact lowercase Git object name');
  }
  if(!isCanonicalGitSigningKeyFingerprint(signingFingerprint)) {
    fail('release-signing fingerprint is not canonical');
  }
  const sourceTag=`usdom-v${packageVersion}`;
  if(!isCanonicalReleaseTag(sourceTag)) fail('derived release tag is not canonical');
  return Object.freeze({
    releaseId:sourceTag,
    sourceCommit,
    sourceTag,
    signingFingerprint,
  });
}

export function materializeReleaseProvenance({
  releaseEvidence,operatorIntent,packageVersion,sourceCommit,signingFingerprint,
}={}) {
  const identity=deriveReleaseProvenanceIdentity({packageVersion,sourceCommit,signingFingerprint});
  if(!releaseEvidence||typeof releaseEvidence!=='object'||Array.isArray(releaseEvidence)
      || releaseEvidence.schema!==1) fail('mainnet release evidence config is invalid');
  if(!operatorIntent||typeof operatorIntent!=='object'||Array.isArray(operatorIntent)
      || operatorIntent.schema!==1) fail('operator intent config is invalid');
  if(!operatorIntent.residual_risk_acceptance
      || typeof operatorIntent.residual_risk_acceptance!=='object'
      || Array.isArray(operatorIntent.residual_risk_acceptance)) {
    fail('operator residual-risk envelope is invalid');
  }
  const nextEvidence=structuredClone(releaseEvidence);
  const nextIntent=structuredClone(operatorIntent);
  for(const key of ['releaseId','sourceCommit','sourceTag']) {
    if(!Object.prototype.hasOwnProperty.call(nextEvidence,key)) {
      fail(`mainnet release evidence lacks ${key}`);
    }
    assignUnset(nextEvidence,key,identity[key],'mainnet release evidence');
  }
  if(!Object.prototype.hasOwnProperty.call(nextIntent,'release_signing_key_fingerprint')) {
    fail('operator intent lacks release-signing fingerprint');
  }
  assignUnset(nextIntent,'release_signing_key_fingerprint',identity.signingFingerprint,'operator intent');
  for(const key of ['releaseId','sourceCommit']) {
    if(!Object.prototype.hasOwnProperty.call(nextIntent.residual_risk_acceptance,key)) {
      fail(`operator residual-risk envelope lacks ${key}`);
    }
    assignUnset(nextIntent.residual_risk_acceptance,key,identity[key],
      'operator residual-risk envelope');
  }
  return {identity,releaseEvidence:nextEvidence,operatorIntent:nextIntent};
}
