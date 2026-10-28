import {createHash} from 'node:crypto';

const sha256=/^[0-9a-f]{64}$/;
const nonzeroSha256=value=>sha256.test(value)&&value!=='0'.repeat(64);
const commit=/^[0-9a-f]{40}$/;
const tag=/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/;

export const SECURITY_VALIDATION_REPORT_SCHEMA='usdom-security-validation-report/v2';
export const SECURITY_VALIDATION_CHECKS=Object.freeze([
  Object.freeze({id:'production-solidity-lint',
    command:'forge lint contracts/USDOMProofReserve.sol contracts/DOMCheckpointRegistry.sol contracts/DOMFinalizedBurnRiscZeroVerifier.sol contracts/DOMCheckpointRiscZeroVerifier.sol --report-unused-suppressions -D warnings'}),
  Object.freeze({id:'production-solidity-build',
    command:'forge build contracts/USDOMProofReserve.sol contracts/DOMCheckpointRegistry.sol contracts/DOMFinalizedBurnRiscZeroVerifier.sol contracts/DOMCheckpointRiscZeroVerifier.sol --force --ignored-error-codes 6335 -D warnings'}),
  Object.freeze({id:'node-regression',command:'node --test test/node/*.test.mjs'}),
  Object.freeze({id:'solidity-regression',command:'forge test -vv'}),
  Object.freeze({id:'deep-solidity-regression',
    command:'FOUNDRY_PROFILE=deep forge test --fuzz-seed 0x5553444f4d20261015 -vv'}),
  Object.freeze({id:'complete-provenance',command:'npm run --silent check:provenance'}),
  Object.freeze({id:'tracked-whitespace',command:'git diff --check'}),
  Object.freeze({id:'final-source-manifest',command:'python3 scripts/source-manifest.py'}),
]);

function fail(message) { throw new Error(message); }
function exact(value,keys) {
  return value&&typeof value==='object'&&!Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
}
function stable(value) {
  if(Array.isArray(value)) return value.map(stable);
  if(value&&typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,stable(value[key])]),
  );
  return value;
}
export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function validateSecurityValidationReleaseEvidence(releaseEvidence) {
  if(!releaseEvidence||releaseEvidence.schema!==1
      || typeof releaseEvidence.releaseId!=='string'||releaseEvidence.releaseId.length===0
      || !commit.test(releaseEvidence.sourceCommit??'')||!tag.test(releaseEvidence.sourceTag??'')) {
    fail('release provenance is incomplete');
  }
  return releaseEvidence;
}

export function buildSecurityValidationReport({releaseEvidence,requirementsSha256,
  sourceManifestSha256,results}={}) {
  validateSecurityValidationReleaseEvidence(releaseEvidence);
  if(!nonzeroSha256(requirementsSha256??'')) fail('requirements SHA-256 is invalid');
  if(!nonzeroSha256(sourceManifestSha256??'')) fail('source manifest SHA-256 is invalid');
  if(!Array.isArray(results)||results.length!==SECURITY_VALIDATION_CHECKS.length) {
    fail('security validation result set is incomplete');
  }
  const checks=SECURITY_VALIDATION_CHECKS.map((expected,index)=>{
    const result=results[index];
    if(!exact(result,['command','exitCode','id','stderrSha256','stdoutSha256','toolSha256'])
        || result.id!==expected.id||result.command!==expected.command
        || result.exitCode!==0||!nonzeroSha256(result.stdoutSha256??'')
        || !nonzeroSha256(result.stderrSha256??'')||!nonzeroSha256(result.toolSha256??'')) {
      fail(`security validation check ${expected.id} did not pass exactly`);
    }
    return {...result};
  });
  for(const group of [['production-solidity-lint','production-solidity-build',
    'solidity-regression','deep-solidity-regression']]) {
    const hashes=group.map(id=>checks.find(check=>check.id===id).toolSha256);
    if(new Set(hashes).size!==1) fail(`security validation tool changed within ${group.join(', ')}`);
  }
  return {schema:SECURITY_VALIDATION_REPORT_SCHEMA,status:'passed',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,requirementsSha256,sourceManifestSha256,checks,
    scope:'The exact immutable source release passed production lint/build, Node and Solidity regressions, deterministic deep fuzz/invariants, complete provenance, tracked whitespace and a final full source-manifest verification, with every executing tool hash pinned and rechecked.',
    limitation:'This report records objective local validation. It does not replace live finalized observations, custody evidence, deployment authorization or explicit real-funds authorization.'};
}

export function validateSecurityValidationReport(report,{releaseEvidence,requirementsSha256,
  sourceManifestSha256}={}) {
  if(!exact(report,['checks','limitation','releaseId','requirementsSha256','schema','scope',
    'sourceCommit','sourceManifestSha256','sourceTag','status'])) fail('security validation report schema is invalid');
  const rebuilt=buildSecurityValidationReport({releaseEvidence,requirementsSha256,
    sourceManifestSha256,results:report.checks});
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(rebuilt))) {
    fail('security validation report differs from its canonical release binding');
  }
  return rebuilt;
}

export function serializeSecurityValidationReport(report) {
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}
