import {getAddress} from 'ethers';
import {checkpointVerifierConfigHash} from './checkpoint-verifier-config.mjs';
import {PRODUCTION_SOLC_LONG_VERSION,PRODUCTION_SOLC_SHA256}
  from './reproducible-build-environment.mjs';

const sha256=/^[0-9a-f]{64}$/;
const bytes32=/^0x[0-9a-fA-F]{64}$/;
const commit=/^[0-9a-f]{40}$/;
const tag=/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/;
const observationKeys=['artifactSha256','buildId','compilerExecutableSha256','compilerVersion','initcodeHash','runtimeCodeHash',
  'sourceSetSha256'];
export const CHECKPOINT_VERIFIER_REPRODUCIBLE_BUILD_REPORT_SCHEMA='usdom-checkpoint-verifier-reproducible-build-report/v1';
export const CHECKPOINT_VERIFIER_REPRODUCIBLE_BUILD_COMMAND=
  'forge build contracts/DOMCheckpointRiscZeroVerifier.sol --root <release-root> --offline --no-auto-detect --use <sha256-pinned-solc-0.8.37> --evm-version cancun --optimize --optimizer-runs 1 --via-ir --force --out <isolated> --cache-path <isolated> --ignored-error-codes 6335 -D warnings';

function fail(message) { throw new Error(message); }
function nonzeroSha256(value) { return sha256.test(value??'')&&!/^0{64}$/.test(value); }
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
function hash(value,name) {
  if(!bytes32.test(value??'')||BigInt(value)===0n) fail(`${name} must be nonzero bytes32`);
  return value.toLowerCase();
}
function document(value,name,expectedPath) {
  if(!exact(value,['path','sha256'])||value.path!==expectedPath||!nonzeroSha256(value.sha256)) {
    fail(`${name} must be exact canonical nonzero hash-addressed evidence`);
  }
  return {...value};
}
function observation(value,id) {
  if(!exact(value,observationKeys)||value.buildId!==id
      ||value.compilerVersion!==PRODUCTION_SOLC_LONG_VERSION
      ||value.compilerExecutableSha256!==PRODUCTION_SOLC_SHA256) fail(`${id} build identity is invalid`);
  for(const key of ['artifactSha256','compilerExecutableSha256','sourceSetSha256']) {
    if(!nonzeroSha256(value[key])) fail(`${id} ${key} must be nonzero SHA-256`);
  }
  return {...value,runtimeCodeHash:hash(value.runtimeCodeHash,`${id} runtimeCodeHash`),
    initcodeHash:hash(value.initcodeHash,`${id} initcodeHash`)};
}

export function buildCheckpointVerifierReproducibleBuildReport({releaseEvidence,releaseConfig,
  verifierConfig,observations}={}) {
  if(!releaseEvidence||releaseEvidence.schema!==1||typeof releaseEvidence.releaseId!=='string'
      ||releaseEvidence.releaseId.length===0||!commit.test(releaseEvidence.sourceCommit??'')
      ||!tag.test(releaseEvidence.sourceTag??'')) fail('release provenance is incomplete');
  const artifact=document(releaseEvidence.checkpointVerifierArtifact,'checkpointVerifierArtifact',
    'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json');
  const configManifest=document(releaseEvidence.checkpointVerifierConfigManifest,'checkpointVerifierConfigManifest',
    'evidence/checkpoint-verifier-config.json');
  if(!releaseConfig||releaseConfig.ethereumChainId!=='1') fail('Ethereum mainnet release is required');
  let checkpointVerifier;
  try {
    checkpointVerifier=getAddress(releaseConfig.checkpointVerifier);
    if(BigInt(checkpointVerifier)===0n) fail('checkpoint verifier address is invalid');
  } catch { fail('checkpoint verifier address is invalid'); }
  const runtimeCodeHash=hash(releaseConfig.checkpointVerifierCodeHash,'checkpointVerifierCodeHash');
  const initcodeHash=hash(releaseConfig.checkpointVerifierInitcodeHash,'checkpointVerifierInitcodeHash');
  const verifierConfigHash=hash(releaseConfig.checkpointVerifierConfigHash,'checkpointVerifierConfigHash');
  let computed;
  try { computed=checkpointVerifierConfigHash(verifierConfig); }
  catch(error) { fail(`checkpoint verifier configuration is invalid: ${error.message}`); }
  if(computed.verifierConfigHash!==verifierConfigHash
      ||computed.manifestSha256.slice(2)!==configManifest.sha256) {
    fail('checkpoint verifier configuration differs from the exact release manifest');
  }
  if(!Array.isArray(observations)||observations.length!==2) fail('two isolated build observations are required');
  const normalized=[observation(observations[0],'isolated-build-a'),
    observation(observations[1],'isolated-build-b')];
  for(const value of normalized) {
    if(value.artifactSha256!==artifact.sha256||value.runtimeCodeHash!==runtimeCodeHash
        ||value.initcodeHash!==initcodeHash) fail(`${value.buildId} differs from the exact release artifact`);
  }
  for(const key of ['artifactSha256','compilerExecutableSha256','compilerVersion','initcodeHash','runtimeCodeHash','sourceSetSha256']) {
    if(normalized[0][key]!==normalized[1][key]) fail(`isolated builds disagree on ${key}`);
  }
  return {schema:CHECKPOINT_VERIFIER_REPRODUCIBLE_BUILD_REPORT_SCHEMA,status:'reproduced',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',checkpointVerifier,verifierConfigHash,
    checkpointVerifierArtifact:artifact,checkpointVerifierConfigManifest:configManifest,
    command:CHECKPOINT_VERIFIER_REPRODUCIBLE_BUILD_COMMAND,observations:normalized,
    conclusion:'Two clean isolated compilations reproduced the exact hash-addressed checkpoint verifier artifact and its configuration-bound deployed runtime and initcode.'};
}

export function validateCheckpointVerifierReproducibleBuildReport(report,context={}) {
  const keys=['command','conclusion','ethereumChainId','observations','releaseId','schema',
    'sourceCommit','sourceTag','status','checkpointVerifier','checkpointVerifierArtifact','verifierConfigHash',
    'checkpointVerifierConfigManifest'];
  if(!exact(report,keys)) fail('checkpoint verifier reproducible-build report schema is invalid');
  const rebuilt=buildCheckpointVerifierReproducibleBuildReport({...context,observations:report.observations});
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(rebuilt))) {
    fail('checkpoint verifier reproducible-build report differs from its canonical release binding');
  }
  return rebuilt;
}

export function serializeCheckpointVerifierReproducibleBuildReport(report) {
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}
