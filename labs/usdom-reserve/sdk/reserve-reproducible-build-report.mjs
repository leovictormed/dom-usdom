import {createHash} from 'node:crypto';
import {getAddress} from 'ethers';

const sha256=/^[0-9a-f]{64}$/;
const bytes32=/^0x[0-9a-fA-F]{64}$/;
const commit=/^[0-9a-f]{40}$/;
const tag=/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/;
const compiler=/^0\.8\.37\+commit\.[0-9a-f]{8}$/;
const observationKeys=['artifactSha256','buildId','compilerExecutableSha256','compilerVersion','initcodeHash','runtimeCodeHash',
  'sourceSetSha256'];
export const RESERVE_REPRODUCIBLE_BUILD_REPORT_SCHEMA='usdom-reserve-reproducible-build-report/v1';
export const RESERVE_REPRODUCIBLE_BUILD_COMMAND=
  'forge build contracts/USDOMProofReserve.sol --root <release-root> --offline --no-auto-detect --use <sha256-pinned-solc-0.8.37> --evm-version cancun --optimize --optimizer-runs 200 --force --out <isolated> --cache-path <isolated> --ignored-error-codes 6335 -D warnings';

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
function hash(value,name) {
  if(!bytes32.test(value??'')||BigInt(value)===0n) fail(`${name} must be nonzero bytes32`);
  return value.toLowerCase();
}
function document(value,name) {
  if(!exact(value,['path','sha256'])||typeof value.path!=='string'||value.path.length===0
      ||value.path.startsWith('/')||value.path.includes('\\')||value.path.split('/').includes('..')
      ||!sha256.test(value.sha256??'')) fail(`${name} must be exact hash-addressed evidence`);
  return {...value};
}
function observation(value,id) {
  if(!exact(value,observationKeys)||value.buildId!==id
      ||!compiler.test(value.compilerVersion??'')) fail(`${id} build identity is invalid`);
  for(const key of ['artifactSha256','compilerExecutableSha256','sourceSetSha256']) {
    if(!sha256.test(value[key]??'')) fail(`${id} ${key} is invalid`);
  }
  return {...value,runtimeCodeHash:hash(value.runtimeCodeHash,`${id} runtimeCodeHash`),
    initcodeHash:hash(value.initcodeHash,`${id} initcodeHash`)};
}

export function sourceSetSha256(metadata) {
  const sources=metadata?.sources;
  if(!sources||typeof sources!=='object'||Array.isArray(sources)||Object.keys(sources).length===0) {
    fail('compiled source set is missing');
  }
  const entries=Object.keys(sources).sort().map(source=>{
    const value=sources[source];
    if(!value||typeof value!=='object'||Array.isArray(value)
        ||!bytes32.test(value.keccak256??'')) fail(`compiled source metadata is invalid: ${source}`);
    return [source,value.keccak256.toLowerCase()];
  });
  return createHash('sha256').update(`${JSON.stringify(entries)}\n`).digest('hex');
}

export function buildReserveReproducibleBuildReport({releaseEvidence,releaseConfig,observations}={}) {
  if(!releaseEvidence||releaseEvidence.schema!==1||typeof releaseEvidence.releaseId!=='string'
      ||releaseEvidence.releaseId.length===0||!commit.test(releaseEvidence.sourceCommit??'')
      ||!tag.test(releaseEvidence.sourceTag??'')) fail('release provenance is incomplete');
  const artifact=document(releaseEvidence.reserveArtifact,'reserveArtifact');
  if(artifact.path!=='out/USDOMProofReserve.sol/USDOMProofReserve.json') {
    fail('reserveArtifact path is not canonical');
  }
  if(!releaseConfig||releaseConfig.ethereumChainId!=='1') fail('Ethereum mainnet release is required');
  let reserve;
  try {
    reserve=getAddress(releaseConfig.reserve);
    if(BigInt(reserve)===0n) fail('reserve address is invalid');
  }
  catch { fail('reserve address is invalid'); }
  const runtimeCodeHash=hash(releaseConfig.reserveRuntimeCodeHash,'reserveRuntimeCodeHash');
  const initcodeHash=hash(releaseConfig.reserveInitcodeHash,'reserveInitcodeHash');
  const reserveConfigHash=hash(releaseConfig.reserveConfigHash,'reserveConfigHash');
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
  return {schema:RESERVE_REPRODUCIBLE_BUILD_REPORT_SCHEMA,status:'reproduced',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',reserve,reserveConfigHash,
    reserveArtifact:artifact,command:RESERVE_REPRODUCIBLE_BUILD_COMMAND,observations:normalized,
    conclusion:'Two clean isolated compilations reproduced the exact hash-addressed reserve artifact and its release-bound deployed runtime and initcode.'};
}

export function validateReserveReproducibleBuildReport(report,context={}) {
  const keys=['command','conclusion','ethereumChainId','observations','releaseId','reserve',
    'reserveArtifact','reserveConfigHash','schema','sourceCommit','sourceTag','status'];
  if(!exact(report,keys)) fail('reserve reproducible-build report schema is invalid');
  const rebuilt=buildReserveReproducibleBuildReport({...context,observations:report.observations});
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(rebuilt))) {
    fail('reserve reproducible-build report differs from its canonical release binding');
  }
  return rebuilt;
}

export function serializeReserveReproducibleBuildReport(report) {
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}
