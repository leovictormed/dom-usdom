import {getAddress} from 'ethers';
import {checkpointRegistryConfigHash} from './checkpoint-registry.mjs';
import {safeOwnersCommitment} from './configuration.mjs';
import {PRODUCTION_SOLC_LONG_VERSION,PRODUCTION_SOLC_SHA256} from './reproducible-build-environment.mjs';

const sha256=/^[0-9a-f]{64}$/;
const bytes32=/^0x[0-9a-fA-F]{64}$/;
const commit=/^[0-9a-f]{40}$/;
const tag=/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/;
const observationKeys=['artifactSha256','buildId','compilerExecutableSha256','compilerVersion','initcodeHash','runtimeCodeHash','sourceSetSha256'];
export const CHECKPOINT_REGISTRY_REPRODUCIBLE_BUILD_REPORT_SCHEMA='usdom-checkpoint-registry-reproducible-build-report/v1';
export const CHECKPOINT_REGISTRY_REPRODUCIBLE_BUILD_COMMAND=
  'forge build contracts/DOMCheckpointRegistry.sol --root <release-root> --offline --no-auto-detect --use <sha256-pinned-solc-0.8.37> --evm-version cancun --optimize --optimizer-runs 1 --via-ir --force --out <isolated> --cache-path <isolated> --ignored-error-codes 6335 -D warnings';

function fail(message) { throw new Error(message); }
function nonzeroSha256(value) { return sha256.test(value??'')&&!/^0{64}$/.test(value); }
function exact(value,keys) { return value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort()); }
function stable(value) { if(Array.isArray(value)) return value.map(stable);
  if(value&&typeof value==='object') return Object.fromEntries(Object.keys(value).sort().map(k=>[k,stable(value[k])]));
  return value; }
function hash(value,name) { if(!bytes32.test(value??'')||BigInt(value)===0n) fail(`${name} must be nonzero bytes32`); return value.toLowerCase(); }
function document(value) { const expected='out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json';
  if(!exact(value,['path','sha256'])||value.path!==expected||!nonzeroSha256(value.sha256)) fail('checkpointRegistryArtifact must be exact canonical nonzero hash-addressed evidence'); return {...value}; }
function observation(value,id) { if(!exact(value,observationKeys)||value.buildId!==id
    ||value.compilerVersion!==PRODUCTION_SOLC_LONG_VERSION
    ||value.compilerExecutableSha256!==PRODUCTION_SOLC_SHA256) fail(`${id} build identity is invalid`);
  if(!nonzeroSha256(value.artifactSha256)||!nonzeroSha256(value.compilerExecutableSha256)
      ||!nonzeroSha256(value.sourceSetSha256)) fail(`${id} build hashes must be nonzero SHA-256`);
  return {...value,runtimeCodeHash:hash(value.runtimeCodeHash,`${id} runtimeCodeHash`),initcodeHash:hash(value.initcodeHash,`${id} initcodeHash`)}; }
function registryConfiguration(c) { return {
  ethereumChainId:c.ethereumChainId,registry:c.checkpointRegistry,bridgeDomain:c.domDomain,
  domNetworkMagic:c.checkpointDomNetworkMagic,domChainId:c.checkpointDomChainId,
  firstV4Height:c.checkpointFirstV4Height,activationEmptyStateRoot:c.checkpointActivationEmptyStateRoot,
  activationScheduleCommitment:c.activationScheduleCommitment,
  checkpointInterval:c.checkpointIntervalBlocks,confirmationDepth:c.checkpointConfirmationDepthBlocks,
  challengePeriod:c.checkpointChallengePeriodSeconds,verifier:c.checkpointVerifier,
  verifierCodeHash:c.checkpointVerifierCodeHash,verifierConfigHash:c.checkpointVerifierConfigHash,
  guardian:c.checkpointGuardian,guardianCodeHash:c.checkpointGuardianCodeHash,
  guardianImplementation:c.checkpointGuardianImplementation,
  guardianImplementationCodeHash:c.checkpointGuardianImplementationCodeHash,
  guardianOwnersCommitment:safeOwnersCommitment(c.checkpointGuardianOwners),
  initialHeight:c.checkpointInitialHeight,initialBlock:c.checkpointInitialBlock,
  initialStateRoot:c.checkpointInitialStateRoot,initialContextHash:c.checkpointInitialContextHash,
  initialTotalDifficulty:c.checkpointInitialTotalDifficulty,
}; }

export function buildCheckpointRegistryReproducibleBuildReport({releaseEvidence,releaseConfig,observations}={}) {
  if(!releaseEvidence||releaseEvidence.schema!==1||typeof releaseEvidence.releaseId!=='string'||releaseEvidence.releaseId.length===0
      ||!commit.test(releaseEvidence.sourceCommit??'')||!tag.test(releaseEvidence.sourceTag??'')) fail('release provenance is incomplete');
  const artifact=document(releaseEvidence.checkpointRegistryArtifact);
  if(!releaseConfig||releaseConfig.ethereumChainId!=='1') fail('Ethereum mainnet release is required');
  let checkpointRegistry; try { checkpointRegistry=getAddress(releaseConfig.checkpointRegistry); if(BigInt(checkpointRegistry)===0n) fail('invalid'); }
  catch { fail('checkpoint registry address is invalid'); }
  const runtimeCodeHash=hash(releaseConfig.checkpointRegistryRuntimeCodeHash,'checkpointRegistryRuntimeCodeHash');
  const initcodeHash=hash(releaseConfig.checkpointRegistryInitcodeHash,'checkpointRegistryInitcodeHash');
  let computed; try { computed=checkpointRegistryConfigHash(registryConfiguration(releaseConfig)); }
  catch(error) { fail(`checkpoint registry configuration is invalid: ${error.message}`); }
  const releaseRegistryConfigHash=hash(releaseConfig.checkpointRegistryConfigHash,'checkpointRegistryConfigHash');
  if(computed.checkpointConfigHash!==releaseRegistryConfigHash) fail('checkpoint registry configuration differs from exact release');
  if(!Array.isArray(observations)||observations.length!==2) fail('two isolated build observations are required');
  const normalized=[observation(observations[0],'isolated-build-a'),observation(observations[1],'isolated-build-b')];
  for(const value of normalized) if(value.artifactSha256!==artifact.sha256||value.runtimeCodeHash!==runtimeCodeHash||value.initcodeHash!==initcodeHash) fail(`${value.buildId} differs from exact release artifact`);
  for(const key of ['artifactSha256','compilerExecutableSha256','compilerVersion','initcodeHash','runtimeCodeHash','sourceSetSha256']) if(normalized[0][key]!==normalized[1][key]) fail(`isolated builds disagree on ${key}`);
  return {schema:CHECKPOINT_REGISTRY_REPRODUCIBLE_BUILD_REPORT_SCHEMA,status:'reproduced',releaseId:releaseEvidence.releaseId,
    sourceCommit:releaseEvidence.sourceCommit,sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',checkpointRegistry,
    checkpointRegistryConfigHash:releaseRegistryConfigHash,checkpointRegistryArtifact:artifact,command:CHECKPOINT_REGISTRY_REPRODUCIBLE_BUILD_COMMAND,
    observations:normalized,conclusion:'Two clean isolated compilations reproduced the exact hash-addressed checkpoint registry artifact and its configuration-bound deployed runtime and initcode.'};
}
export function validateCheckpointRegistryReproducibleBuildReport(report,context={}) {
  const keys=['checkpointRegistry','checkpointRegistryArtifact','checkpointRegistryConfigHash','command','conclusion','ethereumChainId','observations','releaseId','schema','sourceCommit','sourceTag','status'];
  if(!exact(report,keys)) fail('checkpoint registry reproducible-build report schema is invalid');
  const rebuilt=buildCheckpointRegistryReproducibleBuildReport({...context,observations:report.observations});
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(rebuilt))) fail('checkpoint registry reproducible-build report differs from canonical release binding');
  return rebuilt;
}
export function serializeCheckpointRegistryReproducibleBuildReport(report) { return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`); }
