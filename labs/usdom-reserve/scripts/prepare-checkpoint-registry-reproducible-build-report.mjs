#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {mkdir,mkdtemp,readFile,rm} from 'node:fs/promises';
import os from 'node:os'; import path from 'node:path';  import {fileURLToPath} from 'node:url';
import {deriveCheckpointRegistryArtifactBinding} from '../sdk/compiled-runtime.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {sourceSetSha256} from '../sdk/reserve-reproducible-build-report.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {assertExecutableUnchanged,snapshotExecutable} from '../sdk/stable-executable.mjs';
import {assertProductionSolidityMetadata,assertReproducibleBuildEnvironment,productionFoundryBuildArguments,reproducibleFoundryChildEnvironment,snapshotProductionSolc} from '../sdk/reproducible-build-environment.mjs';
import {assertArtifactSourcesUnchanged,snapshotArtifactSources} from '../sdk/artifact-source-snapshot.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {buildCheckpointRegistryReproducibleBuildReport,serializeCheckpointRegistryReproducibleBuildReport} from '../sdk/checkpoint-registry-reproducible-build-report.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
async function isolatedBuild(buildId,directory,releaseConfig,forge,solc) {
  await mkdir(directory,{recursive:true,mode:0o700}); const output=path.join(directory,'out'),cache=path.join(directory,'cache');
  const configHome=path.join(directory,'config'); await mkdir(configHome,{mode:0o700});
  await runPinnedExecutable(forge,productionFoundryBuildArguments('contracts/DOMCheckpointRegistry.sol',output,cache,root,solc.path),{cwd:root,maxBuffer:64*1024*1024,timeout:10*60*1000,env:reproducibleFoundryChildEnvironment(process.env,configHome)});
  const artifactBytes=await readFile(path.join(output,'DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json'));
  const artifact=parseStrictJsonBytes(artifactBytes,{label:`${buildId} checkpoint registry artifact`,maxBytes:64*1024*1024,maxDepth:128});
  assertProductionSolidityMetadata(artifact);
  const sourceContents=Object.create(null); for(const source of Object.keys(artifact?.metadata?.sources??{})) sourceContents[source]=await readDirectProjectFile(root,source,{label:`${buildId} source`});
  const binding=deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig,sourceContents});
  return {buildId,compilerExecutableSha256:solc.sha256,compilerVersion:artifact?.metadata?.compiler?.version,artifactSha256:sha(artifactBytes),sourceSetSha256:sourceSetSha256(artifact.metadata),
    runtimeCodeHash:binding.runtimeCodeHash,initcodeHash:binding.initcodeHash};
}
let temporary;
try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  assertReproducibleBuildEnvironment(process.env);
  const forge=await snapshotExecutable('forge');
  const solc=await snapshotProductionSolc(process.env);
  const evidencePath='config/mainnet-release-evidence.unconfigured.json',releasePath='config/proof-reserve.unconfigured.json';
  const [evidenceBytes,releaseBytes]=await Promise.all([readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,releasePath)]);
  const releaseEvidence=parseStrictJsonBytes(evidenceBytes,{label:evidencePath,maxBytes:4*1024*1024,maxDepth:64});
  const releaseConfig=parseStrictJsonBytes(releaseBytes,{label:releasePath,maxBytes:4*1024*1024,maxDepth:64});
  if(typeof releaseEvidence?.checkpointRegistryArtifact?.path!=='string') throw new Error('checkpoint registry artifact release evidence is missing');
  const canonicalArtifact=await readDirectProjectFile(root,releaseEvidence.checkpointRegistryArtifact.path,{maxBytes:64*1024*1024});
  if(sha(canonicalArtifact)!==releaseEvidence.checkpointRegistryArtifact.sha256) throw new Error('checkpoint registry artifact SHA-256 differs from release evidence');
  const sourceSnapshot=await snapshotArtifactSources(root,canonicalArtifact);
  temporary=await mkdtemp(path.join(os.tmpdir(),'usdom-checkpoint-registry-reproducible-build-'));
  const observations=[await isolatedBuild('isolated-build-a',path.join(temporary,'a'),releaseConfig,forge,solc),await isolatedBuild('isolated-build-b',path.join(temporary,'b'),releaseConfig,forge,solc)];
  const [evidenceAfter,releaseAfter,artifactAfter]=await Promise.all([readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,releasePath),readDirectProjectFile(root,releaseEvidence.checkpointRegistryArtifact.path,{maxBytes:64*1024*1024})]);
  if(!evidenceAfter.equals(evidenceBytes)||!releaseAfter.equals(releaseBytes)||!artifactAfter.equals(canonicalArtifact)) throw new Error('release inputs changed during builds');
  await assertArtifactSourcesUnchanged(root,sourceSnapshot);
  await assertExecutableUnchanged(forge);
  await assertExecutableUnchanged(solc);
  process.stdout.write(serializeCheckpointRegistryReproducibleBuildReport(buildCheckpointRegistryReproducibleBuildReport({releaseEvidence,releaseConfig,observations})));
} catch(error) { writeReleaseFailure('prepare-checkpoint-registry-reproducible-build-report',error); process.exitCode=1; }
finally { if(temporary) await rm(temporary,{recursive:true,force:true}); }
