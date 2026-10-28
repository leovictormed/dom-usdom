#!/usr/bin/env node
import {mkdir,mkdtemp,readFile,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {assertExecutableUnchanged,snapshotExecutable} from '../sdk/stable-executable.mjs';
import {assertProductionSolidityMetadata,assertReproducibleBuildEnvironment,
  reproducibleFoundryChildEnvironment,snapshotProductionSolc} from '../sdk/reproducible-build-environment.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {assertSolidityBuildsEqual,PRODUCTION_SOLIDITY_CONTRACTS,
  solidityArtifactFingerprint} from '../sdk/solidity-build-reproducibility.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
async function build(directory,forge,solc) {
  const config=path.join(directory,'config');
  await mkdir(config,{recursive:true,mode:0o700});
  const result={};
  for(const contract of PRODUCTION_SOLIDITY_CONTRACTS) {
    const output=path.join(directory,contract,'out'),cache=path.join(directory,contract,'cache');
    await runPinnedExecutable(forge,['build',`contracts/${contract}.sol`,'--root',root,'--offline',
      '--no-auto-detect','--use',solc.path,'--evm-version','cancun','--optimize','--optimizer-runs','1',
      '--via-ir','--force','--out',output,'--cache-path',cache,'--extra-output','storageLayout',
      '--ignored-error-codes','6335'],{cwd:root,maxBuffer:64*1024*1024,
      timeout:10*60*1000,env:reproducibleFoundryChildEnvironment(process.env,config)});
    const bytes=await readFile(path.join(output,`${contract}.sol`,`${contract}.json`));
    const artifact=parseStrictJsonBytes(bytes,{label:`${contract} isolated artifact`,
      maxBytes:16*1024*1024,maxDepth:256});
    assertProductionSolidityMetadata(artifact);
    result[contract]=solidityArtifactFingerprint(artifact,contract);
  }
  return result;
}

let temporary;
try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  assertReproducibleBuildEnvironment(process.env);
  const forge=await snapshotExecutable('forge'),solc=await snapshotProductionSolc(process.env);
  temporary=await mkdtemp(path.join(os.tmpdir(),'usdom-final-solidity-build-'));
  const first=await build(path.join(temporary,'a'),forge,solc);
  const second=await build(path.join(temporary,'b'),forge,solc);
  assertSolidityBuildsEqual(first,second);
  await assertExecutableUnchanged(forge); await assertExecutableUnchanged(solc);
  process.stdout.write(`${JSON.stringify({ok:true,builds:2,contracts:first},null,2)}\n`);
} catch(error) {
  writeReleaseFailure('check-final-solidity-build-reproducibility',error);
  process.exitCode=1;
} finally {
  if(temporary) await rm(temporary,{recursive:true,force:true});
}
