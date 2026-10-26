#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';
import {SECURITY_VALIDATION_CHECKS,buildSecurityValidationReport,
  serializeSecurityValidationReport,sha256Hex,validateSecurityValidationReleaseEvidence,
} from '../sdk/security-validation-report.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const common={cwd:root,maxBuffer:64*1024*1024,timeout:60*60*1000};
const forbiddenEnvironment=new Set([
  'BASH_ENV','CARGO_ENCODED_RUSTFLAGS','ENV','FOUNDRY_CONFIG','FOUNDRY_FUZZ_RUNS',
  'FOUNDRY_FUZZ_SEED','FOUNDRY_PROFILE','GIT_CONFIG_GLOBAL','GIT_CONFIG_SYSTEM','GIT_DIR',
  'GIT_WORK_TREE','LD_LIBRARY_PATH','LD_PRELOAD','NODE_OPTIONS','NPM_CONFIG_SCRIPT_SHELL',
  'PYTHONHOME','PYTHONPATH','RISC0_DEV_MODE','RUSTC_WORKSPACE_WRAPPER','RUSTC_WRAPPER','RUSTFLAGS',
  'SOLC_PATH',
]);

function assertCleanEnvironment(environment) {
  const present=Object.keys(environment).filter(name=>
    forbiddenEnvironment.has(name.toUpperCase())&&environment[name]!==undefined&&environment[name]!=='');
  if(present.length) throw new Error(`security validation forbids ambient variables: ${present.sort().join(', ')}`);
}

async function snapshotValidationExecutable(file) {
  if(typeof file!=='string'||file.length===0) throw new Error('validation executable is invalid');
  if(path.isAbsolute(file)) {
    return snapshotExecutable(path.basename(file),{pathValue:path.dirname(file)});
  }
  if(file.includes('/')) throw new Error('validation executable must be a name or absolute path');
  return snapshotExecutable(file);
}

async function execute(id,command,file,args,environment={}) {
  const expected=SECURITY_VALIDATION_CHECKS.find(value=>value.id===id);
  if(!expected||expected.command!==command) throw new Error(`unknown validation check ${id}`);
  const tool=await snapshotValidationExecutable(file);
  // Recheck immediately before launch as well as after it.  A validation
  // result is release evidence, so an executable selected from a writable or
  // relative PATH entry, a linked file, or a replaced inode must never be
  // allowed to attest the source tree.
  try {
    const result=await runPinnedExecutable(tool,args,{...common,env:{...process.env,...environment}});
    return {id,command,exitCode:0,stdoutSha256:sha256Hex(result.stdout),
      stderrSha256:sha256Hex(result.stderr),toolSha256:tool.sha256};
  } catch(error) {
    throw new Error(`${id} failed with exit code ${error.code??'unknown'}`);
  }
}

try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  assertCleanEnvironment(process.env);
  const [releaseEvidenceBytes,requirementsBytes,sourceManifestBytes,testEntries]=await Promise.all([
    readDirectProjectFile(root,'config/mainnet-release-evidence.unconfigured.json'),
    readDirectProjectFile(root,'config/production-requirements.json'),
    readDirectProjectFile(root,'MANIFEST.sha256'),readdir(path.join(root,'test/node')),
  ]);
  const releaseEvidence=parseStrictJsonBytes(releaseEvidenceBytes,{
    label:'mainnet release evidence',maxBytes:4*1024*1024,maxDepth:64});
  validateSecurityValidationReleaseEvidence(releaseEvidence);
  const nodeTests=testEntries.filter(name=>name.endsWith('.test.mjs')).sort()
    .map(name=>`test/node/${name}`);
  if(nodeTests.length===0) throw new Error('no Node regression tests were found');
  const results=[];
  results.push(await execute('production-solidity-lint',
    'forge lint contracts/USDOMProofReserve.sol contracts/DOMCheckpointRegistry.sol contracts/DOMFinalizedBurnRiscZeroVerifier.sol contracts/DOMCheckpointRiscZeroVerifier.sol --report-unused-suppressions -D warnings',
    'forge',['lint','contracts/USDOMProofReserve.sol','contracts/DOMCheckpointRegistry.sol',
      'contracts/DOMFinalizedBurnRiscZeroVerifier.sol','contracts/DOMCheckpointRiscZeroVerifier.sol',
      '--report-unused-suppressions','-D','warnings']));
  results.push(await execute('production-solidity-build',
    'forge build contracts/USDOMProofReserve.sol contracts/DOMCheckpointRegistry.sol contracts/DOMFinalizedBurnRiscZeroVerifier.sol contracts/DOMCheckpointRiscZeroVerifier.sol --force --ignored-error-codes 6335 -D warnings',
    'forge',['build','contracts/USDOMProofReserve.sol',
      'contracts/DOMCheckpointRegistry.sol','contracts/DOMFinalizedBurnRiscZeroVerifier.sol',
      'contracts/DOMCheckpointRiscZeroVerifier.sol','--force','--ignored-error-codes','6335','-D','warnings']));
  results.push(await execute('node-regression','node --test test/node/*.test.mjs',
    process.execPath,['--test',...nodeTests]));
  results.push(await execute('solidity-regression','forge test -vv',
    'forge',['test','-vv']));
  results.push(await execute('deep-solidity-regression',
    'FOUNDRY_PROFILE=deep forge test --fuzz-seed 0x5553444f4d20261015 -vv',
    'forge',['test','--fuzz-seed','0x5553444f4d20261015','-vv'],
    {FOUNDRY_PROFILE:'deep'}));
  results.push(await execute('complete-provenance','npm run --silent check:provenance',
    'npm',['run','--silent','check:provenance']));
  results.push(await execute('tracked-whitespace','git diff --check','git',['diff','--check']));
  results.push(await execute('final-source-manifest','python3 scripts/source-manifest.py',
    'python3',['scripts/source-manifest.py']));
  const [releaseEvidenceAfter,requirementsAfter,sourceManifestAfter]=await Promise.all([
    readDirectProjectFile(root,'config/mainnet-release-evidence.unconfigured.json'),
    readDirectProjectFile(root,'config/production-requirements.json'),
    readDirectProjectFile(root,'MANIFEST.sha256'),
  ]);
  if(!releaseEvidenceAfter.equals(releaseEvidenceBytes)||!requirementsAfter.equals(requirementsBytes)
      ||!sourceManifestAfter.equals(sourceManifestBytes)) {
    throw new Error('release inputs changed during security validation');
  }
  const report=buildSecurityValidationReport({releaseEvidence,
    requirementsSha256:sha256Hex(requirementsBytes),sourceManifestSha256:sha256Hex(sourceManifestBytes),results});
  process.stdout.write(serializeSecurityValidationReport(report));
} catch(error) {
  writeReleaseFailure('prepare-security-validation-report',error);
  process.exitCode=1;
}
