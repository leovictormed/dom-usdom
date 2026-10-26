import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const checker=new URL('../../scripts/check-mainnet-readiness.mjs',import.meta.url);
const assessor=new URL('../../sdk/mainnet-readiness.mjs',import.meta.url);

test('mainnet readiness JSON boundary rejects ambiguous bytes',()=>{
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'mainnet readiness',maxBytes:16*1024*1024,
    maxDepth:64}),/duplicate (?:object )?key|invalid UTF-8/);
});

test('mainnet readiness byte-parses every JSON authority and cross-binds four build reports',async()=>{
  const source=await readFile(checker,'utf8');
  assert.equal((source.match(/parseStrictJsonBytes\(/g)??[]).length,8);
  assert.doesNotMatch(source,/parseStrictJson\(/);
  for(const name of ['reproducibleBuildReport','verifierReproducibleBuildReport',
    'checkpointRegistryReproducibleBuildReport','checkpointVerifierReproducibleBuildReport']) {
    assert.match(source,new RegExp(`evidence\\.${name}`));
  }
  assert.match(source,/deriveReserveArtifactBinding/);
  assert.match(source,/deriveFinalizedBurnVerifierArtifactBinding/);
  assert.match(source,/deriveCheckpointRegistryArtifactBinding/);
  assert.match(source,/deriveCheckpointVerifierArtifactBinding/);
});

test('mainnet readiness validates the exact evidence bytes recorded by its SHA snapshot',async()=>{
  const source=await readFile(checker,'utf8');
  assert.match(source,/const evidenceFileBytes = new Map\(\)/);
  assert.match(source,/evidenceFiles\[document\.path\]=createHash\('sha256'\)\.update\(bytes\)/);
  assert.match(source,/evidenceFileBytes\.set\(document\.path,bytes\)/);
  assert.ok((source.match(/evidenceFileBytes\.get\(/g)??[]).length>=4);
  assert.doesNotMatch(source,
    /parseStrictJsonBytes\(await readEvidenceFile\(document\.path\)/);
  assert.doesNotMatch(source,
    /parseStrictJsonBytes\(\s*await readEvidenceFile\(evidence\.(?:checkpoint)?verifierConfigManifest\.path\)/);
});

test('mainnet readiness snapshots the final Safe recovery bundle before parsing it',async()=>{
  const source=await readFile(checker,'utf8');
  const documents=source.slice(source.indexOf('const documents = ['),
    source.indexOf('].filter(Boolean);',source.indexOf('const documents = [')));
  assert.match(documents,/evidence\.safeRecoveryFinalEvidenceBundle/);
  assert.match(source,
    /readOptionalEvidenceJson\(evidence\.safeRecoveryFinalEvidenceBundle,[\s\S]*?'Safe recovery final evidence bundle'\)/);
});

test('mainnet readiness snapshots every document required by the assessor',async()=>{
  const [checkerSource,assessorSource]=await Promise.all([
    readFile(checker,'utf8'),readFile(assessor,'utf8'),
  ]);
  const requiredBlock=assessorSource.slice(
    assessorSource.indexOf('const evidenceDocuments = ['),
    assessorSource.indexOf('];',assessorSource.indexOf('const evidenceDocuments = [')),
  );
  const snapshotBlock=checkerSource.slice(
    checkerSource.indexOf('const documents = ['),
    checkerSource.indexOf('].filter(Boolean);',checkerSource.indexOf('const documents = [')),
  );
  const required=[...requiredBlock.matchAll(/'([A-Za-z][A-Za-z0-9]+)'/g)].map(match=>match[1]);
  assert.ok(required.length>0);
  for(const name of required) {
    assert.match(snapshotBlock,new RegExp(`evidence\\.${name}(?:[,\\]])`),
      `${name} must be captured in the hash-addressed evidence snapshot`);
  }
});

test('mainnet readiness rechecks every evidence byte snapshot before output',async()=>{
  const source=await readFile(checker,'utf8');
  const recheck=source.indexOf(
    'await assertEvidenceByteSnapshotsUnchanged(authorityFileBytes,readRawDirectFile,');
  const output=source.indexOf('console.log(JSON.stringify(report,null,2));');
  assert.ok(recheck>source.indexOf('const report = assessMainnetReadiness('));
  assert.ok(output>recheck);
  assert.match(source,/const readDirectFile=async\(relative,options\)=>/);
  assert.match(source,/authorityFileBytes\.set\(relative,Buffer\.from\(bytes\)\)/);
  assert.doesNotMatch(source,/readDirectProjectFile\(root,source,/);
});

test('mainnet readiness pins and strictly frames native checker authority',async()=>{
  const source=await readFile(checker,'utf8');
  assert.match(source,/const cargo=await snapshotExecutable\('cargo'\)/);
  assert.match(source,/runPinnedExecutable\(cargo,/);
  assert.match(source,/await assertExecutableUnchanged\(cargo\)/);
  assert.match(source,/encoding:'buffer',maxBuffer:4\*1024\*1024/);
  assert.match(source,/checked\.stderr\.length!==0/);
  assert.match(source,/new TextDecoder\('utf-8',\{fatal:true\}\)\.decode\(output\)/);
  assert.match(source,/text\.endsWith\('\\n\\n'\)|text\.includes\('\\r'\)/);
  assert.doesNotMatch(source,/process\.env\.USDOM_CARGO|output\.trim\(\)\.split/);
});

test('mainnet readiness pins Forge and Git release children',async()=>{
  const source=await readFile(checker,'utf8');
  assert.match(source,
    /const forgeExecutable=diagnosticNoBuild\?null:await snapshotExecutable\('forge'\)/);
  assert.match(source,/const gitExecutable=await snapshotExecutable\('git'\)/);
  assert.match(source,/const pythonExecutable=await snapshotExecutable\('python3'\)/);
  assert.match(source,/runPinnedExecutable\(forgeExecutable,/);
  assert.match(source,/runPinnedExecutable\(gitExecutable,/);
  assert.match(source,/runPinnedExecutable\(pythonExecutable,/);
  assert.doesNotMatch(source,/execFileAsync|execPinned/);
  assert.match(source,/maxBuffer:64\*1024\*1024,timeout:10\*60\*1000/);
  assert.match(source,/maxBuffer:4\*1024\*1024,timeout:30_000/);
  assert.match(source,/assertExecutableUnchanged\(forgeExecutable\)/);
  assert.match(source,/assertExecutableUnchanged\(gitExecutable\)/);
  assert.match(source,/assertExecutableUnchanged\(pythonExecutable\)/);
  assert.match(source,/new TextDecoder\('utf-8',\{fatal:true\}\)/);
  assert.match(source,/diffResult\.stderr\.length!==0/);
  assert.doesNotMatch(source,/process\.env\.USDOM_FORGE|execFileAsync\('git'|execFileAsync\('python3'/);
});

test('no-build diagnostic does not require or attest an unused Forge executable',async()=>{
  const source=await readFile(checker,'utf8');
  const snapshot=source.indexOf(
    "const forgeExecutable=diagnosticNoBuild?null:await snapshotExecutable('forge')",
  );
  const buildGuard=source.indexOf('if(!diagnosticNoBuild)',snapshot);
  const forgeRun=source.indexOf('runPinnedExecutable(forgeExecutable,',buildGuard);
  const finalRecheck=source.lastIndexOf('forgeExecutable===null?[]:');
  assert.ok(snapshot>=0);
  assert.ok(buildGuard>snapshot && forgeRun>buildGuard);
  assert.ok(finalRecheck>forgeRun);
});
