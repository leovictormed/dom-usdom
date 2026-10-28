import assert from 'node:assert/strict';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {captureRiscZeroHealthCatalogInputs} from '../../sdk/risc0-health-catalog-input-snapshot.mjs';

const source=await readFile(new URL(
  '../../scripts/materialize-risc0-health-source-catalog.mjs',import.meta.url),'utf8');

test('RISC Zero source catalog is immutable and inputs remain bound through metadata update',()=>{
  assert.match(source,/writePrivateFileDurableNew\(target,bytes\)/);
  assert.match(source,/immutable RISC Zero health source catalog differs/);
  assert.match(source,/existing\.equals\(bytes\)/);
  assert.match(source,/captureRiscZeroHealthCatalogInputs/);
  assert.match(source,/process\.umask\(0o077\)/);
  assert.match(source,/async function ensureDirectParent/);
  assert.match(source,/metadata\.isSymbolicLink\(\)/);
  assert.match(source,/metadata\.uid!==currentUid/);
  assert.doesNotMatch(source,/mkdir\(path\.dirname\(target\),\{recursive:true/);
  assert.equal((source.match(/await snapshot\.assertOriginsUnchanged\(\)/g)??[]).length,2);
  assert.match(source,/snapshot\.assertOriginsEqual\(\{catalog:snapshot\.catalog,[\s\S]*evidence:Buffer\.from\(result\.evidenceContent\)/);
  assert.ok(source.indexOf('await immutableWrite(RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH')
    <source.lastIndexOf('await snapshot.assertOriginsUnchanged()'));
  assert.ok(source.indexOf('await compareAndSwapEvidence(metadataPath')
    <source.indexOf('await snapshot.assertOriginsEqual('));
  assert.match(source,/replaceLockedParentFileDurable/);
  assert.match(source,/expectedPreviousSha256:sha256\(previousBytes\)/);
  assert.match(source,/expectedMode:0o600/);
  assert.match(source,/process\.exitCode=durableReplacementFailureExitCode\(error\)/);
  assert.match(source,/if\(primaryError===null\) throw cleanupError/);
});

test('RISC Zero source catalog snapshot rejects evidence mutation',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-risc0-catalog-test-'));
  await chmod(root,0o700);
  const catalog=path.join(root,'catalog.json'),evidence=path.join(root,'evidence.json');
  await writeFile(catalog,'{"catalog":"original"}\n',{mode:0o600});
  await writeFile(evidence,'{"evidence":"original"}\n',{mode:0o600});
  let snapshot;
  try {
    snapshot=await captureRiscZeroHealthCatalogInputs({catalog,evidence},{
      beforeOriginRecheck:()=>writeFile(evidence,'{"evidence":"changed"}\n',{mode:0o600}),
    });
    assert.equal(snapshot.evidence.toString(),'{"evidence":"original"}\n');
    await assert.rejects(()=>snapshot.assertOriginsUnchanged(),
      /RISC Zero health catalog inputs changed during materialization/);
  } finally { await snapshot?.cleanup(); await rm(root,{recursive:true,force:true}); }
});

test('RISC Zero source catalog snapshot rejects an incomplete catalog',async()=>{
  await assert.rejects(()=>captureRiscZeroHealthCatalogInputs({}),/fixed absolute catalog/);
});

test('RISC Zero source catalog snapshot accepts only the intentional evidence generation',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-risc0-catalog-generation-'));
  await chmod(root,0o700);
  const catalog=path.join(root,'catalog.json'),evidence=path.join(root,'evidence.json');
  await writeFile(catalog,'{"catalog":"original"}\n',{mode:0o600});
  await writeFile(evidence,'{"evidence":"original"}\n',{mode:0o600});
  let snapshot;
  try {
    snapshot=await captureRiscZeroHealthCatalogInputs({catalog,evidence});
    const next=Buffer.from('{"evidence":"next"}\n');
    await writeFile(evidence,next,{mode:0o600});
    await snapshot.assertOriginsEqual({catalog:snapshot.catalog,evidence:next});
    await assert.rejects(()=>snapshot.assertOriginsUnchanged(),
      /inputs changed during materialization/);
  } finally { await snapshot?.cleanup(); await rm(root,{recursive:true,force:true}); }
});
