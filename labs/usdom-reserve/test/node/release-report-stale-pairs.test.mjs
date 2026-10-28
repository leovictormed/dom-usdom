import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const cases=[
 ['write-operations-review-report.sh','.operationsReviewReport=null','prepare-operations-review-report.mjs'],
 ['write-residual-risk-report.sh','.residualRiskAcceptanceReport=null','prepare-residual-risk-report.mjs'],
 ['write-trusted-setup-decision-report.sh','.trustedSetup.decisionReport=null','prepare-trusted-setup-decision-report.mjs'],
 ['write-mainnet-fork-rehearsal-report.sh','.mainnetForkRehearsalReport=null','prepare-mainnet-fork-rehearsal-report.mjs'],
];
for(const [name,clearMarker,prepareMarker] of cases) test(`${name} invalidates completion pair before rebuild`,async()=>{
 const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
 const installToken='replace-locked-source-stdin.mjs';
 const clear=source.indexOf(clearMarker);
 const clearInstall=source.indexOf(installToken,clear);
 const remove=source.indexOf('remove-private-file-durable.mjs',clearInstall);
 const prepare=source.indexOf(prepareMarker,remove);
 const reportInstall=source.indexOf('install-private-file-immutable-stdin.mjs',prepare);
 const finalPointer=source.indexOf(installToken,reportInstall);
 assert.ok(clear>=0&&clearInstall>clear&&remove>clearInstall&&prepare>remove
   &&reportInstall>prepare&&finalPointer>reportInstall);
 assert.equal((source.match(/replace-locked-source-stdin\.mjs/g)??[]).length,2);
 assert.match(source,/metadata_sha256=\$candidate_sha256/);
 assert.match(source,/pin_(?:tool|runtime_tool) python3/);
 if(name==='write-mainnet-fork-rehearsal-report.sh') {
  assert.match(source,/INVALIDATION_IDENTITY=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$INVALIDATION"\)/);
  assert.match(source,/TEMPORARY_IDENTITY=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$TEMPORARY"\)/);
  assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$TEMPORARY" 2>\/dev\/null\) == "\$TEMPORARY_IDENTITY"/);
  assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$INVALIDATION" 2>\/dev\/null\) == "\$INVALIDATION_IDENTITY"/);
 }
 if(name==='write-operations-review-report.sh') {
  assert.match(source,/invalidation_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$invalidation"\)/);
  assert.match(source,/temporary_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary"\)/);
  assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary" 2>\/dev\/null\) == "\$temporary_identity"/);
  assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$invalidation" 2>\/dev\/null\) == "\$invalidation_identity"/);
 }
});
