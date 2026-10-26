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
 const clear=source.indexOf(clearMarker);
 const clearInstall=source.indexOf('install-release-config-stdin.mjs',clear);
 const remove=source.indexOf('remove-private-file-durable.mjs',clearInstall);
 const prepare=source.indexOf(prepareMarker,remove);
 const reportInstall=source.indexOf('install-private-file-immutable-stdin.mjs',prepare);
 const finalPointer=source.indexOf('install-release-config-stdin.mjs',reportInstall);
 assert.ok(clear>=0&&clearInstall>clear&&remove>clearInstall&&prepare>remove
   &&reportInstall>prepare&&finalPointer>reportInstall);
});
