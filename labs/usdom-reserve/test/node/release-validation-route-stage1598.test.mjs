import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');
const generator=path.join(root,'scripts/generate-closed-mainnet-phase-command.sh');

test('capacity runs public vectors before ceremony and privacy only after final VK installation',()=>{
 const result=spawnSync('/usr/bin/bash',[generator,'measure-release-capacity'],{
  cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
 assert.equal(result.status,0,result.stderr);
 const vector=result.stdout.indexOf('execute:release-validation-jobs');
 const capacity=result.stdout.indexOf('check:checkpoint-capacity-e2e');
 assert(vector>0&&capacity>vector,'release vectors must precede capacity promotion');
 assert.match(result.stdout,/execute:release-validation-jobs -- pre-ceremony/);
 assert.doesNotMatch(result.stdout,/post-ceremony/);
 const ceremony=spawnSync('/usr/bin/bash',[generator,'finalize-native-privacy-ceremony-secret'],{
  cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
 assert.equal(ceremony.status,0,ceremony.stderr);
 assert(ceremony.stdout.indexOf('cmp -s "$vk" "$installation/spend-verifying-key.bin"')
   <ceremony.stdout.indexOf('execute:release-validation-jobs -- post-ceremony'));
});

test('complete route derives release identity and uses three sequential systemd identities',async()=>{
 const [runner,pkg]=await Promise.all([
  readFile(path.join(root,'scripts/execute-usdom-release-validation-jobs.sh'),'utf8'),
  readFile(path.join(root,'package.json'),'utf8'),
 ]);
 for(const token of ['mainnet-release-evidence.unconfigured.json','install-supervised-proof-user-service.py',
  'prepare-usdom-release-validation-jobs.sh','systemctl --user start',
  'control-supervised-long-proof.py','materialize-usdom-release-validation-report.py',
  'materialize:release-validation-evidence']) assert.match(runner,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 assert.match(runner,/selected=\("\$\{ids\[0\]\}" "\$\{ids\[1\]\}"\)/);
 assert.match(runner,/selected=\("\$\{ids\[2\]\}"\)/);
 assert.match(runner,/usdom-release-validation-job-set\/v1/);
 assert.equal(JSON.parse(pkg).scripts['execute:release-validation-jobs'],
  './scripts/mainnet-tool-dispatcher bash scripts/execute-usdom-release-validation-jobs.sh');
});

test('a schema-valid synthetic report is rederived from immutable raw evidence before installation',async()=>{
 const installer=await readFile(path.join(root,'scripts/materialize-usdom-release-validation-evidence.mjs'),'utf8');
 for(const token of ['materialize-usdom-release-validation-report.py','.config/usdom-proof/jobs',
  '.local/state/usdom-proof','reproduced.equals(reportBytes)','raw release-vector authentication',
  'snapshotExecutablePath(pythonLock.realpath)','replaceLockedParentFileDurable',
  'expectedPreviousSha256:sha(evidenceBytes)','expectedSha256:sha(nextBytes)',
  'metadataInspectorSha256:python.sha256','expectedMode:0o600',
  'process.exitCode=durableReplacementFailureExitCode(error)']) {
  assert.match(installer,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 }
 assert.doesNotMatch(installer,/writePrivateFileDurable\(path\.join\(root,evidencePath\)/);
});

test('collector requires the exact per-vector source closure used by preparation',async()=>{
 const [preparer,collector]=await Promise.all([
  readFile(path.join(root,'scripts/prepare-usdom-release-validation-jobs.sh'),'utf8'),
  readFile(path.join(root,'scripts/materialize-usdom-release-validation-report.py'),'utf8'),
 ]);
 for(const source of ['checkpoint-program/src/economic_chunks.rs','checkpoint-program/src/sync_attestation.rs',
  'dom-usdom-state/src/sparse.rs','randomx-portable/src/bytecode.rs','dom-usdom-privacy/MANIFEST.sha256',
  'dom-usdom-privacy/src/phase1.rs']) {
  assert(preparer.includes(source),`${source} absent from preparation`);
  assert(collector.includes(source),`${source} absent from authentication`);
 }
 assert.match(collector,/seen!=expected_inputs/);
});
