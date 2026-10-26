import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

test('release provenance uses evidence-first completion-last assembly with stable rereads',async()=>{
 const source=await readFile(new URL('../../scripts/materialize-release-provenance.sh',import.meta.url),'utf8');
 const prepare=source.indexOf('prepare-release-provenance-materialization.mjs');
 const stable=source.indexOf('assert_targets_unchanged',prepare);
 const evidence=source.indexOf('install-release-config-stdin.mjs',stable);
 const evidenceReadback=source.indexOf('Installed release evidence differs',evidence);
 const intent=source.indexOf('install-private-file-stdin.mjs',evidenceReadback);
 const finalRead=source.lastIndexOf('read_current_targets');
 assert.ok(prepare>=0&&stable>prepare&&evidence>stable&&evidenceReadback>evidence
  &&intent>evidenceReadback&&finalRead>intent);
});

for(const name of ['commit-release-source.sh','commit-release-evidence.sh']) test(`${name} does not bypass staged generation`,async()=>{
 const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
 assert.match(source,/diff --cached --quiet/);
 assert.match(source,/ls-files --stage/);
 assert.match(source,/git_bin/);
});
