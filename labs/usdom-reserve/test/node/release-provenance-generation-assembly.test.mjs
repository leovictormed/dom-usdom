import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

test('release provenance uses evidence-first completion-last assembly with stable rereads',async()=>{
 const source=await readFile(new URL('../../scripts/materialize-release-provenance.sh',import.meta.url),'utf8');
 const prepare=source.indexOf('prepare-release-provenance-materialization.mjs');
 const stable=source.indexOf('assert_targets_unchanged',prepare);
 const evidence=source.indexOf('replace-locked-source-stdin.mjs',stable);
 const evidenceReadback=source.indexOf('Installed release evidence differs',evidence);
 const intent=source.indexOf('replace-locked-private-stdin.mjs',evidenceReadback);
 const finalRead=source.lastIndexOf('read_current_targets');
 assert.ok(prepare>=0&&stable>prepare&&evidence>stable&&evidenceReadback>evidence
  &&intent>evidenceReadback&&finalRead>intent);
});

for(const name of ['commit-release-source.sh','commit-release-evidence.sh']) test(`${name} does not bypass staged generation`,async()=>{
 const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
 const boundary=await readFile(new URL('../../scripts/git-release-ceremony-boundary.sh',import.meta.url),'utf8');
 assert.match(source,/diff --cached --quiet/);
 assert.match(source,/assert_tree_path_is_raw_file/);
 assert.match(source,/commit-tree -S/);
 assert.match(boundary,/ls-tree/);
 assert.match(boundary,/hash-object --no-filters/);
 assert.match(source,/git_bin/);
});
