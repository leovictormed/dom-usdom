import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
const checker=new URL('../../scripts/check-risc0-index-authority.py',import.meta.url);
test('seven proof paths use strict bounded index authority',()=>{
 const result=spawnSync('/usr/bin/python3',[checker.pathname,'--self-test'],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},timeout:10_000});
 assert.equal(result.status,0,result.stderr); assert.match(result.stdout,/PASS: five hosts\/seven proof paths/);
});
test('authority checker requires strict fields and canonical generated plans',async()=>{
 const source=await readFile(checker,'utf8');
 assert.match(source,/deny_unknown_fields/);
 assert.match(source,/a deserialized struct lacks deny_unknown_fields/);
 assert.match(source,/canonical re-encoding mutation accepted/);
 assert.match(source,/published_index != expected_index_bytes/);
 assert.match(source,/statement_count != source\.statements\.len\(\)/);
});
