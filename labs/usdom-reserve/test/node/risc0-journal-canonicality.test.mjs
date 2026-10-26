import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
const checker=new URL('../../scripts/check-risc0-journal-canonicality.py',import.meta.url);
test('seven journals are exact, domain-separated and adapter-bound',()=>{
 const result=spawnSync('/usr/bin/python3',[checker.pathname,'--self-test'],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},timeout:10_000});
 assert.equal(result.status,0,result.stderr); assert.match(result.stdout,/PASS: 7\/7 journals/);
});
test('journal checker pins seven guests, typed hashes and trailing-byte defenses',async()=>{
 const source=await readFile(checker,'utf8');
 assert.equal([...source.matchAll(/^ '([a-z_]+)':\('crates\/dom-usdom-[^\n]+$/gm)].length,7);
 assert.match(source,/source\.count\('env::commit_slice\('\)!=1/);
 assert.match(source,/journal\.bytes\.as_slice\(\) !=/);
 assert.match(source,/serde-framed journal mutation accepted/);
 assert.match(source,/cross-proof domain mutation accepted/);
});
