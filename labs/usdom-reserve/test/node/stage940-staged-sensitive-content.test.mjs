import test from 'node:test';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
const scanner=new URL('../../scripts/check-staged-sensitive-content.mjs',import.meta.url);
const run=input=>spawnSync(process.execPath,[scanner.pathname,'--path','config/example.json'],{input,encoding:'utf8'});
test('rejects high-confidence secrets under benign names',()=>{for(const x of ['-----BEGIN '+'PRIVATE KEY-----\nabc','{"password":"correct horse battery staple"}','{"rawTransaction":"0x02'+ 'ab'.repeat(100)+'"}','{"private_witness":"'+ 'ab'.repeat(64)+'"}'])assert.notEqual(run(x).status,0)});
test('accepts public hashes and redacted configuration',()=>assert.equal(run('{"password":"REDACTED","statement_hash":"'+ 'ab'.repeat(32)+'"}').status,0));
