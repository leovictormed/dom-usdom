import test from 'node:test';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';import {readFileSync} from 'node:fs';
const scanner=new URL('../../scripts/check-staged-sensitive-content.mjs',import.meta.url);
const run=input=>spawnSync(process.execPath,[scanner.pathname,'--path','config/example.json'],{input,encoding:'utf8'});
test('rejects high-confidence secrets under benign names',()=>{for(const x of ['-----BEGIN '+'PRIVATE KEY-----\nabc','{"pass'+'word":"correct horse battery staple"}','{"raw'+'Transaction":"0x02'+ 'ab'.repeat(100)+'"}','{"private_'+'witness":"'+ 'ab'.repeat(64)+'"}','AWS_SECRET_ACCESS_'+'KEY=abcdefghijklmnopqrstuvwxyz1234567890ABCD'])assert.notEqual(run(x).status,0)});
test('scans the entire accepted text instead of only its first megabyte',()=>{
  const input='a'.repeat(2*1024*1024)+'\n{"pass'+'word":"secret-after-the-old-scan-prefix"}\n';
  assert.notEqual(run(input).status,0);
});
test('rejects credential-store paths even when their syntax is not JSON',()=>{
  const result=spawnSync(process.execPath,[scanner.pathname,'--path','.npmrc'],
    {input:'//registry.npmjs.org/:_auth'+'Token=secret-value-that-must-not-publish\n'});
  assert.notEqual(result.status,0);
});
test('the adversarial regression source remains publishable',()=>{
  const source=new URL(import.meta.url);
  const result=spawnSync(process.execPath,[scanner.pathname,'--path','test/node/stage940-staged-sensitive-content.test.mjs'],
    {input:readFileSync(source)});
  assert.equal(result.status,0);
});
test('accepts public hashes and redacted configuration',()=>assert.equal(run('{"password":"REDACTED","statement_hash":"'+ 'ab'.repeat(32)+'"}').status,0));
test('accepts lowercase source variables that name private paths',()=>assert.equal(run('private_key="$ssh_directory/$key_name"\n').status,0));
test('accepts uppercase secret file variables that resolve paths at runtime',()=>assert.equal(run('RPC_TOKEN="$HOME/.local/share/service/rpc.token"\n').status,0));
