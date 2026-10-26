import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJson,parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');

test('strict JSON accepts canonical nested release data',()=>{
 const parsed=parseStrictJson('{"ready":false,"limits":{"daily":"2000"},"reports":[null,true]}');
 assert.equal(parsed.ready,false);
 assert.equal(parsed.limits.daily,'2000');
 assert.deepEqual([...parsed.reports],[null,true]);
 assert.equal(Object.getPrototypeOf(parsed),null);
});

test('strict JSON rejects direct and escape-equivalent duplicate keys',()=>{
 assert.throws(()=>parseStrictJson('{"ready":false,"ready":true}'),/duplicate object key "ready"/);
 assert.throws(()=>parseStrictJson('{"ready":false,"\\u0072eady":true}'),/duplicate object key "ready"/);
 assert.throws(()=>parseStrictJson('{"outer":{"hash":"a","hash":"b"}}'),/duplicate object key "hash"/);
});

test('strict JSON byte boundary rejects invalid UTF-8 and escaped duplicate keys',()=>{
 assert.throws(()=>parseStrictJsonBytes(Buffer.from([
  0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d,
 ]),{label:'checkpoint authority'}),/invalid UTF-8/);
 assert.throws(()=>parseStrictJsonBytes(Buffer.from(
  '{"transactionHash":"one","\\u0074ransactionHash":"two"}'),
 {label:'checkpoint authority'}),/duplicate object key "transactionHash"/);
});

test('strict JSON rejects malformed, ambiguous and resource-exhausting input',()=>{
 for(const text of ['{"a":1,}','[1,]','01','1 trailing','"unterminated']) {
  assert.throws(()=>parseStrictJson(text),SyntaxError,text);
 }
 assert.throws(()=>parseStrictJson('1e999'),/non-finite number/);
 assert.throws(()=>parseStrictJson('[[[0]]]',{maxDepth:2}),/nesting exceeds 2/);
 assert.throws(()=>parseStrictJson('{"a":1}',{maxBytes:4}),/input exceeds 4 bytes/);
});

test('configuration CLI rejects duplicate keys before semantic validation',async()=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-strict-json-'));
 try {
  const candidate=path.join(directory,'duplicate.json');
  await writeFile(candidate,'{"ethereumChainId":"1","ethereumChainId":"31337"}\n');
  const run=spawnSync(process.execPath,['scripts/check-configuration.mjs',candidate],{
   cwd:root,encoding:'utf8',timeout:10_000,
  });
  assert.equal(run.status,1);
  assert.match(run.stderr,/duplicate object key "ethereumChainId"/);
 } finally {
  await rm(directory,{recursive:true,force:true});
 }
});
