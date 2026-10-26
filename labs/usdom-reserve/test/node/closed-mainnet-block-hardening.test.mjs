import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL(
  '../../scripts/mine-closed-mainnet-issuance-block.mjs',import.meta.url),'utf8');
const genesis=await readFile(new URL(
  '../../scripts/initialize-closed-mainnet-genesis.mjs',import.meta.url),'utf8');

test('closed Mainnet issuance block uses strict transport and immutable evidence',()=>{
  assert.match(source,/TextDecoder\('utf-8',\{fatal:true\}\)/);
  assert.match(source,/parseStrictJson\(payload/);
  assert.match(source,/parseStrictJson\(submissionJson/);
  assert.match(source,/TextDecoder\('utf-8',\{fatal:true\}\)\.decode\(submissionBytes\)/);
  assert.match(source,/writePrivateFileDurableNew\(file,value/);
  assert.doesNotMatch(source,/writePrivateFileDurable\(file,value/);
});

test('closed Mainnet genesis uses strict transport, double identity reads and create-once receipt',()=>{
  for(const marker of ["TextDecoder('utf-8',{fatal:true})",'parseStrictJson(payload',
    'writePrivateFileDurableNew(file,value','beforeRecheck','identityRecheck',
    'genesis initialization receipt already exists']) assert.ok(genesis.includes(marker),marker);
  assert.ok(genesis.indexOf('beforeRecheck')
    <genesis.indexOf("rpc('POST','/closed-mainnet/mine-one/v1'"));
  assert.ok(genesis.indexOf('identityRecheck')<genesis.indexOf('await atomicWrite(receiptFile'));
  assert.doesNotMatch(genesis,/writePrivateFileDurable\(file,value/);
  assert.doesNotMatch(genesis,/JSON\.parse\(payload\)/);
});

test('closed Mainnet issuance block rechecks canonical identity around mutation',()=>{
  assert.match(source,/beforeRecheck/);
  assert.match(source,/canonical identity changed before issuance block production/);
  assert.match(source,/afterRecheck/);
  assert.match(source,/canonical identity changed after issuance block production/);
  assert.ok(source.indexOf('beforeRecheck')<source.indexOf("rpc('POST','/closed-mainnet/mine-one/v1'"));
  assert.ok(source.indexOf('afterRecheck')<source.indexOf('await atomicWrite(receiptFile'));
  assert.match(source,/validatePersistedIssuanceBlock/);
  assert.match(source,/if\(!completed\)/);
  assert.ok(source.indexOf('validatePersistedIssuanceBlock')
    <source.indexOf("rpc('POST','/closed-mainnet/mine-one/v1'"));
});
