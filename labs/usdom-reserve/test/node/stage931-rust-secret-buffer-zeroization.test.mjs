import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const cases=[
 ['dom-usdom-build-private-burn.rs','proving_key'],
 ['dom-usdom-submit-private-burn.rs','payload'],
 ['dom-usdom-bootstrap-tpm-wallet-authority.rs','payload']
];
test('plaintext key and private-burn payload allocations erase on every exit',async()=>{
 for(const [name,variable] of cases){
  const source=await readFile(new URL(`../../../../crates/dom-node/src/bin/${name}`,import.meta.url),'utf8');
  assert.match(source,new RegExp(`let ${variable} = Zeroizing::new\\(read_direct_file\\(`),name);
 }
});
