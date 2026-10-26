import test from 'node:test'; import assert from 'node:assert/strict'; import {readFile} from 'node:fs/promises';
const crates=['checkpoint','economic','randomx','finalized-burn'];
test('all ten proof-host private read buffers are Zeroizing',async()=>{
 const files=['dom-usdom-checkpoint-proof-host/src/lib.rs','dom-usdom-economic-proof-host/src/lib.rs','dom-usdom-randomx-proof-host/src/aggregate.rs','dom-usdom-finalized-burn-proof-host/src/lib.rs'];
 const src=(await Promise.all(files.map(p=>readFile(new URL(`../../../../crates/${p}`,import.meta.url),'utf8')))).join('\n');
 assert.equal((src.match(/Zeroizing::new\((?:checked_source|read_direct|read_direct_regular_file)\(/g)||[]).length,10);
 for(const crate of crates){const cargo=await readFile(new URL(`../../../../crates/dom-usdom-${crate}-proof-host/Cargo.toml`,import.meta.url),'utf8');assert.match(cargo,/zeroize\.workspace = true/);}
});
