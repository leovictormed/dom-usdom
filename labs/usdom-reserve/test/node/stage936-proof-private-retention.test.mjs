import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
const paths=['dom-usdom-checkpoint-proof-host/src/lib.rs','dom-usdom-economic-proof-host/src/lib.rs','dom-usdom-randomx-proof-host/src/aggregate.rs','dom-usdom-finalized-burn-proof-host/src/lib.rs'];
const src=(await Promise.all(paths.map(p=>readFile(new URL(`../../../../crates/${p}`,import.meta.url),'utf8')))).join('\n');
test('four private source classes are hash bound and owner-only persisted',()=>{assert.match(src,/private_input_file/);assert.match(src,/witness_file/);assert.match(src,/finalized-burn-input\.bin/);assert.match(src,/save_private_bytes/);assert.match(src,/private_input_sha256|input_sha256/)});
test('success paths do not prematurely delete retry inputs',()=>{for(const name of ['private_input_file','witness_file','INPUT_LOGICAL_PATH'])assert.doesNotMatch(src,new RegExp(`remove_file\\([^\\n]*${name}`));});
