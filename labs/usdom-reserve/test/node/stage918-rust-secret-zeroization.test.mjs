import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source=await readFile(
 new URL('../../../../crates/dom-node/src/secret_file.rs',import.meta.url),'utf8');

test('Rust secret loader transfers one allocation and zeroizes rejected plaintext',()=>{
 assert.match(source,/let bytes = std::mem::take\(&mut \*raw\);/);
 assert.doesNotMatch(source,/String::from_utf8\(raw\.to_vec\(\)\)/);
 assert.match(source,/Err\(error\) => \{[\s\S]*let mut invalid = error\.into_bytes\(\);[\s\S]*invalid\.zeroize\(\);/);
 assert.match(source,/if length < minimum_bytes \|\| length > maximum_bytes \{\s*secret\.zeroize\(\);/);
});
