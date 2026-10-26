import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
const source=await readFile(new URL('../../sdk/runtime-secret-json.mjs',import.meta.url),'utf8');
test('shared runtime secret reader bounds inheritance and erases both captures',()=>{assert.match(source,/const file=process\.env\[fileVariable\];\s*delete process\.env\[fileVariable\]/);assert.match(source,/finally \{\s*if\(bytes\) bytes\.fill\(0\);\s*if\(verification\) verification\.fill\(0\)/s);assert.match(source,/TextDecoder\('utf-8',\{fatal:true\}\)/)});
