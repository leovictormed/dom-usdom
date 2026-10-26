import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
const source=await readFile(new URL('../../scripts/check-recoverable-safe-recovery-raw-transaction.mjs',import.meta.url),'utf8');
test('Safe raw checker erases JSON and raw file captures on all exits',()=>{assert.equal((source.match(/finally \{ bytes\.fill\(0\); \}/g)||[]).length,2);assert.match(source,/strictJsonFile[\s\S]*finally \{ bytes\.fill\(0\); \}/);assert.match(source,/strictRawFile[\s\S]*finally \{ bytes\.fill\(0\); \}/)});
