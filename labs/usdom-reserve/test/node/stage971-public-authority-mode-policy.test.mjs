import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source=await readFile(new URL(
  '../../../../crates/dom-wallet-crypto/src/lib.rs',import.meta.url),'utf8');
test('public authority reader forbids group/other mutation on parent and leaf',()=>{
  for(const expression of [
    'named_parent.mode() & 0o022 != 0','retained_parent.mode() & 0o022 != 0',
    'retained.mode() & 0o022 != 0','anchored_metadata.mode() & 0o022 != 0',
    'named.mode() & 0o022 != 0','current_parent.mode() & 0o022 != 0',
  ]) assert.ok(source.includes(expression),expression);
});

test('policy permits world-readable authority while testing mutable modes',()=>{
  assert.match(source,/from_mode\(0o644\)[\s\S]*read_captured_bytes\(&source, 15\)\.unwrap\(\)/);
  assert.match(source,/from_mode\(0o664\)[\s\S]*read_captured_bytes\(&writable_file, 15\)/);
  assert.match(source,/from_mode\(0o770\)[\s\S]*read_captured_bytes\(&nested, 15\)/);
});
