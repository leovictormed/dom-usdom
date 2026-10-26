import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const root=new URL('../../../../crates/dom-usdom-randomx-proof-host/src/',import.meta.url);

test('RandomX production launchers do not canonicalize through artifact symlinks',()=>{
  for(const file of ['bin/plan.rs','bin/prove.rs']){
    const source=readFileSync(new URL(file,root),'utf8');
    assert.doesNotMatch(source,/canonicalize/);
    assert.doesNotMatch(source,/use std::fs/);
    assert.match(source,/elf: production(?:\.plan)?\.elf/);
    assert.match(source,/program: production(?:\.plan)?\.program/);
    assert.match(source,/image_id: production(?:\.plan)?\.image_id/);
  }
});

test('RandomX artifact reads remain bounded, direct and hash-bound',()=>{
  const source=readFileSync(new URL('lib.rs',root),'utf8');
  assert.match(source,/fn read_direct_regular_file\(path: &Path, maximum: usize\)[\s\S]*read_captured_bytes\(path, maximum\)/);
  assert.match(source,/fn validate_artifact\(path: &Path, maximum: usize, expected: &str\)[\s\S]*sha256\(&bytes\) != expected/);
});
