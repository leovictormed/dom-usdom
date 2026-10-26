import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

test('checkpoint receipt removal durably syncs its parent directory',()=>{
  const source=readFileSync(new URL('../../../../crates/dom-usdom-checkpoint-proof-host/src/lib.rs',import.meta.url),'utf8');
  const start=source.indexOf('fn remove_direct_file(path: &Path)');
  const end=source.indexOf('fn existing_verified_segment_receipt',start);
  const helper=source.slice(start,end);
  assert.match(helper,/file_type\(\)\.is_symlink\(\) \|\| !metadata\.file_type\(\)\.is_file\(\)/);
  assert.match(helper,/fs::remove_file\(path\)/);
  assert.match(helper,/fs::File::open\(parent\)[\s\S]*directory\.sync_all\(\)/);
});

test('single-statement invalidation rejects indirect paths and syncs its parent',()=>{
  const source=readFileSync(new URL('../../../../crates/dom-usdom-checkpoint-program/src/bin/dom-usdom-export-randomx-statement.rs',import.meta.url),'utf8');
  const start=source.indexOf('fn invalidate_output(path: &Path)');
  const end=source.indexOf('fn read_direct_regular_file',start);
  const helper=source.slice(start,end);
  assert.match(helper,/file_type\(\)\.is_symlink\(\) \|\| !metadata\.is_file\(\)/);
  assert.match(helper,/fs::remove_file\(path\)/);
  assert.match(helper,/fs::File::open\(parent\)[\s\S]*directory\.sync_all\(\)/);
});
