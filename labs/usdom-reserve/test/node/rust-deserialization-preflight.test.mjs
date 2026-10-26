import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const source=readFileSync(new URL('../../../../crates/dom-usdom-checkpoint-program/src/portable.rs',import.meta.url),'utf8');

test('portable envelope proves minimum headers before allocation',()=>{
  const start=source.indexOf('fn parse_envelope(');
  const allocation=source.indexOf('Vec::with_capacity(count)',start);
  const preflight=source.indexOf('checked_mul(CHECKPOINT_USDOM_V4_ENTRY_HEADER_BYTES)',start);
  const length=source.indexOf('if bytes.len() < minimum',preflight);
  assert.ok(start>=0 && start<preflight && preflight<length && length<allocation);
});

test('native witness list proves every length prefix before allocation',()=>{
  const start=source.indexOf('fn parse_native_witnesses(');
  const allocation=source.indexOf('Vec::with_capacity(count)',start);
  const preflight=source.indexOf('checked_mul(4)',start);
  const length=source.indexOf('if bytes.len() < minimum',preflight);
  assert.ok(start>=0 && start<preflight && preflight<length && length<allocation);
});

test('checkpoint private block list proves every block header before allocation',()=>{
  const input=readFileSync(new URL('../../../../crates/dom-usdom-checkpoint-program/src/lib.rs',import.meta.url),'utf8');
  const start=input.indexOf('pub struct CheckpointSegmentPrivateInput');
  const allocation=input.indexOf('Vec::with_capacity(count)',start);
  const preflight=input.indexOf('checked_mul(CHECKPOINT_SEGMENT_PRIVATE_BLOCK_HEADER_BYTES)',start);
  const length=input.indexOf('if bytes.len() < minimum',preflight);
  assert.ok(start>=0 && start<preflight && preflight<length && length<allocation);
});

test('economic old-utxo list proves every presence flag before allocation',()=>{
  const input=readFileSync(new URL('../../../../crates/dom-usdom-checkpoint-program/src/economic_chunks.rs',import.meta.url),'utf8');
  const allocation=input.indexOf('Vec::with_capacity(old_count)');
  const preflight=input.lastIndexOf('checked_add(old_count)',allocation);
  const length=input.indexOf('if bytes.len() < minimum',preflight);
  assert.ok(preflight>=0 && preflight<length && length<allocation);
});
