import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source=relative=>readFile(new URL(`../../scripts/${relative}`,import.meta.url),'utf8');

test('handoff and checkpoint authorities share the descriptor-bound durable publisher',async()=>{
  for(const file of ['adapt-randomx-v5-proof-handoff.py','check-long-proof-handoff.py',
    'aggregate-checkpoint-rebuild-receipts.py','materialize-checkpoint-rebuild-v3-manifest.py']) {
    const text=await source(file);
    assert.match(text,/from durable_create_once import install_create_once/,file);
    assert.match(text,/install_create_once\(/,file);
    assert.doesNotMatch(text,/os\.replace\(temporary, target\)|os\.replace\(temp,target\)/,file);
  }
});

test('rebuild resume marker is recoverable create-once and rejects markerless partial initialization',async()=>{
  const text=await source('orchestrate-checkpoint-rebuild.py');
  assert.match(text,/marker_bytes =/);
  assert.match(text,/install_create_once\(resume_marker,marker_bytes/);
  assert.match(text,/rebuild resume workspace initialization is incomplete/);
  assert.doesNotMatch(text,/resume_marker\.write_text/);
});
