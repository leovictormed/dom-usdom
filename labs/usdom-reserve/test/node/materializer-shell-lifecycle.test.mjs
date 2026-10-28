import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');
const writers=['write-mainnet-preflight-rpc-catalog.sh',
  'write-checkpoint-bootstrap-rpc-catalog.sh','write-checkpoint-finalized-event-observation.sh'];

test('catalog and finalized-event writers bound every Node child and exit on signals',async()=>{
  for(const name of writers) {
    const source=await readFile(path.join(root,'scripts',name),'utf8');
    const nodeCommands=source.split('\n').filter(line=>/^\s*(?:node|"\$node_bin") /.test(line));
    assert(nodeCommands.length>=2,name);
    assert.equal((source.match(/(?:timeout|"\$timeout_bin") --signal=TERM --kill-after=/g)??[]).length,
      nodeCommands.length,name);
    for(const [signal,status] of [['HUP','129'],['INT','130'],['TERM','143']]) {
      assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`),name);
    }
    assert.match(source,/cleanup\(\) \{\s*local status=\$\{1:-\$\?\};?\s*trap - EXIT HUP INT TERM;?/,name);
    assert.doesNotMatch(source,/(?:^|\s)&\s*(?:#.*)?$/m,name);
  }
});

test('preflight attestation materializer replaces shell with a bounded process group',async()=>{
  const source=await readFile(path.join(root,'scripts','materialize-mainnet-preflight-attestation.sh'),'utf8');
  assert.match(source,/exec "\$timeout_bin" --signal=TERM --kill-after=5s 300s[\s\\]+"\$node_bin" scripts\/materialize-mainnet-preflight-attestation\.mjs/);
  assert.doesNotMatch(source,/(?:^|\s)&\s*(?:#.*)?$|\bwait\b|(?:^|\n)\s*kill\s/m);
});
