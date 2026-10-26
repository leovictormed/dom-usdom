import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const root=new URL('../../../../crates/',import.meta.url);
const files=[
  'dom-usdom-checkpoint-proof-host/src/lib.rs','dom-usdom-economic-proof-host/src/lib.rs',
  'dom-usdom-finalized-burn-proof-host/src/lib.rs','dom-usdom-randomx-proof-host/src/lib.rs',
  'dom-usdom-randomx-proof-host/src/aggregate.rs','dom-usdom-wallet/src/rpc_client.rs',
];
const sources=files.map(file=>[file,readFileSync(new URL(file,root),'utf8')]);

test('all production JSON response/index structs reject unknown and duplicate fields',()=>{
  for(const [file,source] of sources){
    for(const match of source.matchAll(/#\[derive\([^\]]*Deserialize[^\]]*\)\]/g)){
      const declaration=source.slice(match.index,match.index+180);
      assert.match(declaration,/serde\(deny_unknown_fields\)/,`${file}:${match.index}`);
    }
  }
});

test('all eight receipt decoders are bounded, trailing-strict, canonical and cryptographically bound',()=>{
  const proofSources=sources.slice(0,5).map(([,source])=>source).join('\n');
  const sites=[...proofSources.matchAll(/\.deserialize\(bytes\)/g)];
  assert.equal(sites.length,8);
  for(const site of sites){
    const before=proofSources.slice(Math.max(0,site.index-500),site.index);
    const after=proofSources.slice(site.index,site.index+1800);
    assert.match(before,/bytes\.len\(\) > MAX_(?:COMPOSITE_)?RECEIPT_BYTES/);
    assert.match(before,/reject_trailing_bytes\(\)[\s\S]*with_limit\(/);
    assert.match(after,/serialize\(&receipt\)[\s\S]*!= bytes/);
    assert.match(after,/receipt\.journal\.bytes/);
    assert.match(after,/\.verify\(Risc0Digest::from\(image_id\)\)/);
  }
});

test('inventory retains 22 production JSON sites plus one test fixture decoder',()=>{
  const count=sources.reduce((sum,[,source])=>sum+[...source.matchAll(/serde_json::from_slice/g)].length,0);
  assert.equal(count,23);
  const rpc=sources.at(-1)[1];
  assert.match(rpc,/const MAX_RPC_RESPONSE_BYTES:/);
  assert.match(rpc,/const MAX_HISTORY_RPC_RESPONSE_BYTES:/);
  assert.match(rpc,/response\.take\(/);
});
