import assert from 'node:assert/strict';
import test from 'node:test';
import {parseStrictJson} from '../../sdk/strict-json.mjs';

test('strict JSON independently bounds strings, width and total nodes',()=>{
  assert.throws(()=>parseStrictJson('"abcdefgh"',{maxBytes:64,maxStringBytes:4}),/string exceeds/);
  assert.throws(()=>parseStrictJson('{"a":1,"b":2}',{maxBytes:64,maxObjectEntries:1}),
    /object entries exceed/);
  assert.throws(()=>parseStrictJson('[1,2]',{maxBytes:64,maxArrayEntries:1}),/array entries exceed/);
  assert.throws(()=>parseStrictJson('[1,2]',{maxBytes:64,maxNodes:2}),/node count exceeds/);
  assert.deepEqual(parseStrictJson('{"a":["ok"]}',{maxBytes:64,maxNodes:3,
    maxStringBytes:8,maxObjectEntries:1,maxArrayEntries:1}),Object.assign(Object.create(null),{a:['ok']}));
});
