import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const checker=new URL('../../scripts/check-checkpoint-bootstrap-ratification-request.mjs',
  import.meta.url);

test('checkpoint ratification JSON boundary rejects ambiguous bytes',()=>{
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'checkpoint ratification',
    maxBytes:4*1024*1024,maxDepth:64}),/duplicate (?:object )?key|invalid UTF-8/);
});

test('checkpoint ratification checker byte-parses all five authorities and rechecks them',async()=>{
  const source=await readFile(checker,'utf8');
  assert.match(source,/parseStrictJsonBytes\(bytes/);
  assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);
  assert.match(source,/inputBytes\.map\(\s*\(bytes,index\)=>parse\(bytes,inputs\[index\]\)\)/);
  assert.match(source,/request=parse\(requestBytes/);
  assert.match(source,/requestAfter\.equals\(requestBytes\)/);
  assert.match(source,/inputsAfter\.some\(\(bytes,index\)=>!bytes\.equals\(inputBytes\[index\]\)\)/);
});
