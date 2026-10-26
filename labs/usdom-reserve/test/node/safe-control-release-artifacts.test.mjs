import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {parseSafeControlReleaseArtifactBytes}
  from '../../scripts/safe-control-release-artifacts.mjs';

test('Safe control release artifacts reject ambiguous JSON bytes',()=>{
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseSafeControlReleaseArtifactBytes(bytes,'Safe artifact'),
    /duplicate (?:object )?key|invalid UTF-8/);
});

test('Safe control release authority uses byte-strict JSON parsing',async()=>{
  const source=await readFile(new URL('../../scripts/safe-control-release-artifacts.mjs',
    import.meta.url),'utf8');
  assert.match(source,/parseStrictJsonBytes\(bytes/);
  assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);
});
