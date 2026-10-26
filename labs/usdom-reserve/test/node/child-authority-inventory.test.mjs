import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const monitor=new URL('../../scripts/candidate-monitor.mjs',import.meta.url);

test('candidate snapshot child has immutable executable and canonical byte authority',async()=>{
  const source=await readFile(monitor,'utf8');
  assert.match(source,/snapshotExecutablePath\(binary\)/);
  assert.match(source,/runPinnedExecutable\(executableSnapshot,/);
  assert.match(source,/timeout:timeoutMs,maxBuffer:2\*1024\*1024/);
  assert.match(source,/stderr\.length,0/);
  assert.match(source,/parseCandidateMonitorJsonBytes\(stdout/);
  assert.match(source,/stdout\.equals\(Buffer\.from\(`\$\{JSON\.stringify\(verified\)\}\\n`\)\)/);
  assert.doesNotMatch(source,/parseCandidateMonitorJson\(stdout|execFileAsync|node:child_process|promisify/);
});
