import assert from 'node:assert/strict';
import test from 'node:test';
import {runPinnedExecutable} from '../../sdk/pinned-executable-child.mjs';
import {snapshotExecutable} from '../../sdk/stable-executable.mjs';

test('pinned child timeout kills and reaps its descendant process group',async()=>{
  const shell=await snapshotExecutable('sh');
  let failure;
  try {
    await runPinnedExecutable(shell,['-c',
      'sleep 30 & child=$!; printf "%s\\n" "$child"; wait "$child"'],
    {maxBuffer:4096,timeout:2000});
  } catch(error) { failure=error; }
    assert.match(failure?.message??'',/pinned child timed out/);
    const pidText=failure.stdout.toString('utf8').trim();
    assert.match(pidText,/^[1-9][0-9]*$/);
    const pid=Number(pidText);
    assert.ok(Number.isSafeInteger(pid)&&pid>1);
    assert.throws(()=>process.kill(pid,0),error=>error?.code==='ESRCH');
});

test('pinned child output overflow terminates the process group',async()=>{
  const shell=await snapshotExecutable('sh');
  await assert.rejects(runPinnedExecutable(shell,['-c','while :; do printf 1234567890; done'],
    {maxBuffer:1024,timeout:5000}),/stdout exceeded its bound/);
});
