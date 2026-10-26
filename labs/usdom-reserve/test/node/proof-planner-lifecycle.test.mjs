import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const names=[
  'plan-authenticated-economic-receipt-set.sh',
  'plan-authenticated-randomx-receipt-set.sh',
  'plan-authenticated-finalized-burn.sh',
  'export-canonical-finalized-burn-source.sh',
  'export-authenticated-randomx-statement.sh',
  'export-authenticated-randomx-statement-set.sh',
  'plan-authenticated-checkpoint-segment-set.sh',
  'plan-authenticated-checkpoint-outer.sh',
];

test('finite proof planning and export cargo children have a hard deadline',()=>{
  for(const name of names){
    const script=fileURLToPath(new URL(`../../scripts/${name}`,import.meta.url));
    assert.equal(spawnSync('bash',['-n',script]).status,0,name);
    const source=readFileSync(script,'utf8');
    assert.equal((source.match(/cargo run /g)??[]).length,1,name);
    assert.match(source,/timeout --signal=TERM --kill-after=30s 3600s \\\n+  cargo run /,name);
    assert.doesNotMatch(source,/^cargo run /m,name);
  }
});
