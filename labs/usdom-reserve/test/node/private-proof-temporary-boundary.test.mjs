import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const scripts=[
  'export-authenticated-randomx-statement-set.sh',
  'export-authenticated-randomx-statement.sh',
  'package-authenticated-finalized-burn-evm-proof.sh',
  'plan-authenticated-checkpoint-outer.sh',
  'plan-authenticated-checkpoint-segment-set.sh',
  'plan-authenticated-economic-receipt-set.sh',
  'plan-authenticated-finalized-burn.sh',
  'plan-authenticated-randomx-receipt-set.sh',
  'prove-authenticated-checkpoint-outer.sh',
  'prove-authenticated-checkpoint-segment-set.sh',
  'prove-authenticated-economic-receipt-set.sh',
  'prove-authenticated-finalized-burn.sh',
  'prove-authenticated-randomx-receipt-set.sh',
];

test('private proof snapshots use fixed owner-only volatile storage and signal cleanup',()=>{
  for(const name of scripts) {
    const source=readFileSync(path.join(root,'scripts',name),'utf8');
    assert.match(source,/^umask 077$/m,name);
    assert.match(source,/mktemp -d "\/dev\/shm\/usdom-[^" ]+\.XXXXXX"/,name);
    assert.match(source,/chmod 0700 "\$SNAPSHOT_ROOT"/,name);
    assert.match(source,/trap 'rm -rf -- "\$SNAPSHOT_ROOT"' EXIT HUP INT TERM/,name);
    assert.doesNotMatch(source,/TMPDIR|\/tmp\/usdom-/,name);
  }
});
