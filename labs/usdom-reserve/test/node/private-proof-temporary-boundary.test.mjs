import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const scripts=[
  'export-canonical-checkpoint-source.sh',
  'export-canonical-checkpoint-source-set.sh',
  'export-canonical-finalized-burn-source.sh',
  'export-authenticated-randomx-statement-set.sh',
  'export-authenticated-randomx-statement.sh',
  'package-authenticated-checkpoint-outer-evm-proof.sh',
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
  'prove-authenticated-randomx-aggregate-set.sh',
  'prove-authenticated-randomx-receipt-set.sh',
];

test('private proof snapshots use fixed owner-only volatile storage and signal cleanup',()=>{
  for(const name of scripts) {
    const source=readFileSync(path.join(root,'scripts',name),'utf8');
    assert.match(source,/^umask 077$/m,name);
    assert.match(source,/(?:\/dev\/shm\/usdom-[^" ]+\.XXXXXX|-p \/dev\/shm usdom-[^" ]+\.XXXXXXXX)/,name);
    if(['export-canonical-checkpoint-source-set.sh','export-canonical-checkpoint-source.sh',
        'export-canonical-finalized-burn-source.sh'].includes(name)) {
      assert.match(source,/mktemp -d -p \/dev\/shm usdom-[^" ]+\.XXXXXXXX/,name);
      assert.match(source,/chmod 0700 -- "\$SNAPSHOT_DIRECTORY"/,name);
      assert.match(source,/SNAPSHOT_DIRECTORY_IDENTITY=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' "\$SNAPSHOT_DIRECTORY"\)/,name);
      assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' "\$SNAPSHOT_DIRECTORY" 2>\/dev\/null\) == "\$SNAPSHOT_DIRECTORY_IDENTITY"/,name);
      assert.match(source,/trap 'cleanup_snapshot \$\?' EXIT/,name);
      for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
        assert.match(source,new RegExp(`trap 'cleanup_snapshot ${status}' ${signal}`),name);
    } else if(name==='package-authenticated-checkpoint-outer-evm-proof.sh'
        ||name==='package-authenticated-finalized-burn-evm-proof.sh') {
      assert.match(source,/"\$mktemp_bin" -d/,name);
      assert.match(source,/%F:%u:%a:%h/,name);
      assert.match(source,/:700:2"/,name);
      assert.match(source,/:600:1"/,name);
      assert.doesNotMatch(source,/chmod (?:0700|0600|-R)/,name);
      assert.match(source,/trap 'cleanup_snapshot \$\?' EXIT/,name);
      for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
        assert.match(source,new RegExp(`trap 'cleanup_snapshot ${status}' ${signal}`),name);
    } else if(['prove-authenticated-finalized-burn.sh','prove-authenticated-checkpoint-outer.sh',
        'prove-authenticated-checkpoint-segment-set.sh','prove-authenticated-economic-receipt-set.sh',
        'prove-authenticated-randomx-receipt-set.sh','prove-authenticated-randomx-aggregate-set.sh',
        'plan-authenticated-finalized-burn.sh','plan-authenticated-checkpoint-outer.sh',
        'plan-authenticated-checkpoint-segment-set.sh','plan-authenticated-economic-receipt-set.sh',
        'plan-authenticated-randomx-receipt-set.sh','export-authenticated-randomx-statement.sh',
        'export-authenticated-randomx-statement-set.sh'].includes(name)) {
      assert.match(source,/mktemp -d "\/dev\/shm\/usdom-[^" ]+\.XXXXXX"/,name);
      assert.match(source,/chmod 0700 "\$SNAPSHOT_ROOT"/,name);
      assert.match(source,/SNAPSHOT_ROOT_IDENTITY=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' "\$SNAPSHOT_ROOT"\)/,name);
      assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' "\$SNAPSHOT_ROOT" 2>\/dev\/null\) == "\$SNAPSHOT_ROOT_IDENTITY"/,name);
      assert.match(source,/trap 'cleanup_snapshot \$\?' EXIT/,name);
      for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
        assert.match(source,new RegExp(`trap 'cleanup_snapshot ${status}' ${signal}`),name);
    } else {
      assert.match(source,/mktemp -d "\/dev\/shm\/usdom-[^" ]+\.XXXXXX"/,name);
      assert.match(source,/chmod 0700 "\$SNAPSHOT_ROOT"/,name);
      assert.match(source,/trap 'rm -rf -- "\$SNAPSHOT_ROOT"' EXIT HUP INT TERM/,name);
    }
    assert.doesNotMatch(source,/TMPDIR|\/tmp\/usdom-/,name);
  }
});
