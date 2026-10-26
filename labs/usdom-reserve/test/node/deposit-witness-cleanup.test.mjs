import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');

test('finalized-deposit witness snapshots have pinned status-preserving cleanup',async()=>{
  const source=await readFile(path.join(component,'scripts/build-finalized-deposit-witness.sh'),'utf8');
  assert.match(source,/NODE_BIN=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/assert_node_unchanged\(\)[\s\S]*node_identity[\s\S]*node_sha256/);
  assert.match(source,/cleanup\(\) \{[\s\S]*trap - EXIT HUP INT TERM/);
  assert.match(source,/"\$NODE_BIN" -e 'require\("fs"\)\.rmSync[\s\S]*"\$SNAPSHOT_DIRECTORY" \|\| status=1/);
  for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
    assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`));
  assert.match(source,/trap 'cleanup \$\?' EXIT/);
  assert.doesNotMatch(source,/trap 'rm -rf|rm -rf -- "\$SNAPSHOT_DIRECTORY"/);
  assert.doesNotMatch(source,/(?:^|\n)node\s+"\$LAB_ROOT\//);
  assert.equal(source.split('\n').filter(line=>/(?:^|\s)&\s*(?:#.*)?$/.test(line)).length,0);
});

test('witness cleanup inventory rejects PATH deletion and ambiguous signal traps',async()=>{
  const source=await readFile(path.join(component,'scripts/build-finalized-deposit-witness.sh'),'utf8');
  const audit=value=>{
    assert.doesNotMatch(value,/rm -rf -- "\$SNAPSHOT_DIRECTORY"|find "\$SNAPSHOT_DIRECTORY" -depth -delete/);
    assert.doesNotMatch(value,/trap cleanup EXIT HUP INT TERM|trap 'rm -rf/);
    assert.match(value,/trap 'cleanup 143' TERM/);
  };
  assert.doesNotThrow(()=>audit(source));
  assert.throws(()=>audit(`${source}\nrm -rf -- "$SNAPSHOT_DIRECTORY"\n`));
  assert.throws(()=>audit(`${source}\ntrap cleanup EXIT HUP INT TERM\n`));
});
