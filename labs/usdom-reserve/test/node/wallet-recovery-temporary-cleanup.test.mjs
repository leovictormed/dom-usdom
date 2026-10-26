import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');

test('wallet recovery drill pins cleanup and gives signals exact statuses',async()=>{
  const source=await readFile(path.join(component,'scripts/drill-closed-mainnet-wallet-recovery.sh'),'utf8');
  assert.match(source,/NODE_BIN=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/assert_node_unchanged\(\)[\s\S]*node_identity[\s\S]*node_sha256/);
  assert.match(source,/cleanup\(\) \{[\s\S]*trap - EXIT HUP INT TERM[\s\S]*unset recovery_password/);
  assert.match(source,/"\$NODE_BIN" -e 'require\("fs"\)\.rmSync[\s\S]*"\$SECRET_DIRECTORY" \|\| status=1/);
  for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
    assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`));
  assert.match(source,/trap 'cleanup \$\?' EXIT/);
  assert.doesNotMatch(source,/find "\$SECRET_DIRECTORY" -depth -delete|trap cleanup EXIT HUP INT TERM/);
  assert.doesNotMatch(source,/(?:^|\n)node\s+"\$LAB_ROOT\//);
  assert.equal(source.split('\n').filter(line=>/(?:^|\s)&\s*(?:#.*)?$/.test(line)).length,0);
});

test('wallet recovery cleanup inventory rejects legacy deletion/trap forms',async()=>{
  const source=await readFile(path.join(component,'scripts/drill-closed-mainnet-wallet-recovery.sh'),'utf8');
  const audit=value=>{
    assert.doesNotMatch(value,/find "\$SECRET_DIRECTORY" -depth -delete|rm -rf -- "\$SECRET_DIRECTORY"/);
    assert.doesNotMatch(value,/trap cleanup EXIT HUP INT TERM/);
    assert.match(value,/trap 'cleanup 143' TERM/);
  };
  assert.doesNotThrow(()=>audit(source));
  assert.throws(()=>audit(`${source}\nfind "$SECRET_DIRECTORY" -depth -delete\n`));
  assert.throws(()=>audit(`${source}\ntrap cleanup EXIT HUP INT TERM\n`));
});
