import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');

test('finalized-deposit wallet registration has pinned status-preserving cleanup',async()=>{
  const source=await readFile(path.join(component,'scripts/register-finalized-deposit-wallet.sh'),'utf8');
  assert.match(source,/NODE_BIN=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/assert_node_unchanged\(\)[\s\S]*node_identity[\s\S]*node_sha256/);
  assert.match(source,/cleanup\(\) \{[\s\S]*trap - EXIT HUP INT TERM[\s\S]*unset recovery_password/);
  assert.match(source,/SECRET_DIRECTORY_IDENTITY=\$\(stat -c '%u:%d:%i:%a' "\$SECRET_DIRECTORY"\)/);
  assert.match(source,/stat -c '%u:%d:%i:%a' "\$SECRET_DIRECTORY" 2>\/dev\/null\) == "\$SECRET_DIRECTORY_IDENTITY"/);
  assert.match(source,/# Do not remove a replacement for the private registration directory\.[\s\S]*status=1/);
  assert.match(source,/assert_node_unchanged &&[\s\S]*run_pinned_timeout --foreground --signal=TERM --kill-after=5s 30s[\s\S]*"\$NODE_BIN" -e 'require\("fs"\)\.rmSync/);
  assert.match(source,/assert_node_unchanged && assert_runtime_tool timeout && test ! -e "\$SECRET_DIRECTORY"[\s\S]*else\n      status=1/);
  for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
    assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`));
  assert.match(source,/trap 'cleanup \$\?' EXIT/);
  assert.doesNotMatch(source,/find "\$SECRET_DIRECTORY" -depth -delete|trap cleanup EXIT HUP INT TERM/);
  assert.doesNotMatch(source,/(?:^|\n)node\s+"\$LAB_ROOT\//);
  assert.equal(source.split('\n').filter(line=>/(?:^|\s)&\s*(?:#.*)?$/.test(line)).length,0);
});

test('registration cleanup inventory rejects legacy deletion and signal traps',async()=>{
  const source=await readFile(path.join(component,'scripts/register-finalized-deposit-wallet.sh'),'utf8');
  const audit=value=>{
    assert.doesNotMatch(value,/find "\$SECRET_DIRECTORY" -depth -delete|rm -rf -- "\$SECRET_DIRECTORY"/);
    assert.doesNotMatch(value,/trap cleanup EXIT HUP INT TERM/);
    assert.match(value,/trap 'cleanup 143' TERM/);
  };
  assert.doesNotThrow(()=>audit(source));
  assert.throws(()=>audit(`${source}\nfind "$SECRET_DIRECTORY" -depth -delete\n`));
  assert.throws(()=>audit(`${source}\ntrap cleanup EXIT HUP INT TERM\n`));
});
