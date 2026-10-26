import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');

test('finalized-deposit observation has pinned status-preserving cleanup',async()=>{
  const source=await readFile(path.join(component,'scripts/observe-finalized-deposit-wallet.sh'),'utf8');
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

test('observation cleanup inventory rejects legacy deletion and signal traps',async()=>{
  const source=await readFile(path.join(component,'scripts/observe-finalized-deposit-wallet.sh'),'utf8');
  const audit=value=>{
    assert.doesNotMatch(value,/find "\$SECRET_DIRECTORY" -depth -delete|rm -rf -- "\$SECRET_DIRECTORY"/);
    assert.doesNotMatch(value,/trap cleanup EXIT HUP INT TERM/);
    assert.match(value,/trap 'cleanup 143' TERM/);
  };
  assert.doesNotThrow(()=>audit(source));
  assert.throws(()=>audit(`${source}\nfind "$SECRET_DIRECTORY" -depth -delete\n`));
  assert.throws(()=>audit(`${source}\ntrap cleanup EXIT HUP INT TERM\n`));
});

test('wallet observation invalidates only derived state before password and RPC',async()=>{
  const source=await readFile(path.join(component,'scripts/observe-finalized-deposit-wallet.sh'),'utf8');
  const removal=source.indexOf('remove-private-directory-durable.mjs" "$OBSERVED_STATE"');
  const terminal=source.indexOf('if [[ ! -t 0 || ! -t 2 ]]',removal);
  const rpc=source.indexOf("'http://127.0.0.1:33372/chain/identity'",removal);
  assert.ok(removal>=0&&terminal>removal&&rpc>terminal);
  assert.doesNotMatch(source,/remove-private-directory-durable\.mjs" "\$REGISTERED_STATE"/);
});

test('wallet observation rejects a DOM identity change before accepting derived state',async()=>{
  const source=await readFile(path.join(component,'scripts/observe-finalized-deposit-wallet.sh'),'utf8');
  const observer=source.indexOf('"$observer_binary"');
  const after=source.indexOf('--output "$IDENTITY_AFTER_FILE"',observer);
  const compare=source.indexOf('cmp -s "$IDENTITY_FILE" "$IDENTITY_AFTER_FILE"',after);
  const accept=source.indexOf('test -d "$OBSERVED_STATE"',compare);
  assert.ok(observer>=0&&after>observer&&compare>after&&accept>compare);
  assert.match(source,/DOM mainnet identity changed during finalized-deposit observation/);
});
