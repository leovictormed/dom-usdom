import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');

test('every private deployment snapshot is bounded and immediately reattests Node',()=>{
  const snapshot=source.slice(source.indexOf('snapshot() {'),source.indexOf('read_canonical_line() {'));
  assert.match(snapshot,/assert_node_unchanged\n  assert_timeout_unchanged/);
  assert.match(snapshot,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(snapshot,/read-private-file-stdout\.mjs "\$source"[\s\S]*> "\$output" 2> "\$error"/);
  assert.match(snapshot,/\[process\.argv\[1\],16777216\],[\s\S]*\[process\.argv\[2\],65536\]/);
  assert.match(snapshot,/fatal\.decode\(bytes\)/);
  assert.match(snapshot,/test -s "\$output"\n  test ! -s "\$error"/);
  assert.match(snapshot,/assert_private_file "\$output"\n  assert_private_file "\$error"/);
  assert.doesNotMatch(snapshot,/chmod/);
});

test('deployment success binds final source, receipt and evidence bytes',()=>{
  const output=source.lastIndexOf("printf 'Deployment %s finalizado");
  assert.ok(output>0);
  const final=source.slice(source.lastIndexOf('# Bind success',output),output);
  assert.match(final,/snapshot "\$package_source"[\s\S]*"\$cmp_bin" -s "\$package_snapshot"/);
  assert.match(final,/snapshot "\$observation_source"[\s\S]*"\$cmp_bin" -s "\$observation_snapshot"/);
  assert.match(final,/sha256_file "\$rpc_catalog"[\s\S]*snapshot "\$receipt_file"[\s\S]*"\$cmp_bin" -s "\$receipt_1"/);
  assert.match(final,/snapshot "\$evidence_file"[\s\S]*"\$cmp_bin" -s "\$evidence_draft"[\s\S]*assert_rpc_proxy_alive/);
});

test('deployment invalidates only current derived receipt/evidence before proxy RPC',()=>{
  const lock=source.indexOf('"$flock_bin" -n 9');
  const removal=source.indexOf('remove-private-file-durable.mjs',lock);
  const temporary=source.indexOf('temporary=$("$timeout_bin"',removal);
  const proxy=source.indexOf('rpc_proxy_pid=$!',temporary);
  assert.ok(lock>=0&&removal>lock&&temporary>removal&&proxy>temporary);
  assert.match(source,/contract-deployment-\$index-receipt\.json/);
  assert.match(source,/contract-deployment-\$index-evidence\.json/);
  for(const retained of ['raw-transaction','submission-hash','raw-validation','finalized-anchor']) {
    const block=source.slice(lock,temporary);
    assert.doesNotMatch(block,new RegExp(`contract-deployment-\\$index-${retained}`));
  }
});
