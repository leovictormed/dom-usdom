import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');

test('every private deployment snapshot immediately reattests Node',()=>{
  assert.match(source,/snapshot\(\) \{\n  assert_node_unchanged\n  "\$node_bin" scripts\/read-private-file-stdout\.mjs/);
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
  const temporary=source.indexOf('temporary=$(mktemp',removal);
  const proxy=source.indexOf('rpc_proxy_pid=$!',temporary);
  assert.ok(lock>=0&&removal>lock&&temporary>removal&&proxy>temporary);
  assert.match(source,/contract-deployment-\$index-receipt\.json/);
  assert.match(source,/contract-deployment-\$index-evidence\.json/);
  for(const retained of ['raw-transaction','submission-hash','raw-validation','finalized-anchor']) {
    const block=source.slice(lock,temporary);
    assert.doesNotMatch(block,new RegExp(`contract-deployment-\\$index-${retained}`));
  }
});
