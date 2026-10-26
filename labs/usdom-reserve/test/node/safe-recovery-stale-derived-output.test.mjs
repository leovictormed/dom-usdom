import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL(
  '../../scripts/execute-recoverable-safe-recovery.sh',import.meta.url),'utf8');

test('every private recovery snapshot immediately reattests Node',()=>{
  assert.match(source,/snapshot_private\(\) \{\n  assert_node_unchanged\n  "\$node_bin" "\$project\/scripts\/read-private-file-stdout\.mjs/);
});

test('recovery success rereads installed report and bundle under final source authority',()=>{
  const output=source.lastIndexOf('"$jq_bin" \'{schema,ethereumChainId');
  assert.ok(output>0);
  const final=source.slice(source.lastIndexOf('final_bundle=',output),output);
  assert.match(final,/snapshot_private "\$final_report"[\s\S]*"\$cmp_bin" -s "\$final_consensus"/);
  assert.match(final,/snapshot_private "\$final_bundle_installed"[\s\S]*"\$cmp_bin" -s "\$final_bundle"/);
  assert.match(final,/assert_sources_unchanged[\s\S]*assert_rpc_proxy_alive[\s\S]*assert_jq_unchanged\s*$/);
});

test('Safe recovery invalidates only derived observations under lock before RPC',()=>{
  const lock=source.indexOf('if ! "$flock_bin" -n 9');
  const removal=source.indexOf('remove-private-file-durable.mjs',lock);
  const temporary=source.indexOf('temporary=$(mktemp',removal);
  const rpc=source.indexOf('rpc_proxy_pid=$!',temporary);
  assert.ok(lock>=0&&removal>lock&&temporary>removal&&rpc>temporary);
  for(const name of ['governance-finalized-execution.json','reserveGuardian-finalized-execution.json',
    'checkpointGuardian-finalized-execution.json','safe-recovery-finalized-report.json',
    'safe-recovery-finalized-bundle.json']) assert.ok(source.includes(name));
  for(const retained of ['$raw_file','$hash_file','$envelope_file']) {
    assert.doesNotMatch(source,new RegExp(`remove-private-file-durable\\.mjs[^\\n]*${retained.replace('$','\\$')}`));
  }
});
