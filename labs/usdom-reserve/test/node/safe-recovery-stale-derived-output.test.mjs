import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL(
  '../../scripts/execute-recoverable-safe-recovery.sh',import.meta.url),'utf8');

test('every private recovery snapshot is bounded and immediately reattests Node',()=>{
  const snapshot=source.slice(source.indexOf('snapshot_private() {'),
    source.indexOf('read_canonical_line() {'));
  assert.match(snapshot,/assert_node_unchanged\n  assert_timeout_unchanged\n  if "\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(snapshot,/read-private-file-stdout\.mjs" "\$source"[\s\S]*> "\$output" 2> "\$error"/);
  assert.match(snapshot,/\[process\.argv\[1\],2097152\],[\s\S]*\[process\.argv\[2\],65536\]/);
  assert.match(snapshot,/fatal\.decode\(bytes\)/);
  assert.match(snapshot,/test -s "\$output"\n  test ! -s "\$error"/);
});

test('recovery success rereads installed report and bundle under final source authority',()=>{
  const output=source.lastIndexOf('final_summary_file=');
  assert.ok(output>0);
  const final=source.slice(source.lastIndexOf('final_bundle=',output),output);
  assert.match(final,/snapshot_private "\$final_report"[\s\S]*"\$cmp_bin" -s "\$final_consensus"/);
  assert.match(final,/snapshot_private "\$final_bundle_installed"[\s\S]*"\$cmp_bin" -s "\$final_bundle"/);
  assert.match(final,/assert_sources_unchanged[\s\S]*assert_rpc_proxy_alive[\s\S]*assert_evidence_parent\s*$/);
  assert.match(source.slice(output),/run_jq_json_authority "\$final_summary_file"[\s\S]*"\$final_consensus"/);
});

test('Safe recovery invalidates only derived observations under lock before RPC',()=>{
  const lock=source.indexOf('if ! "$flock_bin" -n 9');
  const removal=source.indexOf('remove-private-file-durable.mjs',lock);
  const temporary=source.indexOf('temporary=$("$mktemp_bin"',lock);
  const rpc=source.indexOf('rpc_proxy_pid=$!',temporary);
  assert.ok(lock>=0&&temporary>lock&&removal>temporary&&rpc>removal);
  const helper=source.slice(source.indexOf('remove_derived_private() {'),
    source.indexOf('rpc_proxy_ready=',source.indexOf('remove_derived_private() {')));
  assert.match(helper,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(helper,/remove-private-file-durable\.mjs"[\s\S]*> "\$output" 2> "\$error"/);
  assert.match(helper,/bytes\.length>65536[\s\S]*fatal\.decode\(bytes\)/);
  assert.match(helper,/test ! -s "\$output"\n  test ! -s "\$error"\n  test ! -e "\$evidence_directory\/\$name"/);
  for(const name of ['governance-finalized-execution.json','reserveGuardian-finalized-execution.json',
    'checkpointGuardian-finalized-execution.json','safe-recovery-finalized-report.json',
    'safe-recovery-finalized-bundle.json']) assert.ok(source.includes(name));
  for(const retained of ['$raw_file','$hash_file','$envelope_file']) {
    assert.doesNotMatch(source,new RegExp(`remove-private-file-durable\\.mjs[^\\n]*${retained.replace('$','\\$')}`));
  }
});
