import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const executor=new URL('../../scripts/execute-recoverable-safe-recovery.sh',import.meta.url);
test('Safe recovery executor pins tools through relayer consent and every publish',async()=>{
  const source=await readFile(executor,'utf8');
  assert.match(source,/cleanup\(\)[\s\S]*\(\( status != 0 \)\) \|\| status=1[\s\S]*exit "\$status"/);
  assert.doesNotMatch(source,/else\n\s+status=1\n\s+fi\n\s+exit "\$status"/);
  assert.match(source,/safe_broadcast_state=clean[\s\S]*cleanup\(\)[\s\S]*safe_broadcast_state != clean[\s\S]*status=80/);
  assert.match(source,/if \[\[ -e "\$raw_file" \]\]; then safe_broadcast_state=signed-unresolved; fi[\s\S]*if \[\[ ! -e "\$envelope_file" \]\]/);
  assert.match(source,/Safe transaction outcome requires exact-hash and finalized-nonce revalidation; do not sign or publish a replacement\./);
  assert.match(source,/safe_broadcast_state=signed-unresolved[\s\S]*if \[\[ \$seen_any == true \]\]; then safe_broadcast_state=observed; fi/);
  assert.ok(source.indexOf('safe_broadcast_state=publishing\n      "$node_bin" scripts/publish-private-raw-transaction.mjs')<
    source.indexOf('safe_broadcast_state=clean\ndone'));
  assert.match(source,/cast_bin=\$\(realpath "\$\(command -v cast\)"\)/);
  assert.match(source,/cast_sha256=\$\(sha256sum "\$cast_bin"/);
  assert.match(source,/cast_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/node_bin=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/node_sha256=\$\(sha256sum "\$node_bin"/);
  assert.match(source,/node_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/jq_bin=\$\(realpath "\$\(command -v jq\)"\)/);
  assert.match(source,/jq_sha256=\$\(sha256sum "\$jq_bin"/);
  assert.match(source,/jq_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/assert_jq_unchanged/);
  assert.match(source,/assert_node_unchanged/);
  assert.match(source,/for auxiliary_tool in mktemp chmod sleep; do pin_auxiliary_tool "\$auxiliary_tool"; done/);
  for(const tool of ['mktemp','chmod','sleep']) assert.match(source,new RegExp(`declare ${tool}_bin`));
  for(const tool of ['mktemp','chmod','sleep']) assert.match(source,new RegExp(`assert_auxiliary_tool ${tool}`));
  assert.match(source,/temporary=\$\("\$mktemp_bin" -d -p \/dev\/shm usdom-safe-recovery-execute\.XXXXXXXX\)/);
  assert.doesNotMatch(source,/(?:^|\n)\s*(?:mktemp|chmod|sleep)\s/m);
  const confined=source.slice(source.indexOf('export PATH=/usr/bin:/bin'));
  assert.ok(confined.startsWith('export PATH=/usr/bin:/bin'));
  assert.doesNotMatch(confined,/command -v/);
  for(const tool of ['cast','node','jq','cmp','timeout','setsid','flock','mktemp'])
    assert.match(confined,new RegExp(`\\$${tool}_bin`));
  assert.match(source,/run_node_json_authority "\$raw_validation" scripts\/check-recoverable-safe-recovery-raw-transaction/);
  const proxyChannels=source.slice(source.indexOf('check_rpc_proxy_channels() {'),
    source.indexOf('check_rpc_proxy_ready() {'));
  assert.match(proxyChannels,/require_empty == bounded \|\| \$require_empty == empty/);
  assert.match(proxyChannels,/assert_node_unchanged\n  assert_timeout_unchanged/);
  assert.match(proxyChannels,/"\$timeout_bin" --foreground --signal=TERM --kill-after=2s 10s/);
  assert.match(proxyChannels,/\[process\.argv\[1\],65536\],[\s\S]*\[process\.argv\[2\],65536\]/);
  assert.match(proxyChannels,/test ! -s "\$output"\n  test ! -s "\$error"/);
  assert.match(source,/assert_setsid_unchanged\nassert_node_unchanged\nassert_timeout_unchanged\n"\$setsid_bin"/);
  const readiness=source.slice(source.indexOf('check_rpc_proxy_ready() {'),
    source.indexOf('assert_setsid_unchanged',source.indexOf('check_rpc_proxy_ready() {')));
  assert.match(readiness,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(readiness,/bytes\.length>65536[\s\S]*fatal\.decode\(bytes\)/);
  assert.match(readiness,/test -s "\$output"\n  test ! -s "\$error"/);
  assert.match(source,/check_rpc_proxy_ready "\$rpc_ready_observation"/);
  assert.match(source,/check_rpc_proxy_ready "\$temporary\/rpc-ready\.current\.txt" "\$rpc_proxy_ready_sha"[\s\S]*"\$cmp_bin" -s "\$rpc_ready_observation"/);
  assert.doesNotMatch(source,/mapfile -t rpc_ready < <\("\$node_bin" scripts\/check-private-rpc-proxy-ready\.mjs/);
  const emptyAuthority=source.slice(source.indexOf('run_node_empty_authority() {'),
    source.indexOf('run_node_json_authority() {'));
  assert.match(emptyAuthority,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s/);
  assert.match(emptyAuthority,/bytes\.length>65536[\s\S]*fatal\.decode\(bytes\)/);
  assert.match(emptyAuthority,/test ! -s "\$output"\n  test ! -s "\$error"/);
  for(const call of [
    'recovery-plan scripts/check-recoverable-safe-recovery-plan.mjs',
    'recovery-transactions scripts/check-recoverable-safe-recovery-transactions.mjs',
    'recovery-envelope scripts/check-recoverable-safe-recovery-envelope.mjs',
    'strict-json scripts/check-private-strict-json-file.mjs',
  ]) assert.ok(source.includes(`run_node_empty_authority ${call}`),call);
  assert.match(source,/run_node_empty_authority "finalized-\$role" scripts\/check-finalized-safe-recovery-execution\.mjs/);
  assert.doesNotMatch(source,/"\$node_bin" scripts\/check-(?:recoverable-safe-recovery-(?:plan|transactions|envelope)|private-strict-json-file|finalized-safe-recovery-execution)\.mjs/);
  const jqAuthority=source.slice(source.indexOf('run_jq_json_authority() {'),
    source.indexOf('run_node_json_authority() {'));
  assert.match(jqAuthority,/assert_jq_unchanged\n  assert_timeout_unchanged/);
  assert.match(jqAuthority,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(jqAuthority,/\[process\.argv\[1\],2097152\],[\s\S]*\[process\.argv\[2\],65536\]/);
  assert.match(jqAuthority,/test -s "\$output"\n  test ! -s "\$error"/);
  assert.match(jqAuthority,/run_node_empty_authority strict-json scripts\/check-private-strict-json-file\.mjs "\$output"/);
  assert.equal((source.match(/run_jq_json_authority "\$temporary\/\$role-target-consensus(?:\.prepublish)?\.state\.json"/g)??[]).length,2);
  assert.doesNotMatch(source,/"\$jq_bin" -S 'del\(\.finalizedBlockNumber,\.finalizedBlockHash\)'/);
  assert.match(source,/run_jq_json_authority "\$final_summary_file"/);
  assert.equal(source.trimEnd().endsWith(`"$final_consensus"
final_summary=$(<"$final_summary_file")
printf '%s\\n' "$final_summary"`),true);
  assert.doesNotMatch(source,/assert_jq_unchanged\n"\$jq_bin" '\{schema,ethereumChainId/);
  const jqLine=source.slice(source.indexOf('run_jq_line_authority() {'),
    source.indexOf('run_node_json_authority() {'));
  assert.match(jqLine,/\[\[ \$label =~ \^\[A-Za-z0-9\._-\]\+\$ \]\]/);
  assert.match(jqLine,/assert_jq_unchanged\n  assert_timeout_unchanged/);
  assert.match(jqLine,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(jqLine,/bytes\.length>65536[\s\S]*fatal\.decode\(bytes\)/);
  assert.match(jqLine,/test -s "\$output"\n  test ! -s "\$error"\n  read_canonical_line "\$output"/);
  // The final two authorities classify each RPC observation as either absent or
  // exactly the expected transaction hash before deciding whether to publish.
  assert.match(source,/run_jq_line_authority "\$role-seen-\$seen_index-matches"[\s\S]*\. == null or \(\(\.hash\|ascii_downcase\)==\(\$hash\|ascii_downcase\)\)/);
  assert.match(source,/run_jq_line_authority "\$role-seen-\$seen_index-null"[\s\S]*'\. == null'/);
  assert.equal((source.match(/run_jq_line_authority "\$role-/g)??[]).length,13);
  assert.doesNotMatch(source,/=\$\("\$jq_bin" -er/);
  assert.equal((source.match(/"\$jq_bin" "\$@"/g)??[]).length,2);
  assert.doesNotMatch(source,/"\$jq_bin" -e/);
  const jsonAuthority=source.slice(source.indexOf('run_node_json_authority() {'),
    source.indexOf('run_safe_observer() {'));
  assert.match(jsonAuthority,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s/);
  assert.match(jsonAuthority,/\[process\.argv\[1\],2097152\],[\s\S]*\[process\.argv\[2\],65536\]/);
  assert.match(jsonAuthority,/fatal\.decode\(bytes\)/);
  assert.match(jsonAuthority,/test -s "\$output"\n  test ! -s "\$error"/);
  assert.match(jsonAuthority,/run_node_empty_authority strict-json scripts\/check-private-strict-json-file\.mjs "\$output"/);
  const observer=source.slice(source.indexOf('run_safe_observer() {'),
    source.indexOf('assert_private_snapshot_unchanged() {'));
  assert.match(observer,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s/);
  assert.match(observer,/\[process\.argv\[1\],2097152\],[\s\S]*\[process\.argv\[2\],65536\]/);
  assert.match(observer,/fatal\.decode\(bytes\)/);
  assert.match(observer,/status == 0[\s\S]*test -s "\$output"[\s\S]*test ! -s "\$error"/);
  assert.match(observer,/status == 3[\s\S]*USDOM_SAFE_RECOVERY_NOT_FINALIZED/);
  assert.doesNotMatch(source,/(^|[;(]\s*)node scripts/m);
  const rpc=source.slice(source.indexOf('rpc() {'),source.indexOf('snapshot_private() {'));
  assert.match(rpc,/assert_cast_unchanged\n  assert_timeout_unchanged\n  if "\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s/);
  assert.match(rpc,/"\$cast_bin" "\$@" >"\$output_file" 2>"\$error_file"/);
  assert.match(rpc,/\[process\.argv\[1\],2097152\],[\s\S]*\[process\.argv\[2\],65536\]/);
  assert.match(rpc,/fatal\.decode\(bytes\)/);
  assert.match(rpc,/test -s "\$output_file"\n  test ! -s "\$error_file"/);
  assert.match(rpc,/read-private-file-stdout\.mjs" "\$output_file"/);
  assert.match(source,/AUTORIZO USAR RELAYER SWAPOWNER \$role ENVELOPE \$envelope_hash[\s\S]*assert_cast_unchanged/);
  assert.match(source,/assert_cast_unchanged\n      assert_node_unchanged\n      assert_jq_unchanged[\s\S]*publish-private-raw-transaction\.mjs[\s\S]*published=\$\(read_canonical_line/);
  assert.match(source,/AUTORIZO USAR RELAYER SWAPOWNER \$role ENVELOPE \$envelope_hash[\s\S]*assert_jq_unchanged/);
  assert.doesNotMatch(source,/(^|[|;(]\s*)jq\s/m);
  assert.doesNotMatch(source,/"\$cast_bin" wallet address|--ledger|wallet sign/i);
  assert.doesNotMatch(source,/(^|[;(]\s*)cast wallet/m);
  const persistence=source.slice(source.indexOf('persist_private_new() {'),
    source.indexOf('persist_private_create_once_or_identical() {'));
  assert.match(persistence,/assert_node_unchanged\n  assert_timeout_unchanged\n  if "\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(persistence,/install-private-file-new-stdin\.mjs" "\$destination"[\s\S]*> "\$output" 2> "\$error"/);
  assert.match(persistence,/bytes\.length>65536[\s\S]*fatal\.decode\(bytes\)/);
  assert.match(persistence,/test ! -s "\$output"\n  test ! -s "\$error"/);
  assert.match(persistence,/snapshot_private "\$destination" "\$installed"\n  assert_cmp_unchanged; "\$cmp_bin" -s "\$source" "\$installed"/);
  assert.doesNotMatch(persistence,/"\$node_bin" "\$project\/scripts\/install-private-file-new-stdin\.mjs" "\$destination" < "\$source"\n/);
});

test('Safe recovery binds durable evidence and publication to the locked parent',async()=>{
  const source=await readFile(executor,'utf8');
  assert.match(source,/realpath -e \/proc\/\$\$\/fd\/9/);
  assert.match(source,/evidence_parent_identity=\$\(stat -Lc '%d:%i:%u:%a' -- \/proc\/\$\$\/fd\/9\)/);
  assert.match(source,/assert_evidence_parent\(\)[\s\S]*realpath -e "\$evidence_directory"[\s\S]*stat -Lc '%d:%i:%u:%a' -- \/proc\/\$\$\/fd\/9/);
  assert.ok((source.match(/assert_evidence_parent/g)??[]).length>=7);
  assert.ok(source.indexOf('assert_evidence_parent\n      safe_broadcast_state=publishing')<
    source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"'));
});
