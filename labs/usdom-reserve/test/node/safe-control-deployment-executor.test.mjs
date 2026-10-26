import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source=readFileSync(new URL('../../scripts/execute-safe-control-deployment.sh',import.meta.url),'utf8');

test('Safe deployment executor uses private RPC quorum and exact target barriers',()=>{
  assert.match(source,/serve-private-rpc-catalog-proxy\.mjs/);
  assert.match(source,/"\$setsid_bin" \/usr\/bin\/env -i/);
  assert.match(source,/kill -0 -- "-\$rpc_proxy_pid"/);
  assert.match(source,/exec 9<"\$control_dir"[\s\S]*assert_runtime_tool flock[\s\S]*"\$flock_bin" -n 9/);
  assert.ok(source.indexOf('"$flock_bin" -n 9')<source.indexOf('wallet address --ledger'));
  assert.match(source,/run_node\(\)\{ assert_runtime_tool node;/);
  assert.match(source,/run_jq\(\)\{ assert_runtime_tool jq;/);
  assert.match(source,/run_cmp\(\)\{ assert_runtime_tool cmp;/);
  for(const tool of ['node','jq','cmp']) {
    const direct=(source.match(new RegExp(`"\\$${tool}_bin"`,'g'))??[]).length;
    assert.equal(direct,tool==='node'?3:1);
  }
  assert.match(source,/check-private-rpc-proxy-ready\.mjs/);
  assert.match(source,/rpc_urls=\("\$\{ready_lines\[@\]:1\}"\)/);
  assert.match(source,/check-safe-control-deployment-target\.mjs "\$role"/);
  assert.match(source,/check-safe-owner-hardware-custody-proofs\.mjs/);
  assert.match(source,/assert_package_rebuild\(\).*prepare-recoverable-safe-controls\.mjs/);
  assert.ok((source.match(/assert_package_rebuild/g)??[]).length>=4);
  assert.match(source,/for endpoint in "\$\{rpc_urls\[@\]\}"; do test "\$\(rpc nonce/);
  assert.doesNotMatch(source,/https:\/\//);
  assert.doesNotMatch(source,/cast send|"\$cast_bin" publish/);
});

test('Safe deployment raw transaction is journaled before split files and publication',()=>{
  const journal=source.indexOf('install-private-file-new-stdin.mjs --json "$journal"');
  const raw=source.indexOf('install-private-file-new-stdin.mjs "$raw"');
  const publish=source.indexOf('rpc publish "$raw_line"');
  assert.ok(journal>=0&&raw>journal&&publish>raw);
  assert.match(source,/usdom-safe-deployment-journal\/v1/);
  assert.match(source,/run_cmp -s "\$source_file"/);
  assert.match(source,/check-safe-control-deployment-raw-transaction\.mjs "\$role" "\$nonce"/);
  assert.match(source,/strict_json "\$seen_file"/);
  assert.match(source,/\.==null or \(\(\.hash\|ascii_downcase\)==\(\$hash\|ascii_downcase\)\)/);
  assert.match(source,/check-safe-control-deployment-receipt\.mjs "\$role"/);
  assert.match(source,/canonical_hash=\$\(rpc block "\$receipt_block" --field hash/);
  assert.match(source,/finalized_number=\$\(rpc block finalized --field number/);
  assert.match(source,/run_cmp -s "\$receipt_consensus" "\$receipt_checked"/);
  assert.match(source,/\[\[ -z \$receipt_existing \]\] \|\| run_cmp -s "\$receipt_existing" "\$receipt_checked"/);
  assert.match(source,/if \[\[ \$state == deployed && \$signed_deployment == false \]\]; then[\s\S]*permissionlessly[\s\S]*continue; fi/);
  assert.match(source,/if \[\[ \$state == deployed \]\]; then printf[\s\S]*revalidating its durable transaction and receipt/);
  assert.ok(source.indexOf('current_validation="$temporary/$role-validation.current.json"')<source.indexOf('if [[ $state == deployed'));
  const finalMessage=source.indexOf("All three recoverable Safes are finalized");
  const finalLoop=source.lastIndexOf('for role in governance reserveGuardian checkpointGuardian; do test');
  assert.ok(finalLoop>0&&finalMessage>finalLoop);
  assert.match(source.slice(finalLoop,finalMessage),/assert_inputs[\s\S]*assert_package_rebuild/);
  assert.match(source.slice(source.lastIndexOf('assert_inputs',finalLoop),finalLoop),/assert_inputs[\s\S]*assert_package_rebuild/);
});

test('Safe deployment ceremony bounds Ledger operations and sanitizes credentials',()=>{
  assert.match(source,/unset LD_PRELOAD[\s\S]+HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY/);
  assert.match(source,/export PATH=\/usr\/lib\/chatgpt\/resources\/cua_node\/bin:[^\n]+:\/bin/);
  assert.doesNotMatch(source,/export PATH=.*\$PATH/);
  assert.match(source,/export LANG=C LC_ALL=C TZ=UTC/);
  assert.match(source,/os\.userInfo\(\)\.homedir/);
  assert.match(source,/\$\{HOME:-\} == "\$account_home"/);
  assert.match(source,/8#\$home_mode & 8#022/);
  assert.match(source,/ulimit -c 0/);
  assert.match(source,/wallet address --ledger/);
  assert.match(source,/--foreground --signal=TERM --kill-after=5s 300s "\$cast_bin" wallet address --ledger/);
  assert.match(source,/--foreground --signal=TERM --kill-after=5s 300s "\$cast_bin" mktx/);
  assert.match(source,/AUTORIZO TRES SAFES 2-DE-3 MAINNET/);
  assert.match(source,/AUTORIZO TRANSMITIR SAFE/);
  assert.match(source,/\[\[n,\(1n<<53n\)-1n\],\[e,1000000n\],\[b,100000000000n\]\]/);
  assert.match(source,/g=e\+e\/4n\+1n;if\(g===0n\|\|g>1000000n\)process\.exit\(1\)/);
  assert.doesNotMatch(source,/gas_limit=\$\(\(estimate/);
});
