import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const executors=['execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh'];
const signers=[
  'sign-release-authorizations.sh',
  'sign-checkpoint-bootstrap-ratification.sh',
  'sign-recoverable-safe-recovery.sh',
];

function auditOperationalShell(source,{executor=false}={}) {
  const background=source.split('\n').filter(line=>/(?:^|\s)&\s*(?:#.*)?$/.test(line));
  if(executor) {
    assert.equal(background.length,1,'executor must have exactly one background child');
    assert.match(background[0],/>"\$rpc_proxy_stdout" 2>"\$rpc_proxy_stderr" &\s*$/);
    assert.match(source,/setsid_sha256=\$\(sha256_file "\$setsid_bin"\)/);
    assert.match(source,/assert_setsid_unchanged[\s\S]*"\$setsid_bin" \/usr\/bin\/env -i/);
    assert.match(source,/"\$timeout_bin" --signal=TERM --kill-after=2s 24h[\s\\]+"\$node_bin" scripts\/serve-private-rpc-catalog-proxy\.mjs "\$rpc_proxy_ready"/);
    assert.match(source,/rpc_proxy_pid=\$!/);
    assert.match(source,/kill -TERM -- "-\$rpc_proxy_pid"[\s\S]*kill -KILL -- "-\$rpc_proxy_pid"[\s\S]*wait "\$rpc_proxy_pid"/);
    assert.match(source,/if wait "\$rpc_proxy_pid"; then rpc_proxy_status=0; else rpc_proxy_status=\$\?; fi/);
    assert.match(source,/if wait "\$rpc_proxy_pid"; then rpc_proxy_status=0; else rpc_proxy_status=\$\?; fi[\s\S]*stop_rpc_proxy[\s\S]*Private RPC proxy failed before readiness/);
    assert.match(source,/check_rpc_proxy_channels bounded[\s\S]*Private RPC proxy failed before readiness with status %s/);
  } else assert.equal(background.length,0,'signing ceremony must not launch a background child');
  assert.doesNotMatch(source,/\bcoproc\b|&>|2>&1\s*&/);
  assert.doesNotMatch(source,/cat\s+"\$rpc_proxy_(?:stdout|stderr|log)"/);
}

test('mainnet and recovery executors allow only the bounded private RPC proxy child',async()=>{
  for(const name of executors) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    auditOperationalShell(source,{executor:true});
  }
});

test('signing ceremonies contain no background or merged-channel process',async()=>{
  for(const name of signers) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    auditOperationalShell(source);
  }
});

test('inventory rejects untracked, merged, replayed and ambiguously waited children',()=>{
  const safe=`
setsid_sha256=$(sha256_file "$setsid_bin")
assert_setsid_unchanged() { test "$setsid_sha256"; }
assert_setsid_unchanged
"$setsid_bin" /usr/bin/env -i "$timeout_bin" --signal=TERM --kill-after=2s 24h \\
  "$node_bin" scripts/serve-private-rpc-catalog-proxy.mjs "$rpc_proxy_ready" \\
  >"$rpc_proxy_stdout" 2>"$rpc_proxy_stderr" &
rpc_proxy_pid=$!
if wait "$rpc_proxy_pid"; then rpc_proxy_status=0; else rpc_proxy_status=$?; fi
stop_rpc_proxy
check_rpc_proxy_channels bounded
printf 'Private RPC proxy failed before readiness with status %s\\n' "$rpc_proxy_status"
cleanup() { kill -TERM -- "-$rpc_proxy_pid"; kill -KILL -- "-$rpc_proxy_pid"; wait "$rpc_proxy_pid"; }
`;
  assert.doesNotThrow(()=>auditOperationalShell(safe,{executor:true}));
  for(const attack of [
    `${safe}\nmalicious-helper &\n`,
    safe.replace('>"$rpc_proxy_stdout" 2>"$rpc_proxy_stderr" &','>"$rpc_proxy_stdout" 2>&1 &'),
    `${safe}\ncat "$rpc_proxy_stderr"\n`,
    `${safe}\ncoproc hidden { malicious-helper; }\n`,
    safe.replace('kill -TERM -- "-$rpc_proxy_pid"','kill -TERM "$rpc_proxy_pid"'),
    safe.replace('"$setsid_bin" /usr/bin/env -i ','/usr/bin/env -i '),
    safe.replace('--kill-after=2s ',''),
    safe.replace('if wait "$rpc_proxy_pid"; then rpc_proxy_status=0; else rpc_proxy_status=$?; fi','wait "$rpc_proxy_pid" || true'),
  ]) assert.throws(()=>auditOperationalShell(attack,{executor:true}));
});
