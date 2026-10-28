import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const names=`build-finalized-deposit-witness.sh
execute-mainnet-deployment.sh
execute-recoverable-safe-recovery.sh
execute-safe-control-deployment.sh
materialize-limited-mainnet-policy.sh
materialize-mainnet-deployment-identity.sh
materialize-native-preactivation-facts.sh
materialize-native-release-attestations.sh
materialize-production-preactivation-core.sh
materialize-production-release-core.sh
materialize-production-solidity-pins.sh
materialize-release-authorization.sh
materialize-safe-control-release-config.sh
materialize-safe-control-release-metadata.sh
sign-checkpoint-bootstrap-ratification.sh
sign-recoverable-safe-recovery.sh
sign-release-authorizations.sh`.split('\n');

test('reported rmSync cleanup inventory has zero unbounded or unreattested children',()=>{
  for(const name of names){
    const path=fileURLToPath(new URL(`../../scripts/${name}`,import.meta.url));
    assert.equal(spawnSync('bash',['-n',path]).status,0,name);
    const source=readFileSync(path,'utf8');
    const start=Math.max(source.indexOf('cleanup() {'),source.indexOf('cleanup(){'));
    const end=source.indexOf("trap 'cleanup $?",start);
    const cleanup=source.slice(start,end);
    const removal=cleanup.indexOf('rmSync(process.argv[1],{recursive:true,force:true})');
    assert.ok(start>=0&&end>start&&removal>=0,name);
    assert.match(cleanup,/--signal=TERM --kill-after=5s 30s/,name);
    assert.match(cleanup,/> \/dev\/null 2> \/dev\/null/,name);
    assert.match(cleanup,/test ! -e "\$(?:temporary|TEMPORARY|SNAPSHOT_DIRECTORY|temporary_facts)"/,name);
    const before=cleanup.slice(0,removal);
    const after=cleanup.slice(removal);
    assert.match(before,/(?:assert_node_unchanged|assert_runtime_tool node|assert_tool_unchanged node)/,name);
    assert.match(before,/(?:assert_timeout_unchanged|assert_runtime_tool timeout|assert_tool_unchanged timeout|run_pinned_timeout)/,name);
    assert.match(after,/(?:assert_node_unchanged|assert_runtime_tool node|assert_tool_unchanged node)/,name);
    assert.match(after,/(?:assert_timeout_unchanged|assert_runtime_tool timeout|assert_tool_unchanged timeout)/,name);
    assert.match(cleanup,/else\n(?:\s+#.*\n)*\s+(?:status=1|\(\( status != 0 \)\) \|\| status=1)/,name);
  }
});
