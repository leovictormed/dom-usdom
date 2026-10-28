import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const names=[
  'materialize-limited-mainnet-policy.sh',
  'materialize-native-preactivation-facts.sh',
  'materialize-native-release-attestations.sh',
  'materialize-production-preactivation-core.sh',
  'materialize-production-release-core.sh',
  'materialize-production-solidity-pins.sh',
  'materialize-release-authorization.sh',
  'materialize-safe-control-release-config.sh',
  'materialize-safe-control-release-metadata.sh',
];

test('legacy materializer recursive cleanups are authenticated, bounded and fail closed',()=>{
  for(const name of names){
    const path=fileURLToPath(new URL(`../../scripts/${name}`,import.meta.url));
    assert.equal(spawnSync('bash',['-n',path]).status,0,name);
    const source=readFileSync(path,'utf8');
    const cleanup=source.slice(source.indexOf('cleanup() {'),source.indexOf("trap 'cleanup $?' EXIT"));
    assert.match(source,/pin_tool node; pin_tool jq; pin_tool timeout/,name);
    assert.match(cleanup,/assert_tool_unchanged node && assert_tool_unchanged timeout &&[\s\S]*"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/,name);
    assert.equal((cleanup.match(/assert_tool_unchanged node/g)??[]).length,2,name);
    assert.equal((cleanup.match(/assert_tool_unchanged timeout/g)??[]).length,2,name);
    assert.match(cleanup,/> \/dev\/null 2> \/dev\/null/,name);
    assert.match(cleanup,/test ! -e "\$(?:temporary|temporary_facts)"[\s\S]*else\n    status=1/,name);
  }
});
