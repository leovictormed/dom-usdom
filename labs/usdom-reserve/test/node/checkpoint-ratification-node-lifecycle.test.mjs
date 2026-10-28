import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const script=fileURLToPath(new URL('../../scripts/sign-checkpoint-bootstrap-ratification.sh',import.meta.url));

test('checkpoint ratification bounds every finite Node child',()=>{
  assert.equal(spawnSync('bash',['-n',script],{encoding:'utf8'}).status,0);
  const source=readFileSync(script,'utf8');
  const helper=source.slice(source.indexOf('run_bounded_node() {'),source.indexOf('snapshot() {'));
  assert.match(helper,/assert_node_unchanged; assert_timeout_unchanged/);
  assert.match(helper,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$node_bin"/);
  assert.ok((helper.match(/assert_node_unchanged/g)??[]).length>=4);
  const operational=source.slice(source.indexOf('snapshot() {'));
  assert.ok((operational.match(/run_bounded_node/g)??[]).length>=12);
  assert.match(operational,/run_bounded_walletconnect/);
  assert.doesNotMatch(operational,/"\$node_bin"/);
});
