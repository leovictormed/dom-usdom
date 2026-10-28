import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const script=fileURLToPath(new URL('../../scripts/sign-release-authorizations.sh',import.meta.url));
test('release authorization bounds every finite Node child',()=>{
  assert.equal(spawnSync('bash',['-n',script]).status,0);
  const source=readFileSync(script,'utf8');
  assert.match(source,/temporary_identity=\$\(stat -c '%u:%d:%i:%a' "\$temporary"\)/);
  assert.match(source,/stat -c '%u:%d:%i:%a' "\$temporary" 2>\/dev\/null\) == "\$temporary_identity"/);
  const helper=source.slice(source.indexOf('run_bounded_node() {'),source.indexOf('run_bounded_walletconnect() {'));
  assert.match(helper,/assert_node_unchanged; assert_timeout_unchanged/);
  assert.match(helper,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$node_bin"/);
  assert.equal((helper.match(/assert_node_unchanged/g)??[]).length,2);
  const walletConnectHelper=source.slice(source.indexOf('run_bounded_walletconnect() {'),source.indexOf('snapshot_private() {'));
  assert.match(walletConnectHelper,/--kill-after=15s 330s "\$node_bin"/);
  assert.equal((walletConnectHelper.match(/assert_node_unchanged/g)??[]).length,2);
  const operational=source.slice(source.indexOf('snapshot_private() {'));
  assert.ok((operational.match(/run_bounded_node/g)??[]).length>=12);
  assert.equal((operational.match(/run_bounded_walletconnect/g)??[]).length,1);
  assert.doesNotMatch(operational,/"\$node_bin"/);
});
