import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const executor=new URL('../../scripts/execute-recoverable-safe-recovery.sh',import.meta.url);
test('Safe recovery executor pins cast through TTY consent and every publish',async()=>{
  const source=await readFile(executor,'utf8');
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
  assert.match(source,/run_node_json_authority "\$raw_validation" scripts\/check-recoverable-safe-recovery-raw-transaction/);
  assert.doesNotMatch(source,/(^|[;(]\s*)node scripts/m);
  assert.match(source,/assert_timeout_unchanged[\s\S]*"\$timeout_bin" --signal=TERM 120s "\$cast_bin"/);
  assert.match(source,/AUTORIZO TRES SWAPOWNER SAFE MAINNET[\s\S]*assert_cast_unchanged/);
  assert.match(source,/assert_cast_unchanged\n      assert_node_unchanged\n      assert_jq_unchanged[\s\S]*rpc publish[\s\S]*published=\$\(read_canonical_line/);
  assert.match(source,/AUTORIZO TRES SWAPOWNER SAFE MAINNET[\s\S]*assert_jq_unchanged/);
  assert.doesNotMatch(source,/(^|[|;(]\s*)jq\s/m);
  assert.match(source,/"\$cast_bin" wallet address/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cast wallet/m);
  assert.match(source,/persist_private_new\(\)[\s\S]*assert_node_unchanged[\s\S]*snapshot_private "\$destination" "\$installed"[\s\S]*\.equals\(fs\.readFileSync/);
});
