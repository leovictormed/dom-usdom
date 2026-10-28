import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const script=fileURLToPath(new URL('../../scripts/run-closed-mainnet-node.sh',import.meta.url));

test('closed-mainnet launcher bounds setup children and leaves only the supervised node long-lived',()=>{
  assert.equal(spawnSync('bash',['-n',script]).status,0);
  const source=readFileSync(script,'utf8');
  assert.match(source,/timeout --signal=TERM --kill-after=2s 30s \\\n+  python3 - "\$NODE_ROOT" "\$DATA_ROOT"/);
  assert.match(source,/run_pinned_timeout --signal=TERM --kill-after=30s 3600s \\\n+[\s\S]*"\$cargo_bin" build --quiet --release --frozen --no-default-features -p dom-node \\\n+    --features native-usdom-v4-poc --bin dom-node/);
  assert.match(source,/exec "\$NODE_BINARY"\s*$/);
  assert.doesNotMatch(source,/^python3 - "\$NODE_ROOT" "\$DATA_ROOT"/m);
  assert.doesNotMatch(source,/^cargo build /m);
  assert.doesNotMatch(source,/\s&\s*(?:#.*)?$/m);
});
