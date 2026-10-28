import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '../..');
const helper = path.join(root, 'scripts/canonical-uint256.mjs');
const run = (...args) => spawnSync(process.execPath, [helper, ...args], {cwd: root, encoding: 'utf8'});

test('on-chain successor and ordering stay exact across the uint256 boundary', () => {
  const aboveIeee = (1n << 53n) + 1n;
  const maximum = (1n << 256n) - 1n;
  assert.equal(run('add1', aboveIeee.toString()).stdout.trim(), (aboveIeee + 1n).toString());
  assert.equal(run('ge', maximum.toString(), aboveIeee.toString()).stdout.trim(), 'true');
  assert.notEqual(run('add1', maximum.toString()).status, 0);
});

test('production gates and preactivation avoid lossy on-chain arithmetic', () => {
  const gate = readFileSync(path.join(root, 'scripts/execute-pilot-deposit-gate.sh'), 'utf8');
  const cancel = readFileSync(path.join(root, 'scripts/execute-pilot-deposit-gate-cancel.sh'), 'utf8');
  const clear = readFileSync(path.join(root, 'scripts/execute-expired-pilot-gate-clear.sh'), 'utf8');
  const facts = readFileSync(path.join(root, 'scripts/materialize-native-preactivation-facts.sh'), 'utf8');
  assert.doesNotMatch(gate, /test "\$\(cast block finalized[^\n]+" -ge|\$\(\( \$\(jq -er \.generation/);
  assert.match(gate, /canonical-uint256\.mjs add1/);
  assert.match(gate, /canonical-uint256\.mjs ge/);
  assert.doesNotMatch(clear, /test "\$\(cast block finalized[^\n]+" -ge/);
  assert.match(clear, /canonical-uint256\.mjs ge/);
  assert.doesNotMatch(cancel, /test "\$\(cast block finalized[^\n]+" -ge/);
  assert.match(cancel, /canonical-uint256\.mjs ge/);
  assert.doesNotMatch(facts, /tonumber/);
  assert.match(facts, /canonical-uint256\.mjs add1/);
});
