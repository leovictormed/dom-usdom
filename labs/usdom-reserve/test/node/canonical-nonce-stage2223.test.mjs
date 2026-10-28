import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '../..');
const helper = path.join(root, 'scripts/canonical-uint256.mjs');
const run = (...args) => spawnSync(process.execPath, [helper, ...args], {cwd: root, encoding: 'utf8'});

test('nonce normalization preserves the full uint256 domain', () => {
  const aboveIeee = (1n << 53n) + 1n;
  const maximum = (1n << 256n) - 1n;
  for (const value of [aboveIeee, maximum]) {
    assert.equal(run('normalize', value.toString()).stdout.trim(), value.toString());
    assert.equal(run('normalize', `0x${value.toString(16)}`).stdout.trim(), value.toString());
  }
  assert.notEqual(run('normalize', (1n << 256n).toString()).status, 0);
  assert.notEqual(run('normalize', `0x1${'0'.repeat(64)}`).status, 0);
});

test('gate executors compare nonces without jq number coercion', () => {
  for (const name of [
    'execute-pilot-deposit-gate.sh',
    'execute-pilot-deposit-gate-cancel.sh',
    'execute-expired-pilot-gate-clear.sh',
  ]) {
    const source = readFileSync(path.join(root, 'scripts', name), 'utf8');
    assert.doesNotMatch(source, /\.nonce\|tonumber/);
    assert.match(source, /canonical-uint256\.mjs normalize "\$\(jq -er \.nonce/);
  }
});
