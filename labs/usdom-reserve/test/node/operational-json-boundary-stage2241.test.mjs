import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '../..');

test('gate configuration authorities are strict before their first jq read', () => {
  const cases = new Map([
    ['execute-pilot-deposit-gate.sh', [
      '$snapshot','$state','$release','$USDOM_SAFE_PACKAGE','$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE',
    ]],
    ['execute-pilot-deposit-gate-cancel.sh', ['$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE']],
    ['execute-expired-pilot-gate-clear.sh', ['$release','$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE']],
  ]);
  for (const [name, authorities] of cases) {
    const source = readFileSync(path.join(root, 'scripts', name), 'utf8');
    const firstRead = source.indexOf('test "$(jq -er \'length\' "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE")"');
    assert.ok(firstRead > 0, `${name} first authority read is missing`);
    const prefix = source.slice(0, firstRead);
    assert.match(prefix, /check-direct-strict-json-file\.mjs/);
    for (const authority of authorities) assert.ok(prefix.includes(authority), `${name} misses ${authority}`);
  }
});

test('remaining operational families expose a strict JSON boundary', () => {
  for (const name of [
    'execute-mainnet-deployment.sh','execute-safe-control-deployment.sh',
    'execute-recoverable-safe-recovery.sh','execute-closed-mainnet-deposit.sh',
    'execute-closed-mainnet-redemption.sh','execute-reserve-resume.sh',
  ]) {
    const source = readFileSync(path.join(root, 'scripts', name), 'utf8');
    assert.match(source, /check-(?:private|direct)-strict-json-file\.mjs/, name);
  }
});
