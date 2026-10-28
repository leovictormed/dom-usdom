import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '../..');
const executors = [
  'execute-pilot-deposit-gate.sh','execute-pilot-deposit-gate-cancel.sh',
  'execute-expired-pilot-gate-clear.sh','execute-closed-mainnet-deposit.sh',
  'execute-closed-mainnet-redemption.sh',
];

test('transaction value accepts only the canonical zero quantity', () => {
  const expression = '.value=="0x0"';
  for (const [value,accepted] of [['0x0',true],['0x00',false],['0x000',false],['0X0',false],['0x',false]]) {
    const result = spawnSync('jq', ['-e', expression], {input: `${JSON.stringify({value})}\n`, encoding:'utf8'});
    assert.equal(result.status === 0, accepted, value);
  }
});

test('operational transaction observations reject leading-zero quantities', () => {
  for (const name of executors) {
    const source = readFileSync(path.join(root, 'scripts', name), 'utf8');
    assert.doesNotMatch(source, /\.value=="0x00"/);
    assert.match(source, /\.value=="0x0"/);
  }
});
