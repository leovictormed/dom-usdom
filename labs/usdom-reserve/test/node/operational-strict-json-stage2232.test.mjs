import assert from 'node:assert/strict';
import {chmodSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '../..');
const checker = path.join(root, 'scripts/check-private-strict-json-file.mjs');

test('private authority parser rejects duplicate keys and trailing JSON', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'usdom-strict-json-'));
  try {
    for (const [contents, accepted] of [
      ['{"schema":"v1","value":"a"}\n', true],
      ['{"schema":"v1","value":"a","value":"b"}\n', false],
      ['{"schema":"v1"}\n{"schema":"v2"}\n', false],
    ]) {
      const file = path.join(directory, 'authority.json');
      writeFileSync(file, contents, {mode: 0o600}); chmodSync(file, 0o600);
      const result = spawnSync(process.execPath, [checker, file], {cwd: root, encoding: 'utf8'});
      assert.equal(result.status === 0, accepted);
    }
  } finally { rmSync(directory, {recursive: true, force: true}); }
});

test('gate executors validate durable JSON before jq consumption', () => {
  for (const name of [
    'execute-pilot-deposit-gate.sh',
    'execute-pilot-deposit-gate-cancel.sh',
    'execute-expired-pilot-gate-clear.sh',
  ]) {
    const source = readFileSync(path.join(root, 'scripts', name), 'utf8');
    assert.match(source, /check-private-strict-json-file\.mjs/);
  }
});
