import assert from 'node:assert/strict';
import {chmodSync,linkSync,mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '../..');
const checker = path.join(root, 'scripts/check-direct-strict-json-file.mjs');

test('direct authority parser accepts safe modes and rejects parser differentials', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'usdom-direct-json-'));
  try {
    const file = path.join(directory, 'authority.json');
    for (const mode of [0o600, 0o644]) {
      writeFileSync(file, '{"schema":"v1","value":"a"}\n', {mode}); chmodSync(file, mode);
      assert.equal(spawnSync(process.execPath, [checker, file], {cwd: root}).status, 0);
      const captured=spawnSync(process.execPath, [checker,'--stdout',file], {cwd: root});
      assert.equal(captured.status,0); assert.equal(captured.stdout.toString(),readFileSync(file,'utf8'));
    }
    for (const contents of [
      '{"schema":"v1","value":"a","value":"b"}\n',
      '{"schema":"v1"}\n{"schema":"v2"}\n',
    ]) {
      writeFileSync(file, contents, {mode: 0o600}); chmodSync(file, 0o600);
      assert.notEqual(spawnSync(process.execPath, [checker, file], {cwd: root}).status, 0);
    }
    writeFileSync(file, '{"schema":"v1"}\n', {mode:0o600}); chmodSync(file,0o600);
    const hardlink=path.join(directory,'hardlink.json'); linkSync(file,hardlink);
    assert.notEqual(spawnSync(process.execPath,[checker,file],{cwd:root}).status,0);
    rmSync(hardlink);
    const target=path.join(directory,'target.json'),symlink=path.join(directory,'symlink.json');
    writeFileSync(target,'{"schema":"v1"}\n',{mode:0o600}); symlinkSync(target,symlink);
    assert.notEqual(spawnSync(process.execPath,[checker,symlink],{cwd:root}).status,0);
  } finally { rmSync(directory, {recursive: true, force: true}); }
});

test('reserve resume validates every configuration authority before jq', () => {
  const source = readFileSync(path.join(root, 'scripts/execute-reserve-resume.sh'), 'utf8');
  const boundary = source.indexOf('reserve=$(jq -er');
  assert.ok(boundary > 0);
  const prefix = source.slice(0, boundary);
  for (const authority of [
    '$USDOM_MAINNET_DEPLOYMENT_PACKAGE',
    '$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE',
    '$USDOM_SAFE_PACKAGE',
    '$PWD/config/proof-reserve.unconfigured.json',
  ]) assert.ok(prefix.includes(authority));
  assert.match(prefix, /check-direct-strict-json-file\.mjs/);
});
