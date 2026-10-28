import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../../../..', import.meta.url));
const roots = [
  'crates/dom-usdom-state/src',
  'crates/dom-usdom-privacy/src',
  'crates/dom-usdom-prover/src',
  'crates/dom-usdom-wallet/src',
  'crates/dom-usdom-checkpoint-program/src',
  'crates/dom-usdom-finalized-burn-program/src',
  'labs/usdom-ethereum-finality/src',
];

async function rustFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return rustFiles(absolute);
    return entry.isFile() && entry.name.endsWith('.rs') ? [absolute] : [];
  }));
  return nested.flat();
}

test('native USDOM and Ethereum-finality production sources contain no unsafe Rust or C FFI', async () => {
  const files = (await Promise.all(roots.map((root) => rustFiles(path.join(repository, root))))).flat();
  assert.ok(files.length > 20, 'audit scope unexpectedly empty');
  const violations = [];
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    if (/\bunsafe\s+(?:fn|impl|trait|extern)|\bunsafe\s*\{|extern\s+"C"/.test(source)) {
      violations.push(path.relative(repository, file));
    }
  }
  assert.deepEqual(violations, []);
});

test('debug-only fixture oracles remain impossible in optimized builds', async () => {
  for (const file of [
    'crates/dom-usdom-state/src/lib.rs',
    'labs/usdom-ethereum-finality/src/lib.rs',
  ]) {
    const source = await readFile(path.join(repository, file), 'utf8');
    assert.match(source, /#\[cfg\(all\(feature = "unsafe-test-oracle", not\(debug_assertions\)\)\)\]\s*compile_error!/s);
  }
});

test('checkpoint witness authenticates directory ownership through safe rustix API', async () => {
  const source = await readFile(
    path.join(repository, 'labs/usdom-ethereum-finality/src/bin/usdom-build-checkpoint-witness.rs'),
    'utf8',
  );
  const manifest = await readFile(
    path.join(repository, 'labs/usdom-ethereum-finality/Cargo.toml'),
    'utf8',
  );
  assert.match(source, /parent_metadata\.uid\(\) == rustix::process::geteuid\(\)\.as_raw\(\)/);
  assert.doesNotMatch(source, /libc::geteuid|\bunsafe\s*\{/);
  assert.match(manifest, /^rustix = \{ version = "=1\.1\.4", default-features = false, features = \["process", "std"\] \}$/m);
  assert.doesNotMatch(manifest, /^libc\s*=/m);
});
