import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(
  new URL('../../../../crates/dom-node/src/native_usdom_config.rs', import.meta.url),
  'utf8',
);

test('all hash-pinned startup files are opened nofollow and descriptor-bound', () => {
  assert.match(
    source,
    /open\(\s*path,\s*OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::CLOEXEC,\s*Mode::empty\(\),\s*\)/s,
  );
  assert.match(source, /named\.dev\(\) != opened\.dev\(\)/);
  assert.match(source, /named\.ino\(\) != opened\.ino\(\)/);
  assert.match(source, /opened\.nlink\(\) != 1/);
  assert.match(source, /file\.take\(limit \+ 1\)/);
  assert.doesNotMatch(source, /File::open\(path\)/);
});

test('regression covers symlink and hard-link authority substitution', () => {
  assert.match(source, /fn startup_authority_rejects_symlinked_and_hardlinked_inputs\(\)/);
  assert.match(source, /a symlinked manifest must fail closed/);
  assert.match(source, /a symlinked verifying key must fail closed/);
  assert.match(source, /a multiply-linked verifying key must fail closed/);
});
