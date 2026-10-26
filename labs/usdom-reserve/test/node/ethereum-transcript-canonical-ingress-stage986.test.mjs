import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(
  new URL('../../../usdom-ethereum-finality/src/lib.rs', import.meta.url),
  'utf8',
);

test('Ethereum transcript canonicality is enforced before cryptographic replay', () => {
  const restore = source.slice(
    source.indexOf('pub fn restore_transcript_bounded('),
    source.indexOf('pub(crate) fn finalized_execution('),
  );
  const decodeAt = restore.indexOf('decode_canonical_transcript(bytes)?');
  const bootstrapAt = restore.indexOf('Self::bootstrap(');
  const acceptAt = restore.indexOf('client.accept(');
  assert.ok(decodeAt >= 0, 'bounded restore must decode canonically');
  assert.ok(bootstrapAt > decodeAt, 'canonical check must precede bootstrap verification');
  assert.ok(acceptAt > decodeAt, 'canonical check must precede update verification');
});

test('canonical decoder round-trips exact bytes and replay-slot parser uses it', () => {
  const decoder = source.slice(
    source.indexOf('fn decode_canonical_transcript('),
    source.indexOf('/// Compatibility alias'),
  );
  assert.match(decoder, /serde_json::from_slice\(bytes\)/);
  assert.match(decoder, /serde_json::to_vec\(&transcript\)/);
  assert.match(decoder, /canonical\.as_slice\(\) == bytes/);

  const replay = source.slice(
    source.indexOf('pub(crate) fn canonical_transcript_replay_slot('),
    source.indexOf('fn decode_canonical_transcript('),
  );
  assert.match(replay, /decode_canonical_transcript\(bytes\)\?/);
});

test('production transcript restoration always requires an external slot ceiling', () => {
  assert.doesNotMatch(source, /pub fn restore_transcript\s*\(/);
  assert.match(
    source,
    /pub fn restore_transcript_bounded\s*\([\s\S]*?max_current_slot: u64/,
  );
});
