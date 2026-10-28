import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {parseSafeControlReleaseArtifactBytes}
  from '../../scripts/safe-control-release-artifacts.mjs';

test('Safe control release artifacts reject ambiguous JSON bytes',()=>{
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseSafeControlReleaseArtifactBytes(bytes,'Safe artifact'),
    /duplicate (?:object )?key|invalid UTF-8/);
});

test('Safe control release authority uses byte-strict JSON parsing',async()=>{
  const source=await readFile(new URL('../../scripts/safe-control-release-artifacts.mjs',
    import.meta.url),'utf8');
  assert.match(source,/parseStrictJsonBytes\(bytes/);
  assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);
  assert.equal((source.match(/Object\.entries\(SAFE_CONTROL_EVIDENCE_PATHS\)/g)??[]).length,2);
  assert.match(source,/Safe control release artifacts changed during materialization/);
});

test('Safe release materializers rebuild before publish and verify installed bytes',async()=>{
  for(const [file,prepare] of [
    ['../../scripts/materialize-safe-control-release-config.sh',
      'prepare-safe-control-release-config-materialization.mjs'],
    ['../../scripts/materialize-safe-control-release-metadata.sh',
      'prepare-safe-control-release-metadata-materialization.mjs'],
  ]) {
    const materializer=await readFile(new URL(file,import.meta.url),'utf8');
    assert.equal((materializer.match(new RegExp(prepare.replaceAll('.','\\.'),'g'))??[]).length,2);
    const install=materializer.indexOf('replace-locked-source-stdin.mjs');
    const compare=materializer.indexOf('cmp -s "$prepared" "$rechecked"');
    assert.ok(compare>=0&&install>compare);
    assert.ok(materializer.indexOf('read-release-config-file-stdout.mjs',install)>install);
  }
});

test('Safe control configuration is reread after its directory is durable',async()=>{
  const source=await readFile(new URL(
    '../../scripts/materialize-safe-control-release-config.sh',import.meta.url),'utf8');
  const sync=source.lastIndexOf('sync -f "$config_directory"');
  const readback=source.indexOf(
    'snapshot_public "$target" "$temporary/installed.durable.json"',sync);
  const compare=source.indexOf(
    'cmp -s "$prepared" "$temporary/installed.durable.json"',readback);
  assert.ok(sync>=0&&readback>sync&&compare>readback);
  const definition=source.indexOf('snapshot_public() {');
  assert.ok(definition>=0&&definition<readback,'snapshot_public must be defined before durable readback');
  assert.match(source,/snapshot_public\(\) \{[\s\S]*read-release-config-file-stdout\.mjs[\s\S]*chmod 0600/);
  assert.match(source,/replace-locked-source-stdin\.mjs/);
  assert.match(source,/"\$target_sha256"\s+"\$parent_device" "\$parent_inode"\s+\\?\s*"\$python3_bin" "\$python3_sha256"/);
  assert.match(source,/pin_tool python3/);
});

test('Safe control metadata is reread after its directory is durable',async()=>{
  const source=await readFile(new URL(
    '../../scripts/materialize-safe-control-release-metadata.sh',import.meta.url),'utf8');
  const sync=source.lastIndexOf('sync -f "$config_directory"');
  const readback=source.indexOf('installed.durable.json',sync);
  const compare=source.indexOf(
    'cmp -s "$prepared" "$temporary/installed.durable.json"',readback);
  assert.ok(sync>=0&&readback>sync&&compare>readback);
  assert.match(source,/replace-locked-source-stdin\.mjs/);
  assert.match(source,/"\$target_sha256"\s+"\$parent_device" "\$parent_inode"\s+\\?\s*"\$python3_bin" "\$python3_sha256"/);
  assert.match(source,/pin_tool python3/);
});
