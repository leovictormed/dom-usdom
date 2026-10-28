import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const cases=[
 ['finalized-burn evidence','../../scripts/materialize-finalized-burn-release-evidence.mjs',
  'immutableWrite(FINALIZED_BURN_E2E_EVIDENCE_PATH','compareAndSwapEvidence(evidencePath',
  /installed finalized-burn release generation differs from prepared bytes/],
 ['checkpoint capacity evidence','../../scripts/materialize-checkpoint-capacity-release-evidence.mjs',
  'immutableWrite(CHECKPOINT_CAPACITY_EVIDENCE_PATH','compareAndSwapEvidence(evidencePath',
  /installed checkpoint capacity release generation differs from prepared bytes/],
 ['RISC Zero health catalog','../../scripts/materialize-risc0-health-source-catalog.mjs',
  'immutableWrite(RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH','compareAndSwapEvidence(metadataPath',
  /installed RISC Zero health generation differs from prepared bytes/],
 ['deployment identity','../../scripts/materialize-mainnet-deployment-identity.sh',
  'install-private-file-immutable-stdin.mjs --json "$observation_target"',
  'replace-locked-source-stdin.mjs "$target"',/observation\.final\.json/],
 ['native attestations','../../scripts/materialize-native-release-attestations.sh',
  'publish_and_verify_immutable "$temporary/native-attestation-finalized-observation.json"',
  'replace-locked-source-stdin.mjs" "$metadata"',/successful return proves one coherent five-document generation/],
 ['release authorization','../../scripts/materialize-release-authorization.sh',
  'publish_immutable "$observation"',
  'replace-locked-private-stdin.mjs" "$intent_target"',/release-authorization-finalized-observation\.final\.json/],
 ['release provenance','../../scripts/materialize-release-provenance.sh',
  'replace-locked-source-stdin.mjs" "$evidence_target"',
  'replace-locked-private-stdin.mjs" "$intent_target"',/read_current_targets/],
];

test('release multi-file materializers publish immutable precursors before aggregate completion',async()=>{
 assert.equal(cases.length,7,'update inventory for every new multi-file release materializer');
 for(const [name,file,precursor,completion,readback] of cases) {
  const source=await readFile(new URL(file,import.meta.url),'utf8');
  const first=source.lastIndexOf(precursor),last=source.lastIndexOf(completion);
  assert.ok(first>=0,`${name}: precursor publication missing`);
  assert.ok(last>first,`${name}: aggregate completion must be published last`);
  assert.match(source,readback,`${name}: retry/readback evidence missing`);
 }
});

test('checkpoint capacity success is emitted only after snapshot cleanup completes',async()=>{
 const source=await readFile(new URL(
  '../../scripts/materialize-checkpoint-capacity-release-evidence.mjs',import.meta.url),'utf8');
 const cleanup=source.indexOf('await latest.snapshot.cleanup()');
 const success=source.indexOf('console.log(JSON.stringify(successRecord');
 assert.ok(cleanup>=0&&success>cleanup);
 assert.doesNotMatch(source,/console\.log\(JSON\.stringify\(\{ok:true/);
});

test('RISC Zero health success is emitted only after snapshot cleanup completes',async()=>{
 const source=await readFile(new URL(
  '../../scripts/materialize-risc0-health-source-catalog.mjs',import.meta.url),'utf8');
 const cleanup=source.indexOf('await snapshot.cleanup()');
 const success=source.indexOf('console.log(JSON.stringify(successRecord');
 assert.ok(cleanup>=0&&success>cleanup);
 assert.doesNotMatch(source,/console\.log\(JSON\.stringify\(\{ok:true/);
});

test('release provenance crash prefixes are replaceable and both aggregates are reread after completion',async()=>{
 const source=await readFile(new URL(
  '../../scripts/materialize-release-provenance.sh',import.meta.url),'utf8');
 const evidenceInstall=source.indexOf(
  'replace-locked-source-stdin.mjs" "$evidence_target"');
 const evidenceReadback=source.indexOf(
  'cmp -s "$evidence_temporary" "$evidence_observed"',evidenceInstall);
 const unchangedIntent=source.indexOf(
  'cmp -s "$intent_snapshot" "$intent_observed"',evidenceReadback);
 const intentInstall=source.indexOf(
  'replace-locked-private-stdin.mjs" "$intent_target"',unchangedIntent);
 const finalRead=source.indexOf('read_current_targets',intentInstall);
 const finalEvidence=source.indexOf(
  'cmp -s "$evidence_temporary" "$evidence_observed"',finalRead);
 const finalIntent=source.indexOf(
  'cmp -s "$intent_temporary" "$intent_observed"',finalEvidence);
 assert.ok(evidenceInstall>=0&&evidenceReadback>evidenceInstall);
 assert.ok(unchangedIntent>evidenceReadback&&intentInstall>unchangedIntent);
 assert.ok(finalRead>intentInstall&&finalEvidence>finalRead&&finalIntent>finalEvidence);
 assert.doesNotMatch(source,/install-private-file-(?:immutable|new)-stdin\.mjs" "\$intent_target"/);
 assert.match(source,/pin_runtime_tool python3/);
 assert.match(source,/"\$evidence_sha256" "\$parent_device" "\$parent_inode"/);
 assert.match(source,/"\$intent_sha256" "\$parent_device" "\$parent_inode"/);
});

test('native attestation generation is reread after directory synchronization',async()=>{
 const source=await readFile(new URL(
  '../../scripts/materialize-native-release-attestations.sh',import.meta.url),'utf8');
 const sync=source.lastIndexOf('sync -f "$metadata"; sync -f "$output"; sync -f "$config_directory"');
 const durableAggregate=source.indexOf('mainnet-release-evidence.durable.json',sync);
 const aggregateCmp=source.indexOf(
  'cmp -s "$next_metadata" "$temporary/mainnet-release-evidence.durable.json"',durableAggregate);
 const precursorReadback=source.indexOf('verify_published_outputs',aggregateCmp);
 const inputReadback=source.indexOf('assert_inputs_unchanged',precursorReadback);
 assert.ok(sync>=0&&durableAggregate>sync&&aggregateCmp>durableAggregate
  &&precursorReadback>aggregateCmp&&inputReadback>precursorReadback);
 assert.match(source,/replace-locked-source-stdin\.mjs/);
 assert.match(source,/"\$metadata_sha256"\s+"\$parent_device" "\$parent_inode"\s+\\?\s*"\$python3_bin" "\$python3_sha256"/);
 assert.match(source,/pin_tool python3/);
});

test('release authorization advances private intent through authenticated CAS',async()=>{
 const source=await readFile(new URL(
  '../../scripts/materialize-release-authorization.sh',import.meta.url),'utf8');
 assert.match(source,/replace-locked-private-stdin\.mjs/);
 assert.match(source,/"\$intent_sha256"\s+"\$parent_device" "\$parent_inode"\s+\\?\s*"\$python3_bin" "\$python3_sha256"/);
 assert.match(source,/pin_tool python3/);
});

test('deployment identity generation is reread after both directories are durable',async()=>{
 const source=await readFile(new URL(
  '../../scripts/materialize-mainnet-deployment-identity.sh',import.meta.url),'utf8');
 const sync=source.lastIndexOf('sync -f "$config_directory"');
 const observation=source.indexOf('observation.durable.json',sync);
 const observationCmp=source.indexOf(
  'cmp -s "$observation" "$temporary/observation.durable.json"',observation);
 const configuration=source.indexOf('configuration.durable.json',observationCmp);
 const configurationCmp=source.indexOf(
  'cmp -s "$configuration" "$temporary/configuration.durable.json"',configuration);
 assert.ok(sync>=0&&observation>sync&&observationCmp>observation
  &&configuration>observationCmp&&configurationCmp>configuration);
 assert.match(source,/replace-locked-source-stdin\.mjs/);
 assert.match(source,/"\$target_sha256" "\$parent_device" "\$parent_inode"/);
 assert.match(source,/pin_runtime_tool python3/);
});
