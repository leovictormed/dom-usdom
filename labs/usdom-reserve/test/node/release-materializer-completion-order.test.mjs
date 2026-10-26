import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const cases=[
 ['finalized-burn evidence','../../scripts/materialize-finalized-burn-release-evidence.mjs',
  'immutableWrite(FINALIZED_BURN_E2E_EVIDENCE_PATH','atomicWrite(evidencePath',
  /installed finalized-burn release generation differs from prepared bytes/],
 ['checkpoint capacity evidence','../../scripts/materialize-checkpoint-capacity-release-evidence.mjs',
  'immutableWrite(CHECKPOINT_CAPACITY_EVIDENCE_PATH','atomicWrite(evidencePath',
  /installed checkpoint capacity release generation differs from prepared bytes/],
 ['RISC Zero health catalog','../../scripts/materialize-risc0-health-source-catalog.mjs',
  'immutableWrite(RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH','atomicWrite(metadataPath',
  /installed RISC Zero health generation differs from prepared bytes/],
 ['deployment identity','../../scripts/materialize-mainnet-deployment-identity.sh',
  'install-private-file-immutable-stdin.mjs --json "$observation_target"',
  'install-release-config-stdin.mjs "$target"',/observation\.final\.json/],
 ['native attestations','../../scripts/materialize-native-release-attestations.sh',
  'publish_and_verify_immutable "$temporary/native-attestation-finalized-observation.json"',
  'install-release-config-stdin.mjs" "$metadata"',/successful return proves one coherent five-document generation/],
 ['release authorization','../../scripts/materialize-release-authorization.sh',
  'publish_immutable "$observation"',
  'install-private-file-stdin.mjs" "$intent_target"',/release-authorization-finalized-observation\.final\.json/],
 ['release provenance','../../scripts/materialize-release-provenance.sh',
  'install-release-config-stdin.mjs" "$evidence_target"',
  'install-private-file-stdin.mjs" "$intent_target"',/read_current_targets/],
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

test('release provenance crash prefixes are replaceable and both aggregates are reread after completion',async()=>{
 const source=await readFile(new URL(
  '../../scripts/materialize-release-provenance.sh',import.meta.url),'utf8');
 const evidenceInstall=source.indexOf(
  'install-release-config-stdin.mjs" "$evidence_target"');
 const evidenceReadback=source.indexOf(
  'cmp -s "$evidence_temporary" "$evidence_observed"',evidenceInstall);
 const unchangedIntent=source.indexOf(
  'cmp -s "$intent_snapshot" "$intent_observed"',evidenceReadback);
 const intentInstall=source.indexOf(
  'install-private-file-stdin.mjs" "$intent_target"',unchangedIntent);
 const finalRead=source.indexOf('read_current_targets',intentInstall);
 const finalEvidence=source.indexOf(
  'cmp -s "$evidence_temporary" "$evidence_observed"',finalRead);
 const finalIntent=source.indexOf(
  'cmp -s "$intent_temporary" "$intent_observed"',finalEvidence);
 assert.ok(evidenceInstall>=0&&evidenceReadback>evidenceInstall);
 assert.ok(unchangedIntent>evidenceReadback&&intentInstall>unchangedIntent);
 assert.ok(finalRead>intentInstall&&finalEvidence>finalRead&&finalIntent>finalEvidence);
 assert.doesNotMatch(source,/install-private-file-(?:immutable|new)-stdin\.mjs" "\$intent_target"/);
});
