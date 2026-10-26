import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
  validateCheckpointRandomxAuthority,validateCheckpointRandomxImageIdBinding,
} from '../../sdk/checkpoint-randomx-authority.mjs';

const sources={
  singleExporter:await readFile(new URL('../../../../crates/dom-usdom-checkpoint-program/src/bin/dom-usdom-export-randomx-statement.rs',import.meta.url),'utf8'),
  setExporter:await readFile(new URL('../../../../crates/dom-node/src/bin/dom-usdom-export-randomx-statement-set.rs',import.meta.url),'utf8'),
  proofHost:await readFile(new URL('../../../../crates/dom-usdom-randomx-proof-host/src/lib.rs',import.meta.url),'utf8'),
  guest:await readFile(new URL('../../../../crates/dom-usdom-randomx-risc0-guest/src/main.rs',import.meta.url),'utf8'),
};

const bindingSources={
  nativeConfig:await readFile(new URL('../../../../crates/dom-node/src/native_usdom_config.rs',import.meta.url),'utf8'),
  checkpointProgram:await readFile(new URL('../../../../crates/dom-usdom-checkpoint-program/src/lib.rs',import.meta.url),'utf8'),
  segmentGuest:await readFile(new URL('../../../../crates/dom-usdom-checkpoint-segment-risc0-guest/src/main.rs',import.meta.url),'utf8'),
  proofHost:sources.proofHost,
  checkpointConfig:await readFile(new URL('../../sdk/checkpoint-verifier-config.mjs',import.meta.url),'utf8'),
  readiness:await readFile(new URL('../../sdk/mainnet-readiness.mjs',import.meta.url),'utf8'),
  capacity:await readFile(new URL('../../sdk/checkpoint-proof-capacity-report.mjs',import.meta.url),'utf8'),
  imageIdArtifact:await readFile(new URL('../../../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid',import.meta.url),'utf8'),
};

test('native reference prevalidates while a pinned receipt remains production authority',()=>{
  assert.deepEqual(validateCheckpointRandomxAuthority(sources),[]);
});

test('RandomX ImageID is one artifact-derived identity across native and release boundaries',()=>{
  assert.deepEqual(validateCheckpointRandomxImageIdBinding(bindingSources),[]);
});

test('every RandomX ImageID release binding mutation fails closed',()=>{
  const mutations=[
    ['nativeConfig','Some(image_id)','None'],
    ['checkpointProgram','image_id: state.randomx_receipt_image_id','image_id: [0; 32]'],
    ['segmentGuest','verify_checkpoint_segment_randomx_bindings_in_guest(executed.randomx_bindings())','Ok(())'],
    ['checkpointConfig','c.randomxReceiptImageId,c.checkpointStatementTypeHash','c.checkpointStatementTypeHash'],
    ['readiness','native_runtime_checkpoint_randomx_image_id_mismatch','ignored_randomx_image_id_mismatch'],
    ['capacity',"'0x'+CHECKPOINT_RANDOMX_IMAGE_ID","'0x'+CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID"],
    ['imageIdArtifact',bindingSources.imageIdArtifact.trim(),'01'.repeat(32)],
  ];
  for(const [key,before,after] of mutations) {
    assert(bindingSources[key].includes(before),`mutation anchor missing: ${before}`);
    const mutated={...bindingSources,[key]:bindingSources[key].replace(before,after)};
    assert.notDeepEqual(validateCheckpointRandomxImageIdBinding(mutated),[],before);
  }
});

test('RandomX prevalidation and receipt authority mutations fail closed',()=>{
  const mutations=[
    ['singleExporter','execute_checkpoint_randomx_reference(&statement)','Ok([0; 32])'],
    ['singleExporter','"  \\"randomxRelationExecuted\\": true,\\n",','"  \\"randomxRelationExecuted\\": false,\\n",'],
    ['setExporter','execute_checkpoint_randomx_reference(&statement)','Ok([0; 32])'],
    ['setExporter','"randomx_relations_executed": true','"randomx_relations_executed": false'],
    ['setExporter','"native_reference_commitment": hex(&native_reference_commitment)','"native_reference_commitment": "00"'],
    ['proofHost','|| !source.randomx_relations_executed','|| source.randomx_relations_executed'],
    ['proofHost','.verify(Risc0Digest::from(image_id))','.verify(Risc0Digest::ZERO)'],
    ['guest','actual, statement.randomx_hash','actual, [0; 32]'],
  ];
  for(const [key,before,after] of mutations) {
    assert(sources[key].includes(before),`mutation anchor missing: ${before}`);
    const mutated={...sources,[key]:sources[key].replaceAll(before,after)};
    assert.notDeepEqual(validateCheckpointRandomxAuthority(mutated),[],before);
  }
});
