import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

test('RandomX durably invalidates its completion marker before receipt resume',async()=>{
 const source=await readFile(new URL('../../../../crates/dom-usdom-randomx-proof-host/src/lib.rs',import.meta.url),'utf8');
 const check=source=>{
 const start=source.indexOf('let final_index = paths.output_directory.join(RECEIPT_INDEX_NAME);');
 const loop=source.indexOf('let mut receipt_records = Vec::with_capacity',start);
 const publish=source.indexOf('atomic_publish(&final_index, &receipt_index_bytes)?;',loop);
 assert.ok(start>0 && loop>start && publish>loop);
 const boundary=source.slice(start,loop);
 assert.match(boundary,/fs::symlink_metadata\(&final_index\)/);
 assert.match(boundary,/remove_invalid_receipt\(&final_index\)\?/);
 assert.doesNotMatch(boundary,/final_index\.exists\(\)/);
 assert.doesNotMatch(boundary,/fs::remove_file\(&final_index\)/);
 const remover=source.slice(source.indexOf('fn remove_invalid_receipt'),start);
 assert.match(remover,/fs::remove_file\(path\)/);
 assert.match(remover,/File::open\(parent\)[\s\S]*directory\.sync_all\(\)/);
 };
 check(source);
 assert.throws(()=>check(source.replace(
  'remove_invalid_receipt(&final_index)?;',
  'fs::remove_file(&final_index)?;')));
});

test('all receipt families retain artifacts-first and completion-index-last publication',async()=>{
 const files=[
  '../../../../crates/dom-usdom-randomx-proof-host/src/lib.rs',
  '../../../../crates/dom-usdom-randomx-proof-host/src/aggregate.rs',
  '../../../../crates/dom-usdom-economic-proof-host/src/lib.rs',
  '../../../../crates/dom-usdom-checkpoint-proof-host/src/lib.rs',
  '../../../../crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',
 ];
 for(const file of files) {
  const source=await readFile(new URL(file,import.meta.url),'utf8');
  assert.match(source,/atomic_publish\(/,file);
  assert.match(source,/sync_all\(\)|save_private_bytes\(|atomic_publish, build_plan/,file);
  assert.match(source,/existing_verified|verify_receipt/,file);
 }
});

test('checkpoint Groth16 invalidates and fsyncs its package marker before artifact reuse',async()=>{
 const source=await readFile(new URL('../../../../crates/dom-usdom-checkpoint-proof-host/src/lib.rs',import.meta.url),'utf8');
 const check=source=>{
  const entry=source.indexOf('pub fn package_outer_evm_proof(');
  const invalidate=source.indexOf('invalidate_outer_evm_package_index(paths.output_directory)?;',entry);
  const reuse=source.indexOf('existing_verified_groth16_receipt(',entry);
  const seal=source.indexOf('atomic_publish(&paths.output_directory.join(evm_seal_name)',entry);
  const completion=source.indexOf('&paths.output_directory.join(OUTER_EVM_PACKAGE_INDEX_NAME)',entry);
  assert.ok(entry>0 && invalidate>entry && reuse>invalidate && seal>reuse && completion>seal);
  const helperStart=source.indexOf('fn invalidate_outer_evm_package_index');
  const helper=source.slice(helperStart,entry);
  assert.match(helper,/fs::symlink_metadata\(&path\)/);
  assert.match(helper,/remove_direct_file\(&path\)/);
  assert.match(helper,/ErrorKind::NotFound => Ok\(\(\)\)/);
 };
 check(source);
 assert.throws(()=>check(source.replace(
  'invalidate_outer_evm_package_index(paths.output_directory)?;',
  '// unsafe: retained stale completion marker')));
});

test('EVM packagers durably clear derived seals after their completion markers',async()=>{
 const checkpoint=await readFile(new URL('../../../../crates/dom-usdom-checkpoint-proof-host/src/lib.rs',import.meta.url),'utf8');
 const finalized=await readFile(new URL('../../../../crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',import.meta.url),'utf8');

 const checkpointStart=checkpoint.indexOf('fn invalidate_outer_evm_package_index');
 const checkpointEnd=checkpoint.indexOf('pub fn prove_segment_set',checkpointStart);
 const checkpointHelper=checkpoint.slice(checkpointStart,checkpointEnd);
 const checkpointIndex=checkpointHelper.indexOf('remove_direct_file(&path)?;');
 const checkpointSeal=checkpointHelper.indexOf('remove_direct_file(&seal_path)');
 assert.ok(checkpointIndex>=0 && checkpointSeal>checkpointIndex);
 assert.match(checkpointHelper,/checkpoint-outer-evm-seal\.bin/);
 assert.match(checkpointHelper,/ErrorKind::NotFound => Ok\(\(\)\)/);

 const finalizedStart=finalized.indexOf('fn invalidate_evm_package_index');
 const finalizedEnd=finalized.indexOf('fn existing_verified_groth16_receipt',finalizedStart);
 const finalizedHelper=finalized.slice(finalizedStart,finalizedEnd);
 const finalizedIndexSync=finalizedHelper.indexOf('.and_then(|directory| directory.sync_all())');
 const finalizedSeal=finalizedHelper.indexOf('remove_direct_file(&seal_path)');
 assert.ok(finalizedIndexSync>=0 && finalizedSeal>finalizedIndexSync);
 assert.match(finalizedHelper,/output_directory\.join\(EVM_SEAL_NAME\)/);
 assert.match(finalizedHelper,/ErrorKind::NotFound => Ok\(\(\)\)/);

 assert.throws(()=>{
  const unsafe=checkpointHelper.replace('remove_direct_file(&seal_path)','Ok(())');
  assert.match(unsafe,/remove_direct_file\(&seal_path\)/);
 });
});
