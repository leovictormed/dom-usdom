import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';

const hosts=[
 {file:'../../../../crates/dom-usdom-randomx-proof-host/src/lib.rs',calls:['program'],markers:[
  'PROGRAM_LOGICAL_PATH: &str =','usdom-randomx.bin','EXPECTED_PROGRAM_SHA256',
  'validate_artifact(\n        paths.plan.program',
 ]},
 {file:'../../../../crates/dom-usdom-randomx-proof-host/src/aggregate.rs',calls:['program'],markers:[
  'AGGREGATE_PROGRAM_LOGICAL_PATH: &str =','usdom-randomx-aggregate.bin',
  'AGGREGATE_PROGRAM_SHA256','paths.plan.aggregate_program',
 ]},
 {file:'../../../../crates/dom-usdom-economic-proof-host/src/lib.rs',
  calls:['chunk_program','block_program'],markers:[
   'CHUNK_PROGRAM_LOGICAL_PATH: &str =','usdom-economic-chunk.bin',
   'BLOCK_PROGRAM_LOGICAL_PATH: &str =','usdom-economic-block.bin',
   'sha256(&chunk_program) != EXPECTED_CHUNK_PROGRAM_SHA256',
   'sha256(&block_program) != EXPECTED_BLOCK_PROGRAM_SHA256',
  ]},
 {file:'../../../../crates/dom-usdom-checkpoint-proof-host/src/lib.rs',
  calls:['segment_program','outer_program'],markers:[
   'SEGMENT_PROGRAM_LOGICAL_PATH: &str =','usdom-checkpoint-segment.bin',
   'OUTER_PROGRAM_LOGICAL_PATH: &str =','usdom-checkpoint-outer.bin',
   'sha256(&segment_program) != SEGMENT_PROGRAM_SHA256',
   'sha256(&outer_program) != OUTER_PROGRAM_SHA256',
  ]},
 {file:'../../../../crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',calls:['program'],markers:[
  'Pinned RISC Zero ProgramBinary','validate_guest_artifacts(paths.program, paths.image_id)',
  'sha256(&program) != PROGRAM_SHA256','pinned finalized-burn ProgramBinary hash mismatch',
 ]},
];

test('every RISC Zero prover receives a hash-pinned packaged ProgramBinary, never raw ELF',async()=>{
 let total=0;
 for(const host of hosts) {
  const source=await readFile(new URL(host.file,import.meta.url),'utf8');
  const operands=[...source.matchAll(
   /\.prove_with_opts\(\s*environment,\s*&([a-z_]+),\s*&options\)/g)].map(match=>match[1]);
  assert.deepEqual(operands,host.calls,host.file);
  total+=operands.length;
  for(const marker of host.markers) assert.ok(source.includes(marker),`${host.file}: ${marker}`);
  for(const operand of operands) {
   assert.notEqual(operand,'elf',`${host.file}: raw ELF passed to prover`);
   assert.ok(source.includes(`let ${operand} =`),`${host.file}: ${operand} is not locally loaded`);
  }
  assert.doesNotMatch(source,/prove_with_opts\([^)]*ELF/si,host.file);
 }
 assert.equal(total,7,'audit every prove_with_opts call when a host adds one');
});

test('packaged ProgramBinary files match the exact hashes pinned by proof hosts',async()=>{
 const artifacts=[
  ['../../../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.bin',
   '0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd'],
  ['../../../../crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.bin',
   '3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f'],
  ['../../../../crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.bin',
   '5e7bc30f65ab4eae7c8b19a8c1c386cd023cd648c85f64008be2bd4729231842'],
  ['../../../../crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.bin',
   'e16e6aea7d470baad85bec45578e0960c02c2d47bce267e26141a2f3fa4a6c1f'],
  ['../../../../crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.bin',
   '426cc782490b8d680e5bd2266cc4a03b3e731194d92eda44875ea5d552cb5f74'],
  ['../../../../crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.bin',
   'ee707b6a1d2a135656ef9ee93a13487b6e1c24bafba8c66e9215708e184b9a90'],
  // This legacy-named file is already the packaged ProgramBinary consumed by
  // the finalized-burn host, not a raw RISC-V ELF (its pinned identity is kept).
  ['../../../../crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf',
   'bf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511'],
 ];
 for(const [file,expected] of artifacts) {
  const bytes=await readFile(new URL(file,import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'),expected,file);
 }
});

test('the no-proof decoder inventory covers every prover ProgramBinary and binds ImageIDs',async()=>{
 const checker=await readFile(new URL('../../scripts/check-risc0-proof-program-binary.py',import.meta.url),'utf8');
 assert.match(checker,/ARTIFACTS = \(/);
 assert.equal([...checker.matchAll(/^    \("[^"]+", "crates\/[^\n]+$/gm)].length,7);
 assert.doesNotMatch(checker,/\[decoder, "--verify", path, expected_iid\]/);
 assert.match(checker,/actual_sha != expected_sha/);
 assert.match(checker,/result\.stdout != expected_iid \+ "\\n" or result\.stderr/);
 assert.match(checker,/snapshot_decoder\(decoder, private_directory\)/);
 assert.match(checker,/DECODER_SHA256 = "[0-9a-f]{64}"/);
 assert.match(checker,/hashlib\.sha256\(payload\)\.hexdigest\(\) != DECODER_SHA256/);
 assert.match(checker,/os\.O_EXCL \| os\.O_CLOEXEC, 0o500/);
 assert.match(checker,/copied\.st_nlink != 1/);
 assert.match(checker,/"st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"/);
 assert.match(checker,/\[decoder_snapshot, "--verify", path, expected_iid\]/);
 const packager=await readFile(new URL('../../../../crates/dom-risc0-program-packager/src/main.rs',import.meta.url),'utf8');
 assert.match(packager,/ProgramBinary::decode\(&bytes\)\?/);
 assert.match(packager,/program\.encode\(\) != bytes/);
 assert.match(packager,/program\.compute_image_id\(\)\?\.to_string\(\)/);
 assert.match(packager,/actual != expected/);
});

test('the ProgramBinary checker rejects a stable but unauthorized decoder',async()=>{
 const directory=await mkdtemp(path.join(tmpdir(),'usdom-decoder-tamper-'));
 try {
  const candidate=path.join(directory,'decoder');
  await writeFile(candidate,'#!/bin/sh\nprintf "%s\\n" "$3"\n',{mode:0o700,flag:'wx'});
  await chmod(candidate,0o700);
  const checker=new URL('../../scripts/check-risc0-proof-program-binary.py',import.meta.url);
  const result=spawnSync('/usr/bin/python3',[checker.pathname,'--decoder',candidate],{
   cwd:new URL('../../',import.meta.url),encoding:'utf8',timeout:30_000,
   env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},
  });
  assert.equal(result.status,1);
  assert.equal(result.stdout,'');
  assert.match(result.stderr,/decoder SHA-256 differs from the source-controlled release pin/);
 } finally {
  await rm(directory,{recursive:true,force:true});
 }
});

test('every future proof runner decodes its snapshotted ProgramBinary before proving',async()=>{
 const runners=[
  ['../../scripts/prove-authenticated-randomx-receipt-set.sh',1],
  ['../../scripts/prove-authenticated-randomx-aggregate-set.sh',1],
  ['../../scripts/prove-authenticated-economic-receipt-set.sh',2],
  ['../../scripts/prove-authenticated-checkpoint-segment-set.sh',1],
  ['../../scripts/prove-authenticated-checkpoint-outer.sh',2],
  ['../../scripts/prove-authenticated-finalized-burn.sh',1],
 ];
 let calls=0;
 for(const [file,expectedCalls] of runners) {
  const source=await readFile(new URL(file,import.meta.url),'utf8');
  const positions=[...source.matchAll(/verify_risc0_program_binary /g)].map(match=>match.index);
  assert.equal(positions.length,expectedCalls,file);
  const prove=source.indexOf('--features prove');
  assert.ok(prove>0,`${file}: missing proof invocation`);
  assert.ok(positions.every(position=>position<prove),`${file}: decode occurs after proof starts`);
  assert.match(source,/source "\$LAB_ROOT\/scripts\/require-risc0-program-binary\.sh"/);
  assert.match(source,/assert_tool_unchanged cargo/);
  calls+=positions.length;
 }
 assert.equal(calls,8);
 const helper=await readFile(new URL('../../scripts/require-risc0-program-binary.sh',import.meta.url),'utf8');
 assert.match(helper,/-p dom-risc0-program-packager -- --verify "\$program" "\$expected_image_id"/);
 assert.match(helper,/\[\[ \$expected_image_id =~ \^\[0-9a-f\]\{64\}\$ \]\]/);
});
