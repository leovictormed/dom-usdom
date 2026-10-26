#!/usr/bin/env node
import {constants} from 'node:fs';
import {lstat,open} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  RANDOMX_MEASUREMENT_IDENTITY,inspectAuthenticatedRandomxExport,
  inspectCanonicalRandomxStatement,sha256,
} from '../sdk/randomx-measurement.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repository=path.resolve(root,'../..');
const paths={
  statement:path.join(root,'evidence/randomx-canonical-statement.bin'),
  exportReport:path.join(root,'evidence/randomx-canonical-statement-export.json'),
  transition:path.join(root,'evidence/randomx-source/checkpoint-segment-transition.bin'),
  privateInput:path.join(root,'evidence/randomx-source/checkpoint-segment-private-input.bin'),
  policyInput:path.join(root,'evidence/randomx-source/checkpoint-segment-policy-input.bin'),
  nativeOpening:path.join(root,'evidence/randomx-source/checkpoint-segment-native-state-opening.bin'),
  elf:path.join(repository,'crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.elf'),
  program:path.join(repository,'crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.bin'),
  imageId:path.join(repository,'crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid'),
};
const inputSnapshots=new Map();

async function readDirectRegularFile(file,{exact,max,encoding,record=true}={}) {
  const before=await lstat(file);
  if(!before.isFile() || before.isSymbolicLink()
      || (exact!==undefined && before.size!==exact)
      || (max!==undefined && (before.size===0 || before.size>max))) {
    throw new Error('input must be one bounded direct regular file');
  }
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const opened=await handle.stat();
    if(opened.dev!==before.dev || opened.ino!==before.ino || opened.size!==before.size) {
      throw new Error('input changed while it was opened');
    }
    const value=await handle.readFile(encoding===undefined?undefined:{encoding});
    const length=encoding===undefined?value.length:Buffer.byteLength(value,encoding);
    if(length!==before.size) throw new Error('input changed while it was read');
    if(record) inputSnapshots.set(file,encoding===undefined?Buffer.from(value):Buffer.from(value,encoding));
    return value;
  } finally { await handle.close(); }
}

if(process.argv.length!==2) {
  process.stderr.write('Usage: node scripts/plan-randomx-measurement.mjs\n');
  process.exit(2);
}

const blockers=[];
let statement=null;
let statementBytes=null;
let authenticatedExport=null;
try {
  const [elf,program,imageId]=await Promise.all([
    readDirectRegularFile(paths.elf,{max:512*1024*1024}),
    readDirectRegularFile(paths.program,{max:512*1024*1024}),
    readDirectRegularFile(paths.imageId,{max:4096,encoding:'utf8'}),
  ]);
  if(sha256(elf)!==RANDOMX_MEASUREMENT_IDENTITY.userElfSha256) blockers.push('user_elf_hash_mismatch');
  if(sha256(program)!==RANDOMX_MEASUREMENT_IDENTITY.programBinarySha256) {
    blockers.push('program_binary_hash_mismatch');
  }
  if(imageId.trim()!==RANDOMX_MEASUREMENT_IDENTITY.imageId) blockers.push('image_id_mismatch');
} catch(error) {
  blockers.push(`artifact_unavailable:${error.code??'read_failure'}`);
}
try {
  statementBytes=await readDirectRegularFile(paths.statement,{
    exact:RANDOMX_MEASUREMENT_IDENTITY.statementBytes,
  });
  statement=inspectCanonicalRandomxStatement(statementBytes);
} catch(error) {
  blockers.push('canonical_statement_unavailable');
}
try {
  if(statementBytes===null) throw new Error('canonical statement is unavailable');
  const [reportText,transition,privateInput,policyInput,nativeOpening]=await Promise.all([
    readDirectRegularFile(paths.exportReport,{max:4096,encoding:'utf8'}),
    readDirectRegularFile(paths.transition,{max:8192}),
    readDirectRegularFile(paths.privateInput,{max:64*1024*1024}),
    readDirectRegularFile(paths.policyInput,{max:1024*1024}),
    readDirectRegularFile(paths.nativeOpening,{max:2048}),
  ]);
  authenticatedExport=inspectAuthenticatedRandomxExport(parseStrictJson(reportText,{
    label:'RandomX authenticated export',maxBytes:4096,maxDepth:16}),{
    transition,privateInput,policyInput,nativeOpening,
  },statementBytes);
} catch(error) {
  blockers.push('authenticated_export_unavailable');
}

try {
  for(const [file,expected] of inputSnapshots) {
    const current=await readDirectRegularFile(file,{exact:expected.length,record:false});
    if(!current.equals(expected)) throw new Error('authenticated RandomX input changed during planning');
  }
} catch(error) {
  blockers.push('authenticated_input_changed');
}

const report={
  schema:'usdom-randomx-measurement-plan-v1',
  mode:'plan-only',
  executesGuest:false,
  generatesProof:false,
  mines:false,
  identity:RANDOMX_MEASUREMENT_IDENTITY,
  statementPath:'evidence/randomx-canonical-statement.bin',
  statement,
  authenticatedExport,
  readyForAuthorizedExecution:blockers.length===0,
  blockers,
};
process.stdout.write(`${JSON.stringify(report,null,2)}\n`);
if(blockers.length!==0) process.exitCode=1;
