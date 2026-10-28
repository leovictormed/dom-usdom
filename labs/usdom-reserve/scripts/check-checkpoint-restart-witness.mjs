#!/usr/bin/env node
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateCheckpointRestartWitnessReport} from '../sdk/checkpoint-restart-witness-report.mjs';

if(process.argv.length!==2) throw new Error('this command accepts no arguments');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const reportPath=process.env.USDOM_CHECKPOINT_RESTART_WITNESS_REPORT;
if(typeof reportPath!=='string'||!path.isAbsolute(reportPath)) {
  throw new Error('USDOM_CHECKPOINT_RESTART_WITNESS_REPORT must be absolute');
}
const manifestPath=path.join(root,'evidence/native-runtime/native-usdom-v2.json');
const manifestBytes=await readDirectFile(manifestPath,{minimum:2,maximum:4*1024*1024,
  label:'native runtime manifest'});
const manifest=parseStrictJsonBytes(manifestBytes,{label:'native runtime manifest',
  maxBytes:4*1024*1024,maxDepth:32});
const witnessName=manifest.restart_checkpoint?.witness_file;
if(typeof witnessName!=='string'||!/^[A-Za-z0-9._-]+$/.test(witnessName)) {
  throw new Error('native runtime restart witness path is invalid');
}
const witnessPath=path.join(path.dirname(manifestPath),witnessName);
const [witnessBytes,reportBytes]=await Promise.all([
  readDirectFile(witnessPath,{minimum:1,maximum:64*1024*1024,label:'restart witness'}),
  readDirectFile(reportPath,{minimum:2,maximum:64*1024,privateMode:true,
    label:'checkpoint restart witness report'}),
]);
const report=validateCheckpointRestartWitnessReport(parseStrictJsonBytes(reportBytes,{
  label:'checkpoint restart witness report',maxBytes:64*1024,maxDepth:8}),{manifestBytes,witnessBytes});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
if(report.manifestSha256!==sha(manifestBytes)||report.witnessSha256!==sha(witnessBytes)
    ||manifest.restart_checkpoint?.witness_sha256!==report.witnessSha256) {
  throw new Error('restart witness report differs from current manifest or witness bytes');
}
const [manifestAfter,witnessAfter,reportAfter]=await Promise.all([
  readDirectFile(manifestPath,{minimum:2,maximum:4*1024*1024,label:'native runtime manifest'}),
  readDirectFile(witnessPath,{minimum:1,maximum:64*1024*1024,label:'restart witness'}),
  readDirectFile(reportPath,{minimum:2,maximum:64*1024,privateMode:true,
    label:'checkpoint restart witness report'}),
]);
if(!manifestAfter.equals(manifestBytes)||!witnessAfter.equals(witnessBytes)
    ||!reportAfter.equals(reportBytes)) throw new Error('restart witness inputs changed during validation');
process.stdout.write('PASS: checkpoint restart witness report matches current authenticated bytes\n');
