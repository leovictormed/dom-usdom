#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildCheckpointFinalizedEventReport,serializeCheckpointFinalizedEventReport}
  from '../sdk/checkpoint-finalized-event-report.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const read=relative=>readDirectProjectFile(root,relative,{minimum:2,maximum:2*1024*1024});
const parse=(relative,bytes)=>parseStrictJsonBytes(bytes,{
  label:relative,maxBytes:2*1024*1024,maxDepth:24,
});
try {
  if(process.argv.length!==2) throw new Error('this fixed report preparer accepts no arguments');
  const paths=['config/mainnet-release-evidence.unconfigured.json',
    'config/proof-reserve.unconfigured.json',
    'evidence/checkpoint-finalized/raw/finalized-event-observation.json'];
  const before=await Promise.all(paths.map(read));
  const [releaseEvidence,releaseConfig,observation]=before.map((bytes,index)=>
    parse(paths[index],bytes));
  const report=buildCheckpointFinalizedEventReport({releaseEvidence,releaseConfig,observation});
  const after=await Promise.all(paths.map(read));
  if(after.some((bytes,index)=>!bytes.equals(before[index]))) {
    throw new Error('checkpoint finalized-event inputs changed during preparation');
  }
  process.stdout.write(serializeCheckpointFinalizedEventReport(report));
} catch(error) {
  writeReleaseFailure('prepare-checkpoint-finalized-event-report',error);
  process.exitCode=1;
}
