#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {buildCheckpointBootstrapRatificationReport,serializeCheckpointBootstrapRatificationReport}
  from '../sdk/checkpoint-bootstrap-ratification-report.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const read=relative=>readDirectProjectFile(root,relative,{minimum:2,maximum:1024*1024});
const parse=(relative,bytes)=>parseStrictJson(bytes.toString('utf8'),{
  label:relative,maxBytes:1024*1024,maxDepth:20,
});
try {
  if(process.argv.length!==2) throw new Error('this fixed report preparer accepts no arguments');
  const paths=['config/mainnet-release-evidence.unconfigured.json',
    'config/proof-reserve.unconfigured.json',
    'evidence/native-preactivation/ethereum-checkpoint-consensus.json',
    'config/native-preactivation-facts.unconfigured.json',
    'evidence/checkpoint-bootstrap/raw/ratification-observation.json'];
  const before=await Promise.all(paths.map(read));
  const [releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,observation]=
    before.map((bytes,index)=>parse(paths[index],bytes));
  const report=buildCheckpointBootstrapRatificationReport({releaseEvidence,releaseConfig,
    checkpointConsensus,nativeFacts,observation});
  const after=await Promise.all(paths.map(read));
  if(after.some((bytes,index)=>!bytes.equals(before[index]))) {
    throw new Error('checkpoint bootstrap ratification inputs changed during preparation');
  }
  process.stdout.write(serializeCheckpointBootstrapRatificationReport(report));
} catch(error) {
  writeReleaseFailure('prepare-checkpoint-bootstrap-ratification-report',error);
  process.exitCode=1;
}
