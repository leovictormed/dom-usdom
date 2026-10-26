#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildMainnetForkRehearsalReport,serializeForkRehearsalEvidenceDocument,
  serializeMainnetForkRehearsalReport}
  from '../sdk/mainnet-fork-rehearsal-report.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const readJson=relative=>readDirectProjectFile(root,relative,{minimum:2,maximum:4*1024*1024});
const parse=(relative,bytes)=>parseStrictJsonBytes(bytes,{
  label:relative,maxBytes:4*1024*1024,maxDepth:32,
});
try {
  if(process.argv.length!==2) throw new Error('this fixed report preparer accepts no arguments');
  const source='evidence/fork-rehearsal/raw/mainnet-fork-rehearsal-observations.json';
  const evidencePath='config/mainnet-release-evidence.unconfigured.json';
  const releasePath='config/proof-reserve.unconfigured.json';
  const [observationsBytes,evidenceBytes,releaseBytes]=await Promise.all([
    readJson(source),readJson(evidencePath),readJson(releasePath),
  ]);
  const observations=parse(source,observationsBytes);
  const releaseEvidence=parse(evidencePath,evidenceBytes);
  const releaseConfig=parse(releasePath,releaseBytes);
  const references=observations.scenarios?.flatMap(scenario=>
    [scenario.faultEvidence?.path,scenario.recoveryEvidence?.path])??[];
  const evidenceFiles={};
  const rawBytes=new Map();
  for(const relative of references) {
    if(typeof relative!=='string'||relative===source) throw new Error('invalid raw rehearsal evidence path');
    const content=await readDirectProjectFile(root,relative,{minimum:1,maximum:16*1024*1024});
    rawBytes.set(relative,content);
    const document=parseStrictJsonBytes(content,{
      label:relative,maxBytes:16*1024*1024,maxDepth:16});
    if(!content.equals(serializeForkRehearsalEvidenceDocument(document))) {
      throw new Error(`${relative} must use canonical exact bytes`);
    }
    evidenceFiles[relative]={sha256:createHash('sha256').update(content).digest('hex'),document};
  }
  const report=buildMainnetForkRehearsalReport({observations,releaseEvidence,releaseConfig,evidenceFiles});
  const [observationsAfter,evidenceAfter,releaseAfter,...rawAfter]=await Promise.all([
    readJson(source),readJson(evidencePath),readJson(releasePath),
    ...[...rawBytes.keys()].map(relative=>readDirectProjectFile(root,relative,
      {minimum:1,maximum:16*1024*1024})),
  ]);
  if(!observationsAfter.equals(observationsBytes)||!evidenceAfter.equals(evidenceBytes)
      ||!releaseAfter.equals(releaseBytes)
      ||rawAfter.some((bytes,index)=>!bytes.equals([...rawBytes.values()][index]))) {
    throw new Error('mainnet fork rehearsal inputs changed during preparation');
  }
  process.stdout.write(serializeMainnetForkRehearsalReport(report));
} catch(error) {
  writeReleaseFailure('prepare-mainnet-fork-rehearsal-report',error);
  process.exitCode=1;
}
