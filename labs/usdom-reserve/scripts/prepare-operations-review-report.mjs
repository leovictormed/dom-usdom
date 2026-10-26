#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {OPERATIONS_REVIEW_EVIDENCE_NAMES,buildOperationsReviewReport,serializeOperationsReviewReport,
} from '../sdk/operations-review-report.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const parse=(relative,bytes)=>parseStrictJsonBytes(bytes,{
    label:relative,maxBytes:4*1024*1024,maxDepth:64,
  });

try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const evidencePath='config/mainnet-release-evidence.unconfigured.json';
  const releasePath='config/proof-reserve.unconfigured.json';
  const runbookPath='docs/CLOSED-MAINNET-LINUX-RUNBOOK.md';
  const [evidenceBytes,releaseBytes,runbook]=await Promise.all([
    readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,releasePath),
    readDirectProjectFile(root,'docs/CLOSED-MAINNET-LINUX-RUNBOOK.md'),
  ]);
  const releaseEvidence=parse(evidencePath,evidenceBytes);
  const releaseConfig=parse(releasePath,releaseBytes);
  const operationalBytes=new Map();
  for(const name of OPERATIONS_REVIEW_EVIDENCE_NAMES) {
    const document=releaseEvidence[name];
    if(!document||typeof document.path!=='string'||typeof document.sha256!=='string') {
      throw new Error(`${name} release evidence is missing`);
    }
    const bytes=await readDirectProjectFile(root,document.path,{minimum:1,maximum:64*1024*1024,
      label:name});
    if(createHash('sha256').update(bytes).digest('hex')!==document.sha256) {
      throw new Error(`${name} content differs from release evidence`);
    }
    operationalBytes.set(document.path,bytes);
  }
  const report=buildOperationsReviewReport({releaseEvidence,releaseConfig,
    runbookSha256:createHash('sha256').update(runbook).digest('hex')});
  const [evidenceAfter,releaseAfter,runbookAfter]=await Promise.all([
    readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,releasePath),
    readDirectProjectFile(root,runbookPath),
  ]);
  if(!evidenceAfter.equals(evidenceBytes)||!releaseAfter.equals(releaseBytes)
      ||!runbookAfter.equals(runbook)) throw new Error('operations-review inputs changed during preparation');
  for(const [relative,before] of operationalBytes) {
    const after=await readDirectProjectFile(root,relative,{minimum:1,maximum:64*1024*1024,
      label:'operational evidence'});
    if(!after.equals(before)) throw new Error('operational evidence changed during preparation');
  }
  process.stdout.write(serializeOperationsReviewReport(report));
} catch(error) {
  writeReleaseFailure('prepare-operations-review-report',error);
  process.exitCode=1;
}
