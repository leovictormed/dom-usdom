#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildResidualRiskReport,serializeResidualRiskReport} from '../sdk/residual-risk-report.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const parse=(relative,bytes)=>parseStrictJsonBytes(bytes,{
  label:relative,maxBytes:4*1024*1024,maxDepth:64,
});

try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const evidencePath='config/mainnet-release-evidence.unconfigured.json';
  const releasePath='config/proof-reserve.unconfigured.json';
  const requirementsPath='config/production-requirements.json';
  const draftPath='docs/RESIDUAL-RISK-ACCEPTANCE-DRAFT-ETAPA211-2026-10-20.txt';
  const [evidenceBytes,releaseBytes,requirementsBytes,draft]=await Promise.all([
    readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,releasePath),
    readDirectProjectFile(root,requirementsPath),readDirectProjectFile(root,draftPath),
  ]);
  const releaseEvidence=parse(evidencePath,evidenceBytes);
  const releaseConfig=parse(releasePath,releaseBytes);
  const requirements=parse(requirementsPath,requirementsBytes);
  const report=buildResidualRiskReport({releaseEvidence,releaseConfig,requirements,
    draftSha256:createHash('sha256').update(draft).digest('hex')});
  const [evidenceAfter,releaseAfter,requirementsAfter,draftAfter]=await Promise.all([
    readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,releasePath),
    readDirectProjectFile(root,requirementsPath),readDirectProjectFile(root,draftPath),
  ]);
  if(!evidenceAfter.equals(evidenceBytes)||!releaseAfter.equals(releaseBytes)
      ||!requirementsAfter.equals(requirementsBytes)||!draftAfter.equals(draft)) {
    throw new Error('residual-risk inputs changed during preparation');
  }
  process.stdout.write(serializeResidualRiskReport(report));
} catch(error) {
  writeReleaseFailure('prepare-residual-risk-report',error);
  process.exitCode=1;
}
