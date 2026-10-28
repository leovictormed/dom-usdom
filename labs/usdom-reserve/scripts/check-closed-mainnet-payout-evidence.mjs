#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateClosedMainnetPayoutEvidence} from '../sdk/closed-mainnet-payout-evidence.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';

try {
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  if(process.argv.length!==6) throw new Error('usage: check-closed-mainnet-payout-evidence BASELINE EXECUTION PACKAGE EXECUTE_FINALITY');
  const paths=process.argv.slice(2),labels=['payout baseline','payout execution','redemption package','redemption execute finality'];
  const bytes=await Promise.all(paths.map((path,index)=>readDirectFile(path,{
    minimum:2,maximum:4*1024*1024,label:labels[index],
  })));
  const values=bytes.map((value,index)=>parseStrictJsonBytes(value,{
    label:labels[index],maxBytes:4*1024*1024,maxDepth:64,maxNodes:100_000,
    maxStringBytes:4*1024*1024,maxObjectEntries:10_000,maxArrayEntries:10_000,
  }));
  const baselineSha256=createHash('sha256').update(bytes[0]).digest('hex');
  const packageSha256=createHash('sha256').update(bytes[2]).digest('hex');
  const executeFinalitySha256=createHash('sha256').update(bytes[3]).digest('hex');
  const [submissionBytes,releaseBytes,verifierManifestBytes]=await Promise.all([
    readDirectProjectFile(root,'evidence/finalized-burn-submission/finalized-burn-submission.json'),
    readDirectProjectFile(root,'config/proof-reserve.unconfigured.json'),
    readDirectProjectFile(root,'config/finalized-burn-verifier.unconfigured.json'),
  ]);
  const parse=(value,label)=>parseStrictJsonBytes(value,{label,maxBytes:4*1024*1024,maxDepth:64,
    maxNodes:100_000,maxStringBytes:4*1024*1024,maxObjectEntries:10_000,maxArrayEntries:10_000});
  validateClosedMainnetPayoutEvidence({baseline:values[0],baselineSha256,packageSha256,
    execution:values[1],packageValue:values[2],baselineBytes:bytes[0],executionBytes:bytes[1],
    packageBytes:bytes[2],executeFinality:values[3],executeFinalityBytes:bytes[3],executeFinalitySha256,
    submission:parse(submissionBytes,'finalized burn submission'),submissionBytes,
    release:parse(releaseBytes,'proof reserve release'),releaseBytes,
    releaseConfigSha256:createHash('sha256').update(releaseBytes).digest('hex'),verifierManifestBytes,
    verifierManifestSha256:createHash('sha256').update(verifierManifestBytes).digest('hex')});
  process.stdout.write('ok\n');
} catch(error) {
  writePilotFailure('check-closed-mainnet-payout-evidence',error);
  process.exitCode=1;
}
