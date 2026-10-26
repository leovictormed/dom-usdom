#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {materializeSafeControlReleaseMetadata} from '../sdk/safe-control-materialization.mjs';
import {readSafeControlReleaseArtifacts} from './safe-control-release-artifacts.mjs';

try {
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const releaseEvidence=parseStrictJson((await readDirectProjectFile(
    root,'config/mainnet-release-evidence.unconfigured.json',
  )).toString('utf8'),{label:'mainnet release evidence',maxBytes:2*1024*1024,maxDepth:32});
  const {artifactSet,fragment}=await readSafeControlReleaseArtifacts(root);
  const result=materializeSafeControlReleaseMetadata({releaseEvidence,fragment,artifactSet});
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-safe-control-release-metadata-materialization',error);
  process.exitCode=1;
}
