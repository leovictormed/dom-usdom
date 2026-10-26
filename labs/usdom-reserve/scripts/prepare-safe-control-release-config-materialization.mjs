#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {materializeSafeControlReleaseConfig} from '../sdk/safe-control-materialization.mjs';
import {readSafeControlReleaseArtifacts} from './safe-control-release-artifacts.mjs';

try {
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const releaseConfig=parseStrictJson(
    (await readDirectProjectFile(root,'config/proof-reserve.unconfigured.json')).toString('utf8'),
    {label:'proof-reserve release config',maxBytes:1024*1024,maxDepth:24},
  );
  const {artifactSet}=await readSafeControlReleaseArtifacts(root);
  const result=materializeSafeControlReleaseConfig({releaseConfig,artifactSet});
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-safe-control-release-config-materialization',error);
  process.exitCode=1;
}
