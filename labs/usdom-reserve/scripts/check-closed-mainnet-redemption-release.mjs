#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateClosedMainnetRedemptionRelease} from '../sdk/closed-mainnet-redemption-release.mjs';
if(process.argv.length!==7) process.exit(64);
const read=async(path,label)=>{
  const bytes=await readDirectFile(path,{minimum:2,maximum:4*1024*1024,label});
  return {bytes,value:parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64,
    maxNodes:100_000,maxStringBytes:4*1024*1024,maxObjectEntries:10_000,maxArrayEntries:10_000})};
};
try {
  const [submissionSnapshot,packageSnapshot,releaseSnapshot]=await Promise.all([
    read(process.argv[2],'finalized burn submission'),read(process.argv[3],'redemption package'),
    read(process.argv[4],'release configuration'),
  ]);
  process.stdout.write(JSON.stringify(validateClosedMainnetRedemptionRelease({
    submission:submissionSnapshot.value,submissionBytes:submissionSnapshot.bytes,
    packageValue:packageSnapshot.value,packageBytes:packageSnapshot.bytes,
    release:releaseSnapshot.value,releaseBytes:releaseSnapshot.bytes,releaseConfigSha256:process.argv[5],
    verifierManifestSha256:process.argv[6],
  }))+'\n');
} catch(error) {
  writePilotFailure('check-closed-mainnet-redemption-release',error);
  process.exitCode=1;
}
