#!/usr/bin/env node
import {durableReplacementFailureExitCode,replaceLockedParentFileDurable}
  from '../sdk/durable-locked-parent-replacement.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
try {
  if(process.argv.length!==9) throw new Error('usage: replace-locked-private-stdin.mjs TARGET SHA256 PREVIOUS_SHA256 PARENT_DEVICE PARENT_INODE INSPECTOR INSPECTOR_SHA256');
  const chunks=[]; let size=0;
  for await(const chunk of process.stdin) {
    size+=chunk.length;
    if(size>4*1024*1024) throw new Error('replacement input is too large');
    chunks.push(chunk);
  }
  await replaceLockedParentFileDurable({target:process.argv[2],contents:Buffer.concat(chunks),
    expectedSha256:process.argv[3],expectedPreviousSha256:process.argv[4],
    expectedParentDevice:process.argv[5],expectedParentInode:process.argv[6],
    metadataInspectorExecutable:process.argv[7],metadataInspectorSha256:process.argv[8],
    expectedMode:0o600});
} catch(error) {
  writeReleaseFailure('replace-locked-private-stdin',error);
  process.exitCode=durableReplacementFailureExitCode(error);
}
