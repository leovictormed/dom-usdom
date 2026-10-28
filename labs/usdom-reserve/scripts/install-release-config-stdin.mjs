#!/usr/bin/env node
import {writeFileDurable} from '../sdk/durable-private-file.mjs';
import path from 'node:path';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {isExactReleaseEvidenceShape} from '../sdk/release-evidence-schema.mjs';
import {collectReleaseEvidenceDocumentPaths} from '../sdk/release-evidence-document-paths.mjs';

const MAXIMUM_BYTES=16*1024*1024;

if(process.argv.length!==3) {
  console.error('Usage: install-release-config-stdin.mjs ABSOLUTE_TARGET');
  process.exit(64);
}

const target=process.argv[2];
if(typeof target!=='string'||!target.startsWith('/')) {
  throw new Error('release-config target must be absolute');
}

const chunks=[];
let size=0;
for await(const chunk of process.stdin) {
  size+=chunk.length;
  if(size>MAXIMUM_BYTES) throw new Error('release-config input exceeds its size bound');
  chunks.push(chunk);
}
if(size===0) throw new Error('release-config input is empty');
const bytes=Buffer.concat(chunks,size);
const value=parseStrictJsonBytes(bytes,{
  label:'release-config input',maxBytes:MAXIMUM_BYTES,maxDepth:128,
});
if(path.basename(target)==='mainnet-release-evidence.unconfigured.json') {
  if(!isExactReleaseEvidenceShape(value) || value.schema!==1) {
    throw new Error('mainnet release evidence input has an incompatible schema');
  }
  // This shared installation boundary is used by every shell materializer.
  // Reject zero commitments, path aliasing and byte-identical independent
  // evidence before the mutable aggregate can advance.
  collectReleaseEvidenceDocumentPaths(value);
}
await writeFileDurable(target,bytes,{maximum:MAXIMUM_BYTES,mode:0o644});
