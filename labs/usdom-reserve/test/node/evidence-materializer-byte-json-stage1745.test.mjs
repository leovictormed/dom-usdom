import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const scripts=[
  'materialize-finalized-burn-release-evidence.mjs',
  'materialize-checkpoint-capacity-release-evidence.mjs',
  'materialize-risc0-health-source-catalog.mjs',
  'prepare-checkpoint-bootstrap-ratification-report.mjs',
];

test('release evidence materializers reject malformed UTF-8 before JSON parsing',async()=>{
  for(const name of scripts) {
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,/import \{parseStrictJsonBytes\} from '\.\.\/sdk\/strict-json\.mjs';/,
      `${name} must use the byte-oriented strict parser`);
    assert.doesNotMatch(source,/parseStrictJson\([^\n]*\.toString\(['"]utf8['"]\)/,
      `${name} must not perform lossy UTF-8 decoding before parsing`);
  }
});
