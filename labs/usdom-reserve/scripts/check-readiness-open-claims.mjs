import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readFile} from 'node:fs/promises';
import {assertClassifiedOpenReadinessClaims} from '../sdk/readiness-open-claims.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  if(process.argv.length!==2) throw new Error('this fixed provenance checker accepts no arguments');
  const bytes=await readFile(new URL('../config/production-requirements.json',import.meta.url));
  const requirements=parseStrictJsonBytes(bytes,{label:'production requirements',maxBytes:2*1024*1024,maxDepth:32});
  const claims=assertClassifiedOpenReadinessClaims(requirements);
  const counts=Object.fromEntries(['configuration','operational-evidence'].map(category=>[
    category,claims.filter(claim=>claim.category===category).length,
  ]));
  console.log(`PASS: ${claims.length} false readiness claims classified (${counts.configuration} configuration, ${counts['operational-evidence']} operational evidence)`);
} catch(error) {
  writeReleaseFailure('check-readiness-open-claims',error);
  process.exitCode=1;
}
