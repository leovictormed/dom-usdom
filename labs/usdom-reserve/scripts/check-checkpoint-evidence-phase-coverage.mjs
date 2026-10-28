#!/usr/bin/env node
import {readFile} from 'node:fs/promises';
import {checkpointEvidenceClaimCoverage} from '../sdk/checkpoint-evidence-phase-coverage.mjs';
const generator=await readFile(new URL('./generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
const start=generator.indexOf('  produce-checkpoint-evidence-secret)'),end=generator.indexOf('\n  measure-release-capacity)',start);
if(start<0||end<0) throw new Error('checkpoint evidence phase is missing');
const phase=generator.slice(start,end),claims=new Set();
if(checkpointEvidenceClaimCoverage.length!==10) throw new Error('checkpoint evidence coverage must contain exactly ten claims');
for(const row of checkpointEvidenceClaimCoverage) {
 if(claims.has(row.claim)) throw new Error(`duplicate checkpoint claim: ${row.claim}`); claims.add(row.claim);
 const producer=phase.indexOf(`npm run --silent ${row.producer}`),validator=phase.indexOf(`npm run --silent ${row.validator}`);
 if(producer<0||validator<producer) throw new Error(`checkpoint claim lacks ordered producer/validator: ${row.claim}`);
}
process.stdout.write('PASS: checkpoint evidence phase has explicit producer/validator coverage 10/10\n');
