import test from 'node:test';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';import {checkpointEvidenceClaimCoverage} from '../../sdk/checkpoint-evidence-phase-coverage.mjs';
test('checkpoint phase covers exactly ten unique claims with producer and validator',()=>{
 assert.equal(checkpointEvidenceClaimCoverage.length,10);assert.equal(new Set(checkpointEvidenceClaimCoverage.map(x=>x.claim)).size,10);
 const result=spawnSync(process.execPath,['scripts/check-checkpoint-evidence-phase-coverage.mjs'],{cwd:new URL('../..',import.meta.url),encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/10\/10/);
});
