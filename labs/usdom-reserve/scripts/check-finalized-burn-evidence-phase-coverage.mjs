#!/usr/bin/env node
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {finalizedBurnEvidenceClaimCoverage as rows} from '../sdk/finalized-burn-evidence-phase-coverage.mjs';

const root=new URL('..',import.meta.url);
const source=await readFile(new URL('./generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
const slicePhase=name=>{const a=source.indexOf(`  ${name})`),b=source.indexOf('\n    ;;',a+3);if(a<0||b<0)throw new Error(`phase not found: ${name}`);return source.slice(a,b);};
const phase=slicePhase('execute-pilot-redemption-secret');
if(rows.length!==3||new Set(rows.map(x=>x.claim)).size!==3)throw new Error('finalized-burn coverage must contain three claims');
const generated=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{cwd:root,encoding:'utf8'});
if(generated.status!==0)throw new Error('cannot inspect execution plan');
const plan=JSON.parse(generated.stdout),ordinal=new Map(plan.phaseArtifacts.map(row=>[row.phase,row.ordinal]));
for(const row of rows){
 const p=phase.indexOf(`npm run --silent ${row.producer}`),v=phase.indexOf(`npm run --silent ${row.validator}`);
 if(p<0||v<p)throw new Error(`missing finalized-burn producer/validator: ${row.claim}`);
 if(row.prerequisitePhase||row.prerequisiteProducer){
  if(typeof row.prerequisitePhase!=='string'||typeof row.prerequisiteProducer!=='string')throw new Error(`incomplete recursive prerequisite: ${row.claim}`);
  const prerequisitePhase=slicePhase(row.prerequisitePhase);
  if(!prerequisitePhase.includes(`npm run --silent ${row.prerequisiteProducer}`))throw new Error(`missing recursive prerequisite producer: ${row.claim}`);
  if(!(ordinal.get(row.prerequisitePhase)<ordinal.get('execute-pilot-redemption-secret')))throw new Error(`recursive prerequisite must precede redemption: ${row.claim}`);
 }
}
process.stdout.write('PASS: finalized-burn phase producer/validator coverage 3/3; recursive checkpoint prerequisites 2/2\n');
