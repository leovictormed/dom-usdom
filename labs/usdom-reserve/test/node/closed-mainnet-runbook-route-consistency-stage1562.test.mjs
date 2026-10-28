import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const read=relative=>readFileSync(path.join(root,relative),'utf8');
const result=spawnSync(node,['scripts/write-open-claims-execution-plan.mjs'],{cwd:root,encoding:'utf8'});
assert.equal(result.status,0,result.stderr);
const plan=JSON.parse(result.stdout);

test('runbook lists the generated phases in the exact authoritative order',()=>{
  const runbook=read('docs/CLOSED-MAINNET-LINUX-RUNBOOK.md');
  const block=runbook.match(/<!-- BEGIN CLOSED MAINNET PHASE ORDER -->([\s\S]*?)<!-- END CLOSED MAINNET PHASE ORDER -->/);
  assert.ok(block,'runbook phase-order block missing');
  const documented=[...block[1].matchAll(/^\d+\. `([^`]+)`$/gm)].map(match=>match[1]);
  assert.deepEqual(documented,plan.phaseOrder);
  assert.equal(new Set(documented).size,23);
});

test('runbook and plan report distinguish route coverage from external evidence',()=>{
  const text=`${read('docs/CLOSED-MAINNET-LINUX-RUNBOOK.md')}\n${read('docs/reports/OPEN-CLAIMS-EXECUTION-PLAN-ETAPA1484-2026-10-27.txt')}`;
  assert.match(text,/33 rotas (?:implementadas e classificadas|estão implementadas e classificadas)/);
  assert.match(text,/33 (?:incluem|produzem e)/);
  assert.match(text,/cerimônia multiparte\s+externa/);
  assert.match(text,/instalação\s+create-once/);
  assert.match(text,/não significa que o\s+piloto ou o uso de fundos estejam prontos/);
  assert.match(text,/Interrompa imediatamente se um comando retornar código diferente de zero/);
  assert.doesNotMatch(text,/risco zero|zero risk|auditoria externa obrigatória|external audit required/i);
});

test('all 33 routes use only current implementation statuses',()=>{
  assert.equal(plan.entries.length,33);
  const counts=Object.fromEntries([...new Set(plan.entries.map(row=>row.implementationStatus))]
    .map(status=>[status,plan.entries.filter(row=>row.implementationStatus===status).length]));
  assert.deepEqual(counts,{'external-operation':33});
  assert.ok(plan.entries.every(row=>!['missing-mpc-engine','missing-phase-integration'].includes(row.implementationStatus)));
});
