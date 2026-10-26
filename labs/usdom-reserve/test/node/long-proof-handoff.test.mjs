import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,readFile,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const repository=path.resolve(import.meta.dirname,'../../../..');
const checker=path.join(repository,'labs/usdom-reserve/scripts/check-long-proof-handoff.py');
const sha=value=>createHash('sha256').update(value).digest('hex');
const commit='a'.repeat(40),tree='b'.repeat(40),schema='UDCPST06';
const run=(directory,...extra)=>spawnSync('/usr/bin/python3',[checker,'--run-directory',directory,
 '--expected-source-commit',commit,'--expected-source-tree',tree,'--expected-proof-schema',schema,...extra],{encoding:'utf8'});

async function fixture({sourceCommit=commit,sourceTree=tree,proofSchema=schema,exitStatus=0}={}) {
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-proof-handoff-'));
 const manifest={schema:'usdom-long-proof-run-v1',pid:99999999,processStartTicks:'1',
  commandSha256:'c'.repeat(64),sourceCommit,sourceTree,proofSchema,startedUnix:'100'};
 const manifestRaw=Buffer.from(JSON.stringify(manifest)); await writeFile(path.join(root,'run-manifest.json'),manifestRaw);
 const receipt=Buffer.from('receipt'); const target=Buffer.from('target');
 await writeFile(path.join(root,'receipt.bin'),receipt); await writeFile(path.join(root,'target.bin'),target);
 const index={schema:'usdom-long-proof-receipt-index-v1',proofSchema,
  receipts:[{path:'receipt.bin',sha256:sha(receipt),status:'verified'}]};
 const status={schema:'usdom-long-proof-status-v1',complete:true,proofSchema,receiptCount:1,targetSha256:sha(target)};
 const indexRaw=Buffer.from(JSON.stringify(index)),statusRaw=Buffer.from(JSON.stringify(status));
 await writeFile(path.join(root,'receipt-index.json'),indexRaw); await writeFile(path.join(root,'status.json'),statusRaw);
 const terminal={schema:'usdom-long-proof-terminal-v1',runManifestSha256:sha(manifestRaw),exitStatus,
  finishedUnix:'200',receiptIndex:{path:'receipt-index.json',sha256:sha(indexRaw)},
  status:{path:'status.json',sha256:sha(statusRaw)},target:{path:'target.bin',sha256:sha(target)}};
 await writeFile(path.join(root,'terminal.json'),JSON.stringify(terminal)); return root;
}

test('authenticated current completion is promotable and emits one immutable handoff recipe',async()=>{
 const root=await fixture(),recipe=path.join(root,'handoff.json'); const result=run(root,'--recipe',recipe);
 assert.equal(result.status,0,result.stderr); const report=JSON.parse(result.stdout);
 assert.equal(report.classification,'current-complete'); assert.equal(report.releaseAllowed,true);
 assert.equal(report.promotionAllowed,true); assert.deepEqual(JSON.parse(await readFile(recipe)),report);
 const repeated=run(root,'--recipe',recipe); assert.notEqual(repeated.status,0); assert.match(repeated.stderr,/already exists/);
});

test('successful proof from an old source/schema is historical and can release without promotion',async()=>{
 const root=await fixture({sourceCommit:'d'.repeat(40),proofSchema:'UDCPST04'}); const result=run(root);
 assert.equal(result.status,0,result.stderr); const report=JSON.parse(result.stdout);
 assert.equal(report.classification,'historical-stale'); assert.equal(report.releaseAllowed,true);
 assert.equal(report.promotionAllowed,false);
});

test('authenticated nonzero exit is failed-stale and never promotable',async()=>{
 const root=await fixture({exitStatus:7}); const result=run(root); assert.equal(result.status,0,result.stderr);
 const report=JSON.parse(result.stdout); assert.equal(report.classification,'failed-stale');
 assert.equal(report.releaseAllowed,true); assert.equal(report.promotionAllowed,false);
});

test('receipt, index, status and target substitution fail closed',async()=>{
 for(const name of ['receipt.bin','receipt-index.json','status.json','target.bin']) {
  const root=await fixture(); await writeFile(path.join(root,name),'tampered');
  const result=run(root); assert.notEqual(result.status,0,name); assert.match(result.stderr,/refused/);
 }
});

test('a live authenticated process without terminal status remains active and locked',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-proof-active-'));
 const stat=await readFile(`/proc/${process.pid}/stat`,'utf8');
 const startTicks=stat.slice(stat.lastIndexOf(')')+2).split(' ')[19];
 const command=await readFile(`/proc/${process.pid}/cmdline`);
 const manifest={schema:'usdom-long-proof-run-v1',pid:process.pid,processStartTicks:startTicks,
  commandSha256:sha(command),sourceCommit:commit,sourceTree:tree,proofSchema:schema,startedUnix:'100'};
 await writeFile(path.join(root,'run-manifest.json'),JSON.stringify(manifest));
 const result=run(root); assert.equal(result.status,0,result.stderr); const report=JSON.parse(result.stdout);
 assert.equal(report.classification,'active'); assert.equal(report.releaseAllowed,false);
 assert.equal(report.promotionAllowed,false);
});

test('orphaned nonterminal record and terminal record for a live process are rejected',async()=>{
 let root=await mkdtemp(path.join(os.tmpdir(),'usdom-proof-orphan-'));
 await writeFile(path.join(root,'run-manifest.json'),JSON.stringify({schema:'usdom-long-proof-run-v1',pid:99999999,
  processStartTicks:'1',commandSha256:'c'.repeat(64),sourceCommit:commit,sourceTree:tree,proofSchema:schema,startedUnix:'100'}));
 let result=run(root); assert.notEqual(result.status,0); assert.match(result.stderr,/no live process/);
 root=await fixture(); const manifest=JSON.parse(await readFile(path.join(root,'run-manifest.json')));
 const stat=await readFile(`/proc/${process.pid}/stat`,'utf8'); manifest.pid=process.pid;
 manifest.processStartTicks=stat.slice(stat.lastIndexOf(')')+2).split(' ')[19];
 manifest.commandSha256=sha(await readFile(`/proc/${process.pid}/cmdline`));
 const raw=Buffer.from(JSON.stringify(manifest)); await writeFile(path.join(root,'run-manifest.json'),raw);
 const terminal=JSON.parse(await readFile(path.join(root,'terminal.json'))); terminal.runManifestSha256=sha(raw);
 await writeFile(path.join(root,'terminal.json'),JSON.stringify(terminal)); result=run(root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/still active/);
});
