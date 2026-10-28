import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {archiveClosedMainnetPhaseGeneration} from '../../sdk/closed-mainnet-phase-generation-archive.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const mkdir=value=>{fs.mkdirSync(value,{recursive:true,mode:0o700});fs.chmodSync(value,0o700);};
const testTemporaryRoot=fs.existsSync('/dev/shm')?'/dev/shm':os.tmpdir();
function fixture() {
  const base=fs.mkdtempSync(path.join(testTemporaryRoot,'usdom-phase-archive-')),privateRoot=path.join(base,'private'),publicDirectory=path.join(base,'public');
  mkdir(privateRoot); mkdir(publicDirectory); fs.chmodSync(publicDirectory,0o755);
  const operator=path.join(privateRoot,'operator-phases'),control=path.join(privateRoot,'control-plane'); mkdir(operator); mkdir(control);
  const script=Buffer.from('#!/usr/bin/env bash\ntrue\n'); fs.writeFileSync(path.join(operator,'prepare.sh'),script,{mode:0o600}); fs.writeFileSync(path.join(control,'evidence.json'),'{}\n',{mode:0o600});
  const artifact={phase:'prepare',ordinal:1,prerequisitePhases:[],generatedScriptSha256:sha(script),generatedScriptBytes:script.length};
  const plan={schema:'usdom-open-claims-execution-plan/v1',claimCount:33,phaseOrder:['prepare',...Array.from({length:20},(_,i)=>`unused-${i}`)],phaseArtifacts:[artifact,...Array.from({length:20},(_,i)=>({phase:`unused-${i}`,ordinal:i+2,prerequisitePhases:['prepare',...Array.from({length:i},(_,j)=>`unused-${j}`)],generatedScriptSha256:'0'.repeat(64),generatedScriptBytes:1}))],entries:[]};
  const bytes=Buffer.from(`${JSON.stringify(plan)}\n`),digest=sha(bytes),planPath=path.join(publicDirectory,`open-claims-execution-plan-v1-${digest}.json`); fs.writeFileSync(planPath,bytes,{mode:0o600}); fs.chmodSync(planPath,0o644);
  return {base,privateRoot,publicDirectory,operator,control,script,digest};
}
test('phase generation is fully archived before fixed paths are reset',()=>{
  const base=fs.mkdtempSync(path.join(testTemporaryRoot,'usdom-phase-archive-')),privateRoot=path.join(base,'private'),publicDirectory=path.join(base,'public');
  try {
    mkdir(privateRoot); mkdir(publicDirectory); fs.chmodSync(publicDirectory,0o755); const operator=path.join(privateRoot,'operator-phases'),control=path.join(privateRoot,'control-plane'); mkdir(operator); mkdir(control);
    const script=Buffer.from('#!/usr/bin/env bash\ntrue\n'); fs.writeFileSync(path.join(operator,'prepare.sh'),script,{mode:0o600});
    fs.writeFileSync(path.join(control,'evidence.json'),'{}\n',{mode:0o600});
    const artifact={phase:'prepare',ordinal:1,prerequisitePhases:[],generatedScriptSha256:sha(script),generatedScriptBytes:script.length};
    const plan={schema:'usdom-open-claims-execution-plan/v1',claimCount:33,phaseOrder:['prepare',...Array.from({length:20},(_,i)=>`unused-${i}`)],phaseArtifacts:[artifact,...Array.from({length:20},(_,i)=>({phase:`unused-${i}`,ordinal:i+2,prerequisitePhases:['prepare',...Array.from({length:i},(_,j)=>`unused-${j}`)],generatedScriptSha256:'0'.repeat(64),generatedScriptBytes:1}))],entries:[]};
    const bytes=Buffer.from(`${JSON.stringify(plan)}\n`),digest=sha(bytes),planPath=path.join(publicDirectory,`open-claims-execution-plan-v1-${digest}.json`); fs.writeFileSync(planPath,bytes,{mode:0o600}); fs.chmodSync(planPath,0o644);
    const result=archiveClosedMainnetPhaseGeneration({privateRoot,publicDirectory});
    assert.equal(result.planSha256,digest); assert.deepEqual(fs.readdirSync(operator),[]); assert.deepEqual(fs.readdirSync(control),[]);
    assert.equal(fs.readFileSync(path.join(result.archive,'operator-phases/prepare.sh'),'utf8'),script.toString());
    assert.equal(fs.readFileSync(path.join(result.archive,'control-plane/evidence.json'),'utf8'),'{}\n');
    assert.equal(fs.readFileSync(path.join(result.archive,'original-operator-phases/prepare.sh'),'utf8'),script.toString());
    assert.equal(fs.readFileSync(path.join(result.archive,'original-control-plane/evidence.json'),'utf8'),'{}\n');
    const manifest=JSON.parse(fs.readFileSync(path.join(result.archive,'archive.json'))); assert.equal(manifest.entries.length,2);
  } finally { fs.rmSync(base,{recursive:true,force:true}); }
});

test('unsafe links are rejected without changing source generation',()=>{
  const base=fs.mkdtempSync(path.join(testTemporaryRoot,'usdom-phase-archive-')),privateRoot=path.join(base,'private'),publicDirectory=path.join(base,'public');
  try { mkdir(privateRoot); mkdir(publicDirectory); fs.chmodSync(publicDirectory,0o755); mkdir(path.join(privateRoot,'operator-phases')); mkdir(path.join(privateRoot,'control-plane')); fs.symlinkSync('/etc/passwd',path.join(privateRoot,'operator-phases/bad.sh'));
    assert.throws(()=>archiveClosedMainnetPhaseGeneration({privateRoot,publicDirectory}),/unsafe generation entry/); assert.ok(fs.lstatSync(path.join(privateRoot,'operator-phases/bad.sh')).isSymbolicLink());
  } finally { fs.rmSync(base,{recursive:true,force:true}); }
});
test('inventory rejects hardlinked generation files',()=>{const value=fixture();try{const original=path.join(value.control,'evidence.json'),alias=path.join(value.control,'alias.json');fs.linkSync(original,alias);assert.throws(()=>archiveClosedMainnetPhaseGeneration(value),/unsafe generation entry/)}finally{fs.rmSync(value.base,{recursive:true,force:true})}});

test('materialization and execution retain and revalidate generation locks',()=>{
  const root=path.resolve(import.meta.dirname,'../..');
  const materializer=fs.readFileSync(path.join(root,'scripts/materialize-closed-mainnet-phase-script.sh'),'utf8');
  const generator=fs.readFileSync(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8');
  const checker=fs.readFileSync(path.join(root,'scripts/check-closed-mainnet-phase-dependency.mjs'),'utf8');
  assert.match(materializer,/exec 10<"\$private_root"[\s\S]*flock -n 10/);
  assert.ok((materializer.match(/realpath -e \/proc\/\$\$\/fd\/9/g)??[]).length>=3);
  assert.ok((materializer.match(/realpath -e \/proc\/\$\$\/fd\/10/g)??[]).length>=3);
  assert.match(materializer,/candidate_identity=[\s\S]*candidate_sha256=[\s\S]*check-closed-mainnet-phase-dependency[\s\S]*stat -c '%u:%d:%i:%a:%h:%s'/);
  assert.match(generator,/exec 7<"\\\$USDOM_MAINNET_PRIVATE_ROOT"[\s\S]*flock -n 7/);
  assert.match(generator,/USDOM_PILOT_PHASE_LOCK_DEVICE[\s\S]*USDOM_PILOT_PHASE_LOCK_INODE/);
  assert.ok((generator.match(/check-closed-mainnet-phase-dependency\.mjs/g)??[]).length===2);
  assert.match(checker,/USDOM_PILOT_PHASE_LOCK_DEVICE[\s\S]*USDOM_PILOT_PHASE_LOCK_INODE/);
});

test('every durable fault boundary is recovered by retry and the result is idempotent',()=>{
  const points=['journal','stage-created','operator-frozen','control-frozen','operator-reset','control-reset','identity','operator-copied','control-copied','manifest','verified','published','last-marker','committed'];
  for(const point of points) {
    const value=fixture(); let injected=false;
    try {
      assert.throws(()=>archiveClosedMainnetPhaseGeneration({...value,faultInjection:at=>{if(at===point&&!injected){injected=true;throw new Error(`fault:${point}`);}}}),new RegExp(`fault:${point}`));
      const recovered=archiveClosedMainnetPhaseGeneration(value),again=archiveClosedMainnetPhaseGeneration(value);
      assert.ok(fs.existsSync(path.join(recovered.archive,'archive.json')),point); assert.equal(again.archive,recovered.archive,point); assert.equal(again.idempotent,true,point);
      const manifest=JSON.parse(fs.readFileSync(path.join(recovered.archive,'archive.json'))); assert.equal(manifest.schema,'usdom-closed-mainnet-phase-generation-archive/v2');
    } finally { fs.rmSync(value.base,{recursive:true,force:true}); }
  }
});

test('frozen originals defeat same-size TOCTOU and separate repeated generations',()=>{
  const value=fixture();
  try {
    const first=archiveClosedMainnetPhaseGeneration(value),original=fs.readFileSync(path.join(first.archive,'original-operator-phases/prepare.sh')),copy=fs.readFileSync(path.join(first.archive,'operator-phases/prepare.sh'));
    assert.deepEqual(copy,original);
    fs.writeFileSync(path.join(value.operator,'prepare.sh'),value.script,{mode:0o600}); fs.writeFileSync(path.join(value.control,'evidence.json'),'{}\n',{mode:0o600});
    const second=archiveClosedMainnetPhaseGeneration(value); assert.notEqual(second.archiveId,first.archiveId); assert.ok(fs.existsSync(first.archive)); assert.ok(fs.existsSync(second.archive));
  } finally { fs.rmSync(value.base,{recursive:true,force:true}); }
});

test('archive implementation durably syncs files and directory rename boundaries',()=>{
  const source=fs.readFileSync(new URL('../../sdk/closed-mainnet-phase-generation-archive.mjs',import.meta.url),'utf8');
  assert.match(source,/fs\.fsyncSync/); assert.match(source,/fs\.renameSync\(stage,destination\);sync\(ar,true\)/); assert.match(source,/sync\(to\)/); assert.match(source,/sync\(path\.dirname\(p\),true\)/);
  assert.match(source,/O_NOFOLLOW/);assert.match(source,/namedAfter/);assert.doesNotMatch(source,/existsSync\(ip\)/);
});

test('partial authority JSON writes recover without accepting partial bytes',()=>{
  for(const point of ['journal-written','manifest-written','last-written']) {
    const value=fixture();let injected=false;
    try {
      assert.throws(()=>archiveClosedMainnetPhaseGeneration({...value,faultInjection:at=>{if(at===point&&!injected){injected=true;throw new Error(point)}}}),new RegExp(point));
      const recovered=archiveClosedMainnetPhaseGeneration(value);assert.ok(fs.existsSync(path.join(recovered.archive,'archive.json')),point);
    } finally {fs.rmSync(value.base,{recursive:true,force:true});}
  }
});

test('authority files reject traversal, symlink and hardlink substitution',()=>{
  const value=fixture();
  try {
    const result=archiveClosedMainnetPhaseGeneration(value),root=path.join(value.privateRoot,'phase-generation-archive'),last=path.join(root,'last-completed.json');
    fs.writeFileSync(last,JSON.stringify({schema:'usdom-closed-mainnet-phase-generation-last/v1',archiveId:`../${result.archiveId}`})+'\n',{mode:0o600});
    assert.throws(()=>archiveClosedMainnetPhaseGeneration(value),/invalid last completed archive/);
    fs.unlinkSync(last);fs.symlinkSync(path.join(result.archive,'archive.json'),last);assert.throws(()=>archiveClosedMainnetPhaseGeneration(value),/unsafe last completed/);
    fs.unlinkSync(last);fs.linkSync(path.join(result.archive,'archive.json'),last);assert.throws(()=>archiveClosedMainnetPhaseGeneration(value),/unsafe last completed/);
  } finally {fs.rmSync(value.base,{recursive:true,force:true});}
});

test('recovery rejects reset substitution and a new generation after staging loss',()=>{
  for(const point of ['reset-identities','operator-frozen']) {
    const value=fixture();let injected=false;
    try {
      assert.throws(()=>archiveClosedMainnetPhaseGeneration({...value,faultInjection:at=>{if(at===point&&!injected){injected=true;throw new Error(point)}}}),new RegExp(point));
      if(point==='reset-identities') {fs.renameSync(value.operator,value.operator+'.replaced');mkdir(value.operator);assert.throws(()=>archiveClosedMainnetPhaseGeneration(value),/substituted/);}
      else {fs.rmSync(path.join(value.privateRoot,'phase-generation-archive','.transaction'),{recursive:true,force:true});mkdir(value.operator);fs.writeFileSync(path.join(value.operator,'new.sh'),'new\n',{mode:0o600});assert.throws(()=>archiveClosedMainnetPhaseGeneration(value),/identity changed|lost its staging/);}
    } finally {fs.rmSync(value.base,{recursive:true,force:true});}
  }
});
