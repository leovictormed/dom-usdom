import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmod,link,mkdir,mkdtemp,readFile,symlink,writeFile} from 'node:fs/promises';
import os from 'node:os'; import path from 'node:path';
import {spawnSync} from 'node:child_process'; import test from 'node:test';
import {validateReleaseValidationReport} from '../../sdk/release-validation-report.mjs';
const repo=path.resolve(import.meta.dirname,'../../../..');
const script=path.join(repo,'labs/usdom-reserve/scripts/materialize-usdom-release-validation-report.py');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const sorted=value=>Array.isArray(value)?value.map(sorted):value&&typeof value==='object'
  ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,sorted(value[key])])):value;
const canonical=value=>Buffer.from(JSON.stringify(sorted(value))+'\n');
const sourceCommit='12'.repeat(20), sourceTag='usdom-v1.0.0', releaseId='release-vector-test';
const definitions={
 checkpoint390:{package:'dom-usdom-checkpoint-program',test:'full_360_plus_30_v2_checkpoint_extension_is_recomputed',success:'test full_360_plus_30_v2_checkpoint_extension_is_recomputed ... ok',extra:['--features','host-reference','--test','v2_checkpoint_extension'],inputs:['crates/dom-usdom-checkpoint-program/Cargo.toml','crates/dom-usdom-checkpoint-program/src/economic_chunks.rs','crates/dom-usdom-checkpoint-program/src/lib.rs','crates/dom-usdom-checkpoint-program/src/outer.rs','crates/dom-usdom-checkpoint-program/src/portable.rs','crates/dom-usdom-checkpoint-program/src/reference.rs','crates/dom-usdom-checkpoint-program/src/source.rs','crates/dom-usdom-checkpoint-program/src/sync_attestation.rs','crates/dom-usdom-checkpoint-program/tests/v2_checkpoint_extension.rs','crates/dom-usdom-checkpoint-statement/Cargo.toml','crates/dom-usdom-checkpoint-statement/src/lib.rs','crates/dom-usdom-state/Cargo.toml','crates/dom-usdom-state/src/lib.rs','crates/dom-usdom-state/src/sparse.rs']},
 randomxCache:{package:'dom-usdom-randomx-portable',test:'dataset::tests::upstream_randomx_argon2d_cache_vector_matches',success:'test dataset::tests::upstream_randomx_argon2d_cache_vector_matches ... ok',extra:[],inputs:['crates/dom-usdom-randomx-portable/Cargo.toml','crates/dom-usdom-randomx-portable/src/bytecode.rs','crates/dom-usdom-randomx-portable/src/dataset.rs','crates/dom-usdom-randomx-portable/src/lib.rs','crates/dom-usdom-randomx-portable/src/superscalar.rs']},
 nativePrivacy:{package:'dom-usdom-privacy',test:'phase1::tests::production_specialization_matches_real_prover_and_all_public_inputs',success:'test phase1::tests::production_specialization_matches_real_prover_and_all_public_inputs ... ok',extra:[],inputs:['crates/dom-usdom-privacy/Cargo.toml','crates/dom-usdom-privacy/MANIFEST.sha256','crates/dom-usdom-privacy/src/circuit.rs','crates/dom-usdom-privacy/src/ceremony.rs','crates/dom-usdom-privacy/src/lib.rs','crates/dom-usdom-privacy/src/phase1.rs','crates/dom-usdom-privacy/src/verifier.rs']},
};
async function fixture(){
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-release-results-')); const jobs=path.join(root,'jobs'),state=path.join(root,'state'),runs=path.join(state,'runs');
 await mkdir(jobs,{mode:0o700}); await mkdir(runs,{recursive:true,mode:0o700}); await chmod(root,0o700); await chmod(state,0o700); await chmod(runs,0o700);
 const evidencePath=path.join(root,'release.json'); await writeFile(evidencePath,canonical({schema:1,releaseId,sourceCommit,sourceTag}),{mode:0o600});
 const toolchainBytes=await readFile(path.join(repo,'labs/usdom-reserve/config/mainnet-toolchain-lock.json')); const lock=JSON.parse(toolchainBytes);
 const cargo=lock.executables.find(value=>value.name==='cargo'),rustc=lock.executables.find(value=>value.name==='rustc');
 const ids={};
 for(const [index,[kind,definition]] of Object.entries(definitions).entries()){
  const inputs=[]; for(const relative of ['Cargo.toml','Cargo.lock','rust-toolchain.toml','labs/usdom-reserve/config/mainnet-toolchain-lock.json',...definition.inputs]) {const bytes=await readFile(path.join(repo,relative));inputs.push({path:relative,sha256:sha(bytes),maxBytes:bytes.length});}
  const argv=[cargo.realpath,'test','--profile','release-validation','--locked','--offline','-j1','-p',definition.package,...definition.extra,definition.test,'--','--exact','--ignored','--nocapture','--test-threads=1'];
  const markers=[definition.success,'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;'];
  const job={schema:'usdom-supervised-proof-command-v2',nonce:'34'.repeat(16),createdUnix:1,argv,cwd:repo,executableSha256:cargo.sha256,
   environment:{CARGO_HOME:path.join(os.homedir(),'.cargo'),RUSTUP_HOME:path.join(os.homedir(),'.rustup'),RUSTC:rustc.realpath,
    CARGO_TARGET_DIR:path.join(os.homedir(),'.local/state/usdom-proof/target-release-validation'),CARGO_INCREMENTAL:'0',
    USDOM_RELEASE_ID:releaseId,USDOM_SOURCE_COMMIT:sourceCommit,USDOM_SOURCE_TAG:sourceTag},inputs,
   limits:{maxLogBytes:67108864,maxRuntimeSeconds:kind==='randomxCache'?14400:43200,minFreeBytes:21474836480},requiredOutput:markers};
  const jobRaw=canonical(job),id=sha(jobRaw); ids[kind]=id; await writeFile(path.join(jobs,`${id}.json`),jobRaw,{mode:0o400});
  const dir=path.join(runs,id); await mkdir(dir,{mode:0o700});
  const supervisorPath=path.join(repo,'labs/usdom-reserve/scripts/run-supervised-long-proof.py');
  const startHour=10+index,finishHour=11+index;
  const run={schema:'usdom-supervised-proof-run-v1',runId:id,commandManifestSha256:id,runnerPid:999999,runnerStartTicks:'1',startedAt:`2026-10-27T${startHour}:00:00Z`,bootId:'12345678-1234-1234-1234-123456789abc',systemdInvocationId:'56'.repeat(16),supervisorSha256:sha(await readFile(supervisorPath)),supervisorPath};
  const runRaw=canonical(run); await writeFile(path.join(dir,'run.json'),runRaw,{mode:0o400});
  const log=Buffer.from(`${markers[0]}\n${markers[1]}\n`); await writeFile(path.join(dir,'process.log'),log,{mode:0o400});
  const eventValues=[{at:`2026-10-27T${startHour}:00:00Z`,event:'runner-started',runnerPid:run.runnerPid,systemdInvocationId:run.systemdInvocationId},{at:`2026-10-27T${startHour}:00:01Z`,event:'child-started',childPid:999998,childStartTicks:'2'},{at:`2026-10-27T${finishHour}:00:00Z`,event:'runner-terminal',exitStatus:0,childSignal:null,supervisorSignal:null,stopRequestSha256:null}];
  const events=Buffer.concat(eventValues.map(canonical)); await writeFile(path.join(dir,'events.jsonl'),events,{mode:0o400});
  const terminal={schema:'usdom-supervised-proof-terminal-v1',runId:id,runSha256:sha(runRaw),processLogSha256:sha(log),eventsSha256:sha(events),finishedAt:`2026-10-27T${finishHour}:00:00Z`,exitStatus:0,childSignal:null,supervisorSignal:null,signalSender:null,stopRequestSha256:null};
  await writeFile(path.join(dir,'terminal.json'),canonical(terminal),{mode:0o400});
 }
 const args=[script,'--repository',repo,'--jobs-directory',jobs,'--state-root',state,'--release-evidence',evidencePath,'--output',path.join(root,'report.json'),
  '--checkpoint390-run-id',ids.checkpoint390,'--randomxCache-run-id',ids.randomxCache,'--nativePrivacy-run-id',ids.nativePrivacy];
 return {root,jobs,state,evidencePath,ids,args,toolchainBytes,lock};
}
test('materializer authenticates and release-binds exactly three complete supervised results',async()=>{
 const f=await fixture(),result=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(result.status,0,result.stderr);
 const raw=await readFile(path.join(f.root,'report.json')),report=JSON.parse(raw); assert.equal(result.stdout.trim(),sha(raw));
 const cargoLockSha256=f.lock.files.find(value=>value.path==='../../Cargo.lock').sha256;
 assert.equal(validateReleaseValidationReport(report,{releaseEvidence:{releaseId,sourceCommit,sourceTag},toolchainLockSha256:sha(f.toolchainBytes),cargoLockSha256}),true);
});
test('hardlinked terminal evidence and symlinked command manifests fail closed',async()=>{
 let f=await fixture(); await link(path.join(f.state,'runs',f.ids.checkpoint390,'terminal.json'),path.join(f.root,'alias'));
 let result=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(result.status,125); assert.match(result.stderr,/unsafe evidence file/);
 f=await fixture(); const job=path.join(f.jobs,`${f.ids.randomxCache}.json`),target=path.join(f.root,'job-copy'); await writeFile(target,await readFile(job)); await chmod(job,0o600);
 await import('node:fs/promises').then(({unlink})=>unlink(job)); await symlink(target,job);
 result=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(result.status,125); assert.match(result.stderr,/symbolic link|Too many levels|unsafe evidence/i);
});
test('partial success, ambiguous output and cross-release replay cannot produce a report',async()=>{
 let f=await fixture(); const terminal=path.join(f.state,'runs',f.ids.nativePrivacy,'terminal.json'); await chmod(terminal,0o600); await writeFile(terminal,Buffer.from('{'));
 let result=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(result.status,125);
 f=await fixture(); const evidence={schema:1,releaseId:'another-release',sourceCommit,sourceTag}; await writeFile(f.evidencePath,canonical(evidence));
 result=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(result.status,125); assert.match(result.stderr,/release\/toolchain environment mismatch/);
});
test('a successful child outside the pinned systemd invocation cannot be promoted',async()=>{
 const f=await fixture(),dir=path.join(f.state,'runs',f.ids.checkpoint390);
 const runPath=path.join(dir,'run.json'),terminalPath=path.join(dir,'terminal.json');
 const run=JSON.parse(await readFile(runPath)); run.systemdInvocationId=null;
 const runRaw=canonical(run); await chmod(runPath,0o600); await writeFile(runPath,runRaw); await chmod(runPath,0o400);
 const terminal=JSON.parse(await readFile(terminalPath)); terminal.runSha256=sha(runRaw);
 await chmod(terminalPath,0o600); await writeFile(terminalPath,canonical(terminal)); await chmod(terminalPath,0o400);
 const result=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'});
 assert.equal(result.status,125); assert.match(result.stderr,/supervisor\/systemd identity mismatch/);
});
test('event history must exactly bind the supervised run, child and terminal chronology',async()=>{
 const f=await fixture(),dir=path.join(f.state,'runs',f.ids.checkpoint390);
 const eventsPath=path.join(dir,'events.jsonl'),terminalPath=path.join(dir,'terminal.json');
 const events=(await readFile(eventsPath,'utf8')).trimEnd().split('\n').map(JSON.parse);
 events[0].runnerPid=7;
 const eventBytes=Buffer.concat(events.map(canonical));
 await chmod(eventsPath,0o600); await writeFile(eventsPath,eventBytes); await chmod(eventsPath,0o400);
 const terminal=JSON.parse(await readFile(terminalPath)); terminal.eventsSha256=sha(eventBytes);
 await chmod(terminalPath,0o600); await writeFile(terminalPath,canonical(terminal)); await chmod(terminalPath,0o400);
 const result=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'});
 assert.equal(result.status,125); assert.match(result.stderr,/event schema or run binding is invalid/);
});
test('readiness report validator rejects replay, overlap, null hashes, toolchain drift and partial vectors',async()=>{
 const base={schema:'usdom-release-validation-report/v1',status:'passed',releaseId,sourceCommit,sourceTag,toolchainLockSha256:sha('tools'),cargoLockSha256:sha('lock'),runs:Object.keys(definitions).map((kind,index)=>({kind,runId:sha(`id${index}`),commandManifestSha256:sha(`id${index}`),runSha256:sha(`run${index}`),terminalSha256:sha(`terminal${index}`),processLogSha256:sha(`log${index}`),eventsSha256:sha(`events${index}`),supervisorSha256:sha('supervisor'),startedAt:`2026-10-27T${10+index}:00:00Z`,finishedAt:`2026-10-27T${11+index}:00:00Z`}))};
 const context={releaseEvidence:{releaseId,sourceCommit,sourceTag},toolchainLockSha256:sha('tools'),cargoLockSha256:sha('lock')}; assert.equal(validateReleaseValidationReport(base,context),true);
 for(const mutate of [value=>value.runs.pop(),value=>value.runs[1].runId=value.runs[0].runId,
  value=>value.runs[1].eventsSha256='0'.repeat(64),
  value=>{value.runs[1].startedAt='2026-10-27T10:59:59Z';},
  value=>value.sourceCommit='56'.repeat(20),value=>value.toolchainLockSha256=sha('other'),
  value=>{value.toolchainLockSha256='0'.repeat(64); value.cargoLockSha256='0'.repeat(64);},]){
  const value=structuredClone(base); mutate(value); assert.throws(()=>validateReleaseValidationReport(value,context));
 }
});
test('closed-mainnet readiness cannot omit or bypass the authenticated vector report',async()=>{
 const [assessor,checker,schema,template,materializer,pkg]=await Promise.all([
  readFile(path.join(repo,'labs/usdom-reserve/sdk/mainnet-readiness.mjs'),'utf8'),
  readFile(path.join(repo,'labs/usdom-reserve/scripts/check-mainnet-readiness.mjs'),'utf8'),
  readFile(path.join(repo,'labs/usdom-reserve/sdk/release-evidence-schema.mjs'),'utf8'),
  readFile(path.join(repo,'labs/usdom-reserve/config/mainnet-release-evidence.unconfigured.json'),'utf8'),
  readFile(path.join(repo,'labs/usdom-reserve/scripts/materialize-usdom-release-validation-evidence.mjs'),'utf8'),
  readFile(path.join(repo,'labs/usdom-reserve/package.json'),'utf8'),
 ]);
 assert.match(assessor,/const evidenceDocuments = \[[\s\S]*'releaseValidationReport'/);
 assert.match(assessor,/validateReleaseValidationReport\(reconstructed/);
 assert.match(assessor,/descriptor-bound release validation authority is unavailable/);
 assert.match(checker,/reconstructReleaseValidation/);
 assert.match(checker,/evidence\.releaseValidationReport/);
 assert.match(checker,/toolchainLockSha256,cargoLockSha256/);
 assert.match(schema,/'releaseValidationReport'/);
 assert.equal(JSON.parse(template).releaseValidationReport,null);
 for(const token of ['validateReleaseSourceBoundary','validateReleaseValidationReport',
  'releaseValidationReport:reference','writePrivateFileDurable','assertExecutableUnchanged',
  'collectReleaseEvidenceDocumentPaths',
  "Git HEAD output is not exactly one lowercase commit plus LF"]) {
  assert.match(materializer,new RegExp(token));
 }
 assert.equal(JSON.parse(pkg).scripts['materialize:release-validation-evidence'],
  'node scripts/materialize-usdom-release-validation-evidence.mjs');
});
