import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmod, link, mkdir, mkdtemp, readFile, readdir, realpath, stat, writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import test from 'node:test';

const repository=path.resolve(import.meta.dirname,'../../../..');
const orchestrator=path.join(repository,'labs/usdom-reserve/scripts/orchestrate-checkpoint-rebuild.py');
const sha=value=>createHash('sha256').update(value).digest('hex');
const fileSha=async value=>sha(await readFile(value));
const run=(argv,cwd)=>spawnSync('/usr/bin/python3',[orchestrator,...argv],{cwd,encoding:'utf8'});
const git=(cwd,...argv)=>{
 const result=spawnSync('git',argv,{cwd,encoding:'utf8'});
 assert.equal(result.status,0,result.stderr); return result.stdout.trim();
};

async function fixture({stale=false,priorReceipt=false,failGate=false,raceOutput=false,mutateInput=false,undeclared=false,badClaims=false,receiptStep=false,stepMutates=false,stepRollback=false}={}) {
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-rebuild-test-'));
 const repo=path.join(root,'repo');
 const output=path.join(root,'published');
 git(root,'init','-q',repo); git(repo,'config','user.name','Test'); git(repo,'config','user.email','test@example.invalid');
 const helper=path.join(repo,'stage.py');
 await writeFile(helper,`#!/usr/bin/python3
import os,pathlib,sys
name,out,*rest=sys.argv[1:]
root=pathlib.Path('.')
order=['segment','pin-segment','outer','pin-outer','finalized-burn','pin-finalized-burn','receipts','gate']
i=order.index(name)
if os.environ.get('CARGO_NET_OFFLINE')!='true': raise SystemExit(18)
if not pathlib.Path(os.environ.get('CARGO_HOME','')).joinpath('registry-index').is_file(): raise SystemExit(19)
if not os.path.isabs(os.environ.get('RUSTC','')) or not os.path.isabs(os.environ.get('RUSTDOC','')): raise SystemExit(17)
if i and not (root/(order[i-1]+'.out')).is_file(): raise SystemExit(20)
expected={} if not i else {order[i-1]+'.out':__import__('hashlib').sha256((root/(order[i-1]+'.out')).read_bytes()).hexdigest()}
if __import__('json').loads(os.environ.get('USDOM_AUTHENTICATED_STAGE_INPUTS','null')) != expected: raise SystemExit(22)
if name=='gate' and rest==['fail']: raise SystemExit(21)
if name=='gate' and len(rest)==2 and rest[0]=='race': pathlib.Path(rest[1]).mkdir()
${mutateInput ? "\nif name=='pin-segment': (root/'segment.out').write_text('substituted\\n')" : ""}
${undeclared ? "\nif name=='pin-segment': (root/'undeclared').write_text('side effect\\n')" : ""}
target=root/out
${stale ? "\nif name!='segment': target.write_text(name+'\\n')" : "\ntarget.write_text(name+'\\n')"}
claims={
'segment':['programDecoded','imageIdRecomputed','elfProgramPaired'],
'pin-segment':['predecessorHashesMatched','consumerImageIdPinned'],
'outer':['programDecoded','imageIdRecomputed','segmentImageIdMatched','journalSchemaMatched'],
'pin-outer':['predecessorHashesMatched','consumerImageIdPinned'],
'finalized-burn':['programDecoded','imageIdRecomputed','outerImageIdMatched','journalSchemaMatched'],
'pin-finalized-burn':['predecessorHashesMatched','solidityImageIdPinned'],
'receipts':['receiptsCryptographicallyVerified','methodImageIdsMatched','journalDigestsMatched','elfReceiptPairsMatched'],
'gate':['completeGraphMatched','solidityVerifierConstantsMatched','publicationReady']}[name]
report={'schema':'usdom-rebuild-stage-verification-v1','stage':name,
'inputs':expected,'outputs':{out:__import__('hashlib').sha256(target.read_bytes()).hexdigest()},
'claims':{item:True for item in claims}}
${badClaims ? "\nif name=='receipts': report['claims']['journalDigestsMatched']=False" : ""}
(root/(name+'.verification.json')).write_text(__import__('json').dumps(report))
`,{mode:0o755});
 const verifier=path.join(repo,'verify-stage');
 await writeFile(verifier,`#!/usr/bin/python3
import hashlib,json,os,pathlib,sys
name,record,*rest=sys.argv[1:]
inputs=json.loads(os.environ['USDOM_AUTHENTICATED_STAGE_INPUTS'])
outputs=json.loads(os.environ['USDOM_AUTHENTICATED_STAGE_OUTPUTS'])
for item,digest in {**inputs,**outputs}.items():
 if hashlib.sha256(pathlib.Path(item).read_bytes()).hexdigest()!=digest: raise SystemExit(31)
claims={
'segment':['programDecoded','imageIdRecomputed','elfProgramPaired'],
'pin-segment':['predecessorHashesMatched','consumerImageIdPinned'],
'outer':['programDecoded','imageIdRecomputed','segmentImageIdMatched','journalSchemaMatched'],
'pin-outer':['predecessorHashesMatched','consumerImageIdPinned'],
'finalized-burn':['programDecoded','imageIdRecomputed','outerImageIdMatched','journalSchemaMatched'],
'pin-finalized-burn':['predecessorHashesMatched','solidityImageIdPinned'],
'receipts':['receiptsCryptographicallyVerified','methodImageIdsMatched','journalDigestsMatched','elfReceiptPairsMatched'],
'gate':['completeGraphMatched','solidityVerifierConstantsMatched','publicationReady']}[name]
report={'schema':'usdom-rebuild-stage-verification-v1','stage':name,'inputs':inputs,'outputs':outputs,'claims':{x:True for x in claims}}
if rest==['false-journal']: report['claims']['journalDigestsMatched']=False
pathlib.Path(record).write_text(json.dumps(report))
`,{mode:0o755});
 const receiptVerifier=path.join(repo,'verify-one');
 await writeFile(receiptVerifier,`#!/usr/bin/python3
import pathlib,sys
${stepMutates ? "pathlib.Path('receipts.out').write_text('mixed generation\\n')" : ""}
${stepRollback ? "pathlib.Path('pin-finalized-burn.out').write_text('rolled back predecessor\\n')" : ""}
pathlib.Path(sys.argv[1]).open('x').write('verified receipt\\n')
`,{mode:0o755});
 if(stale) await writeFile(path.join(repo,'segment.out'),'old\n');
 if(priorReceipt) await writeFile(path.join(repo,'receipts.out'),'valid old receipt\n');
 git(repo,'add','.'); git(repo,'commit','-qm','fixture');
 const python=await realpath('/usr/bin/python3');
 const cache=path.join(root,'cargo-home'); await mkdir(cache,{mode:0o700});
 const cacheFile=path.join(cache,'registry-index'); await writeFile(cacheFile,'offline fixture\n',{mode:0o400});
 const cacheManifestPath=path.join(root,'cargo-home-manifest.json');
 const cacheManifest={schema:'usdom-offline-cache-manifest-v1',root:cache,entries:[{
  path:'registry-index',sha256:await fileSha(cacheFile),size:(await readFile(cacheFile)).length,mode:0o400,
 }]};
 await writeFile(cacheManifestPath,JSON.stringify(cacheManifest));
 await chmod(cache,0o500);
 const order=['segment','pin-segment','outer','pin-outer','finalized-burn','pin-finalized-burn','receipts','gate'];
 const stages=order.map((name,index)=>({
  name,argv:[python,'stage.py',name,`${name}.out`,
   ...(name==='gate'&&failGate?['fail']:name==='gate'&&raceOutput?['race',output]:[])],
  inputs:index?[`${order[index-1]}.out`]:[],outputs:[`${name}.out`],
  verificationSteps:receiptStep&&name==='receipts'?[{argv:[receiptVerifier,'receipt.verify'],outputs:['receipt.verify']}]:[],
  verification:`${name}.verification.json`,
  verificationArgv:[verifier,name,`${name}.verification.json`,
   ...(badClaims&&name==='receipts'?['false-journal']:[])],
 }));
 const manifest={schema:'usdom-checkpoint-rebuild-orchestrator-v3',sourceCommit:git(repo,'rev-parse','HEAD'),
  sourceTree:git(repo,'rev-parse','HEAD^{tree}'),tools:[
   {path:python,sha256:await fileSha(python)},{path:verifier,sha256:await fileSha(verifier)},
   {path:receiptVerifier,sha256:await fileSha(receiptVerifier)}],
  environment:{cargoHome:cache,cargoHomeManifest:cacheManifestPath,
   cargoHomeManifestSha256:await fileSha(cacheManifestPath),rustc:python,rustdoc:python},stages};
 const manifestPath=path.join(root,'manifest.json');
 await writeFile(manifestPath,JSON.stringify(manifest));
 const handoffPath=path.join(root,'handoff.json');
 const handoff={schema:'usdom-long-proof-handoff-v1',classification:'historical-stale',
  releaseAllowed:true,promotionAllowed:false,runManifestSha256:'1'.repeat(64),
  terminalSha256:'2'.repeat(64),proofSchema:'UDCPST04',reason:'authenticated historical fixture'};
 await writeFile(handoffPath,JSON.stringify(handoff));
 return {root,repo,manifestPath,manifestSha:await fileSha(manifestPath),output,
  handoffPath,handoffSha:await fileSha(handoffPath),lock:path.join(root,'rebuild.lock')};
}

const args=value=>['--manifest',value.manifestPath,'--expected-manifest-sha256',value.manifestSha,
 '--handoff-recipe',value.handoffPath,'--expected-handoff-sha256',value.handoffSha,
 '--repository',value.repo,'--output',value.output,'--lock',value.lock];

test('dry-run validates pinned source, tools and exact stage order without publishing',async()=>{
 const value=await fixture(); const result=run([...args(value),'--dry-run'],value.root);
 assert.equal(result.status,0,result.stderr); const report=JSON.parse(result.stdout);
 assert.deepEqual(report.stages,['segment','pin-segment','outer','pin-outer','finalized-burn','pin-finalized-burn','receipts','gate']);
 assert.equal(report.published,false);
});

test('successful rebuild is isolated and published as one immutable candidate directory',async()=>{
 const value=await fixture(); const result=run(args(value),value.root);
 assert.equal(result.status,0,result.stderr); assert.equal(JSON.parse(result.stdout).published,true);
 for(const name of ['segment','pin-segment','outer','pin-outer','finalized-burn','pin-finalized-burn','receipts','gate']) {
  assert.equal(await readFile(path.join(value.output,'candidate',`${name}.out`),'utf8'),`${name}\n`);
 }
 assert.equal((await stat(value.output)).mode&0o777,0o500);
 assert.equal((await stat(path.join(value.output,'REBUILD-RESULT.json'))).mode&0o777,0o400);
 assert.equal(JSON.parse(await readFile(path.join(value.output,'REBUILD-RESULT.json'))).published,true);
 const repeat=run(args(value),value.root); assert.notEqual(repeat.status,0); assert.match(repeat.stderr,/refuses overwrite/);
});

test('failed final gate preserves authenticated work and retry skips completed producers',async()=>{
 const value=await fixture({failGate:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/returned non-zero exit status 21/);
 const probe=spawnSync('test',['!','-e',value.output]); assert.equal(probe.status,0);
 const workspace=path.join(value.root,'.published.resume-v3');
 const segment=path.join(workspace,'candidate','segment.out');
 const before=(await stat(segment)).mtimeNs;
 const retry=run(args(value),value.root); assert.notEqual(retry.status,0);
 assert.equal((await stat(segment)).mtimeNs,before,'completed heavy producer must not rerun');
});

test('unchanged preexisting build output is rejected as stale and rolled back',async()=>{
 const value=await fixture({stale:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/left stale output segment\.out/);
 const probe=spawnSync('test',['!','-e',value.output]); assert.equal(probe.status,0);
});

test('dirty source and substituted manifest fail before executing any stage',async()=>{
 const value=await fixture(); await writeFile(path.join(value.repo,'dirty'),'x');
 let result=run(args(value),value.root); assert.notEqual(result.status,0); assert.match(result.stderr,/source repository is dirty/);
 const clean=await fixture(); result=run([...args(clean),'--expected-manifest-sha256','0'.repeat(64)],clean.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/manifest differs from its pinned SHA-256/);
});

test('control manifests are captured once and reject indirect or multi-link identity',async()=>{
 const value=await fixture(); const alias=value.manifestPath+'.alias';
 await link(value.manifestPath,alias);
 const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/manifest must be a bounded direct single-link file/);
});

test('a concurrent writer is rejected by the nonblocking rebuild lock',async()=>{
 const value=await fixture();
 const holder=spawn('flock',['-n',value.lock,'sleep','3'],{stdio:'ignore'});
 await delay(150);
 try {
  const result=run(args(value),value.root);
  assert.notEqual(result.status,0); assert.match(result.stderr,/another checkpoint rebuild holds the lock/);
 } finally { holder.kill('SIGTERM'); }
});

test('an output created after the initial check cannot be overwritten at publication',async()=>{
 const value=await fixture({raceOutput:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/appeared during publication/);
 const probe=spawnSync('test',['-d',value.output]); assert.equal(probe.status,0);
 assert.equal((await readdir(value.root)).includes('.published.resume-v3'),true);
});

test('offline Cargo inventory and pinned Rust environment fail closed on substitution',async()=>{
 const value=await fixture(); const manifest=JSON.parse(await readFile(value.manifestPath));
 await chmod(manifest.environment.cargoHome+'/registry-index',0o600);
 let result=run([...args(value),'--dry-run'],value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/offline cache entry differs/);
 const second=await fixture(); const changed=JSON.parse(await readFile(second.manifestPath));
 changed.environment.rustc='/usr/bin/false'; await writeFile(second.manifestPath,JSON.stringify(changed));
 second.manifestSha=await fileSha(second.manifestPath);
 result=run([...args(second),'--dry-run'],second.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/rustc is not one of the pinned tools/);
});

test('manifest requires interleaved propagation and exact immediate dependency edges',async()=>{
 const value=await fixture(); const manifest=JSON.parse(await readFile(value.manifestPath));
 manifest.stages[1].inputs=[]; await writeFile(value.manifestPath,JSON.stringify(manifest));
 value.manifestSha=await fileSha(value.manifestPath);
 const result=run([...args(value),'--dry-run'],value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/must consume every output of its immediate predecessor/);
});

test('a producer executable cannot also serve as its semantic verifier',async()=>{
 const value=await fixture(); const manifest=JSON.parse(await readFile(value.manifestPath));
 manifest.stages[0].verificationArgv=[...manifest.stages[0].argv];
 manifest.stages[0].verificationArgv.push('different-arguments-do-not-create-independence');
 await writeFile(value.manifestPath,JSON.stringify(manifest));
 value.manifestSha=await fileSha(value.manifestPath);
 const result=run([...args(value),'--dry-run'],value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/must use a distinct verification command/);
});

test('consumer cannot substitute an authenticated predecessor output during execution',async()=>{
 const value=await fixture({mutateInput:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/changed authenticated predecessor output segment\.out/);
});

test('a stage cannot change a path it did not declare as an output',async()=>{
 const value=await fixture({undeclared:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/changed undeclared path undeclared/);
});

test('command success cannot replace mandatory parsed semantic verification',async()=>{
 const value=await fixture({badClaims:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0);
 assert.match(result.stderr,/receipts verification record lacks mandatory semantic checks/);
});

test('receipt verify-only output is authenticated before aggregation',async()=>{
 const value=await fixture({receiptStep:true}); const result=run(args(value),value.root);
 assert.equal(result.status,0,result.stderr);
 assert.equal(await readFile(path.join(value.output,'candidate','receipt.verify'),'utf8'),'verified receipt\n');
});

test('receipt verifier cannot mutate a producer output between verification and aggregation',async()=>{
 const value=await fixture({receiptStep:true,stepMutates:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/changed fixed output receipts\.out/);
});

test('receipt producer cannot inherit a valid output from an earlier generation',async()=>{
 const value=await fixture({priorReceipt:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/inherited prior-generation output receipts\.out/);
});

test('verify-only cannot roll back the authenticated predecessor generation',async()=>{
 const value=await fixture({receiptStep:true,stepRollback:true}); const result=run(args(value),value.root);
 assert.notEqual(result.status,0); assert.match(result.stderr,/changed fixed output pin-finalized-burn\.out/);
});

test('orphaned crash candidate is never resumed or mixed into a new run',async()=>{
 const value=await fixture(); const orphan=path.join(value.root,'.published.crashed','candidate');
 await mkdir(orphan,{recursive:true}); await writeFile(path.join(orphan,'receipts.out'),'orphan generation\n');
 const result=run(args(value),value.root); assert.equal(result.status,0,result.stderr);
 assert.equal(await readFile(path.join(value.output,'candidate','receipts.out'),'utf8'),'receipts\n');
 assert.equal(await readFile(path.join(orphan,'receipts.out'),'utf8'),'orphan generation\n');
});

test('pinned command execution rejects an aliased executable inode',async()=>{
 const value=await fixture(); const manifest=JSON.parse(await readFile(value.manifestPath));
 const verifier=manifest.stages[0].verificationArgv[0]; await link(verifier,path.join(value.root,'verifier-alias'));
 const result=run(args(value),value.root); assert.notEqual(result.status,0);
 assert.match(result.stderr,/direct executable single-link file/);
});

test('active, substituted or classification-inconsistent handoff cannot start rebuild',async()=>{
 for(const mutate of [
  value=>{value.classification='active'; value.releaseAllowed=false; delete value.terminalSha256;},
  value=>{value.classification='historical-stale'; value.promotionAllowed=true;},
 ]) {
  const fixtureValue=await fixture(); const value=JSON.parse(await readFile(fixtureValue.handoffPath));
  mutate(value); await writeFile(fixtureValue.handoffPath,JSON.stringify(value));
  fixtureValue.handoffSha=await fileSha(fixtureValue.handoffPath);
  const result=run(args(fixtureValue),fixtureValue.root); assert.notEqual(result.status,0);
  assert.match(result.stderr,/handoff/);
 }
 const substituted=await fixture();
 const result=run([...args(substituted).slice(0,7),'0'.repeat(64),...args(substituted).slice(8)],substituted.root);
 assert.notEqual(result.status,0);
});
