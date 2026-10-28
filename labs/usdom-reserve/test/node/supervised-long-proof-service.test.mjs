import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {chmod,mkdir,mkdtemp,readFile,writeFile} from 'node:fs/promises';
import os from 'node:os'; import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process'; import test from 'node:test';
const repo=path.resolve(import.meta.dirname,'../../../..');
const runner=path.join(repo,'labs/usdom-reserve/scripts/run-supervised-long-proof.py');
const unit=path.join(repo,'labs/usdom-reserve/systemd/usdom-proof@.service.in');
const sha=b=>createHash('sha256').update(b).digest('hex');
const sorted=o=>Array.isArray(o)?o.map(sorted):o&&typeof o==='object'
 ?Object.fromEntries(Object.keys(o).sort().map(key=>[key,sorted(o[key])])):o;
const canonical=o=>Buffer.from(JSON.stringify(sorted(o))+'\n');
async function fixture(script,{v2=false,requiredOutput=['VECTOR PASS']}={}) {
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-supervised-')); const executable=path.join(root,'fake.sh');
 await writeFile(executable,script); await chmod(executable,0o700); const bytes=await readFile(executable);
 const spec={argv:[executable],createdUnix:1,cwd:root,environment:{},executableSha256:sha(bytes),nonce:randomBytes(16).toString('hex'),schema:'usdom-supervised-proof-command-v1'};
 if(v2){const input=path.join(root,'bound.txt');await writeFile(input,'bound\n');Object.assign(spec,{schema:'usdom-supervised-proof-command-v2',inputs:[{path:'bound.txt',sha256:sha(await readFile(input)),maxBytes:6}],limits:{maxRuntimeSeconds:60,maxLogBytes:1024,minFreeBytes:1024*1024*1024},requiredOutput});}
 const raw=canonical(spec),id=sha(raw),manifest=path.join(root,'command.json'); await writeFile(manifest,raw);
 const runnerSha=sha(await readFile(runner));
 return {root,id,manifest,args:[runner,'--state-root',path.join(root,'state'),'--run-id',id,'--command-manifest',manifest,'--expected-supervisor-sha256',runnerSha]};
}
test('v2 binds source, resource limits, exact success output and evidence hashes',async()=>{
 let f=await fixture('#!/bin/sh\necho "VECTOR PASS"\n',{v2:true}); let p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(p.status,0,p.stderr);
 let dir=path.join(f.root,'state','runs',f.id),terminal=JSON.parse(await readFile(path.join(dir,'terminal.json')));
 assert.equal(terminal.processLogSha256,sha(await readFile(path.join(dir,'process.log')))); assert.equal(terminal.eventsSha256,sha(await readFile(path.join(dir,'events.jsonl'))));
 f=await fixture('#!/bin/sh\necho wrong\n',{v2:true}); p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(p.status,125,p.stderr);
 dir=path.join(f.root,'state','runs',f.id); assert.match(await readFile(path.join(dir,'events.jsonl'),'utf8'),/required-output-mismatch/);
 f=await fixture('#!/bin/sh\nprintf changed > bound.txt\necho "VECTOR PASS"\n',{v2:true}); p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(p.status,125,p.stderr);
 dir=path.join(f.root,'state','runs',f.id); assert.match(await readFile(path.join(dir,'events.jsonl'),'utf8'),/bound-input-drift/);
});
test('child process cannot persist a core dump even outside the systemd unit',async()=>{
 const f=await fixture('#!/bin/sh\nprintf "CORE=%s\\n" "$(ulimit -c)"\n',{v2:true,requiredOutput:['CORE=0']});
 const p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(p.status,0,p.stderr);
 const log=await readFile(path.join(f.root,'state','runs',f.id,'process.log'),'utf8');
 assert.equal(log,'CORE=0\n');
});
test('successful fake gets immutable identity and terminal evidence; identity cannot restart',async()=>{
 const f=await fixture('#!/bin/sh\necho ok\n'); let p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(p.status,0,p.stderr);
 const dir=path.join(f.root,'state','runs',f.id); const terminal=JSON.parse(await readFile(path.join(dir,'terminal.json')));
 assert.equal(terminal.exitStatus,0); assert.equal(terminal.runId,f.id); assert.match(await readFile(path.join(dir,'events.jsonl'),'utf8'),/runner-terminal/);
 p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(p.status,125); assert.match(p.stderr,/File exists/);
});
test('substituted supervisor source pin fails before creating run state',async()=>{
 const f=await fixture('#!/bin/sh\nexit 0\n'); const args=[...f.args]; args[args.length-1]='0'.repeat(64);
 const p=spawnSync('/usr/bin/python3',args,{encoding:'utf8'}); assert.equal(p.status,125); assert.match(p.stderr,/differs from installed service pin/);
 assert.equal(spawnSync('/usr/bin/test',['!','-e',path.join(f.root,'state')]).status,0);
});
test('SIGTERM is logged, forwarded, and produces attributable supervisor terminal state',async()=>{
 const f=await fixture('#!/bin/sh\ntrap "exit 0" TERM\nwhile :; do :; done\n');
 const p=spawn('/usr/bin/python3',[...f.args,'--termination-grace-seconds','2'],{stdio:'ignore'});
 const dir=path.join(f.root,'state','runs',f.id); let started=false; for(let i=0;i<500;i++){try{if((await readFile(path.join(dir,'events.jsonl'),'utf8')).includes('child-started')){started=true;break}}catch{} await new Promise(r=>setTimeout(r,20));} assert.equal(started,true);
 p.kill('SIGTERM'); const code=await new Promise(r=>p.once('exit',r)); assert.equal(code,143);
 const terminal=JSON.parse(await readFile(path.join(dir,'terminal.json'))); assert.equal(terminal.supervisorSignal,'SIGTERM'); assert.equal(terminal.exitStatus,143); assert.equal(terminal.childSignal,null);
 const events=await readFile(path.join(dir,'events.jsonl'),'utf8'); assert.match(events,/signal-forwarded/); assert.match(events,/senderPid/); assert.match(events,/senderUid/);
});
test('setsid descendant cannot escape supervision or preserve nominal success',async()=>{
 const f=await fixture('#!/bin/sh\nsetsid /bin/sh -c \'trap "exit 0" TERM; while :; do sleep 1; done\' &\necho $!\nsleep 0.2\nexit 0\n');
 const p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8',timeout:30000}); assert.equal(p.status,125,p.stderr);
 const dir=path.join(f.root,'state','runs',f.id); const terminal=JSON.parse(await readFile(path.join(dir,'terminal.json')));
 assert.equal(terminal.exitStatus,125); const events=await readFile(path.join(dir,'events.jsonl'),'utf8'); assert.match(events,/stray-descendants/);
 const detachedMatch=(await readFile(path.join(dir,'process.log'),'utf8')).match(/^([0-9]+)/); assert.ok(detachedMatch);
 const detachedPid=Number(detachedMatch[1]); assert.ok(Number.isInteger(detachedPid)&&detachedPid>1);
 const probe=spawnSync('/bin/kill',['-0',String(detachedPid)]); assert.notEqual(probe.status,0,'detached descendant survived terminal publication');
});
test('job preparation rejects loader injection and noncanonical cwd before publication',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-job-prep-')); const jobs=path.join(root,'jobs');
 const preparer=path.join(repo,'labs/usdom-reserve/scripts/prepare-supervised-proof-job.py');
 let p=spawnSync('/usr/bin/python3',[preparer,'--jobs-directory',jobs,'--cwd',root,'--env','LD_PRELOAD=x','--','/bin/true'],{encoding:'utf8'});
 assert.equal(p.status,125); assert.match(p.stderr,/unsafe environment entry/);
 p=spawnSync('/usr/bin/python3',[preparer,'--jobs-directory',jobs,'--cwd','.', '--','/bin/true'],{encoding:'utf8'});
 assert.equal(p.status,125); assert.match(p.stderr,/absolute canonical directory/);
});
test('job preparation expands and authenticates the complete repository source closure',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-job-closure-')),jobs=path.join(root,'jobs');
 const preparer=path.join(repo,'labs/usdom-reserve/scripts/prepare-supervised-proof-job.py');
 await mkdir(path.join(root,'config')); await writeFile(path.join(root,'Cargo.toml'),'[workspace]\n');
 const cargoSha=sha(await readFile(path.join(root,'Cargo.toml'))),inventoryPath='config/inventory.json';
 const inventory={schema:'usdom-critical-publication-inventory-v2',repositoryCriticalSources:{'Cargo.toml':cargoSha}};
 await writeFile(path.join(root,inventoryPath),JSON.stringify(inventory));
 const args=[preparer,'--jobs-directory',jobs,'--cwd',root,'--bind-source-inventory',inventoryPath,
  '--require-output','ok','--max-runtime-seconds','60','--max-log-bytes','1024',
  '--min-free-bytes','1024','--','/bin/true'];
 let p=spawnSync('/usr/bin/python3',args,{encoding:'utf8'}); assert.equal(p.status,0,p.stderr);
 const spec=JSON.parse(await readFile(path.join(jobs,`${p.stdout.trim()}.json`)));
 assert.deepEqual(spec.inputs.map(value=>value.path),[inventoryPath,'Cargo.toml']);
 await writeFile(path.join(root,'Cargo.toml'),'[workspace]\n# drift\n');
 p=spawnSync('/usr/bin/python3',args,{encoding:'utf8'}); assert.equal(p.status,125);
 assert.match(p.stderr,/source inventory digest mismatch: Cargo\.toml/);
 const releaseJobs=await readFile(path.join(repo,
  'labs/usdom-reserve/scripts/prepare-usdom-release-validation-jobs.sh'),'utf8');
 assert.match(releaseJobs,/--bind-source-inventory labs\/usdom-reserve\/config\/rebuild-v3-critical-source-inventory\.json/);
});
test('durable publications, fd-bound cwd, subreaper and exact status identity remain structural requirements',async()=>{
 const runText=await readFile(runner,'utf8'); const controlText=await readFile(path.join(repo,'labs/usdom-reserve/scripts/control-supervised-long-proof.py'),'utf8');
 for(const required of ['PR_SET_CHILD_SUBREAPER','write_all(events_fd, record)','os.fsync(output_fd)','cwd=f"/proc/self/fd/{cwd_fd}"','pass_fds=(executable_fd, cwd_fd)','terminate_stray_descendants()','supervisor source differs from installed service pin']) assert.ok(runText.includes(required),required);
 for(const required of ['runnerStartTicks','bootId','systemdInvocationId','supervisorPath','process_start_ticks(pid)==run["runnerStartTicks"]','adjacent(cmdline,"--run-id",args.run_id)','adjacent(cmdline,"--expected-supervisor-sha256",run["supervisorSha256"])','terminal does not bind the authenticated run']) assert.ok(controlText.includes(required),required);
});
test('evidence writer survives EINTR and repeated partial writes without truncation',()=>{
 const code=`import importlib.util,os,sys,tempfile\np=importlib.util.spec_from_file_location('runner',sys.argv[1]);m=importlib.util.module_from_spec(p);p.loader.exec_module(m)\nfd,path=tempfile.mkstemp();real=m.os.write;calls=[0]\ndef short(fd,data):\n calls[0]+=1\n if calls[0]==1: raise InterruptedError()\n return real(fd,bytes(data[:3]))\nm.os.write=short\nm.write_all(fd,b'authenticated-evidence')\nos.fsync(fd);os.close(fd)\nassert open(path,'rb').read()==b'authenticated-evidence'\nos.unlink(path)\n`;
 const p=spawnSync('/usr/bin/python3',['-c',code,runner],{encoding:'utf8'}); assert.equal(p.status,0,p.stderr);
});
test('status authenticates canonical run and terminal records and rejects byte tampering',async()=>{
 const f=await fixture('#!/bin/sh\nexit 0\n'); let p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(p.status,0,p.stderr);
 const control=path.join(repo,'labs/usdom-reserve/scripts/control-supervised-long-proof.py');
 const harness=`import importlib.util,sys\np=importlib.util.spec_from_file_location('control',sys.argv[1]);m=importlib.util.module_from_spec(p);p.loader.exec_module(m)\nm.unit_show=lambda unit:{'ActiveState':'inactive','SubState':'dead','MainPID':'0','InvocationID':'','Result':'success','ExecMainStatus':'0'}\nsys.argv=['control','status','--state-root',sys.argv[2],'--run-id',sys.argv[3]]\ntry: raise SystemExit(m.main())\nexcept Exception as e: print(e,file=sys.stderr);raise SystemExit(125)\n`;
 const state=path.join(f.root,'state'); p=spawnSync('/usr/bin/python3',['-c',harness,control,state,f.id],{encoding:'utf8'}); assert.equal(p.status,0,p.stderr);
 const report=JSON.parse(p.stdout); assert.equal(report.runAuthenticated,true); assert.equal(report.terminalAuthenticated,true);
 const runPath=path.join(state,'runs',f.id,'run.json'); await chmod(runPath,0o600); await writeFile(runPath,Buffer.concat([await readFile(runPath),Buffer.from(' ')]));
 p=spawnSync('/usr/bin/python3',['-c',harness,control,state,f.id],{encoding:'utf8'}); assert.equal(p.status,125); assert.match(p.stderr,/invalid canonical record/);
});
test('terminal evidence hashes reject process-log tampering',async()=>{
 const f=await fixture('#!/bin/sh\necho ok\n'); let p=spawnSync('/usr/bin/python3',f.args,{encoding:'utf8'}); assert.equal(p.status,0,p.stderr);
 const control=path.join(repo,'labs/usdom-reserve/scripts/control-supervised-long-proof.py'); const state=path.join(f.root,'state');
 const harness=`import importlib.util,sys\np=importlib.util.spec_from_file_location('control',sys.argv[1]);m=importlib.util.module_from_spec(p);p.loader.exec_module(m)\nm.unit_show=lambda unit:{'ActiveState':'inactive','SubState':'dead','MainPID':'0','InvocationID':'','Result':'success','ExecMainStatus':'0'}\nsys.argv=['control','status','--state-root',sys.argv[2],'--run-id',sys.argv[3]]\ntry: raise SystemExit(m.main())\nexcept Exception as e: print(e,file=sys.stderr);raise SystemExit(125)\n`;
 const log=path.join(state,'runs',f.id,'process.log'); await chmod(log,0o600); await writeFile(log,Buffer.concat([await readFile(log),Buffer.from('tampered')]));
 p=spawnSync('/usr/bin/python3',['-c',harness,control,state,f.id],{encoding:'utf8'}); assert.equal(p.status,125); assert.match(p.stderr,/terminal identity fields are invalid/);
});
test('unit has persistent fail-closed stop and resource policy',async()=>{
 const text=await readFile(unit,'utf8'); for(const required of ['ExitType=cgroup','Restart=no','KillMode=mixed','TimeoutStopSec=10min','OOMPolicy=stop','MemoryHigh=5500M','MemoryMax=6500M','LimitCORE=0','CPUWeight=10','IOWeight=100','ProtectSystem=strict','PrivateNetwork=yes','ReadWritePaths=%h/.local/state/usdom-proof','--expected-supervisor-sha256 @SUPERVISOR_SHA256@']) assert.match(text,new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 assert.doesNotMatch(text,/RuntimeMaxSec|WatchdogSec/);
});
