#!/usr/bin/env node
import {createHash} from 'node:crypto'; import {spawn} from 'node:child_process';
import {constants} from 'node:fs'; import {chmod,mkdtemp,open,readdir,rm,stat,writeFile} from 'node:fs/promises'; import path from 'node:path'; import os from 'node:os'; import {fileURLToPath} from 'node:url';
import {snapshotExecutablePath,assertExecutableUnchanged} from '../sdk/stable-executable.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs'; import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {validateCheckpointRestartWitnessReport} from '../sdk/checkpoint-restart-witness-report.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
if(process.argv.length!==2||process.env.USDOM_RUN_CHECKPOINT_RESTART_WITNESS!=='YES') throw new Error('restart witness exercise requires fixed opt-in YES and no arguments');
const manifestPath=path.join(root,'evidence/native-runtime/native-usdom-v2.json');
const manifestBytes=await readDirectFile(manifestPath,{minimum:2,maximum:4*1024*1024,label:'native runtime manifest'}),manifest=parseStrictJsonBytes(manifestBytes,{label:'native runtime manifest',maxBytes:4*1024*1024,maxDepth:32});
const witnessName=manifest.restart_checkpoint?.witness_file,witnessSha256=manifest.restart_checkpoint?.witness_sha256;
if(typeof witnessName!=='string'||!/^[A-Za-z0-9._-]+$/.test(witnessName)||!/^[0-9a-f]{64}$/.test(witnessSha256)) throw new Error('native runtime manifest has no pinned restart witness');
const witness=await readDirectFile(path.join(path.dirname(manifestPath),witnessName),{minimum:1,maximum:64*1024*1024,label:'restart witness'}); const sha=b=>createHash('sha256').update(b).digest('hex');
if(sha(witness)!==witnessSha256) throw new Error('restart witness bytes differ from manifest pin');
const dataDirectory=path.join(os.homedir(),'.local/share/dom-usdom/mainnet-node/data');
const launcher=await snapshotExecutablePath('/usr/bin/bash');
const nodeLauncherPath=path.join(root,'scripts/run-closed-mainnet-node.sh');
const nodeLauncherHandle=await open(nodeLauncherPath,constants.O_RDONLY|constants.O_NOFOLLOW);
const nodeLauncherStat=await nodeLauncherHandle.stat({bigint:true});
const fileIdentity=value=>[value.dev,value.ino,value.size,value.mtimeNs,value.ctimeNs].join(':');
if(!nodeLauncherStat.isFile()||nodeLauncherStat.nlink!==1n||nodeLauncherStat.size<1n
    ||nodeLauncherStat.size>1024n*1024n||(nodeLauncherStat.mode&0o022n)!==0n) {
  await nodeLauncherHandle.close();
  throw new Error('closed-mainnet node launcher metadata is unsafe');
}
const runtimeSnapshot=await mkdtemp(path.join(os.tmpdir(),'usdom-restart-runtime-'));
await chmod(runtimeSnapshot,0o700);
for(const entry of await readdir(path.dirname(manifestPath),{withFileTypes:true})) {
  if(!entry.isFile()||entry.isSymbolicLink()) throw new Error(`unsafe native runtime entry: ${entry.name}`);
  const captured=await readDirectFile(path.join(path.dirname(manifestPath),entry.name),{maximum:64*1024*1024,label:`native runtime ${entry.name}`});
  await writeFile(path.join(runtimeSnapshot,entry.name),captured,{flag:'wx',mode:0o600});
}
async function assertInputsUnchanged() {
  const [currentManifest,currentWitness]=await Promise.all([
    readDirectFile(manifestPath,{minimum:2,maximum:4*1024*1024,label:'native runtime manifest'}),
    readDirectFile(path.join(path.dirname(manifestPath),witnessName),{minimum:1,maximum:64*1024*1024,label:'restart witness'}),
  ]);
  if(!currentManifest.equals(manifestBytes)||!currentWitness.equals(witness)) {
    throw new Error('restart witness manifest or witness changed during live exercise');
  }
  if(fileIdentity(await nodeLauncherHandle.stat({bigint:true}))!==fileIdentity(nodeLauncherStat)) {
    throw new Error('closed-mainnet node launcher changed during live exercise');
  }
}
async function one(logName) {
  const chunks=[]; let total=0,ready=false,child;
  const exited=()=>child?.exitCode!==null||child?.signalCode!==null;
  const waitForExit=async(deadline)=>{
    while(!exited()&&Date.now()<deadline) await new Promise(r=>setTimeout(r,100));
    return exited();
  };
  try {
    await assertInputsUnchanged();
    child=spawn(launcher.path,['/proc/self/fd/3'],{cwd:root,detached:true,
      env:{...process.env,USDOM_CHECKPOINT_RESTART_RUNTIME_ROOT:runtimeSnapshot},
      stdio:['ignore','pipe','pipe',nodeLauncherHandle.fd]});
    const accept=chunk=>{total+=chunk.length;if(total>4*1024*1024){try{process.kill(-child.pid,'SIGKILL');}catch{}}else{chunks.push(Buffer.from(chunk));const text=Buffer.concat(chunks).toString('utf8');if(/Enabling authenticated RPC listen address/.test(text))ready=true;}};
    child.stdout.on('data',accept);child.stderr.on('data',accept);
    const deadline=Date.now()+90*60*1000; while(!ready&&!exited()&&Date.now()<deadline) await new Promise(r=>setTimeout(r,250));
    if(!ready) throw new Error(`node did not accept checkpoint restart witness during ${logName}`);
    await new Promise(r=>setTimeout(r,1000));
    if(exited()) throw new Error(`node exited after accepting checkpoint restart witness during ${logName}`);
    await assertInputsUnchanged(); return child.pid;
  } finally {
    if(child&&!exited()){
      try{process.kill(-child.pid,'SIGTERM');}catch{}
      if(!await waitForExit(Date.now()+10_000)) {
        try{process.kill(-child.pid,'SIGKILL');}catch{}
        if(!await waitForExit(Date.now()+10_000)) {
          throw new Error(`node process group did not terminate after ${logName}`);
        }
      }
    }
    await assertExecutableUnchanged(launcher);
  }
}
try {
  const first=await one('first startup'),before=await stat(dataDirectory,{bigint:true}),second=await one('second startup'),after=await stat(dataDirectory,{bigint:true});
  await assertInputsUnchanged();
  const report=validateCheckpointRestartWitnessReport({schema:'usdom-checkpoint-restart-witness-live-exercise/v1',manifestSha256:sha(manifestBytes),witnessSha256,
    firstProcessPid:first,secondProcessPid:second,firstStartupAccepted:true,secondStartupAccepted:true,
    sameDataDirectory:before.dev===after.dev&&before.ino===after.ino,checkpointWitnessRequired:true},{manifestBytes,witnessBytes:witness});
  const target=process.env.USDOM_CHECKPOINT_RESTART_WITNESS_REPORT;if(typeof target!=='string'||!path.isAbsolute(target))throw new Error('restart report path must be absolute');
  await writePrivateFileDurableNewOrEqual(target,Buffer.from(JSON.stringify(report)+'\n'),{maximum:64*1024});
  await assertInputsUnchanged();
  process.stdout.write(`${JSON.stringify({schema:report.schema,path:target})}\n`);
} finally { await nodeLauncherHandle.close(); await rm(runtimeSnapshot,{recursive:true,force:true}); }
