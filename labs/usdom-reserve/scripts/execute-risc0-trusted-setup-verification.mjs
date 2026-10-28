#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {constants} from 'node:fs';
import {lstat,mkdir,open,realpath,statfs} from 'node:fs/promises';
import {
  RISC0_TRUSTED_SETUP_PODMAN_PATHS,
  buildRisc0TrustedSetupPodmanPlan,
  validateRisc0TrustedSetupPodmanImageInspection,
  validateRisc0TrustedSetupVerificationEnvironment,
} from '../sdk/risc0-trusted-setup-verification-report.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';

const TMPFS_MAGIC=0x01021994n;
const identity=value=>[value.dev,value.ino,value.size,value.mtimeNs,value.ctimeNs].join(':');

async function readStable(file,{label,maximum=64*1024,executable=false}={}) {
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const before=await handle.stat({bigint:true});
    if(!before.isFile()||before.nlink!==1n||before.size<1n||before.size>BigInt(maximum)
        ||(before.uid!==0n&&before.uid!==BigInt(process.getuid()))||(before.mode&0o022n)!==0n
        ||(executable&&((before.mode&0o111n)===0n||(before.mode&0o6000n)!==0n))) {
      throw new Error(`${label} metadata is unsafe`);
    }
    const bytes=await handle.readFile(),after=await handle.stat({bigint:true});
    if(identity(before)!==identity(after)) throw new Error(`${label} changed while reading`);
    return bytes;
  } finally {await handle.close();}
}

async function hashStable(file,{label,algorithm,maximum}) {
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const before=await handle.stat({bigint:true});
    if(!before.isFile()||before.nlink!==1n||before.size<1n||before.size>BigInt(maximum)
        ||before.uid!==BigInt(process.getuid())||(before.mode&0o077n)!==0n) {
      throw new Error(`${label} metadata is unsafe`);
    }
    const digest=createHash(algorithm),stream=handle.createReadStream({autoClose:false});
    for await(const chunk of stream) digest.update(chunk);
    const after=await handle.stat({bigint:true});
    if(identity(before)!==identity(after)) throw new Error(`${label} changed while hashing`);
    return {digest:digest.digest('hex'),identity:identity(after)};
  } finally {await handle.close();}
}

async function assertPrivateDirectory(directory,{tmpfs=false}={}) {
  const value=await lstat(directory,{bigint:true});
  if(!value.isDirectory()||value.uid!==BigInt(process.getuid())||(value.mode&0o777n)!==0o700n) {
    throw new Error(`private directory metadata is unsafe: ${directory}`);
  }
  if(await realpath(directory)!==directory) throw new Error(`private directory path is not canonical: ${directory}`);
  if(tmpfs&&(await statfs(directory,{bigint:true})).type!==TMPFS_MAGIC) {
    throw new Error('trusted-setup output directory is not tmpfs');
  }
}

async function runCreateOnce(argv,outputPath,label,{maximum,timeoutMs}) {
  if(!Array.isArray(argv)||argv.length<2||argv.some(value=>typeof value!=='string'||value.length===0)) {
    throw new Error(`${label} argv is invalid`);
  }
  let violation=null;
  const chunks=[]; let length=0;
  const code=await new Promise((resolve,reject)=>{
      const child=spawn(argv[0],argv.slice(1),{cwd:'/',env:{HOME:'/nonexistent',LANG:'C',LC_ALL:'C',PATH:'/usr/bin:/bin'},
        stdio:['ignore','pipe','pipe'],shell:false});
      const started=Date.now();
      const consume=chunk=>{
        length+=chunk.length;
        if(length>maximum) { violation=`${label} output exceeded its limit`; child.kill('SIGKILL'); }
        else chunks.push(chunk);
      };
      child.stdout.on('data',consume); child.stderr.on('data',consume);
      const monitor=setInterval(async()=>{
        try {
          if(Date.now()-started>timeoutMs) violation=`${label} exceeded its time limit`;
          if(violation) child.kill('SIGKILL');
        } catch(error) {violation=`${label} output could not be monitored: ${error.message}`;child.kill('SIGKILL');}
      },250);
      monitor.unref();
      child.once('error',error=>{clearInterval(monitor);reject(error);});
      child.once('exit',(status,signal)=>{clearInterval(monitor);
        if(violation) reject(new Error(violation));
        else if(signal) reject(new Error(`${label} terminated by ${signal}`));
        else resolve(status);
      });
  });
  if(code!==0) throw new Error(`${label} exited with status ${code}`);
  const bytes=Buffer.concat(chunks,length);
  if(bytes.length===0||bytes.length>maximum) throw new Error(`${label} output size is invalid`);
  await writePrivateFileDurableNew(outputPath,bytes,{maximum});
}

try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const paths=RISC0_TRUSTED_SETUP_PODMAN_PATHS;
  const environmentBytes=await readStable(paths.environment,{label:'verification environment'});
  const environment=validateRisc0TrustedSetupVerificationEnvironment(parseStrictJsonBytes(environmentBytes,
    {label:'verification environment',maxBytes:64*1024,maxDepth:8}));
  const runtime=await readStable(environment.containerRuntime.path,
    {label:'Podman runtime',maximum:256*1024**2,executable:true});
  if(createHash('sha256').update(runtime).digest('hex')!==environment.containerRuntime.sha256) {
    throw new Error('Podman runtime differs from the committed runtime');
  }
  await assertPrivateDirectory('/home/leonardov/usdom-mainnet-private/trusted-setup');
  await assertPrivateDirectory('/home/leonardov/usdom-mainnet-private/trusted-setup/input');
  // Exclusive creation doubles as a cross-process lock and prevents a stale
  // verification key from being truncated by the container.
  await mkdir('/dev/shm/usdom-risc0-trusted-setup-output',{mode:0o700});
  await assertPrivateDirectory('/dev/shm/usdom-risc0-trusted-setup-output',{tmpfs:true});
  const measurements={
    r1csSha256:await hashStable(paths.r1cs,{label:'R1CS',algorithm:'sha256',maximum:2*1024**3}),
    powersOfTauBlake2b512:await hashStable(paths.powersOfTau,
      {label:'Powers of Tau',algorithm:'blake2b512',maximum:12*1024**3}),
    zkeySha256:await hashStable(paths.zkey,{label:'zkey',algorithm:'sha256',maximum:5*1024**3}),
  };
  for(const [key,value] of Object.entries(measurements)) {
    if(value.digest!==environment.inputArtifacts[key]) throw new Error(`${key} differs from the environment commitment`);
  }
  const plan=buildRisc0TrustedSetupPodmanPlan(environment);
  await runCreateOnce(plan.imageInspection.argv,paths.imageInspection,'Podman image inspection',
    {maximum:64*1024,timeoutMs:60*1000});
  validateRisc0TrustedSetupPodmanImageInspection(
    await readStable(paths.imageInspection,{label:'Podman image inspection'}),plan);
  for(const invocation of plan.invocations) {
    await runCreateOnce(invocation.argv,invocation.stdoutPath,invocation.id,
      {maximum:4*1024*1024,timeoutMs:4*60*60*1000});
  }
  const verificationKey=await readStable(paths.verificationKey,
    {label:'exported verification key',maximum:64*1024**2});
  if(createHash('sha256').update(verificationKey).digest('hex')
      !==environment.inputArtifacts.expectedVerificationKeySha256) {
    throw new Error('exported verification key differs from the environment commitment');
  }
  for(const [key,file] of [['r1csSha256',paths.r1cs],['powersOfTauBlake2b512',paths.powersOfTau],
    ['zkeySha256',paths.zkey]]) {
    const after=await lstat(file,{bigint:true});
    if(!after.isFile()||identity(after)!==measurements[key].identity) {
      throw new Error(`${key} changed during container verification`);
    }
  }
  const [environmentAfter,runtimeAfter]=await Promise.all([
    readStable(paths.environment,{label:'verification environment'}),
    readStable(environment.containerRuntime.path,
      {label:'Podman runtime',maximum:256*1024**2,executable:true}),
  ]);
  if(!environmentAfter.equals(environmentBytes)||!runtimeAfter.equals(runtime)) {
    throw new Error('verification environment or Podman runtime changed during execution');
  }
  process.stdout.write('RISC Zero trusted-setup verification completed with committed artifacts.\n');
} catch(error) {
  writeReleaseFailure('execute-risc0-trusted-setup-verification',error);process.exitCode=1;
}
