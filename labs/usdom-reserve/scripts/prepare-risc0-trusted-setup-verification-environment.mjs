#!/usr/bin/env node
import {createHash,randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {constants} from 'node:fs';
import {lstat,mkdir,open,realpath,rm,statfs} from 'node:fs/promises';
import path from 'node:path';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {validateRiscZeroMainnetReference} from '../sdk/risc0-verifier-reference.mjs';
import {
  PINNED_SNARKJS_KNOWN_ADVISORIES,PINNED_SNARKJS_PACKAGE_INTEGRITY,PINNED_SNARKJS_VERSION,
  RISC0_TRUSTED_SETUP_PODMAN_PATHS,RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS,
  RISC0_TRUSTED_SETUP_VERIFICATION_ENVIRONMENT_SCHEMA,
  validateRisc0TrustedSetupToolchainAttestation,validateRisc0TrustedSetupVerificationEnvironment,
} from '../sdk/risc0-trusted-setup-verification-report.mjs';

const PODMAN='/usr/bin/podman';
const DISCOVERY_IMAGE='localhost/usdom-snarkjs:0.7.6';
const PRIVATE='/home/leonardov/usdom-mainnet-private/trusted-setup';
const INPUT=`${PRIVATE}/input`;
const TMPFS_MAGIC=0x01021994n;
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'
  ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
const identity=value=>[value.dev,value.ino,value.size,value.mtimeNs,value.ctimeNs].join(':');

async function privateDirectory(directory){
  const value=await lstat(directory,{bigint:true});
  if(!value.isDirectory()||value.uid!==BigInt(process.getuid())||(value.mode&0o777n)!==0o700n
      ||await realpath(directory)!==directory) throw new Error(`unsafe private directory: ${directory}`);
}
async function hashFile(file,{algorithm,maximum,expectedSize=null,executable=false,privateFile=false,label}){
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const before=await handle.stat({bigint:true});
    if(!before.isFile()||before.nlink!==1n||before.size<1n||before.size>BigInt(maximum)
        ||(expectedSize!==null&&before.size!==BigInt(expectedSize))
        ||(before.uid!==0n&&before.uid!==BigInt(process.getuid()))||(before.mode&0o022n)!==0n
        ||(privateFile&&(before.uid!==BigInt(process.getuid())||(before.mode&0o077n)!==0n))
        ||(executable&&((before.mode&0o111n)===0n||(before.mode&0o6000n)!==0n))) {
      throw new Error(`${label} metadata is unsafe`);
    }
    const hash=createHash(algorithm),stream=handle.createReadStream({autoClose:false});
    for await(const chunk of stream) hash.update(chunk);
    const after=await handle.stat({bigint:true});
    if(identity(before)!==identity(after)) throw new Error(`${label} changed while hashing`);
    return {digest:hash.digest('hex'),identity:identity(after)};
  } finally {await handle.close();}
}
async function runBounded(argv,{label,maximum,timeoutMs}){
  if(!Array.isArray(argv)||argv[0]!==PODMAN||argv.some(value=>typeof value!=='string'||value.length===0)) {
    throw new Error(`${label} argv is invalid`);
  }
  return await new Promise((resolve,reject)=>{
    const child=spawn(argv[0],argv.slice(1),{cwd:'/',shell:false,
      env:{HOME:'/nonexistent',LANG:'C',LC_ALL:'C',PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe']});
    const chunks=[];let size=0,finished=false,violation=null;
    const timer=setTimeout(()=>{if(!finished){violation=`${label} timed out`;child.kill('SIGKILL');}},timeoutMs);
    const collect=chunk=>{size+=chunk.length;if(size>maximum){violation=`${label} output exceeded its limit`;child.kill('SIGKILL');}
      else if(!violation) chunks.push(chunk);};
    child.stdout.on('data',collect);child.stderr.on('data',collect);
    child.once('error',error=>{finished=true;clearTimeout(timer);reject(error);});
    child.once('close',code=>{finished=true;clearTimeout(timer);if(violation)reject(new Error(violation));
      else if(code!==0)reject(new Error(`${label} exited with status ${code}`));
      else resolve(Buffer.concat(chunks,size));});
  });
}
function isolatedArgv(image,command,outputDirectory){
  return [PODMAN,'run','--rm','--pull=never','--network=none','--read-only',
    '--userns=keep-id:uid=65532,gid=65532','--user=65532:65532','--cap-drop=ALL',
    '--security-opt=no-new-privileges',`--mount=type=bind,src=${INPUT},dst=/input,ro=true`,
    `--mount=type=bind,src=${outputDirectory},dst=/output,rw=true`,
    '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864','--entrypoint=node',image,...command.slice(1)];
}

let temporary=null,temporaryIdentity=null;
try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  await privateDirectory(PRIVATE);await privateDirectory(INPUT);
  const referenceBytes=await readDirectProjectFile(path.resolve(import.meta.dirname,'..'),
    'config/risc0-ethereum-mainnet-v3.json');
  const reference=validateRiscZeroMainnetReference(parseStrictJsonBytes(referenceBytes,
    {label:'RISC Zero mainnet reference'}));
  const authorityBytes=await readDirectProjectFile(path.resolve(import.meta.dirname,'..'),reference.trusted_setup_authority_path);
  if(createHash('sha256').update(authorityBytes).digest('hex')!==reference.trusted_setup_authority_sha256) {
    throw new Error('trusted-setup authority differs from mainnet reference');
  }
  const authority=parseStrictJsonBytes(authorityBytes,{label:'trusted-setup authority',maxBytes:64*1024,maxDepth:8});
  const runtime=await hashFile(PODMAN,{algorithm:'sha256',maximum:256*1024**2,executable:true,label:'Podman runtime'});
  const artifacts={
    r1csSha256:(await hashFile(RISC0_TRUSTED_SETUP_PODMAN_PATHS.r1cs,{algorithm:'sha256',maximum:2*1024**3,
      expectedSize:authority.r1cs_size,privateFile:true,label:'R1CS'})).digest,
    powersOfTauBlake2b512:(await hashFile(RISC0_TRUSTED_SETUP_PODMAN_PATHS.powersOfTau,{algorithm:'blake2b512',
      maximum:12*1024**3,expectedSize:authority.powers_of_tau_size,privateFile:true,label:'Powers of Tau'})).digest,
    zkeySha256:(await hashFile(RISC0_TRUSTED_SETUP_PODMAN_PATHS.zkey,{algorithm:'sha256',maximum:5*1024**3,
      expectedSize:authority.zkey_size,privateFile:true,label:'zkey'})).digest,
  };
  if(artifacts.r1csSha256!==authority.r1cs_sha256
      ||artifacts.powersOfTauBlake2b512!==authority.powers_of_tau_blake2b512) {
    throw new Error('source-pinned trusted-setup artifact digest mismatch');
  }
  const inspection=await runBounded([PODMAN,'image','inspect','--format={{json .Id}}',DISCOVERY_IMAGE],
    {label:'Podman image discovery',maximum:64*1024,timeoutMs:60*1000});
  let image;try{image=JSON.parse(inspection.toString('utf8').trimEnd());}catch{throw new Error('Podman image discovery is not JSON');}
  if(typeof image!=='string'||!/^sha256:[0-9a-f]{64}$/.test(image)) {
    throw new Error('fixed snarkjs image tag does not resolve to one immutable local image ID');
  }
  const imageDigest=image;
  temporary=`/dev/shm/usdom-risc0-environment-${randomBytes(16).toString('hex')}`;
  await mkdir(temporary,{mode:0o700});temporaryIdentity=identity(await lstat(temporary,{bigint:true}));
  if((await statfs(temporary,{bigint:true})).type!==TMPFS_MAGIC) throw new Error('bootstrap output is not tmpfs');
  const base={schema:RISC0_TRUSTED_SETUP_VERIFICATION_ENVIRONMENT_SCHEMA,containerImageDigest:imageDigest,
    containerImageReference:image,containerRuntime:{path:PODMAN,sha256:runtime.digest},networkDisabled:true,
    nodeVersion:'v24.19.0',snarkjsVersion:PINNED_SNARKJS_VERSION,
    snarkjsPackageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY,knownAdvisories:[...PINNED_SNARKJS_KNOWN_ADVISORIES],
    capabilitiesDropped:['ALL'],commands:structuredClone(RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS),
    inputMountReadOnly:true,noNewPrivileges:true,outputTmpfs:true,rootFilesystemReadOnly:true,runAsUser:'65532:65532'};
  const toolchain=await runBounded(isolatedArgv(image,RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS.attestToolchain,temporary),
    {label:'toolchain bootstrap attestation',maximum:64*1024,timeoutMs:5*60*1000});
  validateRisc0TrustedSetupToolchainAttestation(toolchain,{...base,inputArtifacts:{...artifacts,
    expectedVerificationKeySha256:'01'.padEnd(64,'0')}});
  await runBounded(isolatedArgv(image,RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS.exportVerificationKey,temporary),
    {label:'verification-key bootstrap export',maximum:1024*1024,timeoutMs:60*60*1000});
  const verificationKey=await hashFile(`${temporary}/verification-key.json`,{algorithm:'sha256',maximum:64*1024**2,
    privateFile:false,label:'bootstrap verification key'});
  const environment=validateRisc0TrustedSetupVerificationEnvironment({...base,
    inputArtifacts:{...artifacts,expectedVerificationKeySha256:verificationKey.digest}});
  process.stdout.write(`${JSON.stringify(stable(environment),null,2)}\n`);
} catch(error) {writeReleaseFailure('prepare-risc0-trusted-setup-verification-environment',error);process.exitCode=1;
} finally {
  if(temporary&&temporaryIdentity) {
    const current=await lstat(temporary,{bigint:true}).catch(()=>null);
    if(current&&identity(current)===temporaryIdentity) await rm(temporary,{recursive:true});
    else if(current) {writeReleaseFailure('prepare-risc0-trusted-setup-verification-environment',
      new Error('refusing to clean a replaced bootstrap directory'));process.exitCode=1;}
  }
}
