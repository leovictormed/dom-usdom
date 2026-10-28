#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {validateRiscZeroMainnetReference} from '../sdk/risc0-verifier-reference.mjs';
import {buildRisc0TrustedSetupPodmanPlan,buildRisc0TrustedSetupVerificationReport,
  RISC0_TRUSTED_SETUP_PODMAN_PATHS,
  serializeRisc0TrustedSetupVerificationReport,validateRisc0TrustedSetupVerificationEnvironment,
} from '../sdk/risc0-trusted-setup-verification-report.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const identity=stat=>[stat.dev,stat.ino,stat.size,stat.mtimeNs,stat.ctimeNs].join(':');
async function stableHash(file,{algorithm,expectedSize,maximum,label,executable=false}){
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const before=await handle.stat({bigint:true});
    if(!before.isFile()||before.nlink!==1n||(before.uid!==0n&&before.uid!==BigInt(process.getuid()))
        ||before.size<1n||before.size>BigInt(maximum)
        ||(expectedSize!==null&&before.size!==BigInt(expectedSize))||(before.mode&0o022n)!==0n
        ||(executable&&((before.mode&0o111n)===0n||(before.mode&0o6000n)!==0n))) throw new Error(`${label} metadata is unsafe or unexpected`);
    const hash=createHash(algorithm),stream=handle.createReadStream({autoClose:false});
    for await(const chunk of stream) hash.update(chunk);
    const after=await handle.stat({bigint:true});
    if(identity(before)!==identity(after)) throw new Error(`${label} changed while hashing`);
    return {digest:hash.digest('hex'),size:Number(before.size)};
  } finally {await handle.close();}
}
async function stableBytes(file,{maximum,label}){
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const before=await handle.stat({bigint:true});
    if(!before.isFile()||before.nlink!==1n||(before.uid!==0n&&before.uid!==BigInt(process.getuid()))
        ||before.size<1n||before.size>BigInt(maximum)
        ||(before.mode&0o022n)!==0n) throw new Error(`${label} metadata is unsafe`);
    const bytes=await handle.readFile(),after=await handle.stat({bigint:true});
    if(identity(before)!==identity(after)) throw new Error(`${label} changed while reading`);
    return bytes;
  } finally {await handle.close();}
}

try {
  if(process.argv.length===3&&process.argv[2]==='--print-podman-plan') {
    const environmentBytes=await stableBytes(RISC0_TRUSTED_SETUP_PODMAN_PATHS.environment,
      {maximum:64*1024,label:'verification environment'});
    const environment=parseStrictJsonBytes(environmentBytes,{label:'verification environment',maxBytes:64*1024,maxDepth:8});
    process.stdout.write(`${JSON.stringify(buildRisc0TrustedSetupPodmanPlan(environment),null,2)}\n`);
  } else {
  if(process.argv.length!==2) throw new Error('this command accepts no paths; use the fixed private trusted-setup layout');
  const {r1cs:r1csPath,powersOfTau:ptauPath,zkey:zkeyPath,verificationKey:vkPath,
    powersOfTauLog:ptauLogPath,zkeyLog:zkeyLogPath,environment:environmentPath}=
    RISC0_TRUSTED_SETUP_PODMAN_PATHS;
  const referenceBytes=await readDirectProjectFile(root,'config/risc0-ethereum-mainnet-v3.json');
  const reference=validateRiscZeroMainnetReference(parseStrictJsonBytes(referenceBytes,
    {label:'RISC Zero mainnet reference',maxBytes:64*1024,maxDepth:8}));
  const authorityBytes=await readDirectProjectFile(root,reference.trusted_setup_authority_path);
  const authoritySha256=createHash('sha256').update(authorityBytes).digest('hex');
  if(authoritySha256!==reference.trusted_setup_authority_sha256) throw new Error('trusted-setup authority differs from mainnet reference');
  const authority=parseStrictJsonBytes(authorityBytes,{label:'trusted-setup authority',maxBytes:64*1024,maxDepth:8});
  const [r1cs,powersOfTau,zkey,verificationKey,powersOfTauLog,zkeyLog,environmentBytes,runtime,
    podmanImageInspection,toolchainAttestation]=await Promise.all([
    stableHash(r1csPath,{algorithm:'sha256',expectedSize:authority.r1cs_size,maximum:2*1024**3,label:'R1CS'}),
    stableHash(ptauPath,{algorithm:'blake2b512',expectedSize:authority.powers_of_tau_size,maximum:12*1024**3,label:'Powers of Tau'}),
    stableHash(zkeyPath,{algorithm:'sha256',expectedSize:authority.zkey_size,maximum:5*1024**3,label:'zkey'}),
    stableHash(vkPath,{algorithm:'sha256',expectedSize:null,maximum:64*1024**2,label:'verification key'}),
    stableBytes(ptauLogPath,{maximum:4*1024*1024,label:'Powers of Tau verification log'}),
    stableBytes(zkeyLogPath,{maximum:4*1024*1024,label:'zkey verification log'}),
    stableBytes(environmentPath,{maximum:64*1024,label:'verification environment'}),
    stableHash('/usr/bin/podman',{algorithm:'sha256',expectedSize:null,maximum:256*1024**2,
      label:'Podman runtime',executable:true}),
    stableBytes(RISC0_TRUSTED_SETUP_PODMAN_PATHS.imageInspection,
      {maximum:64*1024,label:'Podman image inspection'}),
    stableBytes(RISC0_TRUSTED_SETUP_PODMAN_PATHS.toolchainAttestationLog,
      {maximum:64*1024,label:'toolchain attestation'}),
  ]);
  if(r1cs.digest!==authority.r1cs_sha256||powersOfTau.digest!==authority.powers_of_tau_blake2b512) {
    throw new Error('R1CS or Powers of Tau digest differs from authority');
  }
  const environment=parseStrictJsonBytes(environmentBytes,{label:'verification environment',maxBytes:64*1024,maxDepth:8});
  validateRisc0TrustedSetupVerificationEnvironment(environment);
  if(runtime.digest!==environment.containerRuntime.sha256) throw new Error('Podman runtime differs from environment commitment');
  const report=buildRisc0TrustedSetupVerificationReport({authority,authoritySha256,
    r1cs:{sha256:r1cs.digest,size:r1cs.size},powersOfTau:{blake2b512:powersOfTau.digest,size:powersOfTau.size},
    zkey:{sha256:zkey.digest,size:zkey.size},verificationKeySha256:verificationKey.digest,
    powersOfTauLog,zkeyLog,verificationEnvironment:environment,podmanImageInspection,toolchainAttestation});
  const [referenceAfter,authorityAfter]=await Promise.all([
    readDirectProjectFile(root,'config/risc0-ethereum-mainnet-v3.json'),
    readDirectProjectFile(root,reference.trusted_setup_authority_path),
  ]);
  if(!referenceAfter.equals(referenceBytes)||!authorityAfter.equals(authorityBytes)) {
    throw new Error('trusted-setup authority changed during verification materialization');
  }
  process.stdout.write(serializeRisc0TrustedSetupVerificationReport(report));
  }
} catch(error){writeReleaseFailure('prepare-risc0-trusted-setup-verification-report',error);process.exitCode=1;}
