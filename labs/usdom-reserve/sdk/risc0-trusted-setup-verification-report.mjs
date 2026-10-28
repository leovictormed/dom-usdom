import {createHash} from 'node:crypto';
import {RISC0_TRUSTED_SETUP_AUTHORITY_SHA256,validateRisc0TrustedSetupAuthority}
  from './risc0-trusted-setup-authority.mjs';
import {parseStrictJson} from './strict-json.mjs';

const sha256=/^[0-9a-f]{64}$/;
const blake2b512=/^[0-9a-f]{128}$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'
  ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
const nonzero=value=>sha256.test(value)&&value!=='0'.repeat(64);
function fail(message){throw new Error(message);}

export const RISC0_TRUSTED_SETUP_VERIFICATION_REPORT_SCHEMA=
  'usdom-risc0-groth16-trusted-setup-verification/v6';
export const RISC0_TRUSTED_SETUP_VERIFICATION_ENVIRONMENT_SCHEMA=
  'usdom-risc0-trusted-setup-verification-environment/v7';
export const PINNED_SNARKJS_VERSION='0.7.6';
export const PINNED_SNARKJS_PACKAGE_INTEGRITY=
  'sha512-4uH1xA5JzVU5jaaWS2fXej3+RC6L5Erhr6INTJtUA27du4Elbh4VXCeeRjB4QiwL6N6y7SNKePw5prTxyEf4Zg==';
export const PINNED_SNARKJS_KNOWN_ADVISORIES=Object.freeze(['GHSA-qpx9-hpmf-5gmw']);
export const RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS=Object.freeze({
  attestToolchain:Object.freeze(['node','-e',
    "const fs=require('fs'),c=require('crypto'),p=JSON.parse(fs.readFileSync('/opt/snarkjs/package.json','utf8')),b=fs.readFileSync('/opt/snarkjs-package.tgz');process.stdout.write(JSON.stringify({nodeVersion:process.version,snarkjsVersion:p.version,snarkjsPackageIntegrity:'sha512-'+c.createHash('sha512').update(b).digest('base64')})+'\\n')"]),
  exportVerificationKey:Object.freeze(['node','/opt/snarkjs/build/cli.cjs','zkey','export',
    'verificationkey','/input/circuit.zkey','/output/verification-key.json']),
  verifyPowersOfTau:Object.freeze(['node','/opt/snarkjs/build/cli.cjs','powersoftau','verify',
    '/input/powers.ptau']),
  verifyZkey:Object.freeze(['node','/opt/snarkjs/build/cli.cjs','zkey','verify',
    '/input/circuit.r1cs','/input/powers.ptau','/input/circuit.zkey']),
});
export const RISC0_TRUSTED_SETUP_PODMAN_PLAN_SCHEMA=
  'usdom-risc0-trusted-setup-podman-plan/v1';
const PODMAN='/usr/bin/podman';
const INPUT='/home/leonardov/usdom-mainnet-private/trusted-setup/input';
const OUTPUT='/dev/shm/usdom-risc0-trusted-setup-output';
const PRIVATE='/home/leonardov/usdom-mainnet-private/trusted-setup';
export const RISC0_TRUSTED_SETUP_PODMAN_PATHS=Object.freeze({
  environment:`${PRIVATE}/verification-environment.json`,
  exportVerificationKeyLog:`${PRIVATE}/export-verification-key.log`,
  toolchainAttestationLog:`${PRIVATE}/toolchain-attestation.json`,
  imageInspection:`${PRIVATE}/podman-image-inspection.json`,
  powersOfTauLog:`${PRIVATE}/powers-of-tau.log`,r1cs:`${INPUT}/circuit.r1cs`,
  powersOfTau:`${INPUT}/powers.ptau`,zkey:`${INPUT}/circuit.zkey`,
  verificationKey:`${OUTPUT}/verification-key.json`,zkeyLog:`${PRIVATE}/zkey.log`,
});

export function buildRisc0TrustedSetupPodmanPlan(environment){
  const trusted=validateRisc0TrustedSetupVerificationEnvironment(environment);
  const base=[trusted.containerRuntime.path,'run','--rm','--pull=never','--network=none','--read-only',
    '--userns=keep-id:uid=65532,gid=65532','--user=65532:65532','--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    `--mount=type=bind,src=${INPUT},dst=/input,ro=true`,
    `--mount=type=bind,src=${OUTPUT},dst=/output,rw=true`,
    '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864','--entrypoint=node',
    trusted.containerImageReference];
  const invocation=(id,command,stdoutPath)=>({id,
    argv:[...base,...command.slice(1)],stderr:'merge-into-stdout',stdoutPath});
  return {schema:RISC0_TRUSTED_SETUP_PODMAN_PLAN_SCHEMA,runtime:structuredClone(trusted.containerRuntime),
    image:trusted.containerImageReference,expectedImageDigest:trusted.containerImageDigest,
    expectedArtifacts:structuredClone(trusted.inputArtifacts),
    inputDirectory:INPUT,outputDirectory:OUTPUT,
    outputFilesystem:'tmpfs',imageInspection:{
      argv:[trusted.containerRuntime.path,'image','inspect','--format={{json .Id}}',trusted.containerImageReference],
      expectedImageIdentifier:trusted.containerImageReference,
    },invocations:[
      invocation('attest-toolchain',trusted.commands.attestToolchain,
        RISC0_TRUSTED_SETUP_PODMAN_PATHS.toolchainAttestationLog),
      invocation('verify-powers-of-tau',trusted.commands.verifyPowersOfTau,
        RISC0_TRUSTED_SETUP_PODMAN_PATHS.powersOfTauLog),
      invocation('verify-zkey',trusted.commands.verifyZkey,
        RISC0_TRUSTED_SETUP_PODMAN_PATHS.zkeyLog),
      invocation('export-verification-key',trusted.commands.exportVerificationKey,
        RISC0_TRUSTED_SETUP_PODMAN_PATHS.exportVerificationKeyLog),
    ]};
}

export function validateRisc0TrustedSetupPodmanImageInspection(bytes,plan){
  if(!Buffer.isBuffer(bytes)||bytes.length<3||bytes.length>64*1024) {
    fail('Podman image inspection output is invalid');
  }
  let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{fail('Podman image inspection is not UTF-8');}
  if(!text.endsWith('\n')||text.endsWith('\n\n')||/[\r\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) {
    fail('Podman image inspection framing is invalid');
  }
  let imageIdentifier;try{imageIdentifier=parseStrictJson(text,{label:'Podman image ID',maxDepth:2});}
  catch{fail('Podman image ID output is not JSON');}
  if(!plan||plan.schema!==RISC0_TRUSTED_SETUP_PODMAN_PLAN_SCHEMA
      ||!exact(plan.imageInspection,['argv','expectedImageIdentifier'])
      ||plan.imageInspection.expectedImageIdentifier!==plan.image
      ||typeof imageIdentifier!=='string'||!/^sha256:[0-9a-f]{64}$/.test(imageIdentifier)
      ||imageIdentifier!==plan.imageInspection.expectedImageIdentifier) {
    fail('Podman image inspection does not prove the expected immutable image ID');
  }
  if(text!==`${JSON.stringify(imageIdentifier)}\n`) {
    fail('Podman image ID output is not canonically serialized');
  }
  return imageIdentifier;
}

export function validateRisc0TrustedSetupVerificationEnvironment(environment){
  const nodeMatch=/^v(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/.exec(
    environment?.nodeVersion??'');
  if(!exact(environment,['capabilitiesDropped','commands','containerImageDigest','containerImageReference','containerRuntime','inputArtifacts','inputMountReadOnly',
    'knownAdvisories','networkDisabled','noNewPrivileges','nodeVersion','outputTmpfs','rootFilesystemReadOnly',
    'runAsUser','schema','snarkjsPackageIntegrity','snarkjsVersion'])
      ||environment.schema!==RISC0_TRUSTED_SETUP_VERIFICATION_ENVIRONMENT_SCHEMA
      ||!/^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(environment.containerImageDigest??'')
      ||!/^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(environment.containerImageReference??'')
      ||environment.containerImageReference!==environment.containerImageDigest
      ||!exact(environment.containerRuntime,['path','sha256'])
      ||environment.containerRuntime.path!==PODMAN||!nonzero(environment.containerRuntime.sha256)
      ||!exact(environment.inputArtifacts,['expectedVerificationKeySha256','powersOfTauBlake2b512',
        'r1csSha256','zkeySha256'])
      ||!nonzero(environment.inputArtifacts.r1csSha256)
      ||!blake2b512.test(environment.inputArtifacts.powersOfTauBlake2b512)
      ||environment.inputArtifacts.powersOfTauBlake2b512==='0'.repeat(128)
      ||!nonzero(environment.inputArtifacts.zkeySha256)
      ||!nonzero(environment.inputArtifacts.expectedVerificationKeySha256)
      ||environment.networkDisabled!==true||environment.snarkjsVersion!==PINNED_SNARKJS_VERSION
      ||environment.snarkjsPackageIntegrity!==PINNED_SNARKJS_PACKAGE_INTEGRITY
      ||JSON.stringify(environment.knownAdvisories)!==JSON.stringify(PINNED_SNARKJS_KNOWN_ADVISORIES)
      ||!nodeMatch||Number(nodeMatch[1])!==24||Number(nodeMatch[2])<19
      ||environment.inputMountReadOnly!==true||environment.noNewPrivileges!==true
      ||environment.outputTmpfs!==true||environment.rootFilesystemReadOnly!==true
      ||environment.runAsUser!=='65532:65532'
      ||JSON.stringify(environment.capabilitiesDropped)!==JSON.stringify(['ALL'])
      ||!exact(environment.commands,['attestToolchain','exportVerificationKey','verifyPowersOfTau','verifyZkey'])
      ||JSON.stringify(environment.commands)!==JSON.stringify(RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS)) {
    fail('verification environment descriptor is invalid');
  }
  return structuredClone(environment);
}

export function validateRisc0TrustedSetupToolchainAttestation(bytes,environment){
  if(!Buffer.isBuffer(bytes)||bytes.length<3||bytes.length>64*1024) fail('toolchain attestation size is invalid');
  let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{fail('toolchain attestation is not UTF-8');}
  if(!text.endsWith('\n')||text.endsWith('\n\n')||/[\r\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) {
    fail('toolchain attestation framing is invalid');
  }
  let value;try{value=parseStrictJson(text,{label:'toolchain attestation',maxDepth:8});}
  catch{fail('toolchain attestation is not JSON');}
  if(!exact(value,['nodeVersion','snarkjsPackageIntegrity','snarkjsVersion'])
      ||value.nodeVersion!==environment.nodeVersion||value.snarkjsVersion!==environment.snarkjsVersion
      ||value.snarkjsPackageIntegrity!==environment.snarkjsPackageIntegrity
      ||text!==`${JSON.stringify(value)}\n`) fail('toolchain attestation differs from the committed environment');
  return structuredClone(value);
}

function cleanLog(value,label){
  if(!Buffer.isBuffer(value)||value.length<1||value.length>4*1024*1024) fail(`${label} log size is invalid`);
  let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(value);}catch{fail(`${label} log is not UTF-8`);}
  if(text.includes('\u001b')||text.includes('\r')||!text.endsWith('\n')||text.endsWith('\n\n')
      ||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) {
    fail(`${label} log framing is invalid or colors are enabled`);
  }
  return text;
}
export function parseSnarkjsVerificationLogs({powersOfTauLog,zkeyLog}={}){
  const powers=cleanLog(powersOfTauLog,'Powers of Tau'),zkey=cleanLog(zkeyLog,'zkey');
  const powersLines=powers.slice(0,-1).split('\n'),zkeyLines=zkey.slice(0,-1).split('\n');
  const powerSuccess=/^(?:\[INFO\]\s+)?snarkJS: Powers Of tau file OK!$/;
  const zkeySuccess=/^(?:\[INFO\]\s+)?snarkJS: ZKey Ok!$/;
  if(powersLines.filter(line=>powerSuccess.test(line)).length!==1
      ||!powerSuccess.test(powersLines.at(-1))) fail('Powers of Tau final success marker is missing or ambiguous');
  if(zkeyLines.filter(line=>zkeySuccess.test(line)).length!==1
      ||!zkeySuccess.test(zkeyLines.at(-1))) fail('zkey final success marker is missing or ambiguous');
  if([...powersLines,...zkeyLines].some(line=>/\b(?:ERROR|FATAL|FAIL(?:ED|URE)?)\b/i.test(line))) {
    fail('snarkjs verification log contains a failure marker');
  }
  const contributionDigests=[];
  const contributionHeader=/^(?:\[INFO\]\s+)?snarkJS: Contribution Hash:$/;
  const hashWords=/^\s*((?:[0-9a-fA-F]{8}(?:\s+|$))+?)\s*$/;
  const beforeSuccess=zkeyLines.slice(0,-1);
  for(let index=0;index<beforeSuccess.length;++index){
    const line=beforeSuccess[index];
    if(line.includes('Contribution Hash:')&&!contributionHeader.test(line)) {
      fail('zkey contribution hash header is malformed');
    }
    if(!contributionHeader.test(line)) continue;
    const words=[];
    while(index+1<beforeSuccess.length&&hashWords.test(beforeSuccess[index+1])) {
      words.push(...beforeSuccess[++index].trim().split(/\s+/));
      if(words.length>16) fail('zkey contribution hash has excess words');
    }
    if(words.length!==16) fail('zkey contribution hash is truncated or malformed');
    contributionDigests.push(words.join('').toLowerCase());
  }
  if(contributionDigests.length<1||new Set(contributionDigests).size!==contributionDigests.length) {
    fail('distinct zkey contribution hashes are missing');
  }
  return {contributionDigests,powersOfTauSha256:createHash('sha256').update(powersOfTauLog).digest('hex'),
    zkeySha256:createHash('sha256').update(zkeyLog).digest('hex')};
}

export function buildRisc0TrustedSetupVerificationReport({authority,authoritySha256,r1cs,
  powersOfTau,zkey,verificationKeySha256,powersOfTauLog,zkeyLog,verificationEnvironment,
  podmanImageInspection,toolchainAttestation}={}) {
  const logs=parseSnarkjsVerificationLogs({powersOfTauLog,zkeyLog});
  const environment=validateRisc0TrustedSetupVerificationEnvironment(verificationEnvironment);
  if(environment.inputArtifacts.r1csSha256!==r1cs?.sha256
      ||environment.inputArtifacts.powersOfTauBlake2b512!==powersOfTau?.blake2b512
      ||environment.inputArtifacts.zkeySha256!==zkey?.sha256
      ||environment.inputArtifacts.expectedVerificationKeySha256!==verificationKeySha256) {
    fail('verification environment artifact commitments differ from measured artifacts');
  }
  const plan=buildRisc0TrustedSetupPodmanPlan(environment);
  const imageIdentifier=validateRisc0TrustedSetupPodmanImageInspection(podmanImageInspection,plan);
  validateRisc0TrustedSetupToolchainAttestation(toolchainAttestation,environment);
  const report={schema:RISC0_TRUSTED_SETUP_VERIFICATION_REPORT_SCHEMA,status:'verified',authoritySha256,
    artifacts:{r1cs:{sha256:r1cs?.sha256,size:r1cs?.size},
      powersOfTau:{blake2b512:powersOfTau?.blake2b512,power:authority?.powers_of_tau_power,
        size:powersOfTau?.size},zkey:{sha256:zkey?.sha256,size:zkey?.size,verificationKeySha256}},
    snarkjs:{version:PINNED_SNARKJS_VERSION,packageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY,
      isolated:true,networkDisabled:true,knownAdvisories:[...PINNED_SNARKJS_KNOWN_ADVISORIES],
      powersOfTauVerified:true,zkeyVerified:true},contributionDigests:logs.contributionDigests,
    verificationLogs:{powersOfTauSha256:logs.powersOfTauSha256,
      powersOfTauUtf8:powersOfTauLog.toString('utf8'),zkeySha256:logs.zkeySha256,
      zkeyUtf8:zkeyLog.toString('utf8')},
    containerExecution:{imageInspectionSha256:createHash('sha256').update(podmanImageInspection).digest('hex'),
      imageInspectionUtf8:podmanImageInspection.toString('utf8'),planSha256:createHash('sha256')
        .update(`${JSON.stringify(stable(plan),null,2)}\n`).digest('hex'),imageIdentifier,
      toolchainAttestationSha256:createHash('sha256').update(toolchainAttestation).digest('hex'),
      toolchainAttestationUtf8:toolchainAttestation.toString('utf8')},
    verificationEnvironment:{document:environment,
      sha256:createHash('sha256').update(`${JSON.stringify(stable(environment),null,2)}\n`).digest('hex')}};
  return validateRisc0TrustedSetupVerificationReport(report,{authority,authoritySha256});
}

export function validateRisc0TrustedSetupVerificationReport(report,{authority,authoritySha256}={}) {
  const trusted=validateRisc0TrustedSetupAuthority(authority);
  if(!exact(report,['artifacts','authoritySha256','containerExecution','contributionDigests','schema','snarkjs','status',
    'verificationEnvironment','verificationLogs'])) fail('trusted-setup verification report schema is invalid');
  if(report.schema!==RISC0_TRUSTED_SETUP_VERIFICATION_REPORT_SCHEMA||report.status!=='verified') {
    fail('trusted-setup verification did not complete');
  }
  if(authoritySha256!==RISC0_TRUSTED_SETUP_AUTHORITY_SHA256
      ||report.authoritySha256!==RISC0_TRUSTED_SETUP_AUTHORITY_SHA256) {
    fail('trusted-setup authority digest mismatch');
  }
  if(!exact(report.artifacts,['powersOfTau','r1cs','zkey'])
      ||!exact(report.artifacts.r1cs,['sha256','size'])
      ||!exact(report.artifacts.powersOfTau,['blake2b512','power','size'])
      ||!exact(report.artifacts.zkey,['sha256','size','verificationKeySha256'])) fail('trusted-setup artifact evidence is invalid');
  const {r1cs,powersOfTau,zkey}=report.artifacts;
  if(r1cs.sha256!==trusted.r1cs_sha256||r1cs.size!==trusted.r1cs_size
      ||powersOfTau.blake2b512!==trusted.powers_of_tau_blake2b512
      ||powersOfTau.power!==trusted.powers_of_tau_power
      ||powersOfTau.size!==trusted.powers_of_tau_size
      ||!nonzero(zkey.sha256)||!nonzero(zkey.verificationKeySha256)||zkey.size!==trusted.zkey_size) {
    fail('trusted-setup artifacts differ from the pinned authority');
  }
  if(!exact(report.snarkjs,['isolated','knownAdvisories','networkDisabled','packageIntegrity',
      'powersOfTauVerified','version','zkeyVerified'])
      ||report.snarkjs.version!==PINNED_SNARKJS_VERSION
      ||report.snarkjs.packageIntegrity!==PINNED_SNARKJS_PACKAGE_INTEGRITY
      ||report.snarkjs.isolated!==true||report.snarkjs.networkDisabled!==true
      ||JSON.stringify(report.snarkjs.knownAdvisories)!==JSON.stringify(PINNED_SNARKJS_KNOWN_ADVISORIES)
      ||report.snarkjs.powersOfTauVerified!==true||report.snarkjs.zkeyVerified!==true) {
    fail('pinned snarkjs did not verify both transcripts');
  }
  if(!exact(report.verificationLogs,['powersOfTauSha256','powersOfTauUtf8','zkeySha256','zkeyUtf8'])
      ||!nonzero(report.verificationLogs.powersOfTauSha256)
      ||!nonzero(report.verificationLogs.zkeySha256)) fail('verification log evidence is invalid');
  if(typeof report.verificationLogs.powersOfTauUtf8!=='string'
      ||typeof report.verificationLogs.zkeyUtf8!=='string') fail('verification logs must be self-contained UTF-8 text');
  const reparsed=parseSnarkjsVerificationLogs({
    powersOfTauLog:Buffer.from(report.verificationLogs.powersOfTauUtf8,'utf8'),
    zkeyLog:Buffer.from(report.verificationLogs.zkeyUtf8,'utf8'),
  });
  if(reparsed.powersOfTauSha256!==report.verificationLogs.powersOfTauSha256
      ||reparsed.zkeySha256!==report.verificationLogs.zkeySha256
      ||JSON.stringify(reparsed.contributionDigests)!==JSON.stringify(report.contributionDigests)) {
    fail('verification logs do not reproduce the report evidence');
  }
  if(!exact(report.verificationEnvironment,['document','sha256'])
      ||!nonzero(report.verificationEnvironment.sha256)) fail('verification environment evidence is invalid');
  const environment=validateRisc0TrustedSetupVerificationEnvironment(report.verificationEnvironment.document);
  if(environment.inputArtifacts.r1csSha256!==r1cs.sha256
      ||environment.inputArtifacts.powersOfTauBlake2b512!==powersOfTau.blake2b512
      ||environment.inputArtifacts.zkeySha256!==zkey.sha256
      ||environment.inputArtifacts.expectedVerificationKeySha256!==zkey.verificationKeySha256) {
    fail('verification environment is not bound to the reported artifacts');
  }
  const environmentSha256=createHash('sha256').update(`${JSON.stringify(stable(environment),null,2)}\n`).digest('hex');
  if(environmentSha256!==report.verificationEnvironment.sha256) {
    fail('verification environment hash does not match its canonical document');
  }
  if(!exact(report.containerExecution,['imageIdentifier','imageInspectionSha256','imageInspectionUtf8','planSha256',
      'toolchainAttestationSha256','toolchainAttestationUtf8'])
      ||typeof report.containerExecution.imageInspectionUtf8!=='string'
      ||typeof report.containerExecution.toolchainAttestationUtf8!=='string'
      ||!nonzero(report.containerExecution.imageInspectionSha256)
      ||!nonzero(report.containerExecution.toolchainAttestationSha256)
      ||!nonzero(report.containerExecution.planSha256)) fail('container execution evidence is invalid');
  const plan=buildRisc0TrustedSetupPodmanPlan(environment);
  const planSha256=createHash('sha256').update(`${JSON.stringify(stable(plan),null,2)}\n`).digest('hex');
  const inspectionBytes=Buffer.from(report.containerExecution.imageInspectionUtf8,'utf8');
  const attestationBytes=Buffer.from(report.containerExecution.toolchainAttestationUtf8,'utf8');
  const imageIdentifier=validateRisc0TrustedSetupPodmanImageInspection(inspectionBytes,plan);
  validateRisc0TrustedSetupToolchainAttestation(attestationBytes,environment);
  if(planSha256!==report.containerExecution.planSha256
      ||createHash('sha256').update(inspectionBytes).digest('hex')!==report.containerExecution.imageInspectionSha256
      ||createHash('sha256').update(attestationBytes).digest('hex')!==report.containerExecution.toolchainAttestationSha256
      ||imageIdentifier!==report.containerExecution.imageIdentifier) {
    fail('container execution evidence does not reproduce the trusted plan and image inspection');
  }
  if(!Array.isArray(report.contributionDigests)||report.contributionDigests.length<1
      ||report.contributionDigests.some(value=>!blake2b512.test(value))
      ||new Set(report.contributionDigests).size!==report.contributionDigests.length) {
    fail('distinct ceremony contribution digests are required');
  }
  return structuredClone(report);
}

export function serializeRisc0TrustedSetupVerificationReport(report){
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}
