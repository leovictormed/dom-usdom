import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {finalizedBurnVerifierConfigHash} from '../../sdk/verifier-config.mjs';
import {checkpointVerifierConfigHash} from '../../sdk/checkpoint-verifier-config.mjs';
import {verifierConfigFixture} from './verifier-config.test.mjs';
import {checkpointVerifierConfigFixture} from './checkpoint-verifier-config.test.mjs';
import {buildTrustedSetupDecisionReport,serializeTrustedSetupDecisionReport,
  validateTrustedSetupDecisionReport} from '../../sdk/trusted-setup-decision-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';
import {PINNED_SNARKJS_PACKAGE_INTEGRITY,PINNED_SNARKJS_VERSION,
  PINNED_SNARKJS_KNOWN_ADVISORIES,
  RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS,
  buildRisc0TrustedSetupPodmanPlan,
  serializeRisc0TrustedSetupVerificationReport,
} from '../../sdk/risc0-trusted-setup-verification-report.mjs';

const authorityBytes=await readFile(new URL('../../config/risc0-trusted-setup-authority-v1.json',import.meta.url));
const trustedSetupAuthority=JSON.parse(authorityBytes);
const trustedSetupAuthoritySha256=createHash('sha256').update(authorityBytes).digest('hex');
const contributionWords=Array.from({length:16},(_,index)=>(index+1).toString(16).padStart(8,'0')).join(' ');
const powersOfTauUtf8='[INFO]  snarkJS: Powers Of tau file OK!\n';
const zkeyUtf8=`[INFO]  snarkJS: Contribution Hash:\n ${contributionWords}\n[INFO]  snarkJS: ZKey Ok!\n`;
const verificationEnvironment=verificationKeySha256=>({schema:'usdom-risc0-trusted-setup-verification-environment/v7',
 containerImageDigest:`sha256:${'77'.repeat(32)}`,networkDisabled:true,nodeVersion:'v24.19.0',
 containerImageReference:`sha256:${'77'.repeat(32)}`,inputArtifacts:{
  r1csSha256:trustedSetupAuthority.r1cs_sha256,powersOfTauBlake2b512:trustedSetupAuthority.powers_of_tau_blake2b512,
  zkeySha256:'11'.repeat(32),expectedVerificationKeySha256:verificationKeySha256},
 containerRuntime:{path:'/usr/bin/podman',sha256:'88'.repeat(32)},
 snarkjsVersion:PINNED_SNARKJS_VERSION,snarkjsPackageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY,
 knownAdvisories:[...PINNED_SNARKJS_KNOWN_ADVISORIES],capabilitiesDropped:['ALL'],
 commands:structuredClone(RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS),inputMountReadOnly:true,
 noNewPrivileges:true,outputTmpfs:true,rootFilesystemReadOnly:true,runAsUser:'65532:65532'});
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'
 ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
function verificationReport(verificationKeySha256){const descriptor=verificationEnvironment(verificationKeySha256);
 const verificationEnvironmentSha256=createHash('sha256').update(`${JSON.stringify(stable(descriptor),null,2)}\n`).digest('hex');
 const podmanPlan=buildRisc0TrustedSetupPodmanPlan(descriptor),imageInspectionUtf8=`${JSON.stringify(podmanPlan.image)}\n`;
 const toolchainAttestationUtf8=`${JSON.stringify({nodeVersion:descriptor.nodeVersion,
  snarkjsVersion:descriptor.snarkjsVersion,snarkjsPackageIntegrity:descriptor.snarkjsPackageIntegrity})}\n`;
 const containerExecution={imageInspectionSha256:createHash('sha256').update(imageInspectionUtf8).digest('hex'),
  imageInspectionUtf8,planSha256:createHash('sha256').update(`${JSON.stringify(stable(podmanPlan),null,2)}\n`).digest('hex'),imageIdentifier:podmanPlan.image};
 containerExecution.toolchainAttestationSha256=createHash('sha256').update(toolchainAttestationUtf8).digest('hex');
 containerExecution.toolchainAttestationUtf8=toolchainAttestationUtf8;
 return {schema:'usdom-risc0-groth16-trusted-setup-verification/v6',status:'verified',
 authoritySha256:trustedSetupAuthoritySha256,artifacts:{r1cs:{sha256:trustedSetupAuthority.r1cs_sha256,size:trustedSetupAuthority.r1cs_size},
 powersOfTau:{blake2b512:trustedSetupAuthority.powers_of_tau_blake2b512,power:23,size:trustedSetupAuthority.powers_of_tau_size},
 zkey:{sha256:'11'.repeat(32),size:trustedSetupAuthority.zkey_size,verificationKeySha256}},
 snarkjs:{version:PINNED_SNARKJS_VERSION,packageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY,
  isolated:true,networkDisabled:true,knownAdvisories:[...PINNED_SNARKJS_KNOWN_ADVISORIES],powersOfTauVerified:true,zkeyVerified:true},
 contributionDigests:[contributionWords.replaceAll(' ','')],verificationLogs:{
  powersOfTauSha256:createHash('sha256').update(powersOfTauUtf8).digest('hex'),powersOfTauUtf8,
  zkeySha256:createHash('sha256').update(zkeyUtf8).digest('hex'),zkeyUtf8},
 containerExecution,verificationEnvironment:{document:descriptor,sha256:verificationEnvironmentSha256}};}
function fixture(){
 const verifierConfig={...verifierConfigFixture()},checkpointVerifierConfig={...checkpointVerifierConfigFixture()};
 checkpointVerifierConfig.verifyingKeySha256=verifierConfig.verifyingKeySha256;
 const trustedSetupVerificationReport=verificationReport(verifierConfig.verifyingKeySha256.slice(2));
 const transcript=createHash('sha256').update(serializeRisc0TrustedSetupVerificationReport(trustedSetupVerificationReport)).digest('hex');
 const document={path:'evidence/risc0-groth16-ceremony-verification.json',sha256:transcript};
 verifierConfig.trustedSetupTranscriptSha256=`0x${transcript}`;
 checkpointVerifierConfig.trustedSetupTranscriptSha256=`0x${transcript}`;
 const finalized=finalizedBurnVerifierConfigHash(verifierConfig),checkpoint=checkpointVerifierConfigHash(checkpointVerifierConfig);
 return {releaseEvidence:{schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1.0.0',
   trustedSetup:{required:true,decisionReport:null,transcript:{...document}},
   checkpointTrustedSetup:{required:true,decisionReport:null,transcript:{...document}}},
  releaseConfig:{ethereumChainId:'1',verifierConfigHash:finalized.verifierConfigHash,
   checkpointVerifierConfigHash:checkpoint.verifierConfigHash},verifierConfig,checkpointVerifierConfig,
   trustedSetupVerificationReport,trustedSetupAuthority,trustedSetupAuthoritySha256};
}
test('binds both verifier configurations to one semantically verified ceremony transcript',()=>{const input=fixture(),report=buildTrustedSetupDecisionReport(input);assert.equal(report.status,'required-and-release-bound');assert.equal(report.sharedTranscript.sha256,input.releaseEvidence.trustedSetup.transcript.sha256);assert.deepEqual(validateTrustedSetupDecisionReport(report,input),report);assert.deepEqual(JSON.parse(serializeTrustedSetupDecisionReport(report)),report);});
test('rejects setup, transcript, release and configuration drift',()=>{for(const mutate of [v=>{v.releaseEvidence.trustedSetup.required=false;},v=>{v.releaseEvidence.checkpointTrustedSetup.transcript.sha256='cd'.repeat(32);},v=>{v.releaseConfig.ethereumChainId='31337';},v=>{v.releaseConfig.verifierConfigHash='0x'+'cd'.repeat(32);},v=>{v.verifierConfig.trustedSetupTranscriptSha256='0x'+'cd'.repeat(32);},v=>{v.releaseEvidence.sourceTag='latest';}]){const input=fixture();mutate(input);assert.throws(()=>buildTrustedSetupDecisionReport(input));}});
test('rejects altered or extended decision reports',()=>{for(const mutate of [r=>{r.decision='optional';},r=>{r.sharedTranscript.sha256='cd'.repeat(32);},r=>{r.finalizedBurnVerifier.verifyingKeySha256='0x'+'cd'.repeat(32);},r=>{r.extra=true;}]){const input=fixture(),report=structuredClone(buildTrustedSetupDecisionReport(input));mutate(report);assert.throws(()=>validateTrustedSetupDecisionReport(report,input));}});
test('preparer hashes and rechecks release, authority, configs and verification report',async()=>{const source=await readFile(new URL('../../scripts/prepare-trusted-setup-decision-report.mjs',import.meta.url),'utf8');for(const check of [/evidenceAfter\.equals\(evidenceBytes\)/,/releaseAfter\.equals\(releaseBytes\)/,/referenceAfter\.equals\(referenceBytes\)/,/authorityAfter\.equals\(authorityBytes\)/,/verifierAfter\.equals\(verifierBytes\)/,/checkpointAfter\.equals\(checkpointBytes\)/,/transcriptAfter\.equals\(transcriptBytes\)/])assert.match(source,check);assert.match(source,/verifierPath===checkpointPath/);assert.match(source,/createHash\('sha256'\)\.update\(transcriptBytes\)/);assert.match(source,/createHash\('sha256'\)\.update\(bytes\)\.digest\('hex'\)!==document\.sha256/);assert.match(source,/releaseEvidence\.checkpointVerifierConfigManifest/);assert.match(source,/trustedSetupVerificationReport=parse\(transcriptPath,transcriptBytes\)/);});
test('trusted-setup JSON authority rejects duplicate escaped keys and invalid UTF-8',()=>{for(const bytes of [Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d])])assert.throws(()=>parseStrictJsonBytes(bytes,{label:'trusted setup',maxBytes:4*1024*1024,maxDepth:64}),/duplicate (?:object )?key|invalid UTF-8/);});
test('trusted-setup preparer byte-parses every JSON authority',async()=>{const source=await readFile(new URL('../../scripts/prepare-trusted-setup-decision-report.mjs',import.meta.url),'utf8');assert.match(source,/parseStrictJsonBytes\(bytes/);assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);for(const input of ['evidenceBytes','releaseBytes','referenceBytes','authorityBytes','verifierBytes','checkpointBytes','transcriptBytes'])assert.match(source,new RegExp(`parse\\([^,]+,${input}\\)`));});
