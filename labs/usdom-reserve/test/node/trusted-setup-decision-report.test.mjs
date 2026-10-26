import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {finalizedBurnVerifierConfigHash} from '../../sdk/verifier-config.mjs';
import {checkpointVerifierConfigHash} from '../../sdk/checkpoint-verifier-config.mjs';
import {verifierConfigFixture} from './verifier-config.test.mjs';
import {checkpointVerifierConfigFixture} from './checkpoint-verifier-config.test.mjs';
import {buildTrustedSetupDecisionReport,serializeTrustedSetupDecisionReport,
  validateTrustedSetupDecisionReport} from '../../sdk/trusted-setup-decision-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const transcript='ab'.repeat(32),document={path:'evidence/risc0-groth16-ceremony-transcript.txt',sha256:transcript};
function fixture(){
 const verifierConfig={...verifierConfigFixture(),trustedSetupTranscriptSha256:`0x${transcript}`};
 const checkpointVerifierConfig={...checkpointVerifierConfigFixture(),trustedSetupTranscriptSha256:`0x${transcript}`};
 const finalized=finalizedBurnVerifierConfigHash(verifierConfig),checkpoint=checkpointVerifierConfigHash(checkpointVerifierConfig);
 return {releaseEvidence:{schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1.0.0',
   trustedSetup:{required:true,decisionReport:null,transcript:{...document}},
   checkpointTrustedSetup:{required:true,decisionReport:null,transcript:{...document}}},
  releaseConfig:{ethereumChainId:'1',verifierConfigHash:finalized.verifierConfigHash,
   checkpointVerifierConfigHash:checkpoint.verifierConfigHash},verifierConfig,checkpointVerifierConfig};
}
test('binds both verifier configurations to one shared ceremony transcript',()=>{const input=fixture(),report=buildTrustedSetupDecisionReport(input);assert.equal(report.status,'required-and-release-bound');assert.equal(report.sharedTranscript.sha256,transcript);assert.deepEqual(validateTrustedSetupDecisionReport(report,input),report);assert.deepEqual(JSON.parse(serializeTrustedSetupDecisionReport(report)),report);});
test('rejects setup, transcript, release and configuration drift',()=>{for(const mutate of [v=>{v.releaseEvidence.trustedSetup.required=false;},v=>{v.releaseEvidence.checkpointTrustedSetup.transcript.sha256='cd'.repeat(32);},v=>{v.releaseConfig.ethereumChainId='31337';},v=>{v.releaseConfig.verifierConfigHash='0x'+'cd'.repeat(32);},v=>{v.verifierConfig.trustedSetupTranscriptSha256='0x'+'cd'.repeat(32);},v=>{v.releaseEvidence.sourceTag='latest';}]){const input=fixture();mutate(input);assert.throws(()=>buildTrustedSetupDecisionReport(input));}});
test('rejects altered or extended decision reports',()=>{for(const mutate of [r=>{r.decision='optional';},r=>{r.sharedTranscript.sha256='cd'.repeat(32);},r=>{r.finalizedBurnVerifier.verifyingKeySha256='0x'+'cd'.repeat(32);},r=>{r.extra=true;}]){const input=fixture(),report=structuredClone(buildTrustedSetupDecisionReport(input));mutate(report);assert.throws(()=>validateTrustedSetupDecisionReport(report,input));}});
test('preparer hashes and rechecks release, configs and transcript',async()=>{const source=await readFile(new URL('../../scripts/prepare-trusted-setup-decision-report.mjs',import.meta.url),'utf8');for(const check of [/evidenceAfter\.equals\(evidenceBytes\)/,/releaseAfter\.equals\(releaseBytes\)/,/verifierAfter\.equals\(verifierBytes\)/,/checkpointAfter\.equals\(checkpointBytes\)/,/transcriptAfter\.equals\(transcriptBytes\)/])assert.match(source,check);assert.match(source,/verifierPath===checkpointPath/);assert.match(source,/createHash\('sha256'\)\.update\(transcriptBytes\)/);assert.match(source,/createHash\('sha256'\)\.update\(bytes\)\.digest\('hex'\)!==document\.sha256/);assert.match(source,/releaseEvidence\.checkpointVerifierConfigManifest/);});
test('trusted-setup JSON authority rejects duplicate escaped keys and invalid UTF-8',()=>{for(const bytes of [Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d])])assert.throws(()=>parseStrictJsonBytes(bytes,{label:'trusted setup',maxBytes:4*1024*1024,maxDepth:64}),/duplicate (?:object )?key|invalid UTF-8/);});
test('trusted-setup preparer byte-parses all four JSON authorities',async()=>{const source=await readFile(new URL('../../scripts/prepare-trusted-setup-decision-report.mjs',import.meta.url),'utf8');assert.match(source,/parseStrictJsonBytes\(bytes/);assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);for(const input of ['evidenceBytes','releaseBytes','verifierBytes','checkpointBytes'])assert.match(source,new RegExp(`parse\\([^,]+,${input}\\)`));});
