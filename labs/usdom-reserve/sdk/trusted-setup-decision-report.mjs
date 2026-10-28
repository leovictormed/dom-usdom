import {createHash} from 'node:crypto';
import {finalizedBurnVerifierConfigHash} from './verifier-config.mjs';
import {checkpointVerifierConfigHash} from './checkpoint-verifier-config.mjs';
import {serializeRisc0TrustedSetupVerificationReport,validateRisc0TrustedSetupVerificationReport}
  from './risc0-trusted-setup-verification-report.mjs';
const sha=/^[0-9a-f]{64}$/,commit=/^[0-9a-f]{40}$/,tag=/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/;
const reportKeys=['checkpointVerifier','decision','ethereumChainId','finalizedBurnVerifier','rationale','releaseId','schema','sharedTranscript','sourceCommit','sourceTag','status'];
function fail(m){throw new Error(m);} function exact(v,k){return v&&typeof v==='object'&&!Array.isArray(v)&&JSON.stringify(Object.keys(v).sort())===JSON.stringify([...k].sort());}
function stable(v){if(Array.isArray(v))return v.map(stable);if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])]));return v;}
function doc(v){if(!exact(v,['path','sha256'])||typeof v.path!=='string'||v.path.startsWith('/')||v.path.includes('..')||!sha.test(v.sha256??''))fail('shared transcript pointer is invalid');return {...v};}
export const TRUSTED_SETUP_DECISION_REPORT_SCHEMA='usdom-shared-trusted-setup-decision-report/v1';
export function buildTrustedSetupDecisionReport({releaseEvidence,releaseConfig,verifierConfig,checkpointVerifierConfig,
  trustedSetupVerificationReport,trustedSetupAuthority,trustedSetupAuthoritySha256}={}){
 if(!releaseEvidence||releaseEvidence.schema!==1||typeof releaseEvidence.releaseId!=='string'||!releaseEvidence.releaseId||!commit.test(releaseEvidence.sourceCommit??'')||!tag.test(releaseEvidence.sourceTag??''))fail('release provenance is incomplete');
 if(releaseConfig?.ethereumChainId!=='1')fail('Ethereum mainnet release is required');
 const a=releaseEvidence.trustedSetup,b=releaseEvidence.checkpointTrustedSetup;
 if(!exact(a,['decisionReport','required','transcript'])||!exact(b,['decisionReport','required','transcript'])||a.required!==true||b.required!==true)fail('both verifier trusted setups must be required');
 const transcript=doc(a.transcript); if(JSON.stringify(transcript)!==JSON.stringify(doc(b.transcript)))fail('verifiers must bind the same transcript');
 let fv,cv; try{fv=finalizedBurnVerifierConfigHash(verifierConfig);cv=checkpointVerifierConfigHash(checkpointVerifierConfig);}catch(e){fail(`verifier configuration is invalid: ${e.message}`);}
 if(fv.verifierConfigHash!==releaseConfig.verifierConfigHash||cv.verifierConfigHash!==releaseConfig.checkpointVerifierConfigHash)fail('verifier configuration hash differs from release');
 if(fv.trustedSetupRequired!==true||cv.trustedSetupRequired!==true||fv.trustedSetupTranscriptSha256.slice(2)!==transcript.sha256||cv.trustedSetupTranscriptSha256.slice(2)!==transcript.sha256)fail('trusted setup transcript differs from verifier configuration');
 const verified=validateRisc0TrustedSetupVerificationReport(trustedSetupVerificationReport,
  {authority:trustedSetupAuthority,authoritySha256:trustedSetupAuthoritySha256});
 if(createHash('sha256').update(serializeRisc0TrustedSetupVerificationReport(verified)).digest('hex')
     !==transcript.sha256) fail('trusted setup pointer does not bind the canonical verification report');
 if(verified.artifacts.zkey.verificationKeySha256!==fv.verifyingKeySha256.slice(2)
     ||verified.artifacts.zkey.verificationKeySha256!==cv.verifyingKeySha256.slice(2)) {
   fail('verified ceremony key differs from verifier configuration');
 }
 return {schema:TRUSTED_SETUP_DECISION_REPORT_SCHEMA,status:'required-and-release-bound',releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',sharedTranscript:transcript,
  finalizedBurnVerifier:{proofSystem:fv.proofSystem,verifierConfigHash:fv.verifierConfigHash,verifyingKeySha256:fv.verifyingKeySha256},checkpointVerifier:{proofSystem:cv.proofSystem,verifierConfigHash:cv.verifierConfigHash,verifyingKeySha256:cv.verifyingKeySha256},decision:'required',rationale:'Both production RISC Zero Groth16 verifier configurations require and cryptographically bind the same reviewed ceremony transcript.'};
}
export function validateTrustedSetupDecisionReport(report,context={}){if(!exact(report,reportKeys)||!exact(report.finalizedBurnVerifier,['proofSystem','verifierConfigHash','verifyingKeySha256'])||!exact(report.checkpointVerifier,['proofSystem','verifierConfigHash','verifyingKeySha256']))fail('trusted-setup decision report schema is invalid');const rebuilt=buildTrustedSetupDecisionReport(context);if(JSON.stringify(stable(report))!==JSON.stringify(stable(rebuilt)))fail('trusted-setup decision report differs from canonical release binding');return rebuilt;}
export function serializeTrustedSetupDecisionReport(report){return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);}
