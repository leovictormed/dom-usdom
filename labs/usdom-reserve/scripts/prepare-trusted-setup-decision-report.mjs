#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';import {fileURLToPath} from 'node:url';import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';import {buildTrustedSetupDecisionReport,serializeTrustedSetupDecisionReport} from '../sdk/trusted-setup-decision-report.mjs';
import {validateRiscZeroMainnetReference} from '../sdk/risc0-verifier-reference.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const parse=(p,bytes)=>parseStrictJsonBytes(bytes,{label:p,maxBytes:4*1024*1024,maxDepth:64});
try{
  if(process.argv.length!==2)throw new Error('this command accepts no arguments');
  const evidencePath='config/mainnet-release-evidence.unconfigured.json';
  const releasePath='config/proof-reserve.unconfigured.json';
  const referencePath='config/risc0-ethereum-mainnet-v3.json';
  const [evidenceBytes,releaseBytes,referenceBytes]=await Promise.all([
    readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,releasePath),
    readDirectProjectFile(root,referencePath),
  ]);
  const releaseEvidence=parse(evidencePath,evidenceBytes),releaseConfig=parse(releasePath,releaseBytes),
    reference=validateRiscZeroMainnetReference(parse(referencePath,referenceBytes));
  const authorityPath=reference.trusted_setup_authority_path;
  if(typeof authorityPath!=='string'||typeof reference.trusted_setup_authority_sha256!=='string') {
    throw new Error('RISC Zero trusted-setup authority reference is required');
  }
  const authorityBytes=await readDirectProjectFile(root,authorityPath);
  if(createHash('sha256').update(authorityBytes).digest('hex')!==reference.trusted_setup_authority_sha256) {
    throw new Error('RISC Zero trusted-setup authority content differs from verifier reference');
  }
  const trustedSetupAuthority=parse(authorityPath,authorityBytes);
  const verifierPath=releaseEvidence.verifierConfigManifest?.path;
  const checkpointPath=releaseEvidence.checkpointVerifierConfigManifest?.path;
  if(typeof verifierPath!=='string'||typeof checkpointPath!=='string'||verifierPath===checkpointPath) {
    throw new Error('distinct verifier configuration manifest paths are required');
  }
  const transcriptPath=releaseEvidence.trustedSetup?.transcript?.path;
  if(typeof transcriptPath!=='string') throw new Error('trusted-setup transcript path is required');
  const [verifierBytes,checkpointBytes,transcriptBytes]=await Promise.all([
    readDirectProjectFile(root,verifierPath),readDirectProjectFile(root,checkpointPath),
    readDirectProjectFile(root,transcriptPath,{maximum:64*1024*1024}),
  ]);
  for(const [name,bytes,document] of [
    ['verifier config',verifierBytes,releaseEvidence.verifierConfigManifest],
    ['checkpoint verifier config',checkpointBytes,releaseEvidence.checkpointVerifierConfigManifest],
  ]) {
    if(typeof document?.sha256!=='string'
        ||createHash('sha256').update(bytes).digest('hex')!==document.sha256) {
      throw new Error(`${name} content differs from release evidence`);
    }
  }
  if(createHash('sha256').update(transcriptBytes).digest('hex')
      !==releaseEvidence.trustedSetup.transcript.sha256) {
    throw new Error('trusted-setup transcript content differs from release evidence');
  }
  const trustedSetupVerificationReport=parse(transcriptPath,transcriptBytes);
  const verifierConfig=parse(verifierPath,verifierBytes);
  const checkpointVerifierConfig=parse(checkpointPath,checkpointBytes);
  const report=buildTrustedSetupDecisionReport({releaseEvidence,releaseConfig,verifierConfig,
    checkpointVerifierConfig,trustedSetupVerificationReport,trustedSetupAuthority,
    trustedSetupAuthoritySha256:reference.trusted_setup_authority_sha256});
  const [evidenceAfter,releaseAfter,referenceAfter,authorityAfter,verifierAfter,checkpointAfter,
    transcriptAfter]=await Promise.all([
    readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,releasePath),
    readDirectProjectFile(root,referencePath),readDirectProjectFile(root,authorityPath),
    readDirectProjectFile(root,verifierPath),readDirectProjectFile(root,checkpointPath),
    readDirectProjectFile(root,transcriptPath,{maximum:64*1024*1024}),
  ]);
  if(!evidenceAfter.equals(evidenceBytes)||!releaseAfter.equals(releaseBytes)
      ||!referenceAfter.equals(referenceBytes)||!authorityAfter.equals(authorityBytes)
      ||!verifierAfter.equals(verifierBytes)||!checkpointAfter.equals(checkpointBytes)
      ||!transcriptAfter.equals(transcriptBytes)) {
    throw new Error('trusted-setup decision inputs changed during preparation');
  }
  process.stdout.write(serializeTrustedSetupDecisionReport(report));
}catch(error){writeReleaseFailure('prepare-trusted-setup-decision-report',error);process.exitCode=1;}
