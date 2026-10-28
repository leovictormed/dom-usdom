import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {FINALIZED_BURN_PROOF_SYSTEM,FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
  FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,VERIFIER_CONFIG_SCHEMA,
  finalizedBurnVerifierConfigHash} from '../../sdk/verifier-config.mjs';
import {BURN_INTENT_TYPEHASH,BURN_STATEMENT_TYPEHASH,PRIVATE_BURN_ID_TYPEHASH,
} from '../../sdk/proof-reserve.mjs';
import {buildVerifierReproducibleBuildReport,serializeVerifierReproducibleBuildReport,
  validateVerifierReproducibleBuildReport,
} from '../../sdk/verifier-reproducible-build-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';
import {PRODUCTION_SOLC_LONG_VERSION,PRODUCTION_SOLC_SHA256}
  from '../../sdk/reproducible-build-environment.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const hash=byte=>'0x'+byte.repeat(32);
const verifierConfig={schema:VERIFIER_CONFIG_SCHEMA,statementVersion:'1',
 transitionCommitmentVersion:'2',burnStateWitnessVersion:'3',finalizedBurnProverInputVersion:'2',
 publicOutputVersion:'1',burnStatementTypeHash:BURN_STATEMENT_TYPEHASH,
 burnIntentTypeHash:BURN_INTENT_TYPEHASH,privateBurnIdTypeHash:PRIVATE_BURN_ID_TYPEHASH,
 activationScheduleCommitment:hash('12'),domGenesisHash:hash('13'),domNetworkMagic:'1146047793',
 domChainId:hash('14'),firstV4Height:'100000',activationEmptyStateRoot:hash('15'),
 consensusRulesHash:hash('16'),forkChoiceRulesHash:hash('17'),powRulesHash:hash('18'),
 nativeAssetId:hash('19'),noteTreeRulesHash:hash('1a'),nullifierRulesHash:hash('1b'),
 balanceRulesHash:hash('1c'),finalityRulesHash:hash('1d'),proofSystem:FINALIZED_BURN_PROOF_SYSTEM,
 verifyingKeySha256:hash('1e'),trustedSetupRequired:true,trustedSetupTranscriptSha256:hash('1f'),
 provingProgramSha256:hash('20'),sourceManifestSha256:hash('21'),verifierArtifactSha256:hash('22'),
 maxProofBytes:'260',minimumFinalityBeaconSlot:'1',ethereumChainId:'1',
 riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
 riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
 riscZeroVerifierSelector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
 finalizedBurnGuestImageId:hash('24'),journalSchemaHash:FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH};
const computed=finalizedBurnVerifierConfigHash(verifierConfig);
const artifactSha=sha('artifact'),sourceSha=sha('sources');
const evidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1.2.3',
 verifierArtifact:{path:'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
  sha256:artifactSha},verifierConfigManifest:{path:'evidence/verifier-config.json',
  sha256:computed.manifestSha256.slice(2)}};
const releaseConfig={ethereumChainId:'1',verifier:'0x'+'33'.repeat(20),
 verifierConfigHash:computed.verifierConfigHash,verifierCodeHash:hash('34'),
 verifierInitcodeHash:hash('35')};
const observed=id=>({buildId:id,compilerExecutableSha256:PRODUCTION_SOLC_SHA256,
 compilerVersion:PRODUCTION_SOLC_LONG_VERSION,
 artifactSha256:artifactSha,sourceSetSha256:sourceSha,runtimeCodeHash:releaseConfig.verifierCodeHash,
 initcodeHash:releaseConfig.verifierInitcodeHash});
const context={releaseEvidence:evidence,releaseConfig,verifierConfig,observations:[
 observed('isolated-build-a'),observed('isolated-build-b')]};

test('verifier report requires two identical config-bound isolated builds',()=>{
 const report=buildVerifierReproducibleBuildReport(context);
 assert.equal(report.status,'reproduced');
 assert.deepEqual(validateVerifierReproducibleBuildReport(report,context),report);
 assert(serializeVerifierReproducibleBuildReport(report).equals(
  serializeVerifierReproducibleBuildReport(buildVerifierReproducibleBuildReport(context))));
});

test('verifier report rejects artifact, runtime, config, compiler and source substitution',()=>{
 const report=buildVerifierReproducibleBuildReport(context);
 const mutations=[
  value=>{value.observations[1].artifactSha256=sha('other');},
  value=>{value.observations[1].runtimeCodeHash=hash('99');},
  value=>{value.observations[1].compilerVersion='0.8.36+commit.00000000';},
  value=>{for(const observation of value.observations) observation.compilerExecutableSha256=sha('other-solc');},
  value=>{value.observations[1].sourceSetSha256=sha('other');},
  value=>{value.verifierConfigHash=hash('98');},
  value=>{value.extra=true;},
 ];
 for(const mutate of mutations) {
  const changed=structuredClone(report); mutate(changed);
  assert.throws(()=>validateVerifierReproducibleBuildReport(changed,context));
 }
});

test('verifier report rejects release and manifest drift',()=>{
 for(const input of [
  {releaseEvidence:{...evidence,sourceCommit:null}},
  {releaseEvidence:{...evidence,verifierArtifact:{...evidence.verifierArtifact,path:'out/wrong.json'}}},
  {releaseEvidence:{...evidence,verifierConfigManifest:{...evidence.verifierConfigManifest,sha256:sha('bad')}}},
  {releaseConfig:{...releaseConfig,ethereumChainId:'31337'}},
  {releaseConfig:{...releaseConfig,verifierConfigHash:hash('99')}},
  {verifierConfig:{...verifierConfig,maxProofBytes:1048575}},
  {observations:[observed('isolated-build-a'),observed('isolated-build-a')]},
 ]) assert.throws(()=>buildVerifierReproducibleBuildReport({...context,...input}));
});

test('verifier report rejects zero artifact and source-set SHA-256 placeholders',()=>{
 const zero='0'.repeat(64);
 const zeroArtifact=structuredClone(context);
 zeroArtifact.releaseEvidence.verifierArtifact.sha256=zero;
 for(const observation of zeroArtifact.observations) observation.artifactSha256=zero;
 assert.throws(()=>buildVerifierReproducibleBuildReport(zeroArtifact),/nonzero/);
 const zeroSources=structuredClone(context);
 for(const observation of zeroSources.observations) observation.sourceSetSha256=zero;
 assert.throws(()=>buildVerifierReproducibleBuildReport(zeroSources),/nonzero/);
});

test('fixed verifier writer uses two isolated create-once builds without live capability',async()=>{
 const [prepare,writer]=await Promise.all([
  readFile(new URL('../../scripts/prepare-verifier-reproducible-build-report.mjs',import.meta.url),'utf8'),
  readFile(new URL('../../scripts/write-verifier-reproducible-build-report.sh',import.meta.url),'utf8'),
 ]);
 assert.match(prepare,/isolatedBuild\('isolated-build-a'/);
 assert.match(prepare,/isolatedBuild\('isolated-build-b'/);
 assert.match(prepare,/productionFoundryBuildArguments\(/);
 assert.match(prepare,/output,cache,root,solc\.path/);
 assert.match(prepare,/release inputs changed during builds/);
 assert.equal((prepare.match(/parseStrictJsonBytes\(/g)??[]).length,4);
 assert.doesNotMatch(prepare,/\.toString\(['"]utf8['"]\)/);
 assert.match(prepare,/artifactAfter\.equals\(canonicalArtifact\)/);
 assert.match(prepare,/configAfter\.equals\(verifierConfigBytes\)/);
 assert.match(prepare,/assertArtifactSourcesUnchanged\(root,sourceSnapshot\)/);
 assert.match(prepare,/assertExecutableUnchanged\(forge\)/);
 assert.match(writer,/flock -n 8/);
 assert.match(writer,/flock -n 9/);
 assert.match(writer,/install-private-file-immutable-stdin\.mjs/);
 assert.doesNotMatch(`${prepare}\n${writer}`,/\bcurl\b|cast (?:send|publish)|ledger|git (?:push|commit|tag)/i);
});

test('finalized-burn verifier build JSON rejects duplicate escaped keys and invalid UTF-8',()=>{
 for(const bytes of [
  Buffer.from('{"metadata":{},"\\u006detadata":{}}\n'),
  Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
 ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'verifier build',
  maxBytes:64*1024*1024,maxDepth:128}),/duplicate (?:object )?key|invalid UTF-8/);
});
