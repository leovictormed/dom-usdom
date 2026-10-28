import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {sha256} from 'ethers';
import {
  CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256,
  CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256,
  CHECKPOINT_CAPACITY_ARTIFACT_SET_SCHEMA,CHECKPOINT_PROOF_CAPACITY_REPORT_SCHEMA,
  CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,
  CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256,CHECKPOINT_RANDOMX_IMAGE_ID,
  CHECKPOINT_RANDOMX_PROGRAM_SHA256,
  CHECKPOINT_SEGMENT_IMAGE_ID,CHECKPOINT_SEGMENT_PROGRAM_SHA256,
  buildCheckpointProofCapacityReport,
  checkpointIsolatedEvmReceiptCommitment,
  checkpointCapacityArtifactSetCommitment,
  validateCheckpointProofCapacityAuthority,
  validateCheckpointProofCapacityReport,
} from '../../sdk/checkpoint-proof-capacity-report.mjs';
import {
  CHECKPOINT_PROOF_ACCEPTED_HASH,CHECKPOINT_PROOF_SYSTEM,CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
  CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,
  CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
  CHECKPOINT_VERIFIER_CONFIG_SCHEMA,checkpointVerifierConfigHash,
} from '../../sdk/checkpoint-verifier-config.mjs';
import {
  CHECKPOINT_STATEMENT_TYPEHASH,checkpointRegistryConfigHash,checkpointStatementHash,
} from '../../sdk/checkpoint-registry.mjs';
import {checkpointRegistryConfigurationFromRelease} from '../../sdk/checkpoint-submission.mjs';
import {safeOwnersCommitment} from '../../sdk/configuration.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';
import {
  CHECKPOINT_CAPACITY_EVIDENCE_PATH,
  validateInstalledCheckpointCapacityReleaseEvidence,
} from '../../sdk/checkpoint-capacity-release-evidence-materialization.mjs';

const address=byte=>'0x'+byte.repeat(20);
const bytes32=byte=>'0x'+byte.repeat(32);
const raw=byte=>byte.repeat(32);

function checkpointConfig() {
  return {schema:CHECKPOINT_VERIFIER_CONFIG_SCHEMA,statementVersion:'6',
    checkpointProverInputVersion:'4',continuationContextVersion:'2',transitionCommitmentVersion:'4',
    activationScheduleVersion:'2',publicOutputVersion:'1',publicStatementBytes:'551',
    continuationContextBytes:'695',segmentStateVersion:'2',segmentTransitionVersion:'4',
    randomxStatementVersion:'1',segmentStateBytes:'1105',segmentTransitionBytes:'2320',
    randomxStatementBytes:'384',segmentStateDomainHash:CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,
    segmentTransitionDomainHash:CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
    randomxStatementDomainHash:CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
    randomxReceiptImageId:'0x'+CHECKPOINT_RANDOMX_IMAGE_ID,
    checkpointStatementTypeHash:CHECKPOINT_STATEMENT_TYPEHASH,
    proofAcceptedHash:CHECKPOINT_PROOF_ACCEPTED_HASH,activationScheduleCommitment:bytes32('a2'),
    domGenesisHash:bytes32('a3'),domNetworkMagic:'1146047793',domChainId:bytes32('a4'),
    firstV4Height:'100000',activationEmptyStateRoot:bytes32('a5'),checkpointInterval:'360',
    confirmationDepth:'30',challengePeriod:'172800',maxCheckpointSpan:'390',
    consensusRulesHash:bytes32('a6'),forkChoiceRulesHash:bytes32('a7'),powRulesHash:bytes32('a8'),
    nativeStateRulesHash:bytes32('a9'),continuationContextRulesHash:bytes32('aa'),
    consensusExtensionWitnessRulesHash:bytes32('ab'),proofSystem:CHECKPOINT_PROOF_SYSTEM,
    verifyingKeySha256:bytes32('ac'),trustedSetupRequired:true,
    trustedSetupTranscriptSha256:bytes32('b1'),provingProgramSha256:bytes32('ad'),
    sourceManifestSha256:bytes32('ae'),verifierArtifactSha256:bytes32('af'),maxProofBytes:'260',
    ethereumChainId:'1',riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
    riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
    riscZeroVerifierSelector:CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,
    checkpointGuestImageId:bytes32('b0'),journalSchemaHash:CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH};
}

const layerCounts=[390,2,390,390,2,1];
const layer=(name,programSha256,imageId,index)=>({name,programSha256,imageId,
  inputSetSha256:raw((0x10+index).toString(16)),inputBytes:'4096',
  journalSetSha256:raw((0x20+index).toString(16)),journalBytes:String(layerCounts[index]*32),
  journalCount:String(layerCounts[index]),receiptSetSha256:raw((0x30+index).toString(16)),
  receiptBytes:String(layerCounts[index]*8192),receiptCount:String(layerCounts[index]),
  receiptKind:'succinct',receiptVerified:true,segmentLimitPo2:18,
  provingWallMilliseconds:'1000',peakResidentKiB:'1048576'});

function fixture() {
  const config=checkpointConfig();
  const configHash=checkpointVerifierConfigHash(config).verifierConfigHash;
  const evidence={releaseId:'release-1',sourceCommit:'a'.repeat(40)};
  const checkpointGuardianOwners=[address('01'),address('02'),address('03')];
  const releaseConfig={ethereumChainId:'1',checkpointRegistry:address('11'),
    checkpointVerifier:address('12'),checkpointVerifierCodeHash:bytes32('b1'),
    checkpointVerifierConfigHash:configHash,domDomain:bytes32('b7'),
    checkpointDomNetworkMagic:'1146047793',checkpointDomChainId:config.domChainId,
    checkpointFirstV4Height:config.firstV4Height,
    checkpointActivationEmptyStateRoot:config.activationEmptyStateRoot,
    activationScheduleCommitment:config.activationScheduleCommitment,
    checkpointIntervalBlocks:config.checkpointInterval,
    checkpointConfirmationDepthBlocks:config.confirmationDepth,
    checkpointChallengePeriodSeconds:config.challengePeriod,checkpointGuardian:address('13'),
    checkpointGuardianCodeHash:bytes32('b8'),checkpointGuardianImplementation:address('13'),
    checkpointGuardianImplementationCodeHash:bytes32('b8'),checkpointInitialHeight:'99999',
    checkpointInitialBlock:bytes32('b9'),checkpointInitialStateRoot:config.activationEmptyStateRoot,
    checkpointInitialContextHash:bytes32('bb'),checkpointInitialTotalDifficulty:'999000',
    checkpointGuardianOwners};
  releaseConfig.checkpointRegistryConfigHash=checkpointRegistryConfigHash({
    ethereumChainId:releaseConfig.ethereumChainId,registry:releaseConfig.checkpointRegistry,
    bridgeDomain:releaseConfig.domDomain,domNetworkMagic:releaseConfig.checkpointDomNetworkMagic,
    domChainId:releaseConfig.checkpointDomChainId,firstV4Height:releaseConfig.checkpointFirstV4Height,
    activationEmptyStateRoot:releaseConfig.checkpointActivationEmptyStateRoot,
    activationScheduleCommitment:releaseConfig.activationScheduleCommitment,
    checkpointInterval:releaseConfig.checkpointIntervalBlocks,
    confirmationDepth:releaseConfig.checkpointConfirmationDepthBlocks,
    challengePeriod:releaseConfig.checkpointChallengePeriodSeconds,
    verifier:releaseConfig.checkpointVerifier,verifierCodeHash:releaseConfig.checkpointVerifierCodeHash,
    verifierConfigHash:releaseConfig.checkpointVerifierConfigHash,
    guardian:releaseConfig.checkpointGuardian,guardianCodeHash:releaseConfig.checkpointGuardianCodeHash,
    guardianImplementation:releaseConfig.checkpointGuardianImplementation,
    guardianImplementationCodeHash:releaseConfig.checkpointGuardianImplementationCodeHash,
    guardianOwnersCommitment:safeOwnersCommitment(checkpointGuardianOwners),
    initialHeight:releaseConfig.checkpointInitialHeight,initialBlock:releaseConfig.checkpointInitialBlock,
    initialStateRoot:releaseConfig.checkpointInitialStateRoot,
    initialContextHash:releaseConfig.checkpointInitialContextHash,
    initialTotalDifficulty:releaseConfig.checkpointInitialTotalDifficulty,
  }).checkpointConfigHash;
  const checkpoint={previousHeight:'100000',previousBlock:bytes32('c0'),
    previousStateRoot:bytes32('c1'),previousContextHash:bytes32('c2'),
    previousTotalDifficulty:'1000000',height:'100360',blockHash:bytes32('c3'),
    stateRoot:bytes32('c4'),contextHash:bytes32('c5'),totalDifficulty:'2000000',
    totalIssued:'1000000',totalBurned:'250000',issuanceClosed:false,
    confirmationHeight:'100390',confirmationBlock:bytes32('c6'),
    confirmationTotalDifficulty:'2100000',confirmationTimestamp:'1792640000'};
  const statementHash=checkpointStatementHash(
    checkpointRegistryConfigurationFromRelease(releaseConfig),checkpoint,
  );
  const report={schema:CHECKPOINT_PROOF_CAPACITY_REPORT_SCHEMA,
    artifactSetCommitmentSchema:CHECKPOINT_CAPACITY_ARTIFACT_SET_SCHEMA,
    runId:'20261027T120000Z-123',artifactManifestPath:'artifact-manifest.json',artifactManifestSha256:raw('09'),
    releaseId:evidence.releaseId,
    sourceCommit:evidence.sourceCommit,ethereumChainId:'1',checkpointRegistry:releaseConfig.checkpointRegistry,
    adapter:releaseConfig.checkpointVerifier,adapterRuntimeCodeHash:releaseConfig.checkpointVerifierCodeHash,
    adapterVerifierConfigHash:configHash,riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
    riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
    riscZeroFinalizedBlockNumber:'22000000',riscZeroFinalizedBlockHash:bytes32('bc'),
    riscZeroObservationSourceIds:['drpc','publicnode'],riscZeroObservationEndpointHashes:[
      'c5b9f7564a09b1b2bbdff2c7145d474bbc2ccd025460d9c5b097a39474b7980c',
      '7b71d04b616d2ce47598465ad04d63da212a14b1317f965044bf325b749a6746'],
    riscZeroRuntimeArtifactSha256:raw('bd'),
    risc0ZkvmVersion:'3.0.6',prover:'local',rayonWorkers:1,devMode:false,mines:false,
    broadcastAuthorized:false,releaseSpecific:true,checkpointStartHeight:'100000',
    checkpointEndHeight:'100360',confirmationHeight:'100390',checkpointSpan:'360',
    confirmationDepth:'30',checkpoint,statementHash,sourcePackageSha256:raw('b3'),
    randomxProverTranscriptSha256:raw('b7'),randomxResourceLogSha256:raw('b8'),
    hostFingerprintSha256:raw('b4'),logicalCpus:4,memoryTotalKiB:'8388608',
    layers:[
      layer('randomx',CHECKPOINT_RANDOMX_PROGRAM_SHA256,CHECKPOINT_RANDOMX_IMAGE_ID,0),
      layer('randomx-aggregate',CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256,
        CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,1),
      layer('economic-chunk',CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256,
        CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,2),
      layer('economic-block',CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256,
        CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,3),
      layer('segment',CHECKPOINT_SEGMENT_PROGRAM_SHA256,CHECKPOINT_SEGMENT_IMAGE_ID,4),
      layer('outer',config.provingProgramSha256.slice(2),config.checkpointGuestImageId.slice(2),5),
    ],outerGroth16ReceiptSha256:raw('b5'),outerGroth16ReceiptBytes:'2048',
    outerJournalDigestSha256:sha256(statementHash).slice(2),
    evmSealSha256:raw('b6'),evmSealBytes:'260',adapterCallAccepted:true,
    adapterVerificationGas:'400000',compressionWallMilliseconds:'1000',
    isolatedEvmTransactionHash:bytes32('be'),isolatedEvmBlockHash:bytes32('bf'),
    isolatedEvmBlockNumber:'2',isolatedEvmReceiptSha256:raw('c7'),
    compressionPeakResidentKiB:'1048576',startedAt:'1792640000',completedAt:'1792640010'};
  report.isolatedEvmReceiptSha256=checkpointIsolatedEvmReceiptCommitment({
    transactionHash:report.isolatedEvmTransactionHash,blockHash:report.isolatedEvmBlockHash,
    blockNumber:report.isolatedEvmBlockNumber,adapter:report.adapter,
    adapterRuntimeCodeHash:report.adapterRuntimeCodeHash,
    adapterVerifierConfigHash:report.adapterVerifierConfigHash,
    statementHash:report.statementHash,evmSealSha256:report.evmSealSha256,
    adapterVerificationGas:report.adapterVerificationGas,
  }).sha256;
  return {report,evidence,releaseConfig,checkpointVerifierConfig:config,
    riscZeroReference:PINNED_RISC0_MAINNET_V3};
}

const validate=value=>validateCheckpointProofCapacityReport(value.report,value);

test('checkpoint capacity report binds every recursive receipt and the release adapter',()=>{
  const value=fixture();
  const checked=validate(value);
  assert.equal(checked.releaseSpecific,true);
  assert.equal(checked.layers.length,6);
  assert(Object.isFrozen(checked));
  assert(Object.isFrozen(checked.layers));
  assert(Object.isFrozen(checked.layers[0]));
});

test('checkpoint capacity authority rejects report B under graph A',()=>{
  const value=fixture();
  const manifestBytes=Buffer.from(JSON.stringify({schema:'usdom-checkpoint-capacity-artifact-manifest/v1',runId:value.report.runId,files:[{path:'evidence/a',sha256:raw('01'),bytes:1}]},null,2)+'\n');
  value.report.artifactManifestSha256=createHash('sha256').update(manifestBytes).digest('hex');
  const authority={reportBytes:Buffer.from(JSON.stringify(value.report)),manifestBytes,reconstructedReport:structuredClone(value.report)};
  assert.equal(validateCheckpointProofCapacityAuthority(value.report,authority,value).releaseId,value.report.releaseId);
  const reportB=structuredClone(value.report); reportB.layers[0].receiptSetSha256=raw('fe');
  assert.throws(()=>validateCheckpointProofCapacityAuthority(reportB,authority,value),/byte-authoritative graph/);
  assert.throws(()=>validateCheckpointProofCapacityAuthority(value.report,null,value),/authority is required/);
});

test('installed checkpoint capacity evidence is re-read with exact descriptor, hash and canonical bytes',async()=>{
  const value=fixture();
  const manifestBytes=Buffer.from(JSON.stringify({schema:'usdom-checkpoint-capacity-artifact-manifest/v1',runId:value.report.runId,files:[{path:'evidence/a',sha256:raw('01'),bytes:1}]},null,2)+'\n');
  value.report.artifactManifestSha256=createHash('sha256').update(manifestBytes).digest('hex');
  const reportBytes=Buffer.from(`${JSON.stringify(value.report,null,2)}\n`);
  const evidence=JSON.parse(await readFile(
    new URL('../../config/mainnet-release-evidence.unconfigured.json',import.meta.url),'utf8'));
  evidence.releaseId=value.evidence.releaseId;
  evidence.sourceCommit=value.evidence.sourceCommit;
  evidence.checkpointProofCapacityReport={path:CHECKPOINT_CAPACITY_EVIDENCE_PATH,
    sha256:createHash('sha256').update(reportBytes).digest('hex')};
  const input={...value,evidence,reportBytes,manifestBytes,evidenceBytes:Buffer.from(JSON.stringify(evidence)),
    releaseConfigBytes:Buffer.from(JSON.stringify(value.releaseConfig)),
    checkpointVerifierConfigBytes:Buffer.from(JSON.stringify(value.checkpointVerifierConfig))};
  const checked=validateInstalledCheckpointCapacityReleaseEvidence(input);
  assert.equal(checked.sha256,evidence.checkpointProofCapacityReport.sha256);
  assert.throws(()=>validateInstalledCheckpointCapacityReleaseEvidence({
    ...input,reportBytes:Buffer.concat([reportBytes,Buffer.from(' ')]),
  }),/hash mismatch/);
  const wrongPathEvidence={...evidence,checkpointProofCapacityReport:{
      ...evidence.checkpointProofCapacityReport,path:'evidence/checkpoint-capacity/other.json',
    }};
  assert.throws(()=>validateInstalledCheckpointCapacityReleaseEvidence({
    ...input,evidence:wrongPathEvidence,evidenceBytes:Buffer.from(JSON.stringify(wrongPathEvidence)),
  }),/descriptor is invalid/);
  const noncanonical=Buffer.from(JSON.stringify(value.report));
  const noncanonicalEvidence={...evidence,checkpointProofCapacityReport:{
    path:CHECKPOINT_CAPACITY_EVIDENCE_PATH,
    sha256:createHash('sha256').update(noncanonical).digest('hex'),
  }};
  assert.throws(()=>validateInstalledCheckpointCapacityReleaseEvidence({
    ...input,reportBytes:noncanonical,evidence:noncanonicalEvidence,
    evidenceBytes:Buffer.from(JSON.stringify(noncanonicalEvidence)),
  }),/not canonical/);
  assert.throws(()=>validateInstalledCheckpointCapacityReleaseEvidence({
    ...input,evidence:{...evidence,sourceCommit:'f'.repeat(40)},
  }),/bytes differ from parsed authority/);
});

test('checkpoint artifact-set commitments are ordered, length-bound and domain-separated',()=>{
  const records=[{sha256:raw('01'),bytes:'32'},{sha256:raw('02'),bytes:'32'}];
  const first=checkpointCapacityArtifactSetCommitment('randomx','journal',records);
  assert.deepEqual(first,{
    sha256:'9b1b81467a203da01b1cf7b0edf0e9abc0a51b53b353193a92dc9c1a341e1bfa',
    count:'2',totalBytes:'64',
  });
  assert.notEqual(first.sha256,
    checkpointCapacityArtifactSetCommitment('randomx-aggregate','journal',records).sha256);
  assert.notEqual(first.sha256,
    checkpointCapacityArtifactSetCommitment('randomx','receipt',records).sha256);
  assert.notEqual(first.sha256,
    checkpointCapacityArtifactSetCommitment('randomx','journal',[...records].reverse()).sha256);
  assert.throws(()=>checkpointCapacityArtifactSetCommitment('randomx','journal',[
    {sha256:raw('01'),bytes:'31'},
  ]));
  assert.throws(()=>checkpointCapacityArtifactSetCommitment('unknown','journal',records));
});

test('checkpoint EVM receipt rejects oversized decimal evidence before numeric conversion',()=>{
  const value=fixture().report;
  const input={transactionHash:value.isolatedEvmTransactionHash,
    blockHash:value.isolatedEvmBlockHash,blockNumber:value.isolatedEvmBlockNumber,
    adapter:value.adapter,adapterRuntimeCodeHash:value.adapterRuntimeCodeHash,
    adapterVerifierConfigHash:value.adapterVerifierConfigHash,statementHash:value.statementHash,
    evmSealSha256:value.evmSealSha256,adapterVerificationGas:value.adapterVerificationGas};
  for(const field of ['blockNumber','adapterVerificationGas']) {
    assert.throws(()=>checkpointIsolatedEvmReceiptCommitment({
      ...input,[field]:'9'.repeat(100000),
    }),/canonical unsigned decimal/);
  }
});

test('checkpoint capacity report builder derives every set commitment before validation',()=>{
  const value=fixture();
  const base=structuredClone(value.report);
  delete base.schema;
  delete base.artifactSetCommitmentSchema;
  delete base.outerJournalDigestSha256;
  delete base.layers;
  const measured=value.report.layers.map((layer,index)=>({
    name:layer.name,programSha256:layer.programSha256,imageId:layer.imageId,
    inputs:[{sha256:raw((0x40+index).toString(16)),bytes:'4096'}],
    journals:Array.from({length:layerCounts[index]},()=>({
      sha256:index===5?sha256(value.report.statementHash).slice(2)
        :raw((0x50+index).toString(16)),bytes:'32'})),
    receipts:Array.from({length:layerCounts[index]},()=>({
      sha256:raw((0x60+index).toString(16)),bytes:'8192'})),
    receiptKind:'succinct',receiptVerified:true,segmentLimitPo2:18,
    provingWallMilliseconds:'1000',peakResidentKiB:'1048576',
  }));
  const built=buildCheckpointProofCapacityReport(base,measured,value);
  assert.equal(built.layers.length,6);
  assert.equal(built.layers[0].inputBytes,'4096');
  assert.equal(built.outerJournalDigestSha256,sha256(value.report.statementHash).slice(2));
  assert.notEqual(built.layers[5].journalSetSha256,built.outerJournalDigestSha256);
  const swapped=structuredClone(measured);
  [swapped[0],swapped[1]]=[swapped[1],swapped[0]];
  assert.throws(()=>buildCheckpointProofCapacityReport(base,swapped,value));
});

test('checkpoint capacity report rejects semantic substitutions',()=>{
  const mutations=[
    value=>{value.report.extra=true;},
    value=>{value.report.artifactSetCommitmentSchema='sha256';},
    value=>{value.report.releaseId='other';},
    value=>{value.report.sourceCommit='b'.repeat(40);},
    value=>{value.report.randomxProverTranscriptSha256=value.report.sourcePackageSha256;},
    value=>{value.report.randomxResourceLogSha256='invalid';},
    value=>{value.report.ethereumChainId='31337';},
    value=>{value.report.checkpointRegistry=address('13');},
    value=>{value.report.adapter=address('13');},
    value=>{value.report.adapterRuntimeCodeHash=bytes32('01');},
    value=>{value.report.adapterVerifierConfigHash=bytes32('01');},
    value=>{value.report.riscZeroVerifier=address('13');},
    value=>{value.report.riscZeroVerifierCodeHash=bytes32('01');},
    value=>{value.report.riscZeroFinalizedBlockNumber='0';},
    value=>{value.report.riscZeroFinalizedBlockHash=bytes32('00');},
    value=>{value.report.riscZeroObservationSourceIds.reverse();},
    value=>{value.report.riscZeroObservationEndpointHashes[0]=raw('01');},
    value=>{value.report.riscZeroRuntimeArtifactSha256=value.report.sourcePackageSha256;},
    value=>{value.report.checkpointSpan='359';},
    value=>{value.report.confirmationDepth='29';},
    value=>{value.report.confirmationHeight='100389';},
    value=>{value.report.checkpoint.blockHash=bytes32('01');},
    value=>{value.report.outerJournalDigestSha256=raw('01');},
    value=>{value.report.layers.pop();},
    value=>{value.report.layers[0].extra=true;},
    value=>{value.report.layers[0].name='outer';},
    value=>{value.report.layers[0].programSha256=raw('01');},
    value=>{value.report.layers[1].imageId=raw('01');},
    value=>{value.report.layers[2].receiptVerified=false;},
    value=>{value.report.layers[3].receiptKind='composite';},
    value=>{value.report.layers[1].programSha256=CHECKPOINT_RANDOMX_PROGRAM_SHA256;},
    value=>{value.report.layers[5].segmentLimitPo2=23;},
    value=>{value.report.layers[5].receiptSetSha256=value.report.layers[0].receiptSetSha256;},
    value=>{value.report.layers[2].journalCount='2';},
    value=>{value.report.layers[2].journalBytes='64';},
    value=>{Object.assign(value.report.layers[0],{receiptCount:'389',journalCount:'389',
      journalBytes:String(389*32)});},
    value=>{for(const index of [1,4]) Object.assign(value.report.layers[index],{
      receiptCount:'1',journalCount:'1',journalBytes:'32'});},
    value=>{Object.assign(value.report.layers[5],{receiptCount:'2',journalCount:'2',
      journalBytes:'64'});},
    value=>{value.checkpointVerifierConfig.randomxReceiptImageId=bytes32('01');},
    value=>{value.report.layers[0].provingWallMilliseconds='2000000';},
    value=>{value.report.outerGroth16ReceiptBytes='0';},
    value=>{value.report.compressionWallMilliseconds='0';},
    value=>{value.report.compressionPeakResidentKiB='0';},
    value=>{value.report.evmSealBytes='65537';},
    value=>{value.report.adapterVerificationGas='5000001';},
    value=>{value.report.isolatedEvmTransactionHash=bytes32('01');},
    value=>{value.report.isolatedEvmBlockHash=bytes32('01');},
    value=>{value.report.isolatedEvmBlockNumber='0';},
    value=>{value.report.isolatedEvmReceiptSha256=raw('01');},
    value=>{value.report.adapterCallAccepted=false;},
    value=>{value.report.devMode=true;},
    value=>{value.report.rayonWorkers=2;},
    value=>{value.report.releaseSpecific=false;},
    value=>{value.report.broadcastAuthorized=true;},
    value=>{value.report.mines=true;},
  ];
  for(const mutate of mutations) {
    const value=fixture();
    mutate(value);
    assert.throws(()=>validate(value));
  }
});
