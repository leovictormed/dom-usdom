import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {sha256} from 'ethers';
import {
  CHECKPOINT_EVM_SEAL_BYTES,CHECKPOINT_GROTH16_VERIFIER_PARAMETERS,CHECKPOINT_OUTER_IMAGE_ID,
  CHECKPOINT_STATEMENT_V6_BYTES,buildAuthenticatedCheckpointSubmission,
  encodeCheckpointStatementV6,parseCheckpointStatementV6,
} from '../../sdk/checkpoint-submission.mjs';
import {checkpointRegistryConfigHash,checkpointStatementHash} from '../../sdk/checkpoint-registry.mjs';
import {
  CHECKPOINT_PROOF_ACCEPTED_HASH,CHECKPOINT_PROOF_SYSTEM,CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
  CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,
  CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
  CHECKPOINT_VERIFIER_CONFIG_SCHEMA,checkpointVerifierConfigHash,
} from '../../sdk/checkpoint-verifier-config.mjs';
import {CHECKPOINT_STATEMENT_TYPEHASH} from '../../sdk/checkpoint-registry.mjs';
import {safeOwnersCommitment} from '../../sdk/configuration.mjs';
import {
  CHECKPOINT_FINALIZE_CALLDATA,assessCheckpointCandidateObservation,
} from '../../sdk/checkpoint-candidate-observer.mjs';

const hash=byte=>'0x'+byte.repeat(32);
const address=byte=>'0x'+byte.repeat(20);
const rawSha=value=>createHash('sha256').update(value).digest('hex');

function fixture() {
  const checkpointGuardianOwners=[address('40'),address('41'),address('42')];
  const verifier={
    schema:CHECKPOINT_VERIFIER_CONFIG_SCHEMA,statementVersion:'6',checkpointProverInputVersion:'4',
    continuationContextVersion:'2',transitionCommitmentVersion:'4',activationScheduleVersion:'2',
    publicOutputVersion:'1',publicStatementBytes:'551',continuationContextBytes:'695',
    segmentStateVersion:'2',segmentTransitionVersion:'4',randomxStatementVersion:'1',
    segmentStateBytes:'1105',segmentTransitionBytes:'2320',randomxStatementBytes:'384',
    segmentStateDomainHash:CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,
    segmentTransitionDomainHash:CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
    randomxStatementDomainHash:CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
    randomxReceiptImageId:hash('10'),checkpointStatementTypeHash:CHECKPOINT_STATEMENT_TYPEHASH,
    proofAcceptedHash:CHECKPOINT_PROOF_ACCEPTED_HASH,activationScheduleCommitment:hash('22'),
    domGenesisHash:hash('23'),domNetworkMagic:'2712847316',domChainId:hash('24'),
    firstV4Height:'101',activationEmptyStateRoot:hash('25'),checkpointInterval:'360',
    confirmationDepth:'30',challengePeriod:'86400',maxCheckpointSpan:'390',
    consensusRulesHash:hash('26'),forkChoiceRulesHash:hash('27'),powRulesHash:hash('28'),
    nativeStateRulesHash:hash('29'),continuationContextRulesHash:hash('2a'),
    consensusExtensionWitnessRulesHash:hash('2b'),proofSystem:CHECKPOINT_PROOF_SYSTEM,
    verifyingKeySha256:hash('2c'),trustedSetupRequired:true,
    trustedSetupTranscriptSha256:hash('32'),provingProgramSha256:hash('2d'),
    sourceManifestSha256:hash('2e'),verifierArtifactSha256:hash('2f'),maxProofBytes:'260',
    ethereumChainId:'31337',riscZeroVerifier:address('30'),riscZeroVerifierCodeHash:hash('31'),
    riscZeroVerifierSelector:CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,
    checkpointGuestImageId:CHECKPOINT_OUTER_IMAGE_ID,
    journalSchemaHash:CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,
  };
  const verifierResult=checkpointVerifierConfigHash(verifier);
  const configuration={
    ethereumChainId:'31337',registry:address('11'),bridgeDomain:hash('12'),
    domNetworkMagic:'2712847316',domChainId:verifier.domChainId,firstV4Height:'101',
    activationEmptyStateRoot:verifier.activationEmptyStateRoot,
    activationScheduleCommitment:verifier.activationScheduleCommitment,
    checkpointInterval:'360',confirmationDepth:'30',challengePeriod:'86400',
    verifier:address('13'),verifierCodeHash:hash('14'),
    verifierConfigHash:verifierResult.verifierConfigHash,guardian:address('15'),
    guardianCodeHash:hash('16'),guardianImplementation:address('15'),
    guardianImplementationCodeHash:hash('16'),guardianOwnersCommitment:safeOwnersCommitment(checkpointGuardianOwners),
    initialHeight:'100',initialBlock:hash('17'),
    initialStateRoot:verifier.activationEmptyStateRoot,initialContextHash:hash('18'),
    initialTotalDifficulty:'1000000',
  };
  const checkpoint={
    previousHeight:'100',previousBlock:configuration.initialBlock,
    previousStateRoot:configuration.initialStateRoot,
    previousContextHash:configuration.initialContextHash,previousTotalDifficulty:'1000000',
    height:'460',blockHash:hash('32'),stateRoot:hash('33'),contextHash:hash('34'),
    totalDifficulty:'1000360',totalIssued:'1000000',totalBurned:'250000',issuanceClosed:false,
    confirmationHeight:'490',confirmationBlock:hash('35'),
    confirmationTotalDifficulty:'1000390',confirmationTimestamp:'1792492800',
  };
  const statement=encodeCheckpointStatementV6(configuration,checkpoint);
  const statementHash=checkpointStatementHash(configuration,checkpoint);
  const seal=Buffer.concat([Buffer.from('73c457ba','hex'),Buffer.alloc(256,1)]);
  const proofIndex={
    schema:'usdom-checkpoint-outer-evm-proof-v1',
    outer_receipt_index_path:
      'evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json',
    outer_receipt_index_sha256:'36'.repeat(32),outer_image_id:CHECKPOINT_OUTER_IMAGE_ID.slice(2),
    statement_hash:statementHash.slice(2),journal_digest:sha256(statementHash).slice(2),
    risc0_zkvm_version:'3.0.6',receipt_kind:'groth16',
    groth16_verifier_parameters:CHECKPOINT_GROTH16_VERIFIER_PARAMETERS.slice(2),
    evm_verifier_selector:CHECKPOINT_RISC0_GROTH16_V3_SELECTOR.slice(2),
    groth16_receipt_file:'checkpoint-outer-groth16-receipt.bin',
    groth16_receipt_sha256:'37'.repeat(32),groth16_receipt_bytes:1024,
    evm_seal_file:'checkpoint-outer-evm-seal.bin',evm_seal_sha256:rawSha(seal),
    evm_seal_bytes:seal.length,receipt_verified:true,dev_mode:false,generates_proofs:true,mines:false,
  };
  const proofIndexBytes=Buffer.from(JSON.stringify(proofIndex,null,2)+'\n');
  return {verifier,configuration,checkpoint,statement,statementHash,seal,proofIndex,proofIndexBytes,
    checkpointGuardianOwners};
}

function observerFixture() {
  const value=fixture();
  const submission=buildAuthenticatedCheckpointSubmission({
    registryConfiguration:value.configuration,verifierConfiguration:value.verifier,
    statement:value.statement,proofIndex:value.proofIndexBytes,evmSeal:value.seal,
    releaseConfigSha256:'38'.repeat(32),
  });
  const releaseConfig={
    ethereumChainId:value.configuration.ethereumChainId,
    checkpointRegistry:value.configuration.registry,domDomain:value.configuration.bridgeDomain,
    checkpointDomNetworkMagic:value.configuration.domNetworkMagic,
    checkpointDomChainId:value.configuration.domChainId,
    checkpointFirstV4Height:value.configuration.firstV4Height,
    checkpointActivationEmptyStateRoot:value.configuration.activationEmptyStateRoot,
    activationScheduleCommitment:value.configuration.activationScheduleCommitment,
    checkpointIntervalBlocks:value.configuration.checkpointInterval,
    checkpointConfirmationDepthBlocks:value.configuration.confirmationDepth,
    checkpointChallengePeriodSeconds:value.configuration.challengePeriod,
    checkpointVerifier:value.configuration.verifier,
    checkpointVerifierCodeHash:value.configuration.verifierCodeHash,
    checkpointVerifierConfigHash:value.configuration.verifierConfigHash,
    checkpointGuardian:value.configuration.guardian,
    checkpointGuardianCodeHash:value.configuration.guardianCodeHash,
    checkpointGuardianImplementation:value.configuration.guardianImplementation,
    checkpointGuardianImplementationCodeHash:value.configuration.guardianImplementationCodeHash,
    checkpointGuardianOwners:value.checkpointGuardianOwners,
    checkpointInitialHeight:value.configuration.initialHeight,
    checkpointInitialBlock:value.configuration.initialBlock,
    checkpointInitialStateRoot:value.configuration.initialStateRoot,
    checkpointInitialContextHash:value.configuration.initialContextHash,
    checkpointInitialTotalDifficulty:value.configuration.initialTotalDifficulty,
    checkpointRegistryConfigHash:checkpointRegistryConfigHash(value.configuration).checkpointConfigHash,
    checkpointRegistryRuntimeCodeHash:hash('50'),
  };
  const candidate={statementHash:hash('00'),height:'0',readyAt:'0',blockHash:hash('00'),
    stateRoot:hash('00'),contextHash:hash('00'),totalDifficulty:'0',totalIssued:'0',totalBurned:'0',issuanceClosed:false,confirmationHeight:'0',
    confirmationBlock:hash('00'),confirmationTotalDifficulty:'0',confirmationTimestamp:'0'};
  const observation={
    chainId:value.configuration.ethereumChainId,finalizedBlockNumber:'1000',
    finalizedBlockHash:hash('51'),finalizedBlockTimestamp:'1792492800',
    snapshotBlockHashAfter:hash('51'),registryRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,
    onchainStatementHash:submission.statementHash,submissionCallAccepted:true,
    registry:{checkpointConfigHash:releaseConfig.checkpointRegistryConfigHash,halted:false,
      gracefullyShutdown:false,latestIssuanceClosed:false,latestHeight:value.checkpoint.previousHeight,latestBlock:value.checkpoint.previousBlock,
      latestStateRoot:value.checkpoint.previousStateRoot,
      latestContextHash:value.checkpoint.previousContextHash,
      latestTotalDifficulty:value.checkpoint.previousTotalDifficulty,
      latestTotalIssued:'0',latestTotalBurned:'0'},candidate,
  };
  return {...value,submission,releaseConfig,observation};
}

test('UDCPST06 decoding and authenticated submission calldata are deterministic',()=>{
  const value=fixture();
  assert.equal(value.statement.length,CHECKPOINT_STATEMENT_V6_BYTES);
  assert.deepEqual(parseCheckpointStatementV6(value.statement).checkpoint,value.checkpoint);
  const submission=buildAuthenticatedCheckpointSubmission({
    registryConfiguration:value.configuration,verifierConfiguration:value.verifier,
    statement:value.statement,proofIndex:value.proofIndexBytes,evmSeal:value.seal,
    releaseConfigSha256:'38'.repeat(32),
  });
  assert.equal(submission.statementHash,value.statementHash);
  assert.equal(submission.ethereumChainId,'31337');
  assert.equal(submission.to,value.configuration.registry);
  assert.equal(submission.proof.sha256,rawSha(value.seal));
  assert.equal(submission.source.statementSha256,rawSha(value.statement));
  assert.equal(submission.source.proofIndexSha256,rawSha(value.proofIndexBytes));
  assert.equal(submission.source.outerImageId,CHECKPOINT_OUTER_IMAGE_ID);
  assert.equal(submission.broadcastAuthorized,false);
  assert.match(submission.data,/^0x[0-9a-f]+$/);
  assert.equal(checkpointRegistryConfigHash(value.configuration).checkpointConfigHash,
    parseCheckpointStatementV6(value.statement).identity.checkpointConfigHash);
});

test('authenticated submission rejects mutated statement, proof index, seal and verifier identity',()=>{
  const value=fixture();
  const build=overrides=>buildAuthenticatedCheckpointSubmission({
    registryConfiguration:value.configuration,verifierConfiguration:value.verifier,
    statement:value.statement,proofIndex:value.proofIndexBytes,evmSeal:value.seal,
    releaseConfigSha256:'38'.repeat(32),...overrides,
  });
  const changedStatement=Buffer.from(value.statement); changedStatement[194]^=1;
  assert.throws(()=>build({statement:changedStatement}),/statement/);
  assert.throws(()=>build({proofIndex:Buffer.from(JSON.stringify({...value.proofIndex,extra:true}))}),/exact/);
  assert.throws(()=>build({proofIndex:Buffer.concat([
    Buffer.from('{"schema":"ambiguous",'),value.proofIndexBytes.subarray(1),
  ])}),/duplicate object key "schema"/);
  assert.throws(()=>build({proofIndex:Buffer.from([
    0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d,
  ])}),/invalid UTF-8/);
  assert.throws(()=>build({proofIndex:Buffer.from(JSON.stringify({
    ...value.proofIndex,statement_hash:'39'.repeat(32),
  }))}),/bind/);
  const changedSeal=Buffer.from(value.seal); changedSeal[7]^=1;
  assert.throws(()=>build({evmSeal:changedSeal}),/seal/);
  assert.throws(()=>build({verifierConfiguration:{...value.verifier,checkpointGuestImageId:hash('40')}}),
    /hash differs|ImageID/);
  assert.throws(()=>parseCheckpointStatementV6(value.statement.subarray(0,517)),/framing/);
});

test('checkpoint submission rejects internally consistent noncanonical EVM seal lengths',()=>{
  const value=fixture();
  for(const length of [CHECKPOINT_EVM_SEAL_BYTES-1,CHECKPOINT_EVM_SEAL_BYTES+1]) {
    const seal=Buffer.concat([Buffer.from('73c457ba','hex'),Buffer.alloc(length-4,1)]);
    const proofIndex={...value.proofIndex,evm_seal_bytes:seal.length,evm_seal_sha256:rawSha(seal)};
    assert.throws(()=>buildAuthenticatedCheckpointSubmission({
      registryConfiguration:value.configuration,verifierConfiguration:value.verifier,
      statement:value.statement,proofIndex:Buffer.from(JSON.stringify(proofIndex)+'\n'),evmSeal:seal,
      releaseConfigSha256:'38'.repeat(32),
    }),/bounded|identity|seal/);
  }
});

test('fixed production command fails closed before proof access while release is unconfigured',()=>{
  const result=spawnSync(process.execPath,['scripts/prepare-authenticated-checkpoint-submission.mjs'],{
    cwd:new URL('../..',import.meta.url),encoding:'utf8',
  });
  assert.equal(result.status,1);
  assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED');
  assert.equal(result.stderr.includes('private key'),false);
});

test('single-finalized-snapshot observer classifies submission, challenge, finalization and completion',()=>{
  const value=observerFixture();
  const assess=observation=>assessCheckpointCandidateObservation({
    releaseConfig:value.releaseConfig,submission:value.submission,observation,
  });
  const ready=assess(value.observation);
  assert.equal(ready.valid,true,JSON.stringify(ready)); assert.equal(ready.status,'submission-ready');
  assert.equal(ready.submissionReady,true); assert.equal(ready.finalizationReady,false);
  assert.equal(ready.finalizeTransaction.data,CHECKPOINT_FINALIZE_CALLDATA);
  assert.equal(ready.finalizeTransaction.broadcastAuthorized,false);
  const installed={...value.observation,candidate:{
    statementHash:value.submission.statementHash,height:value.checkpoint.height,readyAt:'1792492900',
    blockHash:value.checkpoint.blockHash,stateRoot:value.checkpoint.stateRoot,
    contextHash:value.checkpoint.contextHash,totalDifficulty:value.checkpoint.totalDifficulty,
    totalIssued:value.checkpoint.totalIssued,totalBurned:value.checkpoint.totalBurned,
    issuanceClosed:value.checkpoint.issuanceClosed,confirmationHeight:value.checkpoint.confirmationHeight,
    confirmationBlock:value.checkpoint.confirmationBlock,
    confirmationTotalDifficulty:value.checkpoint.confirmationTotalDifficulty,
    confirmationTimestamp:value.checkpoint.confirmationTimestamp,
  },submissionCallAccepted:null};
  const challenge=assess(installed);
  assert.equal(challenge.valid,true); assert.equal(challenge.status,'challenge-window');
  const closureMismatch=assess({...installed,candidate:{...installed.candidate,issuanceClosed:true}});
  assert.equal(closureMismatch.valid,false);
  assert(closureMismatch.blockers.some(blocker=>blocker.code==='candidate_fields_mismatch'));
  const finalization=assess({...installed,finalizedBlockTimestamp:'1792493000'});
  assert.equal(finalization.valid,true); assert.equal(finalization.status,'finalization-ready');
  assert.equal(finalization.finalizationReady,true);
  const finalized=assess({...installed,registry:{...installed.registry,
    latestHeight:value.checkpoint.height,latestBlock:value.checkpoint.blockHash,
    latestStateRoot:value.checkpoint.stateRoot,latestContextHash:value.checkpoint.contextHash,
    latestTotalDifficulty:value.checkpoint.totalDifficulty,
    latestTotalIssued:value.checkpoint.totalIssued,latestTotalBurned:value.checkpoint.totalBurned,
    latestIssuanceClosed:value.checkpoint.issuanceClosed}});
  assert.equal(finalized.valid,true); assert.equal(finalized.status,'finalized');
});

test('checkpoint observer fails closed on snapshot, runtime, candidate and predecessor substitution',()=>{
  const value=observerFixture();
  const assess=observation=>assessCheckpointCandidateObservation({
    releaseConfig:value.releaseConfig,submission:value.submission,observation,
  });
  for(const observation of [
    {...value.observation,snapshotBlockHashAfter:hash('52')},
    {...value.observation,registryRuntimeCodeHash:hash('53')},
    {...value.observation,candidate:{...value.observation.candidate,statementHash:hash('54')},
      submissionCallAccepted:null},
    {...value.observation,registry:{...value.observation.registry,latestBlock:hash('55')}},
    {...value.observation,registry:{...value.observation.registry,halted:true}},
    {...value.observation,registry:{...value.observation.registry,gracefullyShutdown:true}},
    {...value.observation,candidate:{...value.observation.candidate,
      statementHash:value.submission.statementHash,issuanceClosed:true},submissionCallAccepted:null},
  ]) {
    const result=assess(observation);
    assert.equal(result.valid,false); assert.equal(result.status,'invalid'); assert(result.blockers.length>0);
  }
});

test('fixed checkpoint observer command is read-only and fails before RPC while release is unconfigured',()=>{
  const result=spawnSync(process.execPath,['scripts/observe-authenticated-checkpoint.mjs'],{
    cwd:new URL('../..',import.meta.url),encoding:'utf8',env:{...process.env,ETHEREUM_RPC_URL:'http://127.0.0.1:1'},
  });
  assert.equal(result.status,2);
  assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED');
  assert.equal(result.stderr.includes('127.0.0.1'),false);
});
