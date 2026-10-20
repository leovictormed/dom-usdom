import test from 'node:test';
import assert from 'node:assert/strict';
import {AbiCoder,id,keccak256} from 'ethers';
import {readFile} from 'node:fs/promises';
import {deriveCheckpointVerifierRuntimeCodeHash} from '../../sdk/compiled-runtime.mjs';
import {CHECKPOINT_STATEMENT_TYPEHASH} from '../../sdk/checkpoint-registry.mjs';
import {
  CHECKPOINT_PROOF_ACCEPTED_HASH,
  CHECKPOINT_PROOF_SYSTEM,
  CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
  CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,
  CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,
  CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,
  CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
  CHECKPOINT_VERIFIER_CONFIG_SCHEMA,
  checkpointVerifierConfigHash,
} from '../../sdk/checkpoint-verifier-config.mjs';

const hash=byte=>'0x'+byte.toString(16).padStart(2,'0').repeat(32);
const zero=hash(0);

export function checkpointVerifierConfigFixture() {
  return {
    schema:CHECKPOINT_VERIFIER_CONFIG_SCHEMA,statementVersion:'4',checkpointProverInputVersion:'4',
    continuationContextVersion:'2',
    transitionCommitmentVersion:'3',activationScheduleVersion:'2',publicOutputVersion:'1',
    publicStatementBytes:'518',continuationContextBytes:'695',
    segmentStateVersion:'2',segmentTransitionVersion:'2',randomxStatementVersion:'1',
    segmentStateBytes:'1105',segmentTransitionBytes:'2254',randomxStatementBytes:'384',
    segmentStateDomainHash:CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,
    segmentTransitionDomainHash:CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
    randomxStatementDomainHash:CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
    randomxReceiptImageId:hash(15),
    checkpointStatementTypeHash:CHECKPOINT_STATEMENT_TYPEHASH,
    proofAcceptedHash:CHECKPOINT_PROOF_ACCEPTED_HASH,activationScheduleCommitment:hash(1),
    domGenesisHash:hash(2),domNetworkMagic:'1146047793',domChainId:hash(3),firstV4Height:'100000',
    activationEmptyStateRoot:hash(4),checkpointInterval:'360',confirmationDepth:'30',
    challengePeriod:'172800',maxCheckpointSpan:'390',consensusRulesHash:hash(5),
    forkChoiceRulesHash:hash(6),powRulesHash:hash(7),nativeStateRulesHash:hash(8),
    continuationContextRulesHash:hash(14),consensusExtensionWitnessRulesHash:hash(9),
    proofSystem:CHECKPOINT_PROOF_SYSTEM,
    verifyingKeySha256:hash(10),trustedSetupRequired:false,trustedSetupTranscriptSha256:zero,
    provingProgramSha256:hash(11),sourceManifestSha256:hash(12),verifierArtifactSha256:hash(13),
    maxProofBytes:'65536',ethereumChainId:'1',riscZeroVerifier:'0x0000000000000000000000000000000000000010',
    riscZeroVerifierCodeHash:hash(16),riscZeroVerifierSelector:CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,
    checkpointGuestImageId:hash(17),journalSchemaHash:CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,
  };
}

test('checkpoint verifier configuration commits every consensus and artifact boundary',()=>{
  const fixture=checkpointVerifierConfigFixture();
  const result=checkpointVerifierConfigHash(fixture);
  assert.match(result.verifierConfigHash,/^0x[0-9a-f]{64}$/);
  assert.match(result.provingProgramConfigHash,/^0x[0-9a-f]{64}$/);
  assert.match(result.manifestSha256,/^0x[0-9a-f]{64}$/);
  assert.deepEqual(JSON.parse(result.canonicalManifest),fixture);
  const adapterTypehash=id(
    'DOMCheckpointRiscZeroVerifier(uint256 chainId,address riscZeroVerifier,bytes32 riscZeroVerifierCodeHash,bytes4 verifierSelector,bytes32 imageId,bytes32 journalSchemaHash,bytes32 proofAccepted)',
  );
  const expectedAdapterHash=keccak256(AbiCoder.defaultAbiCoder().encode(
    ['bytes32','uint256','address','bytes32','bytes4','bytes32','bytes32','bytes32'],
    [adapterTypehash,fixture.ethereumChainId,fixture.riscZeroVerifier,fixture.riscZeroVerifierCodeHash,
      fixture.riscZeroVerifierSelector,fixture.checkpointGuestImageId,fixture.journalSchemaHash,
      fixture.proofAcceptedHash],
  ));
  assert.equal(result.verifierConfigHash,expectedAdapterHash);
  assert.equal(result.verifierConfigHash,
    '0x85b1f2ba490ad5c9643c819c984cfba3e5338bbb02a5a6b2345e1745a6096bf6');
  for(const field of ['activationScheduleCommitment','domGenesisHash','domChainId',
    'activationEmptyStateRoot','consensusRulesHash','forkChoiceRulesHash','powRulesHash',
    'nativeStateRulesHash','continuationContextRulesHash','consensusExtensionWitnessRulesHash','verifyingKeySha256',
    'provingProgramSha256','sourceManifestSha256','verifierArtifactSha256','randomxReceiptImageId']) {
    const changed=checkpointVerifierConfigHash({...fixture,[field]:hash(31)});
    assert.notEqual(changed.provingProgramConfigHash,result.provingProgramConfigHash,field);
    assert.notEqual(changed.manifestSha256,result.manifestSha256,field);
  }
  for(const [field,value] of [['riscZeroVerifierCodeHash',hash(31)],['checkpointGuestImageId',hash(31)],
    ['ethereumChainId','2'],['riscZeroVerifier','0x0000000000000000000000000000000000000011']]) {
    assert.notEqual(checkpointVerifierConfigHash({...fixture,[field]:value}).verifierConfigHash,
      result.verifierConfigHash,field);
  }
  for(const [field,value] of [['domNetworkMagic','1146047794'],['firstV4Height','100001'],
    ['challengePeriod','172801']]) {
    assert.notEqual(checkpointVerifierConfigHash({...fixture,[field]:value}).provingProgramConfigHash,
      result.provingProgramConfigHash,field);
  }
  assert.notEqual(checkpointVerifierConfigHash({...fixture,checkpointInterval:'359',maxCheckpointSpan:'389'})
    .provingProgramConfigHash,result.provingProgramConfigHash,'checkpointInterval');
  assert.notEqual(checkpointVerifierConfigHash({...fixture,confirmationDepth:'29',maxCheckpointSpan:'389'})
    .provingProgramConfigHash,result.provingProgramConfigHash,'confirmationDepth');
});

test('checkpoint verifier configuration rejects ambiguity and unsupported policies',()=>{
  const fixture=checkpointVerifierConfigFixture();
  for(const changed of [
    {...fixture,extra:true},{...fixture,schema:'wrong'},{...fixture,statementVersion:'3'},
    {...fixture,checkpointProverInputVersion:'1'},{...fixture,transitionCommitmentVersion:'2'},
    {...fixture,continuationContextVersion:'1'},
    {...fixture,activationScheduleVersion:'1'},{...fixture,publicOutputVersion:'2'},
    {...fixture,publicStatementBytes:'517'},{...fixture,continuationContextBytes:'694'},
    {...fixture,segmentStateVersion:'1'},{...fixture,segmentTransitionVersion:'1'},
    {...fixture,randomxStatementVersion:'2'},{...fixture,segmentStateBytes:'1073'},
    {...fixture,segmentTransitionBytes:'2190'},{...fixture,randomxStatementBytes:'383'},
    {...fixture,segmentStateDomainHash:hash(20)},
    {...fixture,segmentTransitionDomainHash:hash(20)},
    {...fixture,randomxStatementDomainHash:hash(20)},
    {...fixture,checkpointStatementTypeHash:hash(20)},
    {...fixture,proofAcceptedHash:hash(20)},{...fixture,domNetworkMagic:'0'},
    {...fixture,firstV4Height:'0'},{...fixture,checkpointInterval:'0'},
    {...fixture,checkpointInterval:'361',maxCheckpointSpan:'391'},
    {...fixture,confirmationDepth:'0',maxCheckpointSpan:'360'},
    {...fixture,confirmationDepth:'361',maxCheckpointSpan:'721'},
    {...fixture,challengePeriod:'86399'},{...fixture,challengePeriod:'2592001'},
    {...fixture,maxCheckpointSpan:'389'},{...fixture,maxProofBytes:'65535'},
    {...fixture,ethereumChainId:'0'},
    {...fixture,riscZeroVerifier:'0x0000000000000000000000000000000000000000'},
    {...fixture,riscZeroVerifierSelector:'0x01020304'},
    {...fixture,journalSchemaHash:hash(20)},
    {...fixture,proofSystem:'groth16-bn254-v1'},{...fixture,proofSystem:'Groth16 BN254'},
    {...fixture,trustedSetupRequired:false,trustedSetupTranscriptSha256:hash(20)},
    {...fixture,trustedSetupRequired:true,trustedSetupTranscriptSha256:zero},
  ]) assert.throws(()=>checkpointVerifierConfigHash(changed));
  const missing={...fixture}; delete missing.powRulesHash;
  assert.throws(()=>checkpointVerifierConfigHash(missing),/exact/);
});

test('checkpoint adapter runtime is source-derived with every immutable patched',async()=>{
  const artifact=JSON.parse(await readFile(new URL(
    '../../out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json',import.meta.url,
  ),'utf8'));
  const root=new URL('../../',import.meta.url);
  const sourceContents=Object.create(null);
  for(const source of Object.keys(artifact.metadata.sources)) {
    sourceContents[source]=await readFile(new URL(source,root));
  }
  const fixture=checkpointVerifierConfigFixture();
  const result=deriveCheckpointVerifierRuntimeCodeHash({artifact,verifierConfig:fixture,sourceContents});
  assert.match(result.runtimeCodeHash,/^0x[0-9a-f]{64}$/);
  assert.equal(result.runtimeSize,1922);
  for(const [field,value] of [
    ['riscZeroVerifier','0x0000000000000000000000000000000000000011'],
    ['riscZeroVerifierCodeHash',hash(31)],['checkpointGuestImageId',hash(31)],
    ['ethereumChainId','2'],
  ]) assert.notEqual(deriveCheckpointVerifierRuntimeCodeHash({artifact,
    verifierConfig:{...fixture,[field]:value},sourceContents}).runtimeCodeHash,result.runtimeCodeHash,field);
});
