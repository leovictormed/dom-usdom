import test from 'node:test';
import assert from 'node:assert/strict';
import {AbiCoder,keccak256} from 'ethers';
import {readFile} from 'node:fs/promises';
import {deriveFinalizedBurnVerifierRuntimeCodeHash} from '../../sdk/compiled-runtime.mjs';
import {
  BURN_INTENT_TYPEHASH,
  BURN_STATEMENT_TYPEHASH,
  PRIVATE_BURN_ID_TYPEHASH,
} from '../../sdk/proof-reserve.mjs';
import {
  FINALIZED_BURN_PROOF_ACCEPTED_HASH,
  FINALIZED_BURN_PROOF_SYSTEM,
  FINALIZED_BURN_RISC0_ADAPTER_CONFIG_TYPEHASH,
  FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
  FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,
  VERIFIER_CONFIG_SCHEMA,
  finalizedBurnVerifierConfigHash,
} from '../../sdk/verifier-config.mjs';

const hash = byte => '0x' + byte.toString(16).padStart(2, '0').repeat(32);
const zero = hash(0);

export function verifierConfigFixture() {
  return {
    schema:VERIFIER_CONFIG_SCHEMA,
    statementVersion:'1',transitionCommitmentVersion:'2',burnStateWitnessVersion:'3',
    finalizedBurnProverInputVersion:'2',publicOutputVersion:'1',
    burnStatementTypeHash:BURN_STATEMENT_TYPEHASH,burnIntentTypeHash:BURN_INTENT_TYPEHASH,
    privateBurnIdTypeHash:PRIVATE_BURN_ID_TYPEHASH,activationScheduleCommitment:hash(1),
    domGenesisHash:hash(2),domNetworkMagic:'2712847316',domChainId:hash(3),firstV4Height:'100000',
    activationEmptyStateRoot:hash(16),
    consensusRulesHash:hash(4),forkChoiceRulesHash:hash(5),powRulesHash:hash(6),nativeAssetId:hash(7),
    noteTreeRulesHash:hash(8),nullifierRulesHash:hash(9),balanceRulesHash:hash(10),finalityRulesHash:hash(11),
    proofSystem:FINALIZED_BURN_PROOF_SYSTEM,verifyingKeySha256:hash(12),trustedSetupRequired:false,
    trustedSetupTranscriptSha256:zero,provingProgramSha256:hash(13),sourceManifestSha256:hash(14),
    verifierArtifactSha256:hash(15),maxProofBytes:'65536',minimumFinalityBeaconSlot:'12000000',
    ethereumChainId:'1',riscZeroVerifier:'0x0000000000000000000000000000000000000010',
    riscZeroVerifierCodeHash:hash(17),riscZeroVerifierSelector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
    finalizedBurnGuestImageId:hash(18),journalSchemaHash:FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,
  };
}

test('verifier configuration deterministically commits every production proof boundary', () => {
  const fixture=verifierConfigFixture();
  const result=finalizedBurnVerifierConfigHash(fixture);
  const expectedAdapterHash=keccak256(AbiCoder.defaultAbiCoder().encode(
    ['bytes32','uint256','address','bytes32','bytes4','bytes32','bytes32','bytes32'],
    [FINALIZED_BURN_RISC0_ADAPTER_CONFIG_TYPEHASH,fixture.ethereumChainId,fixture.riscZeroVerifier,
      fixture.riscZeroVerifierCodeHash,fixture.riscZeroVerifierSelector,fixture.finalizedBurnGuestImageId,
      fixture.journalSchemaHash,FINALIZED_BURN_PROOF_ACCEPTED_HASH],
  ));
  assert.equal(result.verifierConfigHash,expectedAdapterHash);
  assert.match(result.provingProgramConfigHash,/^0x[0-9a-f]{64}$/);
  assert.match(result.manifestSha256,/^0x[0-9a-f]{64}$/);
  assert.deepEqual(JSON.parse(result.canonicalManifest),fixture);
  assert.match(result.protocolHash,/^0x[0-9a-f]{64}$/);
  assert.match(result.stateRulesHash,/^0x[0-9a-f]{64}$/);
  assert.match(result.proofSystemHash,/^0x[0-9a-f]{64}$/);
  const changingFields=[
    'activationScheduleCommitment','domGenesisHash','domChainId','activationEmptyStateRoot',
    'consensusRulesHash','forkChoiceRulesHash',
    'powRulesHash','nativeAssetId','noteTreeRulesHash','nullifierRulesHash','balanceRulesHash',
    'finalityRulesHash','verifyingKeySha256','provingProgramSha256','sourceManifestSha256',
    'verifierArtifactSha256',
  ];
  for(const field of changingFields) {
    const changed={...fixture,[field]:hash(31)};
    const changedResult=finalizedBurnVerifierConfigHash(changed);
    assert.notEqual(changedResult.provingProgramConfigHash,result.provingProgramConfigHash,field);
    assert.notEqual(changedResult.manifestSha256,result.manifestSha256,field);
  }
  for(const [field,value] of [
    ['domNetworkMagic','2712847317'],['firstV4Height','100001'],
    ['minimumFinalityBeaconSlot','12000001'],
  ]) {
    assert.notEqual(finalizedBurnVerifierConfigHash({...fixture,[field]:value}).provingProgramConfigHash,
      result.provingProgramConfigHash,field);
  }
  const setup={...fixture,trustedSetupRequired:true,trustedSetupTranscriptSha256:hash(16)};
  assert.notEqual(finalizedBurnVerifierConfigHash(setup).provingProgramConfigHash,result.provingProgramConfigHash);
  for(const [field,value] of [
    ['ethereumChainId','2'],['riscZeroVerifier','0x0000000000000000000000000000000000000011'],
    ['riscZeroVerifierCodeHash',hash(31)],['finalizedBurnGuestImageId',hash(31)],
  ]) assert.notEqual(finalizedBurnVerifierConfigHash({...fixture,[field]:value}).verifierConfigHash,
    result.verifierConfigHash,field);
});

test('verifier configuration rejects ambiguous, stale and incomplete manifests', () => {
  const fixture=verifierConfigFixture();
  for(const changed of [
    {...fixture,extra:true},{...fixture,schema:'wrong'},
    {...fixture,schema:'usdom-finalized-burn-verifier-config-v4'},{...fixture,statementVersion:'2'},
    {...fixture,transitionCommitmentVersion:'1'},{...fixture,burnStateWitnessVersion:'2'},
    {...fixture,finalizedBurnProverInputVersion:'1'},{...fixture,publicOutputVersion:'2'},
    {...fixture,burnStatementTypeHash:hash(20)},{...fixture,burnIntentTypeHash:hash(20)},
    {...fixture,privateBurnIdTypeHash:hash(20)},{...fixture,domNetworkMagic:'0'},
    {...fixture,firstV4Height:'0'},{...fixture,maxProofBytes:'65535'},
    {...fixture,minimumFinalityBeaconSlot:'0'},{...fixture,proofSystem:'groth16-bn254-v1'},
    {...fixture,ethereumChainId:'0'},
    {...fixture,riscZeroVerifier:'0x0000000000000000000000000000000000000000'},
    {...fixture,riscZeroVerifierCodeHash:zero},{...fixture,finalizedBurnGuestImageId:zero},
    {...fixture,riscZeroVerifierSelector:'0x01020304'},{...fixture,journalSchemaHash:hash(31)},
    {...fixture,trustedSetupRequired:false,trustedSetupTranscriptSha256:hash(16)},
    {...fixture,trustedSetupRequired:true,trustedSetupTranscriptSha256:zero},
  ]) assert.throws(()=>finalizedBurnVerifierConfigHash(changed));
  const missing={...fixture}; delete missing.finalityRulesHash;
  assert.throws(()=>finalizedBurnVerifierConfigHash(missing),/exact/);
});

test('finalized-burn adapter runtime is source-derived with every immutable patched',async()=>{
  const artifact=JSON.parse(await readFile(new URL(
    '../../out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',import.meta.url,
  ),'utf8'));
  const root=new URL('../../',import.meta.url);
  const sourceContents=Object.create(null);
  for(const source of Object.keys(artifact.metadata.sources)) {
    sourceContents[source]=await readFile(new URL(source,root));
  }
  const fixture=verifierConfigFixture();
  const result=deriveFinalizedBurnVerifierRuntimeCodeHash({artifact,verifierConfig:fixture,sourceContents});
  assert.match(result.runtimeCodeHash,/^0x[0-9a-f]{64}$/);
  assert.equal(result.runtimeSize,1921);
  for(const [field,value] of [
    ['riscZeroVerifier','0x0000000000000000000000000000000000000011'],
    ['riscZeroVerifierCodeHash',hash(31)],['finalizedBurnGuestImageId',hash(31)],
    ['ethereumChainId','2'],
  ]) assert.notEqual(deriveFinalizedBurnVerifierRuntimeCodeHash({artifact,
    verifierConfig:{...fixture,[field]:value},sourceContents}).runtimeCodeHash,result.runtimeCodeHash,field);
});
