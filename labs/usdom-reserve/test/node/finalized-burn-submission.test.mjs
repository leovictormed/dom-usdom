import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sha256} from 'ethers';
import {
  FINALIZED_BURN_EVM_SEAL_BYTES,FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS,
  FINALIZED_BURN_IMAGE_ID,
  buildAuthenticatedFinalizedBurnSubmission,validateAuthenticatedFinalizedBurnSubmission,
} from '../../sdk/finalized-burn-submission.mjs';
import {
  BURN_INTENT_TYPEHASH,BURN_STATEMENT_TYPEHASH,PRIVATE_BURN_ID_TYPEHASH,
  finalizedBurnStatementHash,
} from '../../sdk/proof-reserve.mjs';
import {
  FINALIZED_BURN_PROOF_SYSTEM,FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
  FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,VERIFIER_CONFIG_SCHEMA,
  finalizedBurnVerifierConfigHash,
} from '../../sdk/verifier-config.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';
import {finalizedBurnAuthorityFixture as fixture} from './finalized-burn-authority-fixture.mjs';

const hash=byte=>'0x'+byte.toString(16).padStart(2,'0').repeat(32);
const rawHash=bytes=>createHash('sha256').update(bytes).digest('hex');
const zero=hash(0);

test('authenticated finalized-burn artifacts produce canonical unsigned reserve calldata',()=>{
  const f=fixture();
  const submission=buildAuthenticatedFinalizedBurnSubmission(f);
  const parsed=validateAuthenticatedFinalizedBurnSubmission(submission);
  assert.equal(submission.broadcastAuthorized,false);
  assert.equal(submission.method,'queueWithdrawal');
  assert.equal(submission.statementHash,f.statementHash);
  assert.equal(submission.proof.selector,FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR);
  assert.equal(parsed.burn.burnId,f.burn.burnId);
  assert.deepEqual(Buffer.from(parsed.proof),f.evmSeal);
});

test('submission construction rejects substitutions across every authenticated handoff',()=>{
  for(const mutate of [
    f=>{f.sourceInput=Buffer.from('changed');},
    f=>{const o=JSON.parse(f.sourceIndex);o.burn.amount='1000001';f.sourceIndex=Buffer.from(JSON.stringify(o)+'\n');},
    f=>{const o=JSON.parse(f.receiptIndex);o.input_sha256='44'.repeat(32);f.receiptIndex=Buffer.from(JSON.stringify(o)+'\n');},
    f=>{const o=JSON.parse(f.proofIndex);o.statement_hash='45'.repeat(32);f.proofIndex=Buffer.from(JSON.stringify(o)+'\n');},
    f=>{f.evmSeal=Buffer.from('01020304','hex');},
  ]) {
    const f=fixture(); mutate(f);
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(f));
  }
});

test('finalized-burn indexes reject invalid UTF-8 and duplicate keys before authority',()=>{
  for(const field of ['sourceIndex','receiptIndex','proofIndex']) {
    const invalid=fixture();
    invalid[field]=Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]);
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(invalid),/invalid UTF-8/);

    const duplicate=fixture();
    duplicate[field]=Buffer.concat([
      Buffer.from('{"schema":"ambiguous",'),duplicate[field].subarray(1),
    ]);
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(duplicate),
      /duplicate object key "schema"/);
  }
});

test('submission construction rejects inconsistent checkpoint and proving-program metadata',()=>{
  for(const mutate of [
    o=>{o.checkpoint_dom_height+=1;},
    o=>{o.checkpoint_dom_block='44'.repeat(32);},
    o=>{o.checkpoint_dom_state_root='45'.repeat(32);},
    o=>{o.checkpoint_beacon_slot+=1;},
    o=>{o.candidate_v2_first_height=o.checkpoint_dom_height+1;},
  ]) {
    const f=fixture(); const source=JSON.parse(f.sourceIndex); mutate(source);
    f.sourceIndex=Buffer.from(JSON.stringify(source)+'\n');
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(f),/checkpoint/);
  }
  for(const mutate of [
    o=>{o.program_path='evidence/finalized-burn-guest/substitute.elf';},
    o=>{o.program_sha256='46'.repeat(32);},
  ]) {
    const f=fixture(); const receipt=JSON.parse(f.receiptIndex); mutate(receipt);
    f.receiptIndex=Buffer.from(JSON.stringify(receipt)+'\n');
    const proof=JSON.parse(f.proofIndex);
    proof.receipt_index_sha256=rawHash(f.receiptIndex);
    f.proofIndex=Buffer.from(JSON.stringify(proof)+'\n');
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(f),/receipt index/);
  }
});

test('submission construction rejects internally consistent noncanonical EVM seal lengths',()=>{
  for(const length of [FINALIZED_BURN_EVM_SEAL_BYTES-1,FINALIZED_BURN_EVM_SEAL_BYTES+1]) {
    const f=fixture();
    f.evmSeal=Buffer.concat([
      Buffer.from(FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2),'hex'),
      Buffer.alloc(length-4,1),
    ]);
    const proof=JSON.parse(f.proofIndex);
    proof.evm_seal_bytes=f.evmSeal.length;
    proof.evm_seal_sha256=rawHash(f.evmSeal);
    f.proofIndex=Buffer.from(JSON.stringify(proof)+'\n');
    assert.throws(()=>buildAuthenticatedFinalizedBurnSubmission(f),/bounded|identity|seal/);
  }
});

test('serialized submission validator rejects calldata, proof and metadata substitution',()=>{
  const valid=buildAuthenticatedFinalizedBurnSubmission(fixture());
  for(const changed of [
    {...valid,data:valid.data.slice(0,-2)+(valid.data.endsWith('00')?'01':'00')},
    {...valid,statementHash:hash(46)},
    {...valid,statementHash:hash(46),journalDigest:sha256(hash(46))},
    {...valid,source:{...valid.source,activationScheduleCommitment:hash(46)}},
    {...valid,source:{...valid.source,sourceIndexSha256:'0'.repeat(64)}},
    {...valid,source:{...valid.source,inputSha256:valid.source.sourceIndexSha256}},
    {...valid,statementHash:valid.statementHash.toUpperCase().replace('0X','0x')},
    {...valid,proof:{...valid.proof,sha256:'47'.repeat(32)}},
    {...valid,broadcastAuthorized:true},
    {...valid,extra:true},
  ]) assert.throws(()=>validateAuthenticatedFinalizedBurnSubmission(changed));
});
