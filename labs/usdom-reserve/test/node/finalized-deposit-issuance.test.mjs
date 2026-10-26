import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sha256Hex,validateDomMainnetIdentity,validateFinalizedDepositIssuance,
  validateIssuanceSubmissionResponse,validatePersistedIssuanceSubmission
} from '../../sdk/finalized-deposit-issuance.mjs';

const witness=Buffer.from('UDOMDPW1-test-vector');
const manifestSha256='11'.repeat(32);
const index={schema:'usdom-finalized-deposit-witness-v1',
  native_manifest_sha256:manifestSha256,witness_sha256:sha256Hex(witness),
  witness_file:'finalized-deposit-witness.bin',witness_bytes:witness.length,
  witness_verified:true,relation_executed:true,broadcasts:false,mines:false,
  amount_base_units:'1000000',deposit_id:`0x${'22'.repeat(32)}`,
  receiving_commitment:`0x${'03'.repeat(32)}`};
const registration={schema:'usdom-expected-deposit-registration-v1',
  native_manifest_sha256:manifestSha256,witness_sha256:sha256Hex(witness),
  deposit_id:'22'.repeat(32),amount_base_units:'1000000',
  receiving_commitment:'03'.repeat(32),note_commitment:'04'.repeat(32),
  wallet_address:'55'.repeat(104),registered_tip_height:'7',registered_tip_hash:'66'.repeat(32),
  snapshot_generation:'1',snapshot_seal:'77'.repeat(48),submits:false,mines:false};

test('issuance binding accepts one exact registered 1 USDT witness',()=>{
  assert.deepEqual(validateFinalizedDepositIssuance({index,registration,witness,manifestSha256}),{
    depositId:index.deposit_id,witnessSha256:sha256Hex(witness),amountBaseUnits:'1000000',
    noteCommitment:`0x${registration.note_commitment}`});
});

test('issuance binding rejects every authority substitution',()=>{
  for(const mutation of [
    {index:{...index,amount_base_units:'1000001'}},
    {index:{...index,witness_verified:false}},
    {registration:{...registration,deposit_id:'88'.repeat(32)}},
    {registration:{...registration,snapshot_generation:'2'}},
    {registration:{...registration,submits:true}},
    {index:{...index,receiving_commitment:`0x${'ff'.repeat(32)}`}},
    {registration:{...registration,note_commitment:'ff'.repeat(32)}},
    {manifestSha256:'99'.repeat(32)},
    {witness:Buffer.from('changed')}
  ]) assert.throws(()=>validateFinalizedDepositIssuance({index,registration,witness,manifestSha256,...mutation}));
});

test('DOM identity and admission response are strict',()=>{
  const identity={rpc_api_version:1,protocol_version:4,network:'mainnet',network_magic:'444f4d31',
    chain_id:'11'.repeat(32),genesis_hash:'22'.repeat(32),tip_height:8,tip_hash:'33'.repeat(32),
    max_scan_range:1000};
  assert.equal(validateDomMainnetIdentity(identity),identity);
  assert.throws(()=>validateDomMainnetIdentity({...identity,network:'regtest'}));
  assert.throws(()=>validateDomMainnetIdentity({...identity,network_magic:'444f4d33'}));
  assert.deepEqual(validateIssuanceSubmissionResponse({schema_version:1,accepted:true,
    candidate_id:'44'.repeat(32),state:'queued'}),{schema_version:1,accepted:true,
    candidate_id:'44'.repeat(32),state:'queued'});
  assert.throws(()=>validateIssuanceSubmissionResponse({schema_version:1,accepted:true,
    candidate_id:'00'.repeat(32),state:'queued'}));
});

test('durable submission receipt is an exact idempotent restart boundary',()=>{
  const identity={rpc_api_version:1,protocol_version:4,network:'mainnet',network_magic:'444f4d31',
    chain_id:'11'.repeat(32),genesis_hash:'22'.repeat(32),tip_height:8,tip_hash:'33'.repeat(32),
    max_scan_range:1000};
  const binding=validateFinalizedDepositIssuance({index,registration,witness,manifestSha256});
  const receipt={schema:'usdom-finalized-deposit-issuance-submission-v1',...binding,
    candidateId:`0x${'44'.repeat(32)}`,state:'queued',domChainId:`0x${identity.chain_id}`,
    domGenesisHash:`0x${identity.genesis_hash}`,observedTipHeight:'7',
    observedTipHash:`0x${'55'.repeat(32)}`,submittedAt:'2026-10-26T12:00:00.000Z',
    mined:false,broadcastsEthereum:false};
  assert.equal(validatePersistedIssuanceSubmission(receipt,{binding,identity}),receipt);
  for(const changed of [
    {...receipt,depositId:`0x${'99'.repeat(32)}`},
    {...receipt,domGenesisHash:`0x${'99'.repeat(32)}`},
    {...receipt,extra:true},
    {...receipt,state:'mined'},
  ]) assert.throws(()=>validatePersistedIssuanceSubmission(changed,{binding,identity}));
});
