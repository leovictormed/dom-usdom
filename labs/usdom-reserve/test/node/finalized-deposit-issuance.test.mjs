import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
  sha256Hex,validateDomMainnetIdentity,validateFinalizedDepositIssuance,
  validateIssuanceSubmissionResponse,validatePersistedIssuanceSubmission
} from '../../sdk/finalized-deposit-issuance.mjs';

const witness=Buffer.from('UDOMDPW1-test-vector');
const manifestSha256='11'.repeat(32);
const index={schema:'usdom-finalized-deposit-witness-v1',
  source_file:'finalized-deposit-source.json',source_sha256:'12'.repeat(32),
  release_config_sha256:'13'.repeat(32),source_transaction_hash:`0x${'14'.repeat(32)}`,
  native_manifest_sha256:manifestSha256,witness_sha256:sha256Hex(witness),
  witness_file:'finalized-deposit-witness.bin',witness_bytes:witness.length,
  witness_verified:true,relation_executed:true,broadcasts:false,mines:false,
  amount_base_units:'1000000',deposit_id:`0x${'22'.repeat(32)}`,
  funder:`0x${'15'.repeat(20)}`,receiving_commitment:`0x${'03'.repeat(32)}`,
  transaction_index:7,receipt_log_index:2,
  deposit_block_number:'5',deposit_block_hash:`0x${'16'.repeat(32)}`,
  finalized_beacon_slot:'8',finalized_beacon_root:`0x${'17'.repeat(32)}`,
  finalized_execution_block_number:'7',finalized_execution_block_hash:`0x${'18'.repeat(32)}`,
  replay_slot:'8',deposit_policy_hash:`0x${'19'.repeat(32)}`};
const registration={schema:'usdom-expected-deposit-registration-v1',
  native_manifest_sha256:manifestSha256,witness_sha256:sha256Hex(witness),
  deposit_id:'22'.repeat(32),amount_base_units:'1000000',
  receiving_commitment:'03'.repeat(32),note_commitment:'04'.repeat(32),
  wallet_address:Buffer.from('USDADR01').toString('hex')+'05'.repeat(32)+'03'.repeat(32)+'06'.repeat(32),
  registered_tip_height:'7',registered_tip_hash:'66'.repeat(32),
  snapshot_generation:'1',snapshot_seal:'77'.repeat(48),submits:false,mines:false};

test('issuance binding accepts one exact registered 1 USDT witness',()=>{
  assert.deepEqual(validateFinalizedDepositIssuance({index,registration,witness,manifestSha256}),{
    depositId:index.deposit_id,witnessSha256:sha256Hex(witness),amountBaseUnits:'1000000',
    noteCommitment:`0x${registration.note_commitment}`});
});

test('consumer schema covers every field emitted by the Rust witness builder',async()=>{
  const source=await readFile(new URL(
    '../../../../crates/dom-node/src/bin/dom-usdom-build-finalized-deposit-witness.rs',
    import.meta.url),'utf8');
  for(const field of Object.keys(index)) {
    assert.match(source,new RegExp(`"${field}"\\s*:`),field);
  }
});

test('issuance binding rejects every authority substitution',()=>{
  for(const mutation of [
    {index:{...index,amount_base_units:'1000001'}},
    {index:{...index,witness_verified:false}},
    {index:{...index,release_config_sha256:'99'.repeat(32),unexpected:true}},
    {index:{...index,deposit_block_number:'8'}},
    {index:{...index,replay_slot:'0'}},
    {index:{...index,deposit_policy_hash:`0x${'00'.repeat(32)}`}},
    {registration:{...registration,deposit_id:'88'.repeat(32)}},
    {registration:{...registration,snapshot_generation:'2'}},
    {registration:{...registration,submits:true}},
    {registration:{...registration,unexpected:true}},
    {registration:{...registration,wallet_address:'00'.repeat(104)}},
    {registration:{...registration,wallet_address:
      Buffer.from('USDADR01').toString('hex')+'05'.repeat(32)+'08'.repeat(32)+'06'.repeat(32)}},
    {registration:{...registration,registered_tip_hash:'00'.repeat(32)}},
    {registration:{...registration,snapshot_seal:'00'.repeat(48)}},
    {registration:{...registration,registered_tip_height:'9'.repeat(100000)}},
    {registration:{...registration,registered_tip_height:(1n<<64n).toString()}},
    {index:{...index,receiving_commitment:`0x${'ff'.repeat(32)}`}},
    {index:{...index,transaction_index:4096}},
    {index:{...index,receipt_log_index:-1}},
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
  assert.throws(()=>validateDomMainnetIdentity({...identity,unexpected:true}));
  assert.throws(()=>validateDomMainnetIdentity(Object.fromEntries(
    Object.entries(identity).filter(([key])=>key!=='tip_hash'))));
  assert.deepEqual(validateIssuanceSubmissionResponse({schema_version:1,accepted:true,
    candidate_id:'44'.repeat(32),state:'queued'}),{schema_version:1,accepted:true,
    candidate_id:'44'.repeat(32),state:'queued'});
  assert.throws(()=>validateIssuanceSubmissionResponse({schema_version:1,accepted:true,
    candidate_id:'00'.repeat(32),state:'queued'}));
  assert.throws(()=>validateIssuanceSubmissionResponse({schema_version:1,accepted:true,
    candidate_id:'44'.repeat(32),state:'queued',unexpected:true}));
  assert.throws(()=>validateIssuanceSubmissionResponse({schema_version:1,accepted:true,
    candidate_id:'44'.repeat(32)}));
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
    {...receipt,observedTipHeight:'9'.repeat(100000)},
    {...receipt,observedTipHeight:(1n<<64n).toString()},
    {...receipt,observedTipHeight:'9'},
    {...receipt,observedTipHeight:'8',observedTipHash:`0x${'55'.repeat(32)}`},
    {...receipt,submittedAt:'2026-10-26 12:00:00Z'},
  ]) assert.throws(()=>validatePersistedIssuanceSubmission(changed,{binding,identity}));
});
