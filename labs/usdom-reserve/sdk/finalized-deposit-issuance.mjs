import {createHash} from 'node:crypto';

const HEX32=/^[0-9a-f]{64}$/;
const BN254_SCALAR_FIELD=BigInt(
  '0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001',
);
const uint64=value=>typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value)
  &&BigInt(value)<(1n<<64n);
// Keep this schema identical to dom-usdom-build-finalized-deposit-witness.  In
// particular, do not reduce the index to the amount and deposit id: the source,
// release, reserve-event locator, finalized execution identity and replay
// policy are the authenticated bridge between Ethereum and native issuance.
const indexFields=['schema','source_file','source_sha256','native_manifest_sha256',
  'release_config_sha256','source_transaction_hash','deposit_id','funder','amount_base_units',
  'receiving_commitment','transaction_index','receipt_log_index','deposit_block_number',
  'deposit_block_hash','finalized_beacon_slot',
  'finalized_beacon_root','finalized_execution_block_number','finalized_execution_block_hash',
  'replay_slot','deposit_policy_hash','witness_file','witness_sha256','witness_bytes',
  'relation_executed','witness_verified','mines','broadcasts'];
const registrationFields=['schema','native_manifest_sha256','witness_sha256','deposit_id',
  'amount_base_units','receiving_commitment','note_commitment','wallet_address',
  'registered_tip_height','registered_tip_hash','snapshot_generation','snapshot_seal','submits','mines'];
const identityFields=['rpc_api_version','protocol_version','network','network_magic','chain_id',
  'genesis_hash','tip_height','tip_hash','max_scan_range'];
const admissionFields=['schema_version','accepted','candidate_id','state'];

function canonicalScalar(value) {
  return HEX32.test(value) && !/^0+$/.test(value) && BigInt(`0x${value}`)<BN254_SCALAR_FIELD;
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function validateFinalizedDepositWitnessIndex(index) {
  if(!index||typeof index!=='object'||Array.isArray(index)
      ||JSON.stringify(Object.keys(index).sort())!==JSON.stringify([...indexFields].sort())
      ||index.schema!=='usdom-finalized-deposit-witness-v1'
      ||index.source_file!=='finalized-deposit-source.json'
      ||![index.source_sha256,index.native_manifest_sha256,index.release_config_sha256,
        index.witness_sha256].every(value=>HEX32.test(value)&&!/^0+$/.test(value))
      ||!/^0x[0-9a-f]{64}$/.test(index.source_transaction_hash)
      ||index.source_transaction_hash===`0x${'0'.repeat(64)}`
      ||index.witness_file!=='finalized-deposit-witness.bin'
      ||!Number.isSafeInteger(index.witness_bytes)||index.witness_bytes<=0
      ||index.witness_bytes>4*1024*1024
      ||index.witness_verified!==true||index.relation_executed!==true
      ||index.broadcasts!==false||index.mines!==false||index.amount_base_units!=='1000000'
      ||!/^0x[0-9a-f]{64}$/.test(index.deposit_id)
      ||!/^0x[0-9a-f]{40}$/.test(index.funder)
      ||!/^0x[0-9a-f]{64}$/.test(index.receiving_commitment)
      ||!canonicalScalar(index.receiving_commitment.slice(2))
      ||!Number.isSafeInteger(index.transaction_index)||index.transaction_index<0
      ||index.transaction_index>4095
      ||!Number.isSafeInteger(index.receipt_log_index)||index.receipt_log_index<0
      ||index.receipt_log_index>4095
      ||![index.deposit_block_number,index.finalized_beacon_slot,
        index.finalized_execution_block_number,index.replay_slot].every(uint64)
      ||[index.deposit_block_number,index.finalized_beacon_slot,
        index.finalized_execution_block_number,index.replay_slot].some(value=>value==='0')
      ||BigInt(index.finalized_execution_block_number)<BigInt(index.deposit_block_number)
      ||![index.deposit_block_hash,index.finalized_beacon_root,
        index.finalized_execution_block_hash,index.deposit_policy_hash]
        .every(value=>/^0x[0-9a-f]{64}$/.test(value)&&value!==`0x${'0'.repeat(64)}`)) {
    throw new Error('witness index does not bind the exact verified closed deposit');
  }
  return index;
}

export function validateFinalizedDepositIssuance({index,registration,witness,manifestSha256}) {
  if(!Buffer.isBuffer(witness) || witness.length===0 || witness.length>4*1024*1024)
    throw new Error('finalized deposit witness is outside its canonical size bound');
  if(!HEX32.test(manifestSha256)) throw new Error('native manifest SHA-256 is invalid');
  const witnessSha256=sha256Hex(witness);
  validateFinalizedDepositWitnessIndex(index);
  if(index.native_manifest_sha256!==manifestSha256
      || index.witness_sha256!==witnessSha256
      || index.witness_bytes!==witness.length
  )
    throw new Error('witness index does not bind the exact verified closed deposit');
  if(!registration||typeof registration!=='object'||Array.isArray(registration)
      ||JSON.stringify(Object.keys(registration).sort())!==JSON.stringify([...registrationFields].sort())
      ||registration.schema!=='usdom-expected-deposit-registration-v1'
      || registration.native_manifest_sha256!==manifestSha256
      || registration.witness_sha256!==witnessSha256
      || registration.deposit_id!==index.deposit_id.slice(2)
      || registration.amount_base_units!=='1000000'
      || registration.receiving_commitment!==index.receiving_commitment.slice(2)
      || !canonicalScalar(registration.receiving_commitment)
      || !canonicalScalar(registration.note_commitment)
      || !/^[0-9a-f]{208}$/.test(registration.wallet_address)
      || registration.wallet_address.slice(0,16)!==Buffer.from('USDADR01').toString('hex')
      || registration.wallet_address.slice(80,144)!==registration.receiving_commitment
      || /^0+$/.test(registration.wallet_address.slice(16,80))
      || /^0+$/.test(registration.wallet_address.slice(144))
      || !uint64(registration.registered_tip_height)
      || !HEX32.test(registration.registered_tip_hash)||/^0+$/.test(registration.registered_tip_hash)
      || registration.snapshot_generation!=='1'
      || !/^[0-9a-f]{96}$/.test(registration.snapshot_seal)||/^0+$/.test(registration.snapshot_seal)
      || registration.submits!==false || registration.mines!==false)
    throw new Error('encrypted wallet registration does not bind the verified deposit');
  return Object.freeze({
    depositId:index.deposit_id,
    witnessSha256,
    amountBaseUnits:index.amount_base_units,
    noteCommitment:`0x${registration.note_commitment}`
  });
}

export function validateDomMainnetIdentity(identity) {
  if(!identity||typeof identity!=='object'||Array.isArray(identity)
      ||JSON.stringify(Object.keys(identity).sort())!==JSON.stringify([...identityFields].sort())
      ||identity.rpc_api_version!==1 || !Number.isSafeInteger(identity.protocol_version)
      || identity.protocol_version<=0 || identity.network!=='mainnet'
      || identity.network_magic!=='444f4d31'
      || !HEX32.test(identity.chain_id) || /^0+$/.test(identity.chain_id)
      || !HEX32.test(identity.genesis_hash) || /^0+$/.test(identity.genesis_hash)
      || !Number.isSafeInteger(identity.tip_height) || identity.tip_height<0
      || !HEX32.test(identity.tip_hash) || /^0+$/.test(identity.tip_hash)
      || !Number.isSafeInteger(identity.max_scan_range) || identity.max_scan_range<=0)
    throw new Error('local DOM RPC does not report a valid mainnet identity');
  return identity;
}

export function validateIssuanceSubmissionResponse(response) {
  if(!response||typeof response!=='object'||Array.isArray(response)
      ||JSON.stringify(Object.keys(response).sort())!==JSON.stringify([...admissionFields].sort())
      ||response.schema_version!==1 || response.accepted!==true
      || !HEX32.test(response.candidate_id) || /^0+$/.test(response.candidate_id)
      || response.state!=='queued')
    throw new Error('DOM node returned an invalid issuance admission receipt');
  return response;
}

export function validatePersistedIssuanceSubmission(receipt,{binding,identity}) {
  const expectedKeys=['amountBaseUnits','broadcastsEthereum','candidateId','depositId',
    'domChainId','domGenesisHash','mined','noteCommitment','observedTipHash',
    'observedTipHeight','schema','state','submittedAt','witnessSha256'].sort();
  if(!receipt || typeof receipt!=='object' || Array.isArray(receipt)
      || JSON.stringify(Object.keys(receipt).sort())!==JSON.stringify(expectedKeys)
      || receipt.schema!=='usdom-finalized-deposit-issuance-submission-v1'
      || receipt.depositId!==binding.depositId
      || receipt.witnessSha256!==binding.witnessSha256
      || receipt.amountBaseUnits!==binding.amountBaseUnits
      || receipt.noteCommitment!==binding.noteCommitment
      || !/^0x[0-9a-f]{64}$/.test(receipt.candidateId)
      || receipt.candidateId===`0x${'0'.repeat(64)}`
      || receipt.state!=='queued' || receipt.mined!==false
      || receipt.broadcastsEthereum!==false
      || receipt.domChainId!==`0x${identity.chain_id}`
      || receipt.domGenesisHash!==`0x${identity.genesis_hash}`
      || !uint64(receipt.observedTipHeight)
      || BigInt(receipt.observedTipHeight)>BigInt(identity.tip_height)
      || !/^0x[0-9a-f]{64}$/.test(receipt.observedTipHash)
      || (BigInt(receipt.observedTipHeight)===BigInt(identity.tip_height)
        &&receipt.observedTipHash!==`0x${identity.tip_hash}`)
      || typeof receipt.submittedAt!=='string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.submittedAt)
      || !Number.isFinite(Date.parse(receipt.submittedAt))
      || new Date(receipt.submittedAt).toISOString()!==receipt.submittedAt) {
    throw new Error('persisted issuance submission does not bind the exact deposit and DOM chain');
  }
  return receipt;
}
