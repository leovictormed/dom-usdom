import {createHash} from 'node:crypto';

const HEX32=/^[0-9a-f]{64}$/;
const DECIMAL=/^(0|[1-9][0-9]*)$/;
const BN254_SCALAR_FIELD=BigInt(
  '0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001',
);

function canonicalScalar(value) {
  return HEX32.test(value) && !/^0+$/.test(value) && BigInt(`0x${value}`)<BN254_SCALAR_FIELD;
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function validateFinalizedDepositIssuance({index,registration,witness,manifestSha256}) {
  if(!Buffer.isBuffer(witness) || witness.length===0 || witness.length>4*1024*1024)
    throw new Error('finalized deposit witness is outside its canonical size bound');
  if(!HEX32.test(manifestSha256)) throw new Error('native manifest SHA-256 is invalid');
  const witnessSha256=sha256Hex(witness);
  if(index?.schema!=='usdom-finalized-deposit-witness-v1'
      || index.native_manifest_sha256!==manifestSha256
      || index.witness_sha256!==witnessSha256
      || index.witness_file!=='finalized-deposit-witness.bin'
      || index.witness_bytes!==witness.length
      || index.witness_verified!==true || index.relation_executed!==true
      || index.broadcasts!==false || index.mines!==false
      || index.amount_base_units!=='1000000'
      || !/^0x[0-9a-f]{64}$/.test(index.deposit_id)
      || !/^0x[0-9a-f]{64}$/.test(index.receiving_commitment)
      || !canonicalScalar(index.receiving_commitment.slice(2)))
    throw new Error('witness index does not bind the exact verified closed deposit');
  if(registration?.schema!=='usdom-expected-deposit-registration-v1'
      || registration.native_manifest_sha256!==manifestSha256
      || registration.witness_sha256!==witnessSha256
      || registration.deposit_id!==index.deposit_id.slice(2)
      || registration.amount_base_units!=='1000000'
      || registration.receiving_commitment!==index.receiving_commitment.slice(2)
      || !canonicalScalar(registration.receiving_commitment)
      || !canonicalScalar(registration.note_commitment)
      || !/^[0-9a-f]{208}$/.test(registration.wallet_address)
      || !DECIMAL.test(registration.registered_tip_height)
      || !HEX32.test(registration.registered_tip_hash)
      || registration.snapshot_generation!=='1'
      || !/^[0-9a-f]{96}$/.test(registration.snapshot_seal)
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
  if(identity?.rpc_api_version!==1 || !Number.isSafeInteger(identity.protocol_version)
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
  if(response?.schema_version!==1 || response.accepted!==true
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
      || !DECIMAL.test(receipt.observedTipHeight)
      || !/^0x[0-9a-f]{64}$/.test(receipt.observedTipHash)
      || typeof receipt.submittedAt!=='string'
      || !Number.isFinite(Date.parse(receipt.submittedAt))) {
    throw new Error('persisted issuance submission does not bind the exact deposit and DOM chain');
  }
  return receipt;
}
