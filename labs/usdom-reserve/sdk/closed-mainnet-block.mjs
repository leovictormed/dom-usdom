const HEX32=/^[0-9a-f]{64}$/;
const exact=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...fields].sort());
const mineFields=['schema_version','count','height','block_hash','initialized_genesis'];
const submissionFields=['schema','amountBaseUnits','broadcastsEthereum','candidateId','depositId',
  'domChainId','domGenesisHash','mined','noteCommitment','observedTipHash','observedTipHeight',
  'state','submittedAt','witnessSha256'];
const blockFields=['schema','candidateId','depositId','parentHeight','parentHash','blockHeight',
  'blockHash','domChainId','domGenesisHash','exactlyOneBlock','continuousMining',
  'issuanceObserved','producedAt'];
const uint64=value=>typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value)
  &&BigInt(value)<(1n<<64n);
const iso=value=>typeof value==='string'
  &&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  &&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;

export function closedMainnetMineRequest(identity) {
  if(identity===null) return Object.freeze({expected_tip_height:0,expected_tip_hash:'0'.repeat(64)});
  if(identity?.network!=='mainnet' || identity.network_magic!=='444f4d31'
      || !Number.isSafeInteger(identity.tip_height) || identity.tip_height<0
      || !HEX32.test(identity.tip_hash) || /^0+$/.test(identity.tip_hash))
    throw new Error('invalid closed Mainnet identity');
  return Object.freeze({
    expected_tip_height:identity.tip_height,
    expected_tip_hash:identity.tip_hash
  });
}

export function validateClosedMainnetMineResponse(response,request) {
  const genesis=request.expected_tip_height===0 && /^0{64}$/.test(request.expected_tip_hash);
  const expectedHeight=genesis?0:request.expected_tip_height+1;
  if(!exact(response,mineFields)||response.schema_version!==1 || response.count!==1
      || response.height!==expectedHeight || !HEX32.test(response.block_hash)
      || /^0+$/.test(response.block_hash)
      || response.initialized_genesis!==genesis)
    throw new Error('invalid exactly-one-block response');
  return Object.freeze(response);
}

export function validateQueuedIssuanceReceipt(receipt,identity) {
  if(!exact(receipt,submissionFields)
      ||receipt.schema!=='usdom-finalized-deposit-issuance-submission-v1'
      || receipt.state!=='queued' || receipt.mined!==false
      || !/^0x[0-9a-f]{64}$/.test(receipt.candidateId)
      || !/^0x[0-9a-f]{64}$/.test(receipt.depositId)
      || !/^[0-9a-f]{64}$/.test(receipt.witnessSha256)
      || receipt.amountBaseUnits!=='1000000'
      || !/^0x[0-9a-f]{64}$/.test(receipt.noteCommitment)
      ||receipt.candidateId===`0x${'0'.repeat(64)}`
      ||receipt.depositId===`0x${'0'.repeat(64)}`||receipt.noteCommitment===`0x${'0'.repeat(64)}`
      || receipt.domChainId!==`0x${identity.chain_id}`
      || receipt.domGenesisHash!==`0x${identity.genesis_hash}`
      || receipt.observedTipHeight!==String(identity.tip_height)
      || receipt.observedTipHash!==`0x${identity.tip_hash}`
      || receipt.broadcastsEthereum!==false||!iso(receipt.submittedAt))
    throw new Error('queued issuance does not bind the current closed Mainnet tip');
  return receipt;
}

export function validatePersistedIssuanceBlock(receipt,submission,identity) {
  if(!exact(receipt,blockFields)||receipt.schema!=='usdom-closed-mainnet-issuance-block-v1'
      || receipt.candidateId!==submission.candidateId || receipt.depositId!==submission.depositId
      || receipt.parentHeight!==submission.observedTipHeight
      || receipt.parentHash!==submission.observedTipHash
      || receipt.domChainId!==submission.domChainId
      || receipt.domGenesisHash!==submission.domGenesisHash
      || receipt.blockHeight!==String(identity.tip_height)
      ||!uint64(receipt.parentHeight)||!uint64(receipt.blockHeight)
      ||BigInt(receipt.blockHeight)!==BigInt(receipt.parentHeight)+1n
      || receipt.blockHash!==`0x${identity.tip_hash}`
      || receipt.domChainId!==`0x${identity.chain_id}`
      || receipt.domGenesisHash!==`0x${identity.genesis_hash}`
      || receipt.exactlyOneBlock!==true || receipt.continuousMining!==false
      || receipt.issuanceObserved!==false
      ||!iso(receipt.producedAt))
    throw new Error('persisted issuance block is stale or does not bind the exact issuance');
  return receipt;
}
