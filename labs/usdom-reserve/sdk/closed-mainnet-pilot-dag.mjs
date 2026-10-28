const hex32=value=>typeof value==='string'&&/^0x[0-9a-f]{64}$/.test(value);
const raw32=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const uint64=value=>typeof value==='string'&&value.length<=20
  &&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<1n<<64n;
const uint256=value=>typeof value==='string'&&value.length<=78
  &&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<1n<<256n;
const baseNonce=(value,reserved)=>uint64(value)&&BigInt(value)<=((1n<<64n)-1n-BigInt(reserved));
const depositFields=['packageSha256','amountBaseUnits','broadcastAuthorized','baseNonce','receipts',
  'pendingNonce','allowanceAfter'];
const redemptionFields=['packageSha256','amountBaseUnits','broadcastAuthorized','burnId','requestId',
  'baseNonce','receipts','pendingNonce','paidBurn','paidRequest'];
function exact(value,fields) {
  return value&&typeof value==='object'&&!Array.isArray(value)
    &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...fields].sort());
}
function validateReceiptPrefix(receipts,base,label) {
  for(let index=0;index<receipts.length;index++) {
    const receipt=receipts[index];
    if(!receipt||typeof receipt!=='object'||Array.isArray(receipt)
        ||JSON.stringify(Object.keys(receipt).sort())!==JSON.stringify(
          ['canonical','finalizedRpcCount','nonce'].sort())
        ||receipt.nonce!==(BigInt(base)+BigInt(index)).toString()) {
      throw new Error(`${label} receipt sequence is stale or malformed`);
    }
    if(receipt.canonical===null) {
      if(receipt.finalizedRpcCount!==0) throw new Error(`${label} pending finality state is malformed`);
    } else if(receipt.canonical!==true||receipt.finalizedRpcCount!==2) {
      throw new Error(`${label} receipt is stale/reorged`);
    }
  }
}

/** Pure offline reconciliation of durable pilot artifacts and observed terminal facts. */
export function reconcileClosedMainnetPilotDag(state) {
  if(!state||typeof state!=='object'||Array.isArray(state)) throw new Error('pilot DAG state required');
  if(Object.keys(state).some(key=>key!=='deposit'&&key!=='redemption')) {
    throw new Error('pilot DAG state schema is not exact');
  }
  const status=[];
  const hasDeposit=Object.hasOwn(state,'deposit'),deposit=state.deposit;
  if(!hasDeposit) status.push({phase:'deposit',status:'missing'});
  else {
    if(!exact(deposit,depositFields)||!raw32(deposit.packageSha256)||deposit.amountBaseUnits!=='1000000'
        ||deposit.broadcastAuthorized!==false||!baseNonce(deposit.baseNonce,3)
        ||!uint64(deposit.pendingNonce)||!Array.isArray(deposit.receipts)||deposit.receipts.length>3
        ||deposit.receipts.some(receipt=>!uint64(receipt?.nonce))||!uint256(deposit.allowanceAfter)) {
      throw new Error('deposit package is foreign or malformed');
    }
    validateReceiptPrefix(deposit.receipts,deposit.baseNonce,'deposit');
    if(deposit.pendingNonce!==(BigInt(deposit.baseNonce)+BigInt(deposit.receipts.length)).toString()) {
      throw new Error('deposit nonce was consumed by foreign transaction');
    }
    if(deposit.allowanceAfter!=='0') throw new Error('deposit left residual allowance');
    if(deposit.receipts.some(receipt=>receipt.canonical===null)) {
      status.push({phase:'deposit',status:'finality-recheck-required'});
    }
    else if(deposit.receipts.length!==0&&deposit.receipts.length!==3) status.push({phase:'deposit',status:'resumable'});
    else if(deposit.receipts.length===0) status.push({phase:'deposit',status:'prepared'});
    else {
      status.push({phase:'deposit',status:'complete'});
    }
  }
  const hasRedemption=Object.hasOwn(state,'redemption'),redemption=state.redemption;
  if(!hasRedemption) status.push({phase:'redemption',status:'missing'});
  else {
    if(!deposit||status.at(-1)?.phase==='deposit'&&status.at(-1).status!=='complete') {
      throw new Error('redemption cannot precede completed deposit');
    }
    if(!exact(redemption,redemptionFields)||!raw32(redemption.packageSha256)||redemption.amountBaseUnits!=='1000000'
        ||redemption.broadcastAuthorized!==false||!hex32(redemption.burnId)||!hex32(redemption.requestId)
        ||!baseNonce(redemption.baseNonce,2)||!uint64(redemption.pendingNonce)
        ||!Array.isArray(redemption.receipts)||redemption.receipts.length>2
        ||redemption.receipts.some(receipt=>!uint64(receipt?.nonce))
        ||typeof redemption.paidBurn!=='boolean'||typeof redemption.paidRequest!=='boolean') {
      throw new Error('redemption package is foreign or malformed');
    }
    validateReceiptPrefix(redemption.receipts,redemption.baseNonce,'redemption');
    if(redemption.pendingNonce!==(BigInt(redemption.baseNonce)+BigInt(redemption.receipts.length)).toString()) {
      throw new Error('redemption nonce was consumed by foreign transaction');
    }
    const redemptionTerminal=redemption.receipts.length===2
      &&redemption.receipts.every(receipt=>receipt.canonical===true);
    if(!redemptionTerminal&&(redemption.paidBurn!==false||redemption.paidRequest!==false)) {
      throw new Error('payout already paid before terminal finalized receipts');
    }
    if(redemption.receipts.length===2&&redemption.receipts.some(receipt=>receipt.canonical===null)) {
      status.push({phase:'redemption',status:'finality-recheck-required'});
    }
    else if(redemption.receipts.length===0) status.push({phase:'redemption',status:'prepared'});
    else if(redemption.receipts.length===1) {
      const receipt=redemption.receipts[0];
      if(receipt.canonical===null) status.push({phase:'redemption',status:'finality-recheck-required'});
      if(receipt.canonical!==null) status.push({phase:'redemption',status:'waiting-delay'});
    } else {
      if(redemption.paidBurn!==true||redemption.paidRequest!==true) throw new Error('payout terminal state is absent');
      status.push({phase:'redemption',status:'complete'});
    }
  }
  return {schema:'usdom-closed-mainnet-pilot-dag/v1',broadcastAuthorized:false,phases:status};
}
