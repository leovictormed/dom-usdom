const hex32=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{64}$/.test(value);
const raw32=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const uint=value=>typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value);

/** Pure offline reconciliation of durable pilot artifacts and observed terminal facts. */
export function reconcileClosedMainnetPilotDag(state) {
  if(!state||typeof state!=='object'||Array.isArray(state)) throw new Error('pilot DAG state required');
  const status=[];
  const deposit=state.deposit;
  if(!deposit) status.push({phase:'deposit',status:'missing'});
  else {
    if(!raw32(deposit.packageSha256)||deposit.amountBaseUnits!=='1000000'
        ||deposit.broadcastAuthorized!==false||!uint(deposit.baseNonce)
        ||!Array.isArray(deposit.receipts)||deposit.receipts.length>3) {
      throw new Error('deposit package is foreign or malformed');
    }
    if(deposit.receipts.some(receipt=>receipt.canonical===null)) {
      status.push({phase:'deposit',status:'finality-recheck-required'});
    }
    else if(deposit.receipts.length!==0&&deposit.receipts.length!==3) status.push({phase:'deposit',status:'resumable'});
    else if(deposit.receipts.length===0) status.push({phase:'deposit',status:'prepared'});
    else {
      for(let i=0;i<3;i++) {
        const receipt=deposit.receipts[i];
        if(receipt.nonce!==(BigInt(deposit.baseNonce)+BigInt(i)).toString()
            ||receipt.finalizedRpcCount!==2||receipt.canonical!==true) throw new Error('deposit receipt is stale/reorged');
      }
      if(deposit.pendingNonce!==(BigInt(deposit.baseNonce)+3n).toString()) throw new Error('deposit nonce was consumed by foreign transaction');
      if(deposit.allowanceAfter!=='0') throw new Error('deposit left residual allowance');
      status.push({phase:'deposit',status:'complete'});
    }
  }
  const redemption=state.redemption;
  if(!redemption) status.push({phase:'redemption',status:'missing'});
  else {
    if(!deposit||status.at(-1)?.phase==='deposit'&&status.at(-1).status!=='complete') {
      throw new Error('redemption cannot precede completed deposit');
    }
    if(!raw32(redemption.packageSha256)||redemption.amountBaseUnits!=='1000000'
        ||redemption.broadcastAuthorized!==false||!hex32(redemption.burnId)||!hex32(redemption.requestId)
        ||!uint(redemption.baseNonce)||!Array.isArray(redemption.receipts)||redemption.receipts.length>2) {
      throw new Error('redemption package is foreign or malformed');
    }
    if(redemption.receipts.length===2&&redemption.receipts.some(receipt=>receipt.canonical===null)) {
      status.push({phase:'redemption',status:'finality-recheck-required'});
    }
    else if(redemption.receipts.length===0) status.push({phase:'redemption',status:'prepared'});
    else if(redemption.receipts.length===1) {
      const receipt=redemption.receipts[0];
      if(receipt.canonical===null) status.push({phase:'redemption',status:'finality-recheck-required'});
      else if(receipt.nonce!==redemption.baseNonce||receipt.finalizedRpcCount!==2||receipt.canonical!==true) {
        throw new Error('queue receipt is stale/reorged');
      }
      if(redemption.pendingNonce!==(BigInt(redemption.baseNonce)+1n).toString()) throw new Error('queue nonce was consumed by foreign transaction');
      if(redemption.paidBurn===true||redemption.paidRequest===true) throw new Error('payout already paid before planned execute');
      if(receipt.canonical!==null) status.push({phase:'redemption',status:'waiting-delay'});
    } else {
      for(let i=0;i<2;i++) {
        const receipt=redemption.receipts[i];
        if(receipt.nonce!==(BigInt(redemption.baseNonce)+BigInt(i)).toString()
            ||receipt.finalizedRpcCount!==2||receipt.canonical!==true) throw new Error('redemption receipt is stale/reorged');
      }
      if(redemption.pendingNonce!==(BigInt(redemption.baseNonce)+2n).toString()) throw new Error('redemption nonce was consumed by foreign transaction');
      if(redemption.paidBurn!==true||redemption.paidRequest!==true) throw new Error('payout terminal state is absent');
      status.push({phase:'redemption',status:'complete'});
    }
  }
  return {schema:'usdom-closed-mainnet-pilot-dag/v1',broadcastAuthorized:false,phases:status};
}
