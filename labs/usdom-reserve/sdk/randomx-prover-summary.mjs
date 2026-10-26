const rawHash=/^[0-9a-f]{64}$/;

/** Parse the bounded stdout emitted only after the RandomX host has verified
 * every succinct receipt and durably published its final index. */
export function parseRandomxProverSummary(text) {
  if(typeof text!=='string' || Buffer.byteLength(text)>4096 || text.includes('\r')
      || text.includes('\0')) throw new Error('invalid RandomX prover summary transport');
  const match=text.match(/^status: proved-and-verified\nreceipt_count: ([1-9][0-9]{0,3})\njob_index_sha256: ([0-9a-f]{64})\nreceipt_index_sha256: ([0-9a-f]{64})\nreceipt_kind: succinct\ndev_mode: false\nmines: false\n$/);
  if(!match || !rawHash.test(match[2]) || !rawHash.test(match[3])
      || match[2]==='0'.repeat(64) || match[3]==='0'.repeat(64)) {
    throw new Error('RandomX prover did not emit one exact verified summary');
  }
  const receiptCount=Number(match[1]);
  if(!Number.isSafeInteger(receiptCount) || receiptCount<1 || receiptCount>720) {
    throw new Error('RandomX prover receipt count is outside the consensus bound');
  }
  return Object.freeze({receiptCount,jobIndexSha256:match[2],receiptIndexSha256:match[3]});
}

export function reconcileRandomxProverSummary(summary,observed) {
  if(!summary || !observed || summary.receiptCount!==observed.receiptCount
      || summary.jobIndexSha256!==observed.jobIndexSha256
      || summary.receiptIndexSha256!==observed.receiptIndexSha256) {
    throw new Error('RandomX receipt graph changed after cryptographic verification');
  }
  return true;
}
