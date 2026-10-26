const hash=/^0x[0-9a-f]{64}$/;
export function classifyPilotNonce(expected,finalizedA,pendingA,finalizedB,pendingB,
  expectedHash='',observedHashA='',observedHashB='') {
  for(const [label,value] of [['expected',expected],['finalizedA',finalizedA],['pendingA',pendingA],
    ['finalizedB',finalizedB],['pendingB',pendingB]]) {
    if(typeof value!=='string'||!/^(0|[1-9][0-9]*)$/.test(value)||BigInt(value)>2n**64n-1n) {
      throw new Error(`${label} nonce is not canonical uint64`);
    }
  }
  if(finalizedA!==finalizedB||pendingA!==pendingB) throw new Error('RPC finalized/pending nonces disagree');
  if(finalizedA===expected&&pendingA===expected) return 'publish';
  const successor=(BigInt(expected)+1n).toString();
  if((finalizedA===expected||finalizedA===successor)&&pendingA===successor) {
    const normalized=String(expectedHash).toLowerCase();
    if(!hash.test(normalized)||String(observedHashA).toLowerCase()!==normalized
        ||String(observedHashB).toLowerCase()!==normalized) {
      throw new Error('nonce successor is not the exact known raw transaction');
    }
    return 'recover-receipt';
  }
  throw new Error('nonce consumed by an unrelated or ambiguous transaction');
}
