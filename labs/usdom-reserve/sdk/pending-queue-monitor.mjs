const ZERO='0x'+'00'.repeat(32);
const HASH=/^0x[0-9a-fA-F]{64}$/;

function normalizedSnapshot(value) {
  if(!value||typeof value!=='object') throw new Error('pending queue snapshot is invalid');
  const result={epoch:BigInt(value.epoch),count:BigInt(value.count),amount:BigInt(value.amount),
    firstBurnId:String(value.firstBurnId).toLowerCase(),lastBurnId:String(value.lastBurnId).toLowerCase()};
  if(!HASH.test(result.firstBurnId)||!HASH.test(result.lastBurnId)||result.epoch<1n
      ||result.count<0n||result.amount<0n) throw new Error('pending queue snapshot is invalid');
  return result;
}

/** Traverse the public linked-list getters at one caller-pinned block. A
 * snapshot before and after the walk rejects providers that ignore blockTag or
 * any concurrent/drifting observation. */
export async function readAuthenticatedPendingQueue({readSnapshot,readPending,maximumEntries}) {
  if(typeof readSnapshot!=='function'||typeof readPending!=='function'
      ||!Number.isSafeInteger(maximumEntries)||maximumEntries<1||maximumEntries>1_000_000) {
    throw new Error('pending queue reader input is invalid');
  }
  const before=normalizedSnapshot(await readSnapshot());
  if(before.count>BigInt(maximumEntries)) throw new Error('pending queue exceeds configured release capacity');
  if(before.count===0n) {
    if(before.amount!==0n||before.firstBurnId!==ZERO||before.lastBurnId!==ZERO) throw new Error('empty pending queue header is inconsistent');
  } else if(before.amount===0n||before.firstBurnId===ZERO||before.lastBurnId===ZERO) {
    throw new Error('nonempty pending queue header is inconsistent');
  }
  const entries=[]; const seen=new Set(); let id=before.firstBurnId; let sum=0n; let previous=ZERO;
  while(id!==ZERO) {
    if(entries.length>=maximumEntries||seen.has(id)) throw new Error('pending queue cycle or bound exceeded');
    seen.add(id);
    const value=await readPending(id);
    if(!value||typeof value!=='object') throw new Error('pending queue entry is invalid');
    const entry={burnId:id,statementHash:String(value.statementHash).toLowerCase(),amount:BigInt(value.amount),
      queueEpoch:BigInt(value.queueEpoch),previous:String(value.previous).toLowerCase(),next:String(value.next).toLowerCase()};
    if(!HASH.test(entry.statementHash)||entry.statementHash===ZERO||entry.amount<=0n
        ||entry.queueEpoch!==before.epoch||entry.previous!==previous||!HASH.test(entry.next)) {
      throw new Error('pending queue linkage is invalid');
    }
    entries.push(entry); sum+=entry.amount; previous=id; id=entry.next;
  }
  if(BigInt(entries.length)!==before.count||sum!==before.amount
      ||(entries.length?entries.at(-1).burnId:ZERO)!==before.lastBurnId) throw new Error('pending queue totals are inconsistent');
  const after=normalizedSnapshot(await readSnapshot());
  if(JSON.stringify(Object.fromEntries(Object.entries(before).map(([k,v])=>[k,String(v)])))
      !==JSON.stringify(Object.fromEntries(Object.entries(after).map(([k,v])=>[k,String(v)])))) {
    throw new Error('pending queue changed while monitored; retry at one pinned block');
  }
  return Object.freeze({snapshot:Object.freeze(before),entries:Object.freeze(entries.map(Object.freeze))});
}
