import test from 'node:test';
import assert from 'node:assert/strict';
import {readAuthenticatedPendingQueue} from '../../sdk/pending-queue-monitor.mjs';

const h=n=>'0x'+Number(n).toString(16).padStart(64,'0');
const zero=h(0);
const snapshot={epoch:'7',count:'2',amount:'30',firstBurnId:h(1),lastBurnId:h(2)};
const entries=new Map([
  [h(1),{statementHash:h(11),amount:'10',queueEpoch:'7',previous:zero,next:h(2)}],
  [h(2),{statementHash:h(12),amount:'20',queueEpoch:'7',previous:h(1),next:zero}],
]);

test('off-chain queue traversal authenticates links, totals and stable boundary snapshots',async()=>{
  const value=await readAuthenticatedPendingQueue({readSnapshot:async()=>snapshot,readPending:async id=>entries.get(id),maximumEntries:1000});
  assert.deepEqual(value.entries.map(row=>row.burnId),[h(1),h(2)]);
});

test('off-chain queue traversal fails closed on cycle, total drift and snapshot drift',async()=>{
  const cycle=new Map(entries); cycle.set(h(2),{...cycle.get(h(2)),next:h(1)});
  await assert.rejects(readAuthenticatedPendingQueue({readSnapshot:async()=>snapshot,readPending:async id=>cycle.get(id),maximumEntries:1000}),/cycle/);
  await assert.rejects(readAuthenticatedPendingQueue({readSnapshot:async()=>({...snapshot,amount:'31'}),readPending:async id=>entries.get(id),maximumEntries:1000}),/totals/);
  let reads=0;
  await assert.rejects(readAuthenticatedPendingQueue({readSnapshot:async()=>reads++?{...snapshot,epoch:'8'}:snapshot,
    readPending:async id=>entries.get(id),maximumEntries:1000}),/changed while monitored/);
});

test('off-chain traversal observes more than one former 256-entry page and catches a cross-boundary cycle',async()=>{
  const many=new Map();
  for(let i=1;i<=300;i++) many.set(h(i),{statementHash:h(1000+i),amount:'1',queueEpoch:'9',
    previous:i===1?zero:h(i-1),next:i===300?zero:h(i+1)});
  const header={epoch:'9',count:'300',amount:'300',firstBurnId:h(1),lastBurnId:h(300)};
  const value=await readAuthenticatedPendingQueue({readSnapshot:async()=>header,readPending:async id=>many.get(id),maximumEntries:300});
  assert.equal(value.entries.length,300);
  many.set(h(257),{...many.get(h(257)),next:h(1)});
  await assert.rejects(readAuthenticatedPendingQueue({readSnapshot:async()=>header,readPending:async id=>many.get(id),maximumEntries:300}),/cycle/);
});
