import test from 'node:test';
import assert from 'node:assert/strict';
import {parseProverResourceMetrics} from '../../sdk/prover-resource-metrics.mjs';

const log=({elapsed='1:02:03.45',resident='2097152',status='0'}={})=>`
 Command being timed: "fixed prover"
 Elapsed (wall clock) time (h:mm:ss or m:ss): ${elapsed}
 Maximum resident set size (kbytes): ${resident}
 Exit status: ${status}
`;

test('GNU time metrics are parsed into canonical bounded values',()=>{
  assert.deepEqual(parseProverResourceMetrics(log()),{
    provingWallMilliseconds:'3723450',peakResidentKiB:'2097152',
  });
  assert.deepEqual(parseProverResourceMetrics(log({elapsed:'0:00.01'})),{
    provingWallMilliseconds:'10',peakResidentKiB:'2097152',
  });
});

test('resource metrics reject failures, missing fields and unbounded values',()=>{
  for(const value of [
    log({status:'1'}),log({elapsed:'0:00'}),log({elapsed:'31:00:00:00'}),
    log({elapsed:'1:60.00'}),log({elapsed:'1.5:00'}),log({elapsed:'0:00.0001'}),
    log({elapsed:`${'9'.repeat(10000)}:00.00`}),
    log({resident:'0'}),log({resident:String(64*1024*1024+1)}),
    log({resident:'9'.repeat(10000)}),
    log().replace('Maximum resident set size (kbytes):','resident:'),
    'x'.repeat(64*1024+1),null,
  ]) assert.throws(()=>parseProverResourceMetrics(value));
});
