import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CHECKPOINT_CONTEXT_BYTES,
  checkpointEconomicStateRoot,
  checkpointContext,
  requiredHistoricalSeedHeights,
} from '../../sdk/checkpoint-context.mjs';

const hash=byte=>'0x'+byte.toString(16).padStart(2,'0').repeat(32);

function vector() {
  const recentHeaders=Array.from({length:11},(_,index)=>({
    height:String(4040+index),block:hash(index+1),timestamp:String(1_700_000_000+index),
  }));
  return {checkpointHeight:'4050',checkpointBlock:hash(11),maxSpan:'390',economicStateRoot:hash(130),recentHeaders,
    seedAnchors:[{height:'1984',block:hash(128)},{height:'4032',block:hash(129)}]};
}

test('UDCCTX02 matches the frozen Rust continuation-context vector',()=>{
  const result=checkpointContext(vector());
  assert.equal((result.encoded.length-2)/2,CHECKPOINT_CONTEXT_BYTES);
  assert.equal(result.contextHash,'0x7bb5a7a3b2cfb770abe46d3c2050fc42429246b71acf0ed27523711ad24d1c80');
  assert.deepEqual(requiredHistoricalSeedHeights('4050','390'),[1984n,4032n]);
});

test('economic state root binds ordered UTXO and kernel roots',()=>{
  assert.equal(checkpointEconomicStateRoot(hash(131),hash(132)),
    '0x92b53aa48ec606fdff0e2159cd11ba2651de6d3c2ac6146092d3712a77e3e50f');
  assert.notEqual(checkpointEconomicStateRoot(hash(131),hash(132)),
    checkpointEconomicStateRoot(hash(132),hash(131)));
  assert.throws(()=>checkpointEconomicStateRoot(hash(0),hash(132)));
});

test('checkpoint context rejects ambiguous history and incorrect RandomX authority',()=>{
  const base=vector();
  const cases=[
    {...base,extra:true},
    {...base,checkpointBlock:hash(12)},
    {...base,maxSpan:'0'},
    {...base,recentHeaders:base.recentHeaders.slice(1)},
    {...base,recentHeaders:base.recentHeaders.map((header,index)=>index===5?{...header,height:'1'}:header)},
    {...base,recentHeaders:base.recentHeaders.map((header,index)=>index===5?{...header,timestamp:'1'}:header)},
    {...base,seedAnchors:base.seedAnchors.slice(1)},
    {...base,seedAnchors:base.seedAnchors.map((anchor,index)=>index===1?{...anchor,height:'4031'}:anchor)},
  ];
  for(const value of cases) assert.throws(()=>checkpointContext(value));

  const overlapping={checkpointHeight:'1993',checkpointBlock:hash(11),maxSpan:'100',
    economicStateRoot:hash(130),
    recentHeaders:Array.from({length:11},(_,index)=>({height:String(1983+index),block:hash(index+1),
      timestamp:String(1_700_000_000+index)})),seedAnchors:[{height:'1984',block:hash(99)}]};
  assert.throws(()=>checkpointContext(overlapping),/disagrees/);
});
