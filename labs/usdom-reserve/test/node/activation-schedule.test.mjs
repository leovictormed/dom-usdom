import test from 'node:test';
import assert from 'node:assert/strict';
import {activationSchedule} from '../../sdk/activation-schedule.mjs';

const hash=byte=>'0x'+byte.repeat(32);

test('UDACTV01 encoding and tagged BLAKE2b commitment match the Rust consensus vector',()=>{
  const schedule=activationSchedule({networkMagic:'1146047793',chainId:hash('02'),
    firstV4Height:'100000',emptyStateRoot:hash('44')});
  assert.equal(schedule.bytes,
    '0x55444143545630310001444f4d31020202020202020202020202020202020202020202020202020202020202020200000000000186a04444444444444444444444444444444444444444444444444444444444444444');
  assert.equal(schedule.commitment,'0x18e9a8c742efbc9601f49a16405a958a8b2e57da1f8691412ae8e0d7ac1fd4a4');
});

test('activation schedule rejects unknown networks, zero fields and ambiguous objects',()=>{
  const base={networkMagic:'1146047793',chainId:hash('02'),firstV4Height:'100000',emptyStateRoot:hash('44')};
  for(const changed of [
    {...base,networkMagic:'1'},{...base,chainId:hash('00')},{...base,firstV4Height:'0'},
    {...base,emptyStateRoot:hash('00')},{...base,extra:true},
  ]) assert.throws(()=>activationSchedule(changed));
});
