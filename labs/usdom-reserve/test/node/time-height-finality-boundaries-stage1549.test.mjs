import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {safeJsonUint} from '../../sdk/safe-json-integer.mjs';
import {closedMainnetBurnScanRequest} from '../../sdk/closed-mainnet-burn-block.mjs';

test('external uints cross the JSON number boundary fail closed without precision loss',()=>{
  assert.equal(safeJsonUint('9007199254740991','height'),Number.MAX_SAFE_INTEGER);
  for(const value of ['9007199254740992','01','0x01','-1',1.5,Number.MAX_SAFE_INTEGER+1]) {
    assert.throws(()=>safeJsonUint(value,'height'));
  }
  assert.equal(safeJsonUint('0xffffffff','index',{bits:32}),0xffffffff);
  assert.throws(()=>safeJsonUint('0x100000000','index',{bits:32}));
});

test('DOM scan request rejects heights that its JSON numeric wire format cannot preserve',()=>{
  const base={domNetworkMagic:1,domChainId:'0x'+'11'.repeat(32),transitionId:'22'.repeat(32),blockHash:'0x'+'33'.repeat(32),parentHash:'0x'+'44'.repeat(32)};
  assert.equal(closedMainnetBurnScanRequest({...base,parentHeight:'8',blockHeight:'9'}).start_height,9);
  assert.throws(()=>closedMainnetBurnScanRequest({...base,parentHeight:'9007199254740991',blockHeight:'9007199254740992'}));
});

test('checkpoint witness collector guards every BigInt-to-JSON-number boundary',()=>{
  const source=readFileSync('scripts/collect-authenticated-checkpoint-witness-source.mjs','utf8');
  for(const label of ['Beacon signature slot','transaction index','checkpoint block number','registry account nonce']) {
    assert.match(source,new RegExp(`safeJsonUint\\([^\\n]+${label}`));
  }
  assert.doesNotMatch(source,/Number\((?:BigInt\()?finality\.signature_slot/);
  assert.doesNotMatch(source,/block_number:Number\(/);
  assert.doesNotMatch(source,/nonce:Number\(/);
});

test('consensus uses inclusive freshness bounds, checked overflow and an exclusive Gloas horizon',()=>{
  const finality=readFileSync('../usdom-ethereum-finality/src/lib.rs','utf8');
  const portable=readFileSync('../../crates/dom-usdom-checkpoint-program/src/portable.rs','utf8');
  assert.match(finality,/checked_add\(maximum_age_seconds\)/);
  assert.match(finality,/finalized_timestamp <= latest_future/);
  assert.match(finality,/epoch < forks\.gloas\.epoch/);
  assert.match(finality,/after\.beacon_slot >= before\.beacon_slot/);
  assert.match(portable,/checked_sub\(ETHEREUM_MAINNET_GENESIS_TIME\)/);
});
