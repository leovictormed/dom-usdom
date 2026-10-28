import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildFinalizedDepositSourceCatalog,matchFinalizedDepositSourceCatalog,
  reconcileFinalizedDepositObservations,
} from '../../sdk/finalized-deposit-source-catalog.mjs';

const runtime=[
  {operatorId:'operator_a',executionUrl:'https://exec-a.example/key-a',beaconUrl:'https://beacon-a.example/key-a'},
  {operatorId:'operator_b',executionUrl:'https://exec-b.example/key-b',beaconUrl:'https://beacon-b.example/key-b'},
];

test('catalog binds independent origins without persisting URL paths or secrets',()=>{
  const catalog=buildFinalizedDepositSourceCatalog(runtime);
  const encoded=JSON.stringify(catalog);
  assert.equal(encoded.includes('key-a'),false);
  assert.deepEqual(matchFinalizedDepositSourceCatalog(catalog,[...runtime].reverse()).map(x=>x.operatorId),
    ['operator_a','operator_b']);
  assert.throws(()=>matchFinalizedDepositSourceCatalog(catalog,[runtime[0],{
    ...runtime[1],executionUrl:'https://wrong.example/key-b',
  }]),/do not match catalog/);
});

test('catalog rejects duplicate infrastructure and fewer than two operators',()=>{
  assert.throws(()=>buildFinalizedDepositSourceCatalog([runtime[0]]),/catalog is invalid/);
  assert.throws(()=>buildFinalizedDepositSourceCatalog([runtime[0],{
    ...runtime[1],executionUrl:'https://exec-a.example/different-secret',
  }]),/independent/);
  assert.throws(()=>buildFinalizedDepositSourceCatalog([
    {...runtime[0],executionUrl:'https://shared.example:443/key-a'},
    {...runtime[1],executionUrl:'https://shared.example:444/key-b'},
  ]),/independent execution and Beacon hostnames/);
  assert.throws(()=>buildFinalizedDepositSourceCatalog([
    {...runtime[0],beaconUrl:'https://127.0.0.1/key-a'},runtime[1],
  ]),/public DNS hostname/);
});

test('observation consensus fails closed on any mutation',()=>{
  const observation={receipt:{blockHash:'0x01'},finality:{slot:'12'}};
  assert.deepEqual(reconcileFinalizedDepositObservations([observation,structuredClone(observation)]),observation);
  const changed=structuredClone(observation); changed.finality.slot='13';
  assert.throws(()=>reconcileFinalizedDepositObservations([observation,changed]),/disagree/);
});
