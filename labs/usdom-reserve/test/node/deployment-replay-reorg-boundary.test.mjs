import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source=readFileSync(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
test('deployment signing and publication revalidate mutable CREATE state after prompts',()=>{
  const sign=source.indexOf('AUTORIZO ASSINAR DEPLOY MAINNET INDICE');
  const create=source.indexOf('rpc mktx --chain 1',sign);
  const presign=source.indexOf('test "$(rpc nonce "$from" --block pending',sign);
  const empty=source.indexOf('test "$(rpc code "$expected" --block finalized',sign);
  assert.ok(sign>=0&&presign>sign&&empty>sign&&create>presign&&create>empty);
  const transmit=source.indexOf('AUTORIZO TRANSMITIR DEPLOY MAINNET INDICE');
  const publish=source.indexOf('rpc publish "$raw"',transmit);
  const renonce=source.indexOf('test "$(rpc nonce "$from" --block pending',transmit);
  const recode=source.indexOf('test "$(rpc code "$expected" --block finalized',transmit);
  const unseen=source.indexOf("'. == null'",transmit);
  assert.ok(transmit>=0&&renonce>transmit&&recode>transmit&&unseen>transmit
    &&publish>renonce&&publish>recode&&publish>unseen);
});

test('deployment completion requires finalized canonical ancestry and a stable post-finality barrier',()=>{
  for(const marker of ['canonical_hash','receiptBlockNumber','finalizedBlockNumber',
    'barrier_finalized_number','barrier_finalized_hash','runtimeCodeHash','initcodeHash']) {
    assert.ok(source.includes(marker),marker);
  }
  assert.ok(source.indexOf('barrier_finalized_number')<source.lastIndexOf('persist_new'));
});
