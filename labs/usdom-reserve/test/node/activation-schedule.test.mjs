import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {activationSchedule} from '../../sdk/activation-schedule.mjs';

const hash=byte=>'0x'+byte.repeat(32);

const nodeMain=await readFile(
  new URL('../../../../crates/dom-node/src/main.rs',import.meta.url),'utf8');
const nodeConfig=await readFile(
  new URL('../../../../crates/dom-node/src/native_usdom_config.rs',import.meta.url),'utf8');
const nodeRuntime=await readFile(
  new URL('../../../../crates/dom-node/src/node.rs',import.meta.url),'utf8');
const requirements=JSON.parse(await readFile(
  new URL('../../config/production-requirements.json',import.meta.url),'utf8'));

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

test('public node startup installs only an exact hash-pinned persisted activation schedule',()=>{
  assert.match(nodeMain,/DOM_USDOM_V4_MANIFEST_FILE/);
  assert.match(nodeMain,/DOM_USDOM_V4_MANIFEST_SHA256/);
  assert.match(nodeMain,/\(Some\(_\), None\) \| \(None, Some\(_\)\)[\s\S]*?must be supplied together/);
  assert.match(nodeMain,/load_native_usdom_v4_node_bundle\(/);
  assert.match(nodeMain,/init_native_usdom_v4_for_schedule_with_spend_verifier\(/);
  assert.match(nodeMain,/init_native_usdom_candidate_for_schedule_with_spend_verifier\(/);

  assert.match(nodeConfig,/Sha256::digest\(&manifest_bytes\)/);
  assert.match(nodeConfig,/computed_manifest_hash != expected_manifest_hash/);
  assert.match(nodeConfig,/NativeUsdomV4ActivationSchedule::from_bytes\(&schedule_bytes\)/);
  assert.match(nodeConfig,/schedule\.network_magic\(\) != expected_network_magic/);

  assert.match(nodeRuntime,/restore_for_schedule_with_spend_verifier\(/);
  assert.match(nodeRuntime,/persisted_usdom_v4_activation_schedule\(&chain\.store\)/);
  assert.match(nodeRuntime,/persisted native USDOM V1 schedule differs from the hash-pinned manifest/);
  assert.equal(requirements.production_activation_schedule_implemented,true);
  assert.equal(requirements.production_reserve_config_hash_configured,false,
    'implementation must not fabricate a release-specific production schedule');
});
