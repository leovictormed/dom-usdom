import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {assembleNativePreActivationFacts} from '../../sdk/native-preactivation-facts.mjs';

const anchor=Object.freeze({schema:'usdom-dom-preactivation-anchor-v1',network:'mainnet',
  networkMagic:'1146047821',chainId:'0x'+'11'.repeat(32),activationPredecessorHeight:'1000',
  activationPredecessorBlock:'0x'+'22'.repeat(32),activationPredecessorContextHash:'0x'+'33'.repeat(32),
  activationPredecessorTotalDifficulty:'987654321',checkpointMaxSpan:'390'});
const policy=Object.freeze({schema:'usdom-preactivation-policy-v1',
  nativeEthereumTrustedCheckpoint:'0x'+'44'.repeat(32),domDomain:'0x'+'55'.repeat(32),
  checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
  checkpointChallengePeriodSeconds:'172800'});

test('authenticated anchor and ratified policy assemble exact native facts',()=>{
  assert.deepEqual(assembleNativePreActivationFacts({anchor,policy}),{
    schema:'usdom-native-preactivation-facts-v1',nativeEthereumTrustedCheckpoint:'0x'+'44'.repeat(32),
    domDomain:'0x'+'55'.repeat(32),checkpointDomNetworkMagic:'1146047821',
    checkpointDomChainId:'0x'+'11'.repeat(32),checkpointFirstV4Height:'1001',
    checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
    checkpointChallengePeriodSeconds:'172800',checkpointInitialHeight:'1000',
    checkpointInitialBlock:'0x'+'22'.repeat(32),checkpointInitialContextHash:'0x'+'33'.repeat(32),
    checkpointInitialTotalDifficulty:'987654321'});
});

test('assembler rejects cross-network, cadence drift and unknown fields',()=>{
  assert.throws(()=>assembleNativePreActivationFacts({anchor:{...anchor,network:'regtest'},policy}));
  assert.throws(()=>assembleNativePreActivationFacts({anchor,policy:{...policy,checkpointConfirmationDepthBlocks:'31'}}));
  assert.throws(()=>assembleNativePreActivationFacts({anchor:{...anchor,extra:true},policy}));
});

test('fixed offline materializer locks the node and cannot publish or authorize',()=>{
  const wrapper=new URL('../../scripts/materialize-native-preactivation-facts.sh',import.meta.url);
  const exporter=new URL('../../scripts/export-dom-preactivation-anchor.sh',import.meta.url);
  const preparer=new URL('../../scripts/prepare-native-preactivation-facts.mjs',import.meta.url);
  const nodeWrapper=new URL('../../scripts/run-closed-mainnet-node.sh',import.meta.url);
  assert.equal(spawnSync('bash',['-n',fileURLToPath(wrapper)]).status,0);
  assert.equal(spawnSync('bash',['-n',fileURLToPath(exporter)]).status,0);
  assert.equal(spawnSync(process.execPath,['--check',fileURLToPath(preparer)]).status,0);
  const source=readFileSync(wrapper,'utf8');
  const exportSource=readFileSync(exporter,'utf8');
  const nodeSource=readFileSync(nodeWrapper,'utf8');
  assert.match(exportSource,/flock -n 8/);
  assert.match(nodeSource,/flock -n 8/);
  assert.match(exportSource,/--bin dom-usdom-export-preactivation-anchor/);
  assert.match(exportSource,/--max-span 390/);
  assert.match(source,/install-release-config-stdin\.mjs/);
  for(const forbidden of ['git push','cast send','eth_sendRawTransaction','productionReady = true',
    'realFundsAuthorized = true','--private-key','--mnemonic']) {
    assert.equal(source.includes(forbidden)||exportSource.includes(forbidden),false);
  }
});
