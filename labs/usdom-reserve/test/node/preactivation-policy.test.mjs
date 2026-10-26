import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {deriveDomDomain,materializePreActivationPolicy} from '../../sdk/preactivation-policy.mjs';

const anchor={schema:'usdom-dom-preactivation-anchor-v1',network:'mainnet',networkMagic:'1146047821',
  chainId:'0x'+'11'.repeat(32),activationPredecessorHeight:'1000',
  activationPredecessorBlock:'0x'+'22'.repeat(32),activationPredecessorContextHash:'0x'+'33'.repeat(32),
  activationPredecessorTotalDifficulty:'9',checkpointMaxSpan:'390'};
const release={productionReady:false,realFundsAuthorized:false,ethereumChainId:'1',
  reserve:'0x1000000000000000000000000000000000000001',
  checkpointRegistry:'0x2000000000000000000000000000000000000002'};
const checkpoint={schema:'usdom-ethereum-checkpoint-consensus-v1',network:'ethereum-mainnet',
  checkpointEpoch:'300000',checkpointSlot:'9600000',checkpointRoot:'0x'+'44'.repeat(32),
  sourceCount:'3',sourceSetCommitment:'0x'+'55'.repeat(32),observedAtUnix:'1790000000'};

test('production policy derives one domain and fixed conservative cadence',()=>{
  const policy=materializePreActivationPolicy({releaseConfig:release,anchor,
    checkpointConsensus:checkpoint,nowUnix:1790000100n});
  assert.deepEqual(policy,{schema:'usdom-preactivation-policy-v1',
    nativeEthereumTrustedCheckpoint:'0x'+'44'.repeat(32),
    domDomain:'0x667d6c2621966e96653b4598b050bd7ee5c1e7779d08aeb29bb39c228102bd8e',
    checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
    checkpointChallengePeriodSeconds:'172800'});
});

test('domain binds both chains and both Ethereum contracts',()=>{
  const base={domNetworkMagic:anchor.networkMagic,domChainId:anchor.chainId,ethereumChainId:'1',
    reserve:release.reserve,checkpointRegistry:release.checkpointRegistry};
  const expected=deriveDomDomain(base);
  for(const mutation of [{...base,domNetworkMagic:'1'},{...base,domChainId:'0x'+'12'.repeat(32)},
    {...base,reserve:'0x3000000000000000000000000000000000000003'},
    {...base,checkpointRegistry:'0x4000000000000000000000000000000000000004'}]) {
    assert.notEqual(deriveDomDomain(mutation),expected);
  }
});

test('policy rejects non-boundary checkpoint, weak source quorum and cadence drift',()=>{
  assert.throws(()=>materializePreActivationPolicy({releaseConfig:release,anchor,
    checkpointConsensus:{...checkpoint,checkpointSlot:'9600001'},nowUnix:1790000100n}));
  assert.throws(()=>materializePreActivationPolicy({releaseConfig:release,anchor,
    checkpointConsensus:{...checkpoint,sourceCount:'2'},nowUnix:1790000100n}));
  assert.throws(()=>materializePreActivationPolicy({releaseConfig:release,
    anchor:{...anchor,checkpointMaxSpan:'391'},checkpointConsensus:checkpoint,nowUnix:1790000100n}));
  assert.throws(()=>materializePreActivationPolicy({releaseConfig:release,anchor,
    checkpointConsensus:checkpoint,nowUnix:1790004001n}),/stale/);
});

test('trusted ceremony clock remains inside the shared uint64 timestamp domain',()=>{
  const maximum=(1n<<64n)-1n;
  const boundaryCheckpoint={...checkpoint,observedAtUnix:maximum.toString()};
  assert.doesNotThrow(()=>materializePreActivationPolicy({releaseConfig:release,anchor,
    checkpointConsensus:boundaryCheckpoint,nowUnix:maximum}));
  assert.throws(()=>materializePreActivationPolicy({releaseConfig:release,anchor,
    checkpointConsensus:boundaryCheckpoint,nowUnix:maximum+1n}),/stale or future-dated/);
  assert.throws(()=>materializePreActivationPolicy({releaseConfig:release,anchor,
    checkpointConsensus:checkpoint,nowUnix:0n}),/stale or future-dated/);
  assert.throws(()=>materializePreActivationPolicy({releaseConfig:release,anchor,
    checkpointConsensus:checkpoint,nowUnix:'1790000100'}),/must be bigint/);
});

test('fixed policy materializer is atomic, source-derived and authorization-free',()=>{
  const wrapper=new URL('../../scripts/materialize-preactivation-policy.sh',import.meta.url);
  const preparer=new URL('../../scripts/prepare-preactivation-policy-materialization.mjs',import.meta.url);
  assert.equal(spawnSync('bash',['-n',fileURLToPath(wrapper)]).status,0);
  assert.equal(spawnSync(process.execPath,['--check',fileURLToPath(preparer)]).status,0);
  const shell=readFileSync(wrapper,'utf8'),source=readFileSync(preparer,'utf8');
  assert.match(shell,/flock -n 9/);
  assert.match(shell,/install-release-config-stdin\.mjs/);
  assert.match(source,/materializePreActivationPolicy/);
  assert.match(source,/ethereum-checkpoint-consensus\.json/);
  for(const forbidden of ['git push','cast send','eth_sendRawTransaction','--private-key','--mnemonic',
    'productionReady = true','realFundsAuthorized = true']) {
    assert.equal(shell.includes(forbidden)||source.includes(forbidden),false,forbidden);
  }
});
