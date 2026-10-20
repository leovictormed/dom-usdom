import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {ContractFactory, Wallet, hexlify, randomBytes, keccak256} from 'ethers';
import {localEvm} from './helpers/evm.mjs';
import {candidateBurnTypes, compareViews, inspectBurn, monitorOnce, snapshotReader} from '../../scripts/candidate-monitor.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const fresh = () => hexlify(randomBytes(32));
const bn254ScalarField = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const freshCommitment = () =>
  '0x' + (BigInt(fresh()) % (bn254ScalarField - 1n) + 1n).toString(16).padStart(64, '0');
async function compile() {
  const files = [['USDOMReserve.sol','USDOMReserve'],['Mocks.sol','HostileToken'],['Mocks.sol','MockGovernance']];
  const artifacts = {};
  for (const [file,name] of files) {
    const a = JSON.parse(await fs.readFile(path.join(root,'out',file,name+'.json'),'utf8'));
    artifacts[file] ??= {};
    artifacts[file][name] = {abi:a.abi,evm:{bytecode:a.bytecode}};
  }
  return artifacts;
}
async function fixture(t) {
  const artifacts = await compile();
  const rpc = await localEvm(t);
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'usdom-monitor-test-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const provider = rpc.provider;
  const owner = await provider.getSigner(0), bob = await provider.getSigner(1);
  const signers = [101,102,103,104].map(n => new Wallet('0x'+n.toString(16).padStart(64,'0')))
    .sort((a, b) => BigInt(a.address) < BigInt(b.address) ? -1 : 1);
  async function deploy(file, name, args = []) {
    const a = artifacts[file][name];
    return (await new ContractFactory(a.abi, a.evm.bytecode.object, owner).deploy(...args)).waitForDeployment();
  }
  const token = await deploy('Mocks.sol', 'HostileToken');
  const governance = await deploy('Mocks.sol', 'MockGovernance');
  const guardianContract = await deploy('Mocks.sol', 'MockGovernance');
  // Test adapter for a contract-based guardian. Production must use a validated
  // multisig/module adapter with the same getAddress/sendTransaction boundary.
  const guardian = {
    provider,
    getAddress: () => guardianContract.getAddress(),
    sendTransaction: tx => guardianContract.execute(tx.to, tx.data),
  };
  const domDomain = fresh(), networkId = fresh();
  const reserve = await deploy('USDOMReserve.sol', 'USDOMReserve', [{
    token: token.target, domDomain, governance: governance.target, guardian: await guardianContract.getAddress(),
    withdrawalDelay: 86400, governanceDelay: 172800, maxOutstanding: 100_000_000_000n,
    outflowCapacity: 2_000_000_000n,
  }, signers.map(s => s.address), 3]);
  const deploymentBlock = (await reserve.deploymentTransaction().wait()).blockNumber;
  await (await token.mint(await owner.getAddress(), 10_000_000_000n)).wait();
  await (await token.approve(reserve.target, 10_000_000_000n)).wait();
  await (await reserve.deposit(10_000_000_000n, fresh(), freshCommitment())).wait();
  const blocks = [fresh(), fresh(), fresh(), fresh()];
  const head = await provider.getBlock('latest');
  const burn = {burnId: fresh(), requestId: fresh(), recipient: await bob.getAddress(), amount: 1_000_000_000n,
    domDomain, height: 2n, blockHash: blocks[2], epoch: 1n, validUntil: BigInt(head.timestamp + 6 * 86400)};
  const domain = {name: 'USDOMReserve', version: '3', chainId: 31337, verifyingContract: reserve.target};
  const signatures = await Promise.all(signers.slice(0, 3).map(s => s.signTypedData(domain, candidateBurnTypes, burn)));
  let view = {version: 1, ordering: 'single-sequencer-experimental', network: networkId, domDomain,
    height: '3', tip: blocks[3], blockHashes: blocks, records: [{
      burnId: burn.burnId, requestId: burn.requestId, recipient: burn.recipient.toLowerCase(), amount: String(burn.amount),
      asset: 1, height: '2', blockHash: blocks[2], confirmations: '2',
    }]};
  const config = {reserve, guardian, networkId, domDomain, chainId: '31337', deploymentBlock,
    expectedCodeHash: keccak256(await provider.getCode(reserve.target)),
    initialCheckpoint: {height: '0', tip: blocks[0]}, stateFile: path.join(directory, 'checkpoint.json'),
    maxNoProgressMs: 300_000, sources: [
      {id: 'verified-source-a', read: async () => structuredClone(view)},
      {id: 'verified-source-b', read: async () => structuredClone(view)},
    ]};
  const now = async () => Number(BigInt((await rpc.request({method: 'eth_getBlockByNumber', params: ['latest', false]})).timestamp)) * 1000;
  const monitor = async override => monitorOnce({...config, now: await now(), ...override});
  return {rpc, provider, reserve, token, governance, signers, burn, signatures, config, view, setView: v => { view = v; }, monitor, now,
    queue: async () => (await reserve.queueWithdrawal(burn, signatures)).wait()};
}

test('candidate monitor binds each public burn field and rejects unsafe normalized views', () => {
  const blocks = [fresh(), fresh(), fresh()]; const domDomain = fresh(), networkId = fresh();
  const burn = {burnId: fresh(), requestId: fresh(), recipient: '0x' + '12'.repeat(20), amount: 42n,
    height: 1n, blockHash: blocks[1], domDomain};
  const view = {version: 1, ordering: 'single-sequencer-experimental', network: networkId, domDomain,
    height: '2', tip: blocks[2], blockHashes: blocks, records: [{...burn, amount: '42', height: '1', asset: 1, confirmations: '2'}]};
  const config = {networkId, domDomain, initialCheckpoint: {height: '0', tip: blocks[0]}};
  assert.equal(inspectBurn(burn, view, 2), null);
  compareViews([view, structuredClone(view)], config);
  for (const [field, value] of Object.entries({burnId: fresh(), requestId: fresh(), recipient: '0x' + '34'.repeat(20),
    amount: 43n, height: 2n, blockHash: fresh(), domDomain: fresh()})) {
    assert(inspectBurn({...burn, [field]: value}, view, 2), field);
  }
  assert(inspectBurn(burn, {...view, records: [{...view.records[0], asset: 0}]}, 2));
  assert(inspectBurn(burn, view, 3));
  assert.throws(() => compareViews([view, {...view, network: fresh()}], config));
  assert.throws(() => compareViews([view, {...view, records: [{...view.records[0], amount: 42}]}], config));
  assert.throws(() => snapshotReader({url: 'https://example.com', binary: '/tmp/verifier', networkDirectory: '/tmp/network', networkId}));
});

test('candidate monitor accepts a consistent queue and persists a restart checkpoint', async t => {
  const f = await fixture(t); await f.queue();
  assert.equal((await f.monitor()).status, 'healthy');
  assert.equal((await f.monitor()).status, 'healthy');
  assert.equal(await f.reserve.paused(), false);
  const saved = JSON.parse(await fs.readFile(f.config.stateFile));
  assert.equal(saved.checkpoint.tip, f.view.tip);
  assert.equal(saved.binding.codeHash, f.config.expectedCodeHash);
  assert.equal(await f.reserve.totalReleased(), 0n);
});

test('a quorum-signed fabricated burn triggers actual emergency pause and revocation', async t => {
  const f = await fixture(t); await f.queue();
  f.setView({...f.view, records: []});
  const outcome = await f.monitor();
  assert.equal(outcome.status, 'paused'); assert.equal(outcome.emergency, true);
  assert.match(outcome.reason, /canonical burn absent/);
  assert.equal(await f.reserve.paused(), true); assert.equal(await f.reserve.recoveryRequired(), true);
  await f.rpc.request({method: 'evm_increaseTime', params: [86400]});
  await f.rpc.request({method: 'evm_mine', params: []});
  await assert.rejects(f.reserve.executeWithdrawal.staticCall(f.burn));
  assert.equal(await f.reserve.totalReleased(), 0n);
  // A restart cannot silently approve the old chain or resume the reserve.
  assert.equal((await f.monitor({sources: f.config.sources.map(s => ({...s, read: async () => { throw Error('must not read'); }}))})).emergency, true);
});

test('destination mismatch triggers emergency pause before payment maturity', async t => {
  const f = await fixture(t); await f.queue();
  f.setView({...f.view, records: [{...f.view.records[0], recipient: '0x' + '56'.repeat(20)}]});
  assert.equal((await f.monitor()).emergency, true);
  assert.equal(await f.reserve.recoveryRequired(), true);
});

test('source outage or timeout causes operational pause without key revocation', async t => {
  const f = await fixture(t); await f.queue();
  const outcome = await f.monitor({sourceTimeoutMs: 20, sources: [f.config.sources[0],
    {id: 'unavailable-source', read: async () => new Promise(() => {})}]});
  assert.equal(outcome.status, 'paused'); assert.equal(outcome.emergency, false);
  assert.equal(await f.reserve.paused(), true); assert.equal(await f.reserve.recoveryRequired(), false);
  assert.equal(await f.reserve.currentEpoch(), 1n);
});

test('disagreeing sources fail closed with operational pause', async t => {
  const f = await fixture(t);
  const fork = {...f.view, records: []};
  const outcome = await f.monitor({sources: [f.config.sources[0], {id: 'divergent-source', read: async () => fork}]});
  assert.equal(outcome.emergency, false); assert.match(outcome.reason, /sources disagree/);
  assert.equal(await f.reserve.paused(), true);
});

test('replayed unchanged checkpoint becomes stale across monitor restarts', async t => {
  const f = await fixture(t);
  assert.equal((await f.monitor({maxNoProgressMs: 100_000})).status, 'healthy');
  await f.rpc.request({method: 'evm_increaseTime', params: [101]});
  await f.rpc.request({method: 'evm_mine', params: []});
  const outcome = await f.monitor({maxNoProgressMs: 100_000});
  assert.equal(outcome.emergency, false); assert.match(outcome.reason, /stopped progressing/);
});

test('a paid burn disappearing from matching views activates emergency recovery', async t => {
  const f = await fixture(t); await f.queue();
  await f.rpc.request({method: 'evm_increaseTime', params: [86400]});
  await f.rpc.request({method: 'evm_mine', params: []});
  await (await f.reserve.executeWithdrawal(f.burn)).wait();
  assert.equal((await f.monitor()).status, 'healthy');
  const fork = {...f.view, records: [], blockHashes: [f.view.blockHashes[0], fresh(), fresh(), fresh()]};
  fork.tip = fork.blockHashes[3]; f.setView(fork);
  const outcome = await f.monitor();
  assert.equal(outcome.emergency, true); assert.match(outcome.reason, /paid .*canonical burn absent/);
  assert.equal(await f.reserve.totalReleased(), f.burn.amount, 'pause cannot reverse a completed payout');
});

test('failed guardian submission is reported as failure and retains incident for retry', async t => {
  const f = await fixture(t); await f.queue(); f.setView({...f.view, records: []});
  const failingGuardian = {provider: f.provider, getAddress: () => f.config.guardian.getAddress(),
    sendTransaction: async () => { throw Error('inclusion unavailable'); }};
  await assert.rejects(f.monitor({guardian: failingGuardian}), /inclusion unavailable/);
  assert.equal(await f.reserve.paused(), false);
  assert.equal(JSON.parse(await fs.readFile(f.config.stateFile)).incident.emergency, true);
  assert.equal((await f.monitor()).emergency, true);
  assert.equal(await f.reserve.paused(), true);
});

test('corrupted durable checkpoint pauses instead of starting over silently', async t => {
  const f = await fixture(t);
  assert.equal((await f.monitor()).status, 'healthy');
  await fs.writeFile(f.config.stateFile, '{partial write');
  const outcome = await f.monitor();
  assert.equal(outcome.emergency, false); assert.match(outcome.reason, /durable checkpoint invalid/);
  assert.equal(await f.reserve.paused(), true);
  assert.equal(await f.reserve.recoveryRequired(), false);
});

test('wrong deployment pin is refused before the guardian signs any transaction', async t => {
  const f = await fixture(t);
  await assert.rejects(f.monitor({expectedCodeHash: fresh()}), /wrong reserve bytecode/);
  assert.equal(await f.reserve.paused(), false);
  await assert.rejects(f.monitor({chainId: '1'}), /wrong Ethereum chain/);
  assert.equal(await f.reserve.paused(), false);
});

test('sticky operational recovery is escalated to real key revocation for a fabricated certificate', async t => {
  const f = await fixture(t); await f.queue();
  await (await f.governance.execute(f.reserve.target, f.reserve.interface.encodeFunctionData('proposeNotaries',
    [f.signers.map(s => s.address), 3]))).wait();
  await (await f.reserve.connect(f.config.guardian).pauseOperational()).wait();
  assert.equal(await f.reserve.recoveryRequired(), true);
  for (const signer of f.signers) assert.equal(await f.reserve.revokedNotary(signer.address), false);
  f.setView({...f.view, records: []});
  assert.equal((await f.monitor()).emergency, true);
  for (const signer of f.signers) assert.equal(await f.reserve.revokedNotary(signer.address), true);
});

test('a lagging view pauses operationally, then proven absence upgrades the latched incident', async t => {
  const f = await fixture(t); await f.queue();
  f.setView({...f.view, height: '1', tip: f.view.blockHashes[1], blockHashes: f.view.blockHashes.slice(0, 2), records: []});
  const lag = await f.monitor();
  assert.equal(lag.emergency, false); assert.match(lag.reason, /insufficient coverage/);
  for (const signer of f.signers) assert.equal(await f.reserve.revokedNotary(signer.address), false);
  f.setView({...f.view, records: []});
  const fabricated = await f.monitor();
  assert.equal(fabricated.emergency, true); assert.match(fabricated.reason, /canonical burn absent/);
  for (const signer of f.signers) assert.equal(await f.reserve.revokedNotary(signer.address), true);
});

test('a journal write failure still attempts the actual pause and reports persistence failure', async t => {
  const f = await fixture(t);
  const sources = f.config.sources.map(source => ({...source, read: async () => {
    // Simulate a path becoming unwritable after checkpoint loading, before commit.
    await fs.mkdir(f.config.stateFile, {recursive: true});
    return structuredClone(f.view);
  }}));
  await assert.rejects(f.monitor({sources}), /durable incident journal failed/);
  assert.equal(await f.reserve.paused(), true);
  assert.equal(await f.reserve.recoveryRequired(), false);
});

test('an existing monitor lock blocks a second worker and never reports healthy', async t => {
  const f = await fixture(t);
  await fs.writeFile(`${f.config.stateFile}.lock`, 'simulated terminated worker');
  await assert.rejects(f.monitor(), {code: 'EEXIST'});
  assert.equal(await f.reserve.paused(), false, 'supervisor must handle failed worker startup');
});

test('a latched old incident preserves replacement keys but never approves resumption', async t => {
  const f = await fixture(t); await f.queue(); f.setView({...f.view, records: []});
  assert.equal((await f.monitor()).emergency, true);
  const replacement = Array.from({length: 4}, () => Wallet.createRandom().address)
    .sort((a, b) => BigInt(a) < BigInt(b) ? -1 : 1);
  const govern = async (name, args = []) => (await f.governance.execute(f.reserve.target,
    f.reserve.interface.encodeFunctionData(name, args))).wait();
  await govern('proposeNotaries', [replacement, 3]);
  await f.rpc.request({method: 'evm_increaseTime', params: [172800]});
  await f.rpc.request({method: 'evm_mine', params: []});
  await (await f.reserve.executeNotaries(replacement, 3)).wait();
  assert.equal(await f.reserve.currentEpoch(), 2n);
  assert.equal((await f.monitor()).emergency, true);
  for (const key of replacement) assert.equal(await f.reserve.revokedNotary(key), false);
  await govern('scheduleResume');
  await f.rpc.request({method: 'evm_increaseTime', params: [172800]});
  await f.rpc.request({method: 'evm_mine', params: []});
  await (await f.reserve.executeResume()).wait();
  assert.equal((await f.monitor()).status, 'paused');
  assert.equal(await f.reserve.paused(), true);
  for (const key of replacement) assert.equal(await f.reserve.revokedNotary(key), false);
});

test('Ethereum reorganization while private views are read prevents a healthy checkpoint', async t => {
  const f = await fixture(t);
  const before = await f.rpc.request({method: 'evm_snapshot', params: []});
  await f.queue();
  let changed = false;
  const sources = f.config.sources.map(source => ({...source, read: async () => {
    if (!changed) {
      changed = true;
      assert(await f.rpc.request({method: 'evm_revert', params: [before]}));
      await f.rpc.request({method: 'evm_increaseTime', params: [1]});
      await f.rpc.request({method: 'evm_mine', params: []});
    }
    return structuredClone(f.view);
  }}));
  const outcome = await f.monitor({sources});
  assert.equal(outcome.status, 'paused'); assert.equal(outcome.emergency, false);
  assert.match(outcome.reason, /Ethereum checkpoint (unstable|changed)/);
});

async function readyRotation(f) {
  const replacement = [201,202,203,204].map(n => new Wallet('0x'+n.toString(16).padStart(64,'0')).address)
    .sort((a,b)=>BigInt(a)<BigInt(b)?-1:1);
  await (await f.governance.execute(f.reserve.target, f.reserve.interface.encodeFunctionData('proposeNotaries',[replacement,3]))).wait();
  await f.rpc.request({method:'evm_increaseTime',params:[172800]});
  await f.rpc.request({method:'evm_mine',params:[]});
  return replacement;
}

test('rotation after observation cannot make an old queued incident revoke new keys', async t => {
  const f = await fixture(t); await f.queue(); f.setView({...f.view,records:[]});
  const replacement=await readyRotation(f);
  let rotation;
  const sources=f.config.sources.map(source=>({...source,read:async()=>{
    rotation ??= (async()=>{await (await f.reserve.executeNotaries(replacement,3)).wait();})();
    await rotation; return {...f.view,records:[]};
  }}));
  const outcome=await f.monitor({sources});
  assert.equal(outcome.status,'paused'); assert.equal(outcome.emergency,true);
  assert.equal(await f.reserve.currentEpoch(),2n);
  for(const key of replacement) assert.equal(await f.reserve.revokedNotary(key),false);
  assert.equal(JSON.parse(await fs.readFile(f.config.stateFile)).incident.epoch,'1');
});

test('epoch-bound pause losing transaction ordering falls back to operational stop', async t => {
  const f=await fixture(t);await f.queue();f.setView({...f.view,records:[]});
  const replacement=await readyRotation(f); let rotated=false;
  const racingGuardian={provider:f.provider,getAddress:()=>f.config.guardian.getAddress(),sendTransaction:async tx=>{
    if(!rotated) {
      assert.equal(tx.data.slice(0,10),f.reserve.interface.getFunction('pauseEpoch').selector);
      rotated=true; await (await f.reserve.executeNotaries(replacement,3)).wait();
    }
    return f.config.guardian.sendTransaction(tx);
  }};
  const outcome=await f.monitor({guardian:racingGuardian});
  assert.equal(outcome.status,'paused');assert.equal(outcome.emergency,true);assert(rotated);
  assert.equal(await f.reserve.paused(),true);
  for(const key of replacement) assert.equal(await f.reserve.revokedNotary(key),false);
});

test('orphaned historical payout does not revoke an unrelated replacement generation',async t=>{
  const f=await fixture(t);await f.queue();
  await f.rpc.request({method:'evm_increaseTime',params:[86400]});await f.rpc.request({method:'evm_mine',params:[]});
  await (await f.reserve.executeWithdrawal(f.burn)).wait();
  const replacement=await readyRotation(f);await (await f.reserve.executeNotaries(replacement,3)).wait();
  f.setView({...f.view,records:[]});
  const outcome=await f.monitor();assert.equal(outcome.emergency,true);assert.equal(await f.reserve.paused(),true);
  assert.equal(await f.reserve.totalReleased(),f.burn.amount);
  for(const key of replacement) assert.equal(await f.reserve.revokedNotary(key),false);
  assert.equal(JSON.parse(await fs.readFile(f.config.stateFile)).incident.epoch,'1');
});
