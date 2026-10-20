// Candidate v3 monitor for the LOCAL private-note chain. Never a DOM light client.
// This module does not import a compiler, EVM fixture, wallet seed or signing service.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes} from 'node:crypto';
import {getAddress, keccak256, TypedDataEncoder} from 'ethers';
import {burnTypes, domain as reserveDomain} from '../sdk/reserve.mjs';

const execFileAsync = promisify(execFile);
const MAX_SNAPSHOT = 16 * 1024 * 1024;
const MAX_EVENTS = 100_000;
const ZERO = '0x' + '00'.repeat(32);
export const candidateBurnTypes = burnTypes;
const fields = candidateBurnTypes.Burn.map(x => x.name);
const lower = value => String(value).toLowerCase();
const hash = value => {
  assert.match(value, /^0x[0-9a-f]{64}$/i, 'invalid hash');
  return lower(value);
};
const uint = value => {
  assert.equal(typeof value, 'string', 'integers must be decimal strings');
  assert.match(value, /^(0|[1-9][0-9]*)$/, 'noncanonical integer');
  return BigInt(value);
};

/** Only this read adapter should consume remote data. Rust replays ALL proofs and
 * checks the network fingerprint before emitting normalized burn records. The
 * manifest, binary and expected fingerprint are locally trusted configuration. */
export function snapshotReader({url, binary, networkDirectory, networkId, timeoutMs = 30_000}) {
  const endpoint = new URL(url);
  assert(endpoint.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(endpoint.hostname),
    'this experimental monitor only accepts loopback sources');
  assert(!endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash
    && endpoint.pathname === '/', 'source must be a bare loopback origin');
  hash(networkId);
  assert(path.isAbsolute(binary) && path.isAbsolute(networkDirectory), 'trusted paths must be absolute');
  return {id: endpoint.origin, read: async () => {
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'usdom-monitor-'));
    try {
      const response = await fetch(new URL('/snapshot', endpoint), {
        signal: AbortSignal.timeout(timeoutMs), redirect: 'error',
      });
      assert(response.ok, 'snapshot RPC unavailable');
      const chunks = []; let length = 0;
      const reader = response.body.getReader();
      try {
        for (;;) {
          const {done, value} = await reader.read();
          if (done) break;
          length += value.length;
          assert(length <= MAX_SNAPSHOT, 'oversized snapshot');
          chunks.push(value);
        }
      } finally { await reader.cancel(); }
      const snapshot = path.join(temporary, 'snapshot.json');
      await fs.writeFile(snapshot, Buffer.concat(chunks), {mode: 0o600, flag: 'wx'});
      const {stdout} = await execFileAsync(binary, ['--network', networkDirectory, '--snapshot', snapshot,
        '--network-id', networkId], {timeout: timeoutMs, maxBuffer: 2 * 1024 * 1024});
      return JSON.parse(stdout);
    } finally { await fs.rm(temporary, {recursive: true, force: true}); }
  }};
}

export function compareViews(views, {networkId, domDomain, initialCheckpoint}) {
  assert(views.length >= 2, 'at least two configured sources required');
  for (const view of views) {
    assert.equal(view.version, 1); assert.equal(view.ordering, 'single-sequencer-experimental');
    assert.equal(hash(view.network), hash(networkId), 'wrong network');
    assert.equal(hash(view.domDomain), hash(domDomain), 'wrong DOM domain');
    const height = uint(view.height);
    assert(height <= 1024n && view.blockHashes.length === Number(height) + 1);
    assert.equal(hash(view.tip), hash(view.blockHashes[Number(height)]));
    assert(height >= uint(initialCheckpoint.height), 'view predates trusted checkpoint');
    assert.equal(hash(view.blockHashes[Number(initialCheckpoint.height)]), hash(initialCheckpoint.tip),
      'view does not extend trusted checkpoint');
    assert(Array.isArray(view.records) && view.records.length <= 256);
    const seen = new Set();
    for (const record of view.records) {
      assert(!seen.has(hash(record.burnId)), 'duplicate burn record'); seen.add(hash(record.burnId));
      hash(record.requestId); getAddress(record.recipient);
      assert([0, 1].includes(record.asset));
      assert(uint(record.amount) > 0n && uint(record.amount) < 2n ** 64n);
      const at = uint(record.height);
      assert(at > 0n && at <= height);
      assert.equal(hash(record.blockHash), hash(view.blockHashes[Number(at)]));
      assert.equal(uint(record.confirmations), height - at + 1n);
    }
  }
  for (const view of views.slice(1)) assert.deepEqual(view, views[0], 'independent sources disagree');
  return views[0];
}

/** Public-certificate consistency only; source verification belongs to snapshotReader. */
export function inspectBurn(burn, view, confirmations) {
  const record = view.records.find(r => hash(r.burnId) === lower(burn.burnId));
  if (!record) return 'canonical burn absent';
  if (record.asset !== 1) return 'burn is not USDOM';
  for (const field of ['burnId', 'requestId', 'recipient', 'blockHash']) {
    if (lower(record[field]) !== lower(burn[field])) return `burn ${field} mismatch`;
  }
  for (const field of ['amount', 'height']) {
    if (uint(record[field]) !== BigInt(burn[field])) return `burn ${field} mismatch`;
  }
  if (burn.domDomain && lower(burn.domDomain) !== lower(view.domDomain)) return 'burn DOM domain mismatch';
  if (uint(record.confirmations) < BigInt(confirmations)) return 'burn confirmations insufficient';
  return null;
}

async function atomicJson(filename, value) {
  const temporary = `${filename}.${randomBytes(8).toString('hex')}.tmp`;
  let file;
  try {
    file = await fs.open(temporary, 'wx', 0o600);
    await file.writeFile(JSON.stringify(value, null, 2) + '\n');
    await file.sync(); await file.close(); file = null;
    await fs.rename(temporary, filename);
    const directory = await fs.open(path.dirname(filename), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } finally {
    if (file) await file.close();
    await fs.rm(temporary, {force: true});
  }
}
async function events(reserve, name, first, last) {
  const result = [];
  for (let from = first; from <= last; from += 2000) {
    result.push(...await reserve.queryFilter(reserve.filters[name](), from, Math.min(from + 1999, last)));
    assert(result.length <= MAX_EVENTS, 'event scan requires archival checkpointing');
  }
  return result;
}
async function currentKeysRevoked(reserve, deploymentBlock) {
  const epoch = await reserve.currentEpoch();
  const installed = await reserve.queryFilter(reserve.filters.NotariesInstalled(epoch), deploymentBlock, 'latest');
  assert.equal(installed.length, 1, 'current key installation unavailable');
  const signers = installed[0].args.signers;
  assert(signers.length >= 3 && signers.length <= 16, 'unexpected key set');
  const revoked = await Promise.all(signers.map(address => reserve.revokedNotary(address)));
  assert.equal(await reserve.currentEpoch(), epoch, 'key generation changed during check');
  return revoked.every(Boolean);
}
function timedRead(source, timeoutMs) {
  let timer;
  return Promise.race([Promise.resolve().then(() => source.read()), new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('source timed out')), timeoutMs);
  })]).finally(() => clearTimeout(timer));
}

/** One serialized monitoring cycle. A supervisor must call this frequently and
 * alert on ANY rejection, especially failed pause inclusion. `sources` are locally
 * trusted adapters (normally snapshotReader); never deserialize executable readers.
 * No notary key is accepted. The configured transaction executor must report the
 * actual on-chain guardian address (for example, a multisig/module adapter).
 * Return success after pause only when its receipt and on-chain state are checked. */
export async function monitorOnce({reserve, guardian, sources, networkId, domDomain, expectedCodeHash,
  chainId, deploymentBlock, initialCheckpoint, stateFile, confirmations = 2,
  maxNoProgressMs = 300_000, sourceTimeoutMs = 30_000, now = Date.now()}) {
  hash(networkId); hash(domDomain); hash(expectedCodeHash);
  assert(Number.isSafeInteger(deploymentBlock) && deploymentBlock >= 0);
  assert(Number.isSafeInteger(confirmations) && confirmations >= 2);
  assert(Number.isSafeInteger(maxNoProgressMs) && maxNoProgressMs > 0);
  assert(Number.isSafeInteger(now) && now >= 0);
  assert(sources.length >= 2 && new Set(sources.map(s => s.id)).size === sources.length,
    'distinct source identities required; endpoints do not prove operator independence');
  assert(path.isAbsolute(stateFile));
  const lock = await fs.open(`${stateFile}.lock`, 'wx', 0o600);
  try {
    const provider = reserve.runner.provider ?? reserve.runner;
    const address = getAddress(await reserve.getAddress());
    assert.equal((await provider.getNetwork()).chainId, BigInt(chainId), 'wrong Ethereum chain');
    assert.equal(keccak256(await provider.getCode(address)), lower(expectedCodeHash), 'wrong reserve bytecode');
    assert.equal(lower(await reserve.domDomain()), lower(domDomain), 'wrong reserve DOM domain');
    assert.equal(getAddress(await reserve.guardian()), getAddress(await guardian.getAddress()), 'wrong guardian');
    const domain = reserveDomain(String(chainId), address);
    const onchainDomain = await reserve.eip712Domain();
    assert.equal(onchainDomain.name, domain.name, 'wrong EIP-712 name');
    assert.equal(onchainDomain.version, domain.version, 'wrong EIP-712 version');
    assert.equal(onchainDomain.chainId, domain.chainId, 'wrong EIP-712 chain');
    assert.equal(getAddress(onchainDomain.verifyingContract), address, 'wrong EIP-712 reserve');
    const binding = {network: lower(networkId), domDomain: lower(domDomain), chainId: String(chainId),
      reserve: address, codeHash: lower(expectedCodeHash), deploymentBlock, initialCheckpoint,
      sourceIds: sources.map(s => s.id).sort(), confirmations, maxNoProgressMs};
    let state; let checkpointError;
    try {
      const content = await fs.readFile(stateFile);
      assert(content.length <= 1024 * 1024, 'oversized monitor checkpoint');
      state = JSON.parse(content);
      assert.equal(state.version, 1, 'unsupported monitor checkpoint');
      assert.deepEqual(state.binding, binding, 'monitor checkpoint configuration changed');
      assert(Number.isSafeInteger(state.observedAt) && now >= state.observedAt, 'clock moved backwards');
      assert(Number.isSafeInteger(state.lastProgressAt) && state.lastProgressAt <= state.observedAt);
      uint(state.checkpoint.height); hash(state.checkpoint.tip);
      if (state.ethereum) {
        assert(Number.isSafeInteger(state.ethereum.height) && state.ethereum.height >= deploymentBlock);
        hash(state.ethereum.hash);
      }
      if (state.incident) {
        assert(typeof state.incident.reason === 'string' && typeof state.incident.emergency === 'boolean');
        if (state.incident.emergency) uint(state.incident.epoch);
      }
    } catch (error) {
      if (error.code !== 'ENOENT') checkpointError = error;
      state = {version: 1, binding, checkpoint: initialCheckpoint, lastProgressAt: now,
        observedAt: now, ethereum: null, incident: null};
    }
    const halt = async (reason, emergency, observedEpoch) => {
      // Retain the prior trusted checkpoint: an incident is never adopted as new truth.
      const incidentEpoch = emergency ? (state.incident?.emergency ? state.incident.epoch
        : String(observedEpoch ?? await reserve.currentEpoch())) : undefined;
      state.incident = {reason, emergency, observedAt: now, ...(emergency ? {epoch: incidentEpoch} : {})};
      state.observedAt = now;
      let journalError;
      try { await atomicJson(stateFile, state); } catch (error) { journalError = error; }
      try {
        const connected = reserve.connect(guardian);
        const currentEpoch = await reserve.currentEpoch();
        const revokeCurrent = emergency && currentEpoch === BigInt(incidentEpoch);
        // recoveryRequired may result from operational pause + pending rotation;
        // it is NOT evidence of revocation. Inspect the installed keys themselves.
        let revoked = false;
        if (revokeCurrent && await reserve.paused()) {
          try { revoked = await currentKeysRevoked(reserve, deploymentBlock); } catch { /* attempt the emergency stop anyway */ }
        }
        if (!await reserve.paused() || (revokeCurrent && !revoked)) {
          try {
            const transaction = await (revokeCurrent ? connected.pauseEpoch(BigInt(incidentEpoch)) : connected.pauseOperational());
            const receipt = await transaction.wait();
            assert(receipt?.status === 1, 'pause transaction failed');
          } catch (error) {
            // A rotation may have won ordering after the monitor's last read.
            // Only an observed epoch advance justifies the operational fallback.
            if (!revokeCurrent || await reserve.currentEpoch() <= BigInt(incidentEpoch)) throw error;
            if (!await reserve.paused()) {
              const receipt = await (await connected.pauseOperational()).wait();
              assert(receipt?.status === 1, 'operational pause transaction failed');
            }
          }
        }
        assert(await reserve.paused(), 'pause not confirmed');
        const finalEpoch = await reserve.currentEpoch();
        if (emergency && finalEpoch === BigInt(incidentEpoch)) {
          assert(await reserve.recoveryRequired(), 'key recovery not activated');
          assert(await currentKeysRevoked(reserve, deploymentBlock), 'active keys not revoked');
        }
        if (emergency) assert(finalEpoch >= BigInt(incidentEpoch), 'incident generation regressed');
        if (journalError) throw new Error(`paused, but durable incident journal failed: ${journalError.message}`);
      } catch (error) {
        // Never convert a failed emergency action into a reported operational success.
        error.monitorPauseFailure = true;
        throw error;
      }
      return {status: 'paused', emergency, reason};
    };
    if (checkpointError) return await halt(`durable checkpoint invalid: ${checkpointError.message}`, false);
    // An incident is latched across restarts. An operator must investigate and
    // provision a new checkpoint/state path; this code never approves resumption.
    if (state.incident?.emergency) return await halt(state.incident.reason, true);
    let view; let ethereum;
    try {
      ethereum = await provider.getBlock('latest');
      assert(ethereum && ethereum.number >= deploymentBlock, 'Ethereum head unavailable');
      assert(now - ethereum.timestamp * 1000 <= maxNoProgressMs
        && ethereum.timestamp * 1000 - now <= 60_000, 'Ethereum head stale or clock invalid');
      if (state.ethereum) {
        const old = await provider.getBlock(state.ethereum.height);
        assert(old?.hash === state.ethereum.hash, 'Ethereum checkpoint reorganized');
        assert(ethereum.number >= state.ethereum.height, 'Ethereum head regressed');
      }
      view = compareViews(await Promise.all(sources.map(s => timedRead(s, sourceTimeoutMs))),
        {networkId, domDomain, initialCheckpoint});
    } catch (error) { return await halt(`source unavailable or untrusted: ${error.message}`, false); }
    const assertEthereumStable = async () => {
      // Bypass getBlock's short-lived provider cache when checking for a reorg
      // across proof verification and log/state queries at a numeric block tag.
      const block = await provider.send('eth_getBlockByNumber', ['0x' + ethereum.number.toString(16), false]);
      assert.equal(block?.hash, ethereum.hash, 'Ethereum checkpoint changed during monitoring');
    };

    let queued; let certificates; let released; let epoch;
    try {
      [queued, certificates, released, epoch] = await Promise.all([
        events(reserve, 'WithdrawalQueued', deploymentBlock, ethereum.number),
        events(reserve, 'WithdrawalCertificate', deploymentBlock, ethereum.number),
        events(reserve, 'Released', deploymentBlock, ethereum.number),
        reserve.currentEpoch({blockTag: ethereum.number}),
      ]);
      const certs = new Map();
      for (const event of certificates) {
        const burn = Object.fromEntries(fields.map(f => [f, event.args.certificate[f]]));
        assert.equal(lower(event.args.burnId), lower(burn.burnId));
        certs.set(TypedDataEncoder.hash(domain, candidateBurnTypes, burn), burn);
      }
      const checked = new Set();
      for (const event of queued) {
        const burnId = event.args.burnId;
        if (checked.has(burnId)) continue;
        checked.add(burnId);
        const pending = await reserve.pendingWithdrawals(burnId, {blockTag: ethereum.number});
        if (pending.digest === ZERO || pending.epoch !== epoch || pending.expiresAt < BigInt(ethereum.timestamp)) continue;
        const burn = certs.get(pending.digest);
        assert(burn, 'queued certificate event unavailable');
        assert.equal(lower(burn.burnId), lower(burnId));
        assert.equal(lower(burn.requestId), lower(pending.requestId));
        assert.equal(BigInt(burn.epoch), pending.epoch);
        assert.equal(BigInt(burn.validUntil), pending.expiresAt);
        if (BigInt(view.height) < BigInt(burn.height) + BigInt(confirmations) - 1n) {
          return await halt(`private view has insufficient coverage for queued ${burnId}`, false);
        }
        const reason = inspectBurn(burn, view, confirmations);
        if (reason) {
          await assertEthereumStable();
          return await halt(`queued ${burnId}: ${reason}`, true, burn.epoch);
        }
      }
      for (const event of released) {
        const burn = Object.fromEntries(['burnId', 'requestId', 'recipient', 'amount', 'height', 'blockHash', 'epoch']
          .map(f => [f, event.args[f]]));
        if (BigInt(view.height) < BigInt(burn.height) + BigInt(confirmations) - 1n) {
          return await halt(`private view has insufficient coverage for paid ${burn.burnId}`, false);
        }
        const reason = inspectBurn(burn, view, confirmations);
        if (reason) {
          await assertEthereumStable();
          return await halt(`paid ${burn.burnId}: ${reason}`, true, burn.epoch);
        }
      }
    } catch (error) {
      if (error.monitorPauseFailure) throw error;
      return await halt(`Ethereum history unavailable or inconsistent: ${error.message}`, false);
    }
    // Evaluate ancestry after obligations so a provably orphaned payout escalates
    // to emergency recovery instead of being classified only as source downtime.
    if (BigInt(view.height) < BigInt(state.checkpoint.height)
      || lower(view.blockHashes[Number(state.checkpoint.height)] ?? '') !== lower(state.checkpoint.tip)) {
      return await halt('verified private chain no longer extends durable checkpoint', false);
    }
    const progressed = BigInt(view.height) > BigInt(state.checkpoint.height);
    if (!progressed && now - state.lastProgressAt > maxNoProgressMs) {
      return await halt('verified private checkpoint stopped progressing', false);
    }
    if (state.incident) return await halt(state.incident.reason, false);
    try { await assertEthereumStable(); }
    catch (error) { return await halt(`Ethereum checkpoint unstable: ${error.message}`, false); }
    const next = {...state, checkpoint: {height: view.height, tip: view.tip},
      lastProgressAt: progressed ? now : state.lastProgressAt, observedAt: now,
      ethereum: {height: ethereum.number, hash: ethereum.hash}};
    try { await atomicJson(stateFile, next); }
    catch (error) { return await halt(`durable checkpoint write failed: ${error.message}`, false); }
    return {status: 'healthy', height: view.height, queued: queued.length, paid: released.length};
  } finally {
    await lock.close(); await fs.rm(`${stateFile}.lock`, {force: true});
  }
}
