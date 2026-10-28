// Candidate v3 monitor for the LOCAL private-note chain. Never a DOM light client.
// This module does not import a compiler, EVM fixture, wallet seed or signing service.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {constants as fsConstants} from 'node:fs';
import {createHash,randomBytes} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {Contract, getAddress, keccak256, TypedDataEncoder} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateJsonDurable} from '../sdk/durable-private-file.mjs';
import {parseStrictJson,parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {snapshotExecutablePath} from '../sdk/stable-executable.mjs';
import {burnTypes, domain as reserveDomain} from '../sdk/reserve.mjs';

const MAX_SNAPSHOT = 16 * 1024 * 1024;
const MAX_EVENTS = 10_000;
const EVENT_PAGE_BLOCKS=512;
const MAX_EVENT_PAGES=256;
const ZERO = '0x' + '00'.repeat(32);
const MONITOR_LOCK_SCHEMA='usdom-candidate-monitor-lock/v1';
const SOURCE_ID=/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
export const candidateBurnTypes = burnTypes;
const fields = candidateBurnTypes.Burn.map(x => x.name);
const lower = value => String(value).toLowerCase();
const hash = value => {
  assert.match(value, /^0x[0-9a-f]{64}$/i, 'invalid hash');
  return lower(value);
};
const uint = value => {
  assert.equal(typeof value, 'string', 'integers must be decimal strings');
  assert(value.length <= 78, 'integer exceeds uint256 lexical bound');
  assert.match(value, /^(0|[1-9][0-9]*)$/, 'noncanonical integer');
  const parsed=BigInt(value);
  assert(parsed < (1n<<256n), 'integer exceeds uint256');
  return parsed;
};
function exactKeys(value, expected, label) {
  assert(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} has unexpected fields`);
}

function validateEthereumSources(sources) {
  assert(Array.isArray(sources)&&sources.length>=2&&sources.length<=5,
    'two to five Ethereum RPC sources required');
  for(const [index,source] of sources.entries()) {
    exactKeys(source,['operatorId','providerId','infrastructureId','originKeccak256','provider'],
      `Ethereum RPC source ${index+1}`);
    for(const field of ['operatorId','providerId','infrastructureId']) {
      assert(typeof source[field]==='string'&&SOURCE_ID.test(source[field]),
        `Ethereum RPC source ${index+1} ${field} is invalid`);
    }
    hash(source.originKeccak256);
    assert(source.provider&&typeof source.provider.getNetwork==='function'
      &&typeof source.provider.getBlock==='function'&&typeof source.provider.getCode==='function'
      &&typeof source.provider.send==='function',`Ethereum RPC source ${index+1} provider is invalid`);
  }
  for(const field of ['operatorId','providerId','infrastructureId','originKeccak256']) {
    assert.equal(new Set(sources.map(source=>lower(source[field]))).size,sources.length,
      `Ethereum RPC ${field} identities must be distinct`);
  }
  return sources;
}

async function collectFinalizedEthereumView({reserve,sources,chainId,address,expectedCodeHash,domDomain,
  guardianAddress,deploymentBlock}) {
  // Anvil does not expose a useful finalized tag. The local-only chain ID uses
  // latest so the same adversarial monitor tests can execute; every other chain,
  // including Ethereum mainnet, is unconditionally pinned to finalized.
  const finalityTag=BigInt(chainId)===31337n?'latest':'finalized';
  const observations=await Promise.all(sources.map(async source=>{
    const provider=source.provider;
    const network=await provider.getNetwork();
    assert.equal(network.chainId,BigInt(chainId),'wrong Ethereum chain');
    const finalized=await provider.getBlock(finalityTag);
    assert(finalized&&Number.isSafeInteger(finalized.number)&&finalized.number>=deploymentBlock
      &&typeof finalized.hash==='string','finalized Ethereum head unavailable');
    return {source,provider,finalized};
  }));
  const height=Math.min(...observations.map(observation=>observation.finalized.number));
  const views=await Promise.all(observations.map(async observation=>{
    const {source,provider}=observation;
    const block=await provider.getBlock(height);
    assert(block&&block.number===height&&typeof block.hash==='string'
      &&Number.isSafeInteger(block.timestamp),'common finalized Ethereum block unavailable');
    const contract=reserve.connect(provider);
    const blockTag=height;
    const [code,domainValue,guardianValue,eip712]=await Promise.all([
      provider.getCode(address,blockTag),contract.domDomain({blockTag}),
      contract.guardian({blockTag}),contract.eip712Domain({blockTag}),
    ]);
    assert.equal(keccak256(code),lower(expectedCodeHash),'wrong reserve bytecode');
    assert.equal(lower(domainValue),lower(domDomain),'wrong reserve DOM domain');
    assert.equal(getAddress(guardianValue),guardianAddress,'wrong guardian');
    return {sourceId:source.operatorId,provider,contract,block,identity:{
      height:block.number,hash:lower(block.hash),timestamp:block.timestamp,
      codeHash:lower(keccak256(code)),domDomain:lower(domainValue),guardian:getAddress(guardianValue),
      eip712:{name:eip712.name,version:eip712.version,chainId:String(eip712.chainId),
        verifyingContract:getAddress(eip712.verifyingContract)},
    }};
  }));
  for(const view of views.slice(1)) assert.deepEqual(view.identity,views[0].identity,
    'independent Ethereum RPC sources disagree');
  return {height,block:views[0].block,views};
}

function normalizedEvent(event,fields,label,first,last) {
  const position=eventPosition(event,label,first,last);
  const args={};
  for(const field of fields) {
    const value=event.args[field];
    const canonical=value=>typeof value==='bigint'?value.toString():
      (typeof value==='string'&&value.startsWith('0x')?lower(value):
        (Array.isArray(value)?Array.from(value,canonical):value));
    args[field]=canonical(value);
  }
  return {...position,args};
}

async function consensusEvents(ethereumViews,name,fields,first,last) {
  const results=await Promise.all(ethereumViews.map(async view=>{
    const raw=await events(view.contract,name,first,last);
    return {raw,normalized:raw.map(event=>normalizedEvent(event,fields,name,first,last))};
  }));
  for(const result of results.slice(1)) assert.deepEqual(result.normalized,results[0].normalized,
    `independent Ethereum RPC sources disagree on ${name}`);
  return results[0].raw;
}

async function consensusContractRead(ethereumViews,label,read) {
  const values=await Promise.all(ethereumViews.map(view=>read(view.contract)));
  const normalized=values.map(value=>typeof value==='bigint'?value.toString():
    Array.from(value??[],entry=>typeof entry==='bigint'?entry.toString():
      (typeof entry==='string'&&entry.startsWith('0x')?lower(entry):entry)));
  for(const value of normalized.slice(1)) assert.deepEqual(value,normalized[0],
    `independent Ethereum RPC sources disagree on ${label}`);
  return values[0];
}

export function parseCandidateMonitorJson(text,label='candidate monitor JSON') {
  return parseStrictJson(text,{label,maxBytes:2*1024*1024,maxDepth:64});
}
function parseCandidateMonitorJsonBytes(bytes,label='candidate monitor JSON') {
  return parseStrictJsonBytes(bytes,{label,maxBytes:2*1024*1024,maxDepth:64});
}

async function linuxProcessIdentity(pid=process.pid) {
  const [bootId,stat]=await Promise.all([
    fs.readFile('/proc/sys/kernel/random/boot_id','utf8'),
    fs.readFile(`/proc/${pid}/stat`,'utf8'),
  ]);
  const suffix=stat.slice(stat.lastIndexOf(') ')+2).trim().split(/ +/u);
  assert(suffix.length>=20,'process identity is unavailable');
  const startTicks=suffix[19];
  assert.match(bootId.trim(),/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    'boot identity is invalid');
  assert.match(startTicks,/^[1-9][0-9]*$/,'process start identity is invalid');
  return {pid,bootId:bootId.trim().toLowerCase(),startTicks};
}
const lockDigest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function validateLockRecord(value) {
  exactKeys(value,['schema','owner','nonce','createdAt','recordSha256'],'candidate monitor lock');
  exactKeys(value.owner,['pid','bootId','startTicks'],'candidate monitor lock owner');
  assert.equal(value.schema,MONITOR_LOCK_SCHEMA,'candidate monitor lock schema is invalid');
  assert(Number.isSafeInteger(value.owner.pid)&&value.owner.pid>0,'candidate monitor lock PID is invalid');
  assert.match(value.owner.bootId,/^[0-9a-f-]{36}$/,'candidate monitor lock boot identity is invalid');
  assert.match(value.owner.startTicks,/^[1-9][0-9]*$/,'candidate monitor lock start identity is invalid');
  assert.match(value.nonce,/^[0-9a-f]{64}$/,'candidate monitor lock nonce is invalid');
  assert(Number.isSafeInteger(value.createdAt)&&value.createdAt>=0,'candidate monitor lock time is invalid');
  assert.match(value.recordSha256,/^[0-9a-f]{64}$/,'candidate monitor lock authenticator is invalid');
  const authenticated={schema:value.schema,owner:value.owner,nonce:value.nonce,createdAt:value.createdAt};
  assert.equal(value.recordSha256,lockDigest(authenticated),'candidate monitor lock authentication failed');
  return value;
}
async function processIdentityIsLive(owner) {
  try {
    const live=await linuxProcessIdentity(owner.pid);
    return live.bootId===owner.bootId&&live.startTicks===owner.startTicks;
  } catch (error) {
    if (['ENOENT','ESRCH'].includes(error.code)) return false;
    throw error;
  }
}
async function readLock(lockPath) {
  const handle=await fs.open(lockPath,fsConstants.O_RDONLY|fsConstants.O_NOFOLLOW);
  try {
    const stat=await handle.stat();
    assert(stat.isFile()&&stat.uid===process.getuid()&&stat.nlink===1&&(stat.mode&0o777)===0o600
      &&stat.size>0&&stat.size<=4096,'candidate monitor lock path policy mismatch');
    const bytes=await handle.readFile();
    const record=validateLockRecord(parseCandidateMonitorJsonBytes(bytes,'candidate monitor lock'));
    assert(bytes.equals(Buffer.from(`${JSON.stringify(record)}\n`)),'candidate monitor lock is not canonical');
    return {record,stat};
  } finally { await handle.close(); }
}
async function removeOrphanByInode(lockPath,expected) {
  const claim=`${lockPath}.recovery-${process.pid}-${randomBytes(16).toString('hex')}`;
  try {
    await fs.link(lockPath,claim);
    const claimed=await fs.lstat(claim);
    if(claimed.dev!==expected.dev||claimed.ino!==expected.ino) return false;
    const current=await fs.lstat(lockPath);
    if(current.dev!==expected.dev||current.ino!==expected.ino) return false;
    await fs.unlink(lockPath);
    return true;
  } catch(error) {
    if(['ENOENT','EEXIST'].includes(error.code)) return false;
    throw error;
  } finally { await fs.rm(claim,{force:true}); }
}
async function syncParent(filename) {
  const directory=await fs.open(path.dirname(filename),fsConstants.O_RDONLY|fsConstants.O_DIRECTORY);
  try { await directory.sync(); } finally { await directory.close(); }
}

/** Linux process-identity lock. An authenticated orphan is reclaimed with an
 * inode-checked hard-link claim, so PID reuse and concurrent recovery cannot
 * remove a replacement owner's lock. Malformed locks fail closed. */
export async function acquireCandidateMonitorLock(stateFile,{createdAt=Date.now()}={}) {
  assert(path.isAbsolute(stateFile),'monitor state path must be absolute');
  const lockPath=`${stateFile}.lock`;
  const owner=await linuxProcessIdentity();
  for(let attempt=0;attempt<4;attempt++) {
    let handle;
    try {
      handle=await fs.open(lockPath,'wx',0o600);
      const authenticated={schema:MONITOR_LOCK_SCHEMA,owner,
        nonce:randomBytes(32).toString('hex'),createdAt};
      const record={...authenticated,recordSha256:lockDigest(authenticated)};
      await handle.writeFile(`${JSON.stringify(record)}\n`);
      await handle.sync(); await syncParent(lockPath);
      const stat=await handle.stat();
      return {lockPath,handle,stat,record};
    } catch(error) {
      if(handle) { try { await handle.close(); } catch {} }
      if(error.code!=='EEXIST') throw error;
      const existing=await readLock(lockPath);
      if(await processIdentityIsLive(existing.record.owner)) {
        throw new Error('candidate monitor is already running');
      }
      if(!await removeOrphanByInode(lockPath,existing.stat)) continue;
      await syncParent(lockPath);
    }
  }
  throw new Error('candidate monitor lock contention did not converge');
}
export async function releaseCandidateMonitorLock(lock) {
  try {
    const current=await fs.lstat(lock.lockPath);
    const held=await lock.handle.stat();
    assert(current.dev===held.dev&&current.ino===held.ino&&current.nlink===1,
      'candidate monitor lock ownership changed');
    await fs.unlink(lock.lockPath); await syncParent(lock.lockPath);
  } finally { await lock.handle.close(); }
}

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
  let executableSnapshot;
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
      executableSnapshot??=await snapshotExecutablePath(binary);
      const {stdout,stderr}=await runPinnedExecutable(executableSnapshot,
        ['--network',networkDirectory,'--snapshot',snapshot,'--network-id',networkId],
        {timeout:timeoutMs,maxBuffer:2*1024*1024});
      assert.equal(stderr.length,0,'snapshot verifier wrote stderr');
      const verified=parseCandidateMonitorJsonBytes(stdout,'verified snapshot output');
      assert(stdout.equals(Buffer.from(`${JSON.stringify(verified)}\n`)),
        'verified snapshot output framing is not canonical');
      return verified;
    } finally { await fs.rm(temporary, {recursive: true, force: true}); }
  }};
}

export function compareViews(views, {networkId, domDomain, initialCheckpoint}) {
  assert(views.length >= 2, 'at least two configured sources required');
  for (const view of views) {
    exactKeys(view,['version','ordering','network','domDomain','height','tip','blockHashes','records'],
      'normalized view');
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
    const seen = new Set(); const seenRequests=new Set();
    for (const record of view.records) {
      exactKeys(record,['burnId','requestId','recipient','amount','asset','height','blockHash','confirmations'],
        'normalized burn record');
      const burnId=hash(record.burnId),requestId=hash(record.requestId);
      assert(!seen.has(burnId), 'duplicate burn record'); seen.add(burnId);
      assert(!seenRequests.has(requestId),'duplicate burn request');seenRequests.add(requestId);
      getAddress(record.recipient);
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
  await writePrivateJsonDurable(filename,value,{maximum:1024*1024});
}
function eventPosition(event,label,first,last) {
  assert.equal(event.removed??false,false,`${label} contains a removed log`);
  assert(Number.isSafeInteger(event.blockNumber)&&event.blockNumber>=first
    &&event.blockNumber<=last,`${label} block is outside the requested range`);
  assert.match(event.blockHash,/^0x[0-9a-f]{64}$/i,`${label} block hash is invalid`);
  assert.match(event.transactionHash,/^0x[0-9a-f]{64}$/i,`${label} transaction hash is invalid`);
  const transactionIndex=event.transactionIndex;
  const logIndex=event.index??event.logIndex;
  assert(Number.isSafeInteger(transactionIndex)&&transactionIndex>=0,
    `${label} transaction index is invalid`);
  assert(Number.isSafeInteger(logIndex)&&logIndex>=0,`${label} log index is invalid`);
  return {blockNumber:event.blockNumber,transactionIndex,logIndex,
    identity:`${lower(event.blockHash)}:${lower(event.transactionHash)}:${logIndex}`};
}

export function validateEventSequence(input,label,first,last) {
  assert(Array.isArray(input),`${label} log page is invalid`);
  assert(input.length<=MAX_EVENTS,`${label} event bound exceeded`);
  const seen=new Set(); let previous=null;
  for(const event of input) {
    const position=eventPosition(event,label,first,last);
    assert(!seen.has(position.identity),`${label} contains a duplicate log`);
    seen.add(position.identity);
    if(previous) assert(position.blockNumber>previous.blockNumber
      ||(position.blockNumber===previous.blockNumber
        &&(position.transactionIndex>previous.transactionIndex
          ||(position.transactionIndex===previous.transactionIndex
            &&position.logIndex>previous.logIndex))),`${label} logs are not canonically ordered`);
    previous=position;
  }
  return input;
}
export function assertBoundedEventRange(first,last) {
  assert(Number.isSafeInteger(first)&&Number.isSafeInteger(last)&&first>=0&&last>=first,
    'event range is invalid');
  const pages=Math.ceil((last-first+1)/EVENT_PAGE_BLOCKS);
  assert(pages<=MAX_EVENT_PAGES,'event scan exceeds the bounded archival window');
  return pages;
}
async function events(reserve, name, first, last) {
  assertBoundedEventRange(first,last);
  const result = [];
  for (let from = first; from <= last; from += EVENT_PAGE_BLOCKS) {
    const to=Math.min(from+EVENT_PAGE_BLOCKS-1,last);
    const page=validateEventSequence(await reserve.queryFilter(reserve.filters[name](),from,to),
      name,from,to);
    result.push(...page);
    assert(result.length <= MAX_EVENTS, 'event scan requires archival checkpointing');
  }
  validateEventSequence(result,name,first,last);
  return result;
}
export function nextEventRange(deploymentBlock,checkpointHeight,headNumber) {
  assert(Number.isSafeInteger(deploymentBlock)&&deploymentBlock>=0,'deployment block is invalid');
  assert(checkpointHeight===null||(Number.isSafeInteger(checkpointHeight)
    &&checkpointHeight>=deploymentBlock),'event cursor is invalid');
  assert(Number.isSafeInteger(headNumber)&&headNumber>=deploymentBlock,'Ethereum head is invalid');
  const first=checkpointHeight===null?deploymentBlock:checkpointHeight+1;
  if(first>headNumber) return null;
  const capacity=EVENT_PAGE_BLOCKS*MAX_EVENT_PAGES;
  return {first,last:Math.min(headNumber,first+capacity-1)};
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
export async function monitorOnce({reserve, guardian, sources, ethereumSources, networkId, domDomain, expectedCodeHash,
  chainId, deploymentBlock, initialCheckpoint, stateFile, confirmations = 2,
  maxNoProgressMs = 300_000, sourceTimeoutMs = 30_000,minimumCycleIntervalMs=5_000,
  now = Date.now()}) {
  hash(networkId); hash(domDomain); hash(expectedCodeHash);
  assert(Number.isSafeInteger(deploymentBlock) && deploymentBlock >= 0);
  assert(Number.isSafeInteger(confirmations) && confirmations >= 2);
  assert(Number.isSafeInteger(maxNoProgressMs) && maxNoProgressMs > 0);
  assert(Number.isSafeInteger(sourceTimeoutMs)&&sourceTimeoutMs>=1_000&&sourceTimeoutMs<=120_000,
    'source timeout is outside the bounded policy');
  assert(Number.isSafeInteger(minimumCycleIntervalMs)&&minimumCycleIntervalMs>=1_000
    &&minimumCycleIntervalMs<=60_000,'cycle interval is outside the bounded policy');
  assert(Number.isSafeInteger(now) && now >= 0);
  exactKeys(initialCheckpoint,['height','tip'],'initial private checkpoint');
  assert(uint(initialCheckpoint.height)<=1024n,'initial private checkpoint height is outside policy');
  hash(initialCheckpoint.tip);
  assert(Array.isArray(sources)&&sources.length>=2&&sources.length<=5
    &&sources.every(source=>typeof source?.id==='string'&&/^[a-zA-Z0-9._:-]{1,64}$/.test(source.id)
      &&typeof source.read==='function')
    &&new Set(sources.map(s => s.id)).size === sources.length,
    'distinct source identities required; endpoints do not prove operator independence');
  validateEthereumSources(ethereumSources);
  assert(path.isAbsolute(stateFile));
  const lock = await acquireCandidateMonitorLock(stateFile,{createdAt:now});
  try {
    const provider = reserve.runner.provider ?? reserve.runner;
    const address = getAddress(await reserve.getAddress());
    const guardianAddress=getAddress(await guardian.getAddress());
    const domain = reserveDomain(String(chainId), address);
    // Validate the locally pinned transaction target before any error path can
    // ask the guardian to sign a pause. RPC quorum disagreement may safely stop
    // this known contract; a wrong chain/address/bytecode configuration may not.
    assert.equal((await provider.getNetwork()).chainId,BigInt(chainId),'wrong Ethereum chain');
    assert.equal(keccak256(await provider.getCode(address)),lower(expectedCodeHash),
      'wrong reserve bytecode');
    assert.equal(lower(await reserve.domDomain()),lower(domDomain),'wrong reserve DOM domain');
    assert.equal(getAddress(await reserve.guardian()),guardianAddress,'wrong guardian');
    const localDomain=await reserve.eip712Domain();
    assert.equal(localDomain.name,domain.name,'wrong EIP-712 name');
    assert.equal(localDomain.version,domain.version,'wrong EIP-712 version');
    assert.equal(localDomain.chainId,domain.chainId,'wrong EIP-712 chain');
    assert.equal(getAddress(localDomain.verifyingContract),address,'wrong EIP-712 reserve');
    const binding = {network: lower(networkId), domDomain: lower(domDomain), chainId: String(chainId),
      reserve: address, codeHash: lower(expectedCodeHash), deploymentBlock, initialCheckpoint,
      sourceIds: sources.map(s => s.id).sort(), ethereumSources:ethereumSources.map(source=>({
        operatorId:source.operatorId,providerId:source.providerId,
        infrastructureId:source.infrastructureId,originKeccak256:lower(source.originKeccak256),
      })).sort((a,b)=>a.operatorId<b.operatorId?-1:a.operatorId>b.operatorId?1:0),
      confirmations,maxNoProgressMs,minimumCycleIntervalMs};
    let state; let checkpointError; let loadedState=false;
    try {
      const content = await readDirectFile(stateFile,{
        minimum:1,maximum:1024*1024,privateMode:true,label:'monitor checkpoint',
      });
      state = parseCandidateMonitorJson(content.toString('utf8'),'monitor checkpoint');
      loadedState=true;
      exactKeys(state,['version','binding','checkpoint','lastProgressAt','observedAt','ethereum','incident'],
        'monitor checkpoint');
      assert.equal(state.version, 1, 'unsupported monitor checkpoint');
      assert.deepEqual(state.binding,parseCandidateMonitorJson(JSON.stringify(binding),'monitor binding'),
        'monitor checkpoint configuration changed');
      assert(Number.isSafeInteger(state.observedAt) && now >= state.observedAt, 'clock moved backwards');
      assert(Number.isSafeInteger(state.lastProgressAt) && state.lastProgressAt <= state.observedAt);
      exactKeys(state.checkpoint,['height','tip'],'monitor private checkpoint');
      uint(state.checkpoint.height); hash(state.checkpoint.tip);
      if (state.ethereum) {
        exactKeys(state.ethereum,['height','hash'],'monitor Ethereum checkpoint');
        assert(Number.isSafeInteger(state.ethereum.height) && state.ethereum.height >= deploymentBlock);
        hash(state.ethereum.hash);
      }
      if (state.incident) {
        exactKeys(state.incident,state.incident.emergency
          ?['reason','emergency','observedAt','epoch']:['reason','emergency','observedAt'],'monitor incident');
        assert(typeof state.incident.reason === 'string'&&state.incident.reason.length>0
          &&state.incident.reason.length<=512&&/^[\x20-\x7e]+$/.test(state.incident.reason)
          &&typeof state.incident.emergency === 'boolean');
        assert(Number.isSafeInteger(state.incident.observedAt)&&state.incident.observedAt<=state.observedAt);
        if (state.incident.emergency) uint(state.incident.epoch);
      }
    } catch (error) {
      if (error.code !== 'ENOENT') checkpointError = error;
      state = {version: 1, binding, checkpoint: initialCheckpoint, lastProgressAt: now,
        observedAt: now, ethereum: null, incident: null};
    }
    if(loadedState&&!checkpointError&&!state.incident&&now-state.observedAt<minimumCycleIntervalMs) {
      return {status:'throttled',retryAt:state.observedAt+minimumCycleIntervalMs};
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
        if (!await reserve.paused() || revokeCurrent) {
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
          // pauseEpoch is deliberately idempotent for the same generation. Calling
          // it above removes the need to reconstruct the active set from unbounded
          // historical logs; recoveryRequired is the contract's durable assertion.
        }
        if (emergency) assert(finalEpoch >= BigInt(incidentEpoch), 'incident generation regressed');
        if (journalError) throw new Error('paused, but durable incident journal failed');
      } catch (error) {
        // Never convert a failed emergency action into a reported operational success.
        const failure=new Error('candidate monitor pause failed',{cause:error});
        failure.monitorPauseFailure=true;
        throw failure;
      }
      return {status: 'paused', emergency, reason};
    };
    if (checkpointError) return await halt('durable checkpoint invalid',false);
    // An incident is latched across restarts. An operator must investigate and
    // provision a new checkpoint/state path; this code never approves resumption.
    if (state.incident?.emergency) return await halt(state.incident.reason, true);
    let view; let ethereum; let ethereumViews;
    try {
      const consensus=await collectFinalizedEthereumView({reserve,sources:ethereumSources,chainId,address,
        expectedCodeHash,domDomain,guardianAddress,deploymentBlock});
      ethereum=consensus.block; ethereumViews=consensus.views;
      const onchainDomain=ethereumViews[0].identity.eip712;
      assert.equal(onchainDomain.name,domain.name,'wrong EIP-712 name');
      assert.equal(onchainDomain.version,domain.version,'wrong EIP-712 version');
      assert.equal(onchainDomain.chainId,String(domain.chainId),'wrong EIP-712 chain');
      assert.equal(onchainDomain.verifyingContract,address,'wrong EIP-712 reserve');
      assert(now - ethereum.timestamp * 1000 <= maxNoProgressMs
        && ethereum.timestamp * 1000 - now <= 60_000, 'Ethereum head stale or clock invalid');
      if (state.ethereum) {
        const old=await Promise.all(ethereumViews.map(entry=>entry.provider.getBlock(state.ethereum.height)));
        assert(old.every(block=>lower(block?.hash??'')===lower(state.ethereum.hash)),
          'Ethereum checkpoint reorganized or RPC sources disagree');
        assert(ethereum.number >= state.ethereum.height, 'Ethereum head regressed');
      }
      const views=await Promise.all(sources.map(s => timedRead(s,sourceTimeoutMs)));
      try { view=compareViews(views,{networkId,domDomain,initialCheckpoint}); }
      catch { return await halt('independent sources disagree',false); }
    } catch (error) { return await halt('source unavailable or untrusted', false); }
    let range; let scanBlock;
    try {
      range=nextEventRange(deploymentBlock,state.ethereum?.height??null,ethereum.number);
      const scanBlocks=range
        ?await Promise.all(ethereumViews.map(entry=>entry.provider.getBlock(range.last))):[ethereum];
      scanBlock=scanBlocks[0];
      assert(scanBlock&&scanBlock.number===(range?.last??ethereum.number),'event cursor block unavailable');
      assert(scanBlocks.every(block=>lower(block?.hash??'')===lower(scanBlock.hash)),
        'independent Ethereum RPC sources disagree on event cursor');
    } catch(error) { return await halt('Ethereum event cursor unavailable or inconsistent',false); }
    const assertEthereumStable = async () => {
      // Bypass getBlock's short-lived provider cache when checking for a reorg
      // across proof verification and log/state queries at a numeric block tag.
      const blocks=await Promise.all(ethereumViews.map(entry=>entry.provider.send(
        'eth_getBlockByNumber',['0x'+ethereum.number.toString(16),false])));
      assert(blocks.every(block=>lower(block?.hash??'')===lower(ethereum.hash)),
        'Ethereum checkpoint changed or RPC sources disagree during monitoring');
      const cursorBlocks=await Promise.all(ethereumViews.map(entry=>entry.provider.send(
        'eth_getBlockByNumber',['0x'+scanBlock.number.toString(16),false])));
      assert(cursorBlocks.every(block=>lower(block?.hash??'')===lower(scanBlock.hash)),
        'Ethereum event cursor changed or RPC sources disagree during monitoring');
    };

    let queued; let certificates; let released; let epoch; let reserveState;
    try {
      [queued, certificates, released, epoch,reserveState] = await Promise.all([
        range?consensusEvents(ethereumViews,'WithdrawalQueued',
          ['burnId','requestId','digest','readyAt','expiresAt'],range.first,range.last):[],
        range?consensusEvents(ethereumViews,'WithdrawalCertificate',['burnId','certificate'],
          range.first,range.last):[],
        range?consensusEvents(ethereumViews,'Released',
          ['burnId','requestId','recipient','amount','height','blockHash','epoch'],range.first,range.last):[],
        consensusContractRead(ethereumViews,'current epoch',
          contract=>contract.currentEpoch({blockTag:ethereum.number})),
        consensusContractRead(ethereumViews,'reserve solvency and outflow state',async contract=>{
          const blockTag=ethereum.number;
          const tokenAddress=await contract.token({blockTag});
          const token=new Contract(tokenAddress,
            ['function balanceOf(address) view returns (uint256)'],contract.runner);
          return Promise.all([
            contract.totalDeposited({blockTag}),contract.totalReleased({blockTag}),
            contract.outstanding({blockTag}),token.balanceOf(address,{blockTag}),
            contract.outflowCapacity({blockTag}),contract.availableOutflow({blockTag}),
            contract.paused({blockTag}),contract.recoveryRequired({blockTag}),
          ]);
        }),
      ]);
      const [deposited,totalReleased,outstanding,reserveBalance,outflowCapacity,availableOutflow]=reserveState;
      if(totalReleased>deposited||outstanding!==deposited-totalReleased
        ||reserveBalance<outstanding||availableOutflow>outflowCapacity) {
        return await halt('reserve accounting or solvency invariant violated',true,epoch);
      }
      const certs = new Map();
      for (const event of certificates) {
        const burn = Object.fromEntries(fields.map(f => [f, event.args.certificate[f]]));
        assert.equal(lower(event.args.burnId), lower(burn.burnId));
        const digest=TypedDataEncoder.hash(domain,candidateBurnTypes,burn);
        assert(!certs.has(digest),'duplicate withdrawal certificate event');
        certs.set(digest,burn);
      }
      const checked = new Set();
      for (const event of queued) {
        const burnId=lower(event.args.burnId);
        assert(!checked.has(burnId),'duplicate withdrawal queue event');
        checked.add(burnId);
        const pending=await consensusContractRead(ethereumViews,`pending withdrawal ${burnId}`,
          contract=>contract.pendingWithdrawals(burnId,{blockTag:ethereum.number}));
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
      const paidBurns=new Set(); const paidRequests=new Set();
      for (const event of released) {
        const burn = Object.fromEntries(['burnId', 'requestId', 'recipient', 'amount', 'height', 'blockHash', 'epoch']
          .map(f => [f, event.args[f]]));
        assert(!paidBurns.has(lower(burn.burnId))&&!paidRequests.has(lower(burn.requestId)),
          'duplicate release identity');
        paidBurns.add(lower(burn.burnId)); paidRequests.add(lower(burn.requestId));
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
      return await halt('Ethereum history unavailable or inconsistent', false);
    }
    // Evaluate ancestry after obligations so a provably orphaned payout escalates
    // to emergency recovery instead of being classified only as source downtime.
    if (BigInt(view.height) < BigInt(state.checkpoint.height)
      || lower(view.blockHashes[Number(state.checkpoint.height)] ?? '') !== lower(state.checkpoint.tip)) {
      // The durable private checkpoint sealed every queue/release examined before
      // the Ethereum cursor advanced. Replacing that ancestry can invalidate an
      // already-paid burn even though its old Ethereum log is intentionally not
      // rescanned, so treat it as key-compromise severity.
      return await halt('verified private chain no longer extends durable checkpoint', true, epoch);
    }
    const progressed = BigInt(view.height) > BigInt(state.checkpoint.height);
    if (!progressed && now - state.lastProgressAt > maxNoProgressMs) {
      return await halt('verified private checkpoint stopped progressing', false);
    }
    if (state.incident) return await halt(state.incident.reason, false);
    try { await assertEthereumStable(); }
    catch (error) { return await halt('Ethereum checkpoint unstable', false); }
    const next = {...state, checkpoint: {height: view.height, tip: view.tip},
      lastProgressAt: progressed ? now : state.lastProgressAt, observedAt: now,
      ethereum: {height: scanBlock.number, hash: scanBlock.hash}};
    if(scanBlock.number<ethereum.number&&!await reserve.paused()) {
      try {
        const receipt=await (await reserve.connect(guardian).pauseOperational()).wait();
        assert(receipt?.status===1&&await reserve.paused(),'indexing pause not confirmed');
      } catch(error) {
        const failure=new Error('candidate monitor indexing pause failed',{cause:error});
        failure.monitorPauseFailure=true;
        throw failure;
      }
    }
    try { await atomicJson(stateFile, next); }
    catch (error) { return await halt('durable checkpoint write failed', false); }
    if(scanBlock.number<ethereum.number) {
      // Never report a partially indexed history as healthy. Production starts
      // paused, so a large historical import can advance one durable bounded
      // chunk per cycle without granting authority to resume.
      return {status:'indexing',from:range.first,to:range.last,head:ethereum.number};
    }
    if(reserveState[6]) {
      return {status:'paused',emergency:reserveState[7],reason:'reserve already paused'};
    }
    return {status: 'healthy', height: view.height, queued: queued.length, paid: released.length};
  } finally {
    await releaseCandidateMonitorLock(lock);
  }
}
