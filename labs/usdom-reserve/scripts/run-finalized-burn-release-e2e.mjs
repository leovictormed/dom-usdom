import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {lstat,mkdir,open,readFile,readdir} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ContractFactory,JsonRpcProvider,getAddress,hexlify,id,keccak256} from 'ethers';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurable,writePrivateJsonDurable} from '../sdk/durable-private-file.mjs';
import {collectFinalizedBurnArtifacts} from '../sdk/finalized-burn-artifact-collector.mjs';
import {
  FINALIZED_BURN_E2E_REPORT_SCHEMA,finalizedBurnReleaseEvmReceiptCommitment,
  validateFinalizedBurnE2eReport,
} from '../sdk/finalized-burn-e2e-report.mjs';
import {proofReserveConfigurationFromRelease} from '../sdk/finalized-burn-submission.mjs';
import {parseProverResourceMetrics} from '../sdk/prover-resource-metrics.mjs';
import {requireRisc0RecursionArtifact} from '../sdk/risc0-recursion-artifact.mjs';
import {validateReleaseSourceBoundary} from '../sdk/release-source-boundary.mjs';
import {observePinnedRiscZeroRuntime} from '../sdk/risc0-capacity-runtime-observer.mjs';
import {
  PINNED_RISC0_MAINNET_V3,validateRiscZeroMainnetReference,
} from '../sdk/risc0-verifier-reference.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {finalizedBurnVerifierConfigHash} from '../sdk/verifier-config.mjs';

const labRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repositoryRoot=path.resolve(labRoot,'../..');
const projectRelative=path.relative(repositoryRoot,labRoot).split(path.sep).join('/');
const currentUid=process.getuid();
const artifactRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-release/finalized-burn');
const runsRoot=path.join(artifactRoot,'runs');
const releaseRelative='config/proof-reserve.unconfigured.json';
const verifierRelative='config/finalized-burn-verifier.unconfigured.json';
const evidenceRelative='config/mainnet-release-evidence.unconfigured.json';
const remoteVariables=Object.freeze([
  'BONSAI_API_URL','BONSAI_API_KEY','BONSAI_POLL_INTERVAL_MS','RISC0_SERVER_PATH',
  'RISC0_SERVER_ADDR','RISC0_EXECUTOR','RISC0_PPROF_OUT',
  'RISC0_PPROF_ENABLE_INLINE_FUNCTIONS','RISC0_KECCAK_PO2','RISC0_DEFAULT_PROVER_NUM_GPUS',
  'RISC0_INFO','RISC0_REDIS_CHANNEL_SIZE',
]);
const rpcSources=Object.freeze([
  Object.freeze({sourceId:'drpc',url:'https://eth.drpc.org/'}),
  Object.freeze({sourceId:'publicnode',url:'https://ethereum-rpc.publicnode.com/'}),
]);
let activeStatus=null;

const rawSha=value=>createHash('sha256').update(value).digest('hex');
async function privateFileSha(target,options) {
  const bytes=await readDirectFile(target,options);
  try { return rawSha(bytes); }
  finally { bytes.fill(0); }
}
function fail(message) { throw new Error(message); }

async function requireDirectory(target,{privateMode=true}={}) {
  const metadata=await lstat(target);
  if(!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid!==currentUid
      || (privateMode && (metadata.mode&0o077)!==0)) {
    fail(`unsafe finalized-burn release directory: ${target}`);
  }
}

async function ensurePrivateDirectory(target) {
  try { await mkdir(target,{mode:0o700}); }
  catch(error) { if(error?.code!=='EEXIST') throw error; }
  await requireDirectory(target);
}

async function createPrivateDirectory(target) {
  await mkdir(target,{mode:0o700});
  await requireDirectory(target);
}

async function directFile(target,{minimum=1,maximum=512*1024*1024,privateMode=false}={}) {
  return readDirectFile(target,{minimum,maximum,privateMode,label:'finalized-burn release file'});
}

async function strictJsonFile(target,label,{maximum=16*1024*1024}={}) {
  const bytes=await directFile(target,{maximum});
  return parseStrictJson(bytes.toString('utf8'),{label,maxBytes:maximum,maxDepth:64});
}

async function atomicJson(target,value) {
  await writePrivateJsonDurable(target,value);
}

async function runCommand(command,args,{cwd,env=process.env,log}) {
  const output=await open(log,'w',0o600);
  try {
    const child=spawn(command,args,{cwd,env,stdio:['ignore',output.fd,output.fd]});
    const result=await new Promise((resolve,reject)=>{
      child.once('error',reject); child.once('close',(code,signal)=>resolve({code,signal}));
    });
    if(result.code!==0) fail(`${path.basename(command)} failed (${result.signal??result.code}); see ${log}`);
  } finally { await output.close(); }
}

async function captureCommand(command,args,{cwd,maximum=16*1024*1024}={}) {
  const child=spawn(command,args,{cwd,stdio:['ignore','pipe','pipe']});
  const chunks=[]; let length=0;
  const append=chunk=>{ length+=chunk.length; if(length>maximum) child.kill('SIGKILL');
    else chunks.push(Buffer.from(chunk)); };
  child.stdout.on('data',append); child.stderr.on('data',append);
  const result=await new Promise((resolve,reject)=>{
    child.once('error',reject); child.once('close',(code,signal)=>resolve({code,signal}));
  });
  if(length>maximum || result.code!==0) {
    fail(`${path.basename(command)} inspection failed (${result.signal??result.code})`);
  }
  return Buffer.concat(chunks,length).toString('utf8');
}

async function ensureArtifactHierarchy() {
  const local=path.join(os.homedir(),'.local'),share=path.join(local,'share');
  await requireDirectory(local,{privateMode:false}); await requireDirectory(share,{privateMode:false});
  for(const directory of [path.join(share,'dom-usdom'),path.join(share,'dom-usdom/prover-release'),
    artifactRoot,runsRoot]) await ensurePrivateDirectory(directory);
}

async function copyPrivateTree(source,destination,state={files:0,bytes:0n}) {
  await requireDirectory(source); await ensurePrivateDirectory(destination);
  const entries=(await readdir(source,{withFileTypes:true}))
    .sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
  for(const entry of entries) {
    if(entry.name==='' || entry.name==='.' || entry.name==='..' || entry.name.includes('\0')) {
      fail('noncanonical finalized-burn source filename');
    }
    const from=path.join(source,entry.name),to=path.join(destination,entry.name);
    const metadata=await lstat(from);
    if(metadata.isSymbolicLink()) fail(`finalized-burn source contains a symlink: ${from}`);
    if(metadata.isDirectory()) await copyPrivateTree(from,to,state);
    else if(metadata.isFile()) {
      const bytes=await directFile(from,{privateMode:true});
      state.files+=1; state.bytes+=BigInt(bytes.length);
      if(state.files>64 || state.bytes>64n*1024n*1024n) fail('finalized-burn source exceeds its bound');
      await writePrivateFileDurable(to,bytes,{maximum:512*1024*1024});
    } else fail(`unsupported finalized-burn source entry: ${from}`);
  }
  return state;
}

function proverEnvironment() {
  const environment={...process.env,RAYON_NUM_THREADS:'1',MALLOC_ARENA_MAX:'2',
    CARGO_BUILD_JOBS:'1',RISC0_PROVER:'local',RISC0_DEV_MODE:'0'};
  for(const name of remoteVariables) delete environment[name];
  return environment;
}

async function requireCapacity() {
  const memory=await readFile('/proc/meminfo','utf8');
  const available=memory.match(/^MemAvailable:\s+([0-9]+) kB$/m)?.[1];
  if(!available || BigInt(available)<3n*1024n*1024n || os.availableParallelism()<1) {
    fail('finalized-burn release proving requires one CPU and 3 GiB of available RAM');
  }
}

async function timedCargo(name,args,{cwd,runRoot,env}) {
  await requireCapacity();
  await runCommand('/usr/bin/time',['-v','-o',path.join(runRoot,`${name}-time.log`),'cargo',...args],{
    cwd,env,log:path.join(runRoot,`${name}.log`),
  });
}

const cargoRun=(binary,{release=false,features=null}={})=>[
  'run','--quiet',...(release?['--release']:[]),'--locked','--manifest-path',
  path.join(repositoryRoot,'Cargo.toml'),'-p','dom-usdom-finalized-burn-proof-host',
  ...(features?['--features',features]:[]),'--bin',binary,
];

async function rpc({source,method,params}) {
  try {
    const response=await fetch(source.url,{method:'POST',redirect:'error',
      headers:{accept:'application/json','content-type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(20_000)});
    if(!response.ok) fail(`HTTP ${response.status}`);
    const declared=response.headers.get('content-length');
    if(declared!==null && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared)>262144n)) {
      fail(`${method} response exceeds its byte bound`);
    }
    if(!response.body) fail(`${method} response has no body`);
    const reader=response.body.getReader(),chunks=[]; let length=0;
    for(;;) {
      const {done,value}=await reader.read(); if(done) break;
      length+=value.length;
      if(length>262144) { await reader.cancel(); fail(`${method} response exceeds its byte bound`); }
      chunks.push(Buffer.from(value));
    }
    let text;
    try { text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,length)); }
    catch { fail(`${method} response is not valid UTF-8`); }
    const body=parseStrictJson(text,{
      label:`${method} response`,maxBytes:262144,
    });
    if(!body || typeof body!=='object' || Array.isArray(body)
        || JSON.stringify(Object.keys(body).sort())!==JSON.stringify(['id','jsonrpc','result'])
        || body.jsonrpc!=='2.0' || body.id!==1 || body.result==null) {
      fail(`${method} returned an invalid JSON-RPC response`);
    }
    return body.result;
  } catch(error) {
    fail(`release source ${source.sourceId} failed`);
  }
}

async function freePort() {
  const server=createServer();
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const address=server.address();
  if(!address || typeof address==='string') fail('cannot allocate an isolated Anvil port');
  await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
  return address.port;
}

async function waitForAnvil(provider,child) {
  for(let attempt=0;attempt<300;attempt++) {
    if(child.exitCode!==null) fail(`Anvil exited before readiness: ${child.exitCode}`);
    try { if(await provider.send('eth_chainId',[])==='0x1') return; } catch {}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  fail('Anvil did not become ready');
}

async function terminate(child) {
  if(child.exitCode!==null) return;
  child.kill('SIGTERM');
  await Promise.race([new Promise(resolve=>child.once('close',resolve)),
    new Promise(resolve=>setTimeout(resolve,5000))]);
  if(child.exitCode===null) child.kill('SIGKILL');
}

async function verifyOnIsolatedEvm({observation,seal,statementHash,release,verifier,runRoot,
  adapterArtifact}) {
  if(seal.length!==260 || hexlify(seal.subarray(0,4)).toLowerCase()!=='0x73c457ba') {
    fail('finalized-burn EVM seal is not the canonical selector-prefixed 260-byte proof');
  }
  const port=await freePort();
  const anvilLog=await open(path.join(runRoot,'anvil.log'),'w',0o600);
  const child=spawn(process.env.USDOM_ANVIL??'anvil',[
    '--host','127.0.0.1','--port',String(port),'--chain-id','1','--silent',
  ],{stdio:['ignore',anvilLog.fd,anvilLog.fd]});
  const provider=new JsonRpcProvider(`http://127.0.0.1:${port}`,1,{staticNetwork:true,cacheTimeout:-1});
  try {
    await waitForAnvil(provider,child);
    await provider.send('anvil_setCode',[observation.riscZeroVerifier,observation.runtimeCode]);
    if(keccak256(await provider.getCode(observation.riscZeroVerifier))!==observation.runtimeCodeHash) {
      fail('Anvil verifier runtime differs from the finalized observation');
    }
    const signer=await provider.getSigner(0);
    const adapter=await new ContractFactory(adapterArtifact.abi,
      adapterArtifact.bytecode.object,signer).deploy(
      observation.riscZeroVerifier,verifier.finalizedBurnGuestImageId,
    );
    await adapter.waitForDeployment();
    const address=await adapter.getAddress();
    const [verifierGasLimit,journalDigest]=await Promise.all([
      adapter.RISC_ZERO_VERIFIER_GAS_LIMIT(),adapter.journalDigest(statementHash),
    ]);
    const expectedJournalDigest='0x'+createHash('sha256')
      .update(Buffer.from(statementHash.slice(2),'hex')).digest('hex');
    if(verifierGasLimit!==4_500_000n || journalDigest.toLowerCase()!==expectedJournalDigest) {
      fail('finalized-burn adapter receipt boundary differs from the host journal/gas policy');
    }
    const runtimeCodeHash=keccak256(await provider.getCode(address));
    const configHash=await adapter.verifierConfigHash();
    if(runtimeCodeHash.toLowerCase()!==release.verifierCodeHash.toLowerCase()
        || configHash.toLowerCase()!==release.verifierConfigHash.toLowerCase()) {
      fail('isolated finalized-burn adapter differs from the exact release identity');
    }
    const proof=hexlify(seal);
    if(await adapter.verifyFinalizedBurn.staticCall(statementHash,proof)
        !==id('USDOM_FINALIZED_BURN_PROOF_V1')) fail('finalized-burn adapter returned the wrong commitment');
    const data=adapter.interface.encodeFunctionData('verifyFinalizedBurn',[statementHash,proof]);
    const transaction=await signer.sendTransaction({to:address,data,gasLimit:5_000_000n});
    const receipt=await transaction.wait();
    if(!receipt || receipt.status!==1 || receipt.gasUsed===0n || receipt.gasUsed>5_000_000n) {
      fail('isolated finalized-burn verification failed or exceeded the gas cap');
    }
    const receiptTranscript=finalizedBurnReleaseEvmReceiptCommitment({
      transactionHash:receipt.hash,blockHash:receipt.blockHash,
      blockNumber:String(receipt.blockNumber),adapter:address,
      adapterRuntimeCodeHash:runtimeCodeHash,verifierConfigHash:configHash,
      statementHash,evmSealSha256:rawSha(seal),
      evmVerificationGas:receipt.gasUsed.toString(),
    });
    await writePrivateFileDurable(path.join(runRoot,'isolated-evm-receipt.json'),
      Buffer.from(receiptTranscript.canonicalTranscript));
    return {adapterRuntimeCodeHash:runtimeCodeHash,adapterVerifierConfigHash:configHash,
      evmVerificationGas:receipt.gasUsed.toString(),evmCallAccepted:true,
      isolatedEvmTransactionHash:receiptTranscript.record.transactionHash,
      isolatedEvmBlockHash:receiptTranscript.record.blockHash,
      isolatedEvmBlockNumber:receiptTranscript.record.blockNumber,
      isolatedEvmReceiptSha256:receiptTranscript.sha256};
  } finally { provider.destroy(); await terminate(child); await anvilLog.close(); }
}

async function snapshotFinalizedBurnAdapterArtifact(runRoot) {
  const source=path.join(labRoot,
    'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json');
  const bytes=await directFile(source,{maximum:16*1024*1024});
  const artifact=parseStrictJson(bytes.toString('utf8'),{
    label:'finalized-burn adapter artifact',maxBytes:16*1024*1024,maxDepth:64,
  });
  const snapshotDirectory=path.join(runRoot,'input-snapshots');
  await createPrivateDirectory(snapshotDirectory);
  const snapshot=path.join(snapshotDirectory,'finalized-burn-adapter-artifact.json');
  await writePrivateFileDurable(snapshot,bytes,{maximum:16*1024*1024});
  const installed=await directFile(snapshot,{maximum:16*1024*1024,privateMode:true});
  const expectedSha256=rawSha(bytes);
  if(!installed.equals(bytes) || rawSha(installed)!==expectedSha256) {
    fail('finalized-burn adapter artifact snapshot changed during installation');
  }
  return artifact;
}

export async function snapshotFinalizedBurnReleaseMetricLogs(runRoot) {
  const inputSnapshots=path.join(runRoot,'input-snapshots');
  await ensurePrivateDirectory(inputSnapshots);
  const snapshotDirectory=path.join(inputSnapshots,'metric-logs');
  await ensurePrivateDirectory(snapshotDirectory);
  const snapshots=new Map();
  for(const name of ['prover-time.log','compression-time.log']) {
    const source=path.join(runRoot,name);
    const bytes=await directFile(source,{maximum:1024*1024,privateMode:true});
    const sha256=rawSha(bytes),snapshot=path.join(snapshotDirectory,name);
    await writePrivateFileDurable(snapshot,bytes,{maximum:1024*1024});
    const installed=await directFile(snapshot,{maximum:1024*1024,privateMode:true});
    if(!installed.equals(bytes) || rawSha(installed)!==sha256) {
      fail(`finalized-burn metric-log snapshot changed during installation: ${name}`);
    }
    snapshots.set(name,{source,bytes,sha256});
  }
  return snapshots;
}

export async function assertFinalizedBurnReleaseMetricOriginsUnchanged(snapshots) {
  for(const [name,record] of snapshots) {
    const current=await directFile(record.source,{maximum:1024*1024,privateMode:true});
    if(!current.equals(record.bytes) || rawSha(current)!==record.sha256) {
      fail(`finalized-burn metric-log origin changed during E2E execution: ${name}`);
    }
  }
}

async function assertExactSourceBoundary(sourceCommit) {
  const head=(await captureCommand('git',['rev-parse','HEAD'],{cwd:repositoryRoot})).trim();
  const status=await captureCommand('git',['status','--porcelain=v1','-z','--untracked-files=all'],{
    cwd:repositoryRoot,
  });
  validateReleaseSourceBoundary({head,sourceCommit,status,projectRelative});
}

async function loadConfiguredInputs() {
  const [releaseBytes,verifierBytes,evidenceBytes]=await Promise.all([
    readDirectProjectFile(labRoot,releaseRelative),readDirectProjectFile(labRoot,verifierRelative),
    readDirectProjectFile(labRoot,evidenceRelative),
  ]);
  const release=parseStrictJson(releaseBytes.toString('utf8'),{label:'production reserve release'});
  const verifier=parseStrictJson(verifierBytes.toString('utf8'),{label:'finalized-burn verifier'});
  const evidence=parseStrictJson(evidenceBytes.toString('utf8'),{label:'release evidence'});
  if(release.productionReady!==true || release.ethereumChainId!=='1'
      || typeof evidence.releaseId!=='string' || evidence.releaseId.length<1
      || !/^[0-9a-f]{40}$/.test(evidence.sourceCommit??'')) {
    fail('the exact production release and evidence must be configured before finalized-burn proving');
  }
  const finalized=finalizedBurnVerifierConfigHash(verifier);
  if(Buffer.compare(verifierBytes,Buffer.from(finalized.canonicalManifest))!==0
      || finalized.verifierConfigHash.toLowerCase()!==release.verifierConfigHash.toLowerCase()
      || verifier.ethereumChainId!=='1'
      || getAddress(verifier.riscZeroVerifier)!==getAddress(PINNED_RISC0_MAINNET_V3.verifier_address)
      || verifier.riscZeroVerifierCodeHash.toLowerCase()
        !==PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash.toLowerCase()) {
    fail('finalized-burn verifier manifest is not the exact canonical release configuration');
  }
  const reserveConfiguration=proofReserveConfigurationFromRelease(release);
  validateRiscZeroMainnetReference(PINNED_RISC0_MAINNET_V3);
  await assertExactSourceBoundary(evidence.sourceCommit);
  return {release,verifier,evidence,reserveConfiguration,releaseBytes,verifierBytes,evidenceBytes,
    releaseConfigSha256:rawSha(releaseBytes),verifierManifestSha256:rawSha(verifierBytes)};
}

async function assertConfiguredInputsUnchanged(configured) {
  const current=await Promise.all([
    readDirectProjectFile(labRoot,releaseRelative),readDirectProjectFile(labRoot,verifierRelative),
    readDirectProjectFile(labRoot,evidenceRelative),
  ]);
  if(!current[0].equals(configured.releaseBytes) || !current[1].equals(configured.verifierBytes)
      || !current[2].equals(configured.evidenceBytes)) {
    fail('release configuration changed during finalized-burn proof execution');
  }
  await assertExactSourceBoundary(configured.evidence.sourceCommit);
}

function runId() {
  return new Date().toISOString().replace(/[-:]/g,'').replace(/\.[0-9]{3}Z$/,'Z')+`-${process.pid}`;
}

async function main() {
  if(process.argv.length!==2) fail('this fixed finalized-burn release command accepts no arguments');
  if(!path.isAbsolute(os.homedir()) || os.homedir()==='/' || os.homedir()!==process.env.HOME
      || os.homedir()!==os.userInfo().homedir) {
    fail('HOME must be the current operating-system account home');
  }
  await requireDirectory(os.homedir(),{privateMode:false});
  const configured=await loadConfiguredInputs();
  await ensureArtifactHierarchy();
  const identifier=runId(),runRoot=path.join(runsRoot,identifier);
  await createPrivateDirectory(runRoot);
  const statusPath=path.join(runRoot,'run-status.json');
  const startedAt=BigInt(Math.floor(Date.now()/1000));
  await atomicJson(statusPath,{schema:'usdom-finalized-burn-release-run-v1',status:'running',
    runId:identifier,sourceCommit:configured.evidence.sourceCommit,recordedAt:new Date().toISOString()});
  activeStatus={path:statusPath,runId:identifier,sourceCommit:configured.evidence.sourceCommit};

  const workRoot=path.join(runRoot,'work'),tempLab=path.join(workRoot,'labs/usdom-reserve');
  for(const directory of [workRoot,path.join(workRoot,'labs'),tempLab,path.join(tempLab,'evidence')]) {
    await ensurePrivateDirectory(directory);
  }
  await copyPrivateTree(path.join(labRoot,'evidence/finalized-burn-source'),
    path.join(tempLab,'evidence/finalized-burn-source'));
  for(const name of ['finalized-burn-proof-job','finalized-burn-receipt','finalized-burn-evm-proof']) {
    await ensurePrivateDirectory(path.join(tempLab,'evidence',name));
  }
  const guestDirectory=path.join(tempLab,'evidence/finalized-burn-guest');
  await ensurePrivateDirectory(path.join(workRoot,'crates'));
  await ensurePrivateDirectory(path.dirname(guestDirectory)); await ensurePrivateDirectory(guestDirectory);
  for(const name of ['usdom-finalized-burn.elf','usdom-finalized-burn.iid']) {
    const source=path.join(repositoryRoot,'crates/dom-usdom-finalized-burn-risc0-guest/elfs',name);
    const bytes=await directFile(source,{privateMode:true});
    await writePrivateFileDurable(path.join(guestDirectory,name),bytes,{maximum:4*1024*1024});
  }

  const recursionArtifact=await requireRisc0RecursionArtifact({environment:proverEnvironment()});
  const environment=recursionArtifact.environment;
  await runCommand('npm',['run','--silent','check:provenance'],{
    cwd:labRoot,env:environment,log:path.join(runRoot,'provenance.log'),
  });
  await runCommand('npm',['run','--silent','pretest'],{
    cwd:labRoot,env:environment,log:path.join(runRoot,'pretest.log'),
  });
  await requireCapacity();
  await runCommand('cargo',['build','--quiet','--release','--locked','--manifest-path',
    path.join(repositoryRoot,'Cargo.toml'),'-p','dom-usdom-finalized-burn-proof-host',
    '--features','prove','--bins'],{
    cwd:repositoryRoot,env:environment,log:path.join(runRoot,'proof-host-build.log'),
  });
  await runCommand('cargo',cargoRun('dom-usdom-plan-finalized-burn-proof',{release:true}),{
    cwd:tempLab,env:environment,log:path.join(runRoot,'planner.log'),
  });
  await timedCargo('prover',cargoRun('dom-usdom-prove-finalized-burn',{
    release:true,features:'prove'}),{cwd:tempLab,runRoot,env:environment});
  await timedCargo('compression',cargoRun('dom-usdom-package-finalized-burn-evm-proof',{
    release:true,features:'prove'}),{cwd:tempLab,runRoot,env:environment});
  const adapterArtifact=await snapshotFinalizedBurnAdapterArtifact(runRoot);
  const metricLogs=await snapshotFinalizedBurnReleaseMetricLogs(runRoot);

  const collected=await collectFinalizedBurnArtifacts(workRoot,{
    reserveConfiguration:configured.reserveConfiguration,
    releaseConfigBytes:configured.releaseBytes,
    verifierConfiguration:configured.verifier,
    verifierConfigBytes:configured.verifierBytes,
    releaseConfigSha256:configured.releaseConfigSha256,
    verifierManifestSha256:configured.verifierManifestSha256,
  });
  const metricLog=name=>metricLogs.get(name)?.bytes??fail(`missing metric-log snapshot: ${name}`);
  const provingMetrics=parseProverResourceMetrics(metricLog('prover-time.log').toString('utf8'));
  const compressionMetrics=parseProverResourceMetrics(
    metricLog('compression-time.log').toString('utf8'));
  const observation=await observePinnedRiscZeroRuntime({
    reference:PINNED_RISC0_MAINNET_V3,sources:rpcSources,rpc,
  });
  await writePrivateFileDurable(path.join(runRoot,'risc0-mainnet-verifier-runtime.hex'),
    observation.runtimeCode+'\n');
  const evm=await verifyOnIsolatedEvm({observation,seal:collected.evmSeal,
    statementHash:collected.submission.statementHash,release:configured.release,
    verifier:configured.verifier,runRoot,adapterArtifact});
  await assertConfiguredInputsUnchanged(configured);
  const completedAt=BigInt(Math.floor(Date.now()/1000));
  const hostFingerprintSha256=rawSha(Buffer.from(JSON.stringify({platform:os.platform(),arch:os.arch(),
    release:os.release(),logicalCpus:os.availableParallelism(),memoryTotalKiB:String(Math.floor(os.totalmem()/1024))})));
  const report={schema:FINALIZED_BURN_E2E_REPORT_SCHEMA,releaseId:configured.evidence.releaseId,
    sourceCommit:configured.evidence.sourceCommit,ethereumChainId:'1',
    reserve:configured.release.reserve,verifier:configured.release.verifier,
    adapterRuntimeCodeHash:evm.adapterRuntimeCodeHash,
    verifierConfigHash:evm.adapterVerifierConfigHash,riscZeroVerifier:observation.riscZeroVerifier,
    riscZeroVerifierCodeHash:observation.runtimeCodeHash,
    guestImageId:configured.verifier.finalizedBurnGuestImageId,
    guestProgramSha256:configured.verifier.provingProgramSha256,
    burn:collected.submission.burn,
    inputSha256:collected.inputSha256,inputBytes:collected.inputBytes,
    statementHash:collected.submission.statementHash,
    succinctReceiptSha256:collected.succinctReceiptSha256,
    succinctReceiptBytes:collected.succinctReceiptBytes,
    groth16ReceiptSha256:collected.groth16ReceiptSha256,
    groth16ReceiptBytes:collected.groth16ReceiptBytes,
    evmSealSha256:collected.evmSealSha256,evmSealBytes:collected.evmSealBytes,
    sourcePackageSha256:collected.sourcePackageSha256,hostFingerprintSha256,
    risc0ZkvmVersion:'3.0.6',receiptKind:'groth16',prover:'local',rayonWorkers:1,
    segmentLimitPo2:18,provingWallMilliseconds:provingMetrics.provingWallMilliseconds,
    peakResidentKiB:provingMetrics.peakResidentKiB,
    compressionWallMilliseconds:compressionMetrics.provingWallMilliseconds,
    compressionPeakResidentKiB:compressionMetrics.peakResidentKiB,
    evmVerificationGas:evm.evmVerificationGas,receiptVerified:true,
    isolatedEvmTransactionHash:evm.isolatedEvmTransactionHash,
    isolatedEvmBlockHash:evm.isolatedEvmBlockHash,
    isolatedEvmBlockNumber:evm.isolatedEvmBlockNumber,
    isolatedEvmReceiptSha256:evm.isolatedEvmReceiptSha256,
    evmCallAccepted:evm.evmCallAccepted,devMode:false,mines:false,broadcastAuthorized:false,
    releaseSpecific:true,startedAt:startedAt.toString(),completedAt:completedAt.toString(),
    finalizedObservationBlockNumber:observation.finalizedBlockNumber,
    finalizedObservationBlockHash:observation.finalizedBlockHash,
    observationSourceIds:[...observation.sourceIds],
    observationEndpointHashes:[...observation.endpointSha256]};
  await assertFinalizedBurnReleaseMetricOriginsUnchanged(metricLogs);
  validateFinalizedBurnE2eReport(report,{evidence:configured.evidence,
    releaseConfig:configured.release,verifierConfig:configured.verifier,
    riscZeroReference:PINNED_RISC0_MAINNET_V3});
  const reportPath=path.join(runRoot,'finalized-burn-e2e-report.json');
  await atomicJson(reportPath,report);
  const reportSha256=await privateFileSha(reportPath,{minimum:1,maximum:16*1024*1024,
    privateMode:true,label:'finalized-burn release report'});
  await atomicJson(statusPath,{schema:'usdom-finalized-burn-release-run-v1',status:'succeeded',
    runId:identifier,sourceCommit:configured.evidence.sourceCommit,reportSha256,
    recordedAt:new Date().toISOString()});
  activeStatus=null;
  console.log(JSON.stringify({ok:true,status:'succeeded',runId:identifier,reportPath,
    reportSha256,evmVerificationGas:evm.evmVerificationGas,broadcastAuthorized:false},null,2));
}

if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  process.umask(0o077);
  try { await main(); }
  catch(error) {
    if(activeStatus) {
      try {
        await atomicJson(activeStatus.path,{schema:'usdom-finalized-burn-release-run-v1',
          status:'failed',runId:activeStatus.runId,sourceCommit:activeStatus.sourceCommit,
          error:'RELEASE_OPERATION_REJECTED',recordedAt:new Date().toISOString()});
      } catch {}
    }
    writeReleaseFailure('run-finalized-burn-release-e2e',error);
    process.exitCode=1;
  }
}
