import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {
  lstat,mkdir,open,readFile,readdir,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ContractFactory,JsonRpcProvider,hexlify,id,keccak256} from 'ethers';
import {buildCheckpointCapacityArtifactManifest,collectCheckpointCapacityArtifacts} from '../sdk/checkpoint-capacity-artifact-collector.mjs';
import {
  buildCheckpointProofCapacityReport,checkpointIsolatedEvmReceiptCommitment,
} from '../sdk/checkpoint-proof-capacity-report.mjs';
import {
  buildAuthenticatedCheckpointSubmission,checkpointRegistryConfigurationFromRelease,
  parseCheckpointStatementV6,
} from '../sdk/checkpoint-submission.mjs';
import {checkpointVerifierConfigHash} from '../sdk/checkpoint-verifier-config.mjs';
import {observePinnedRiscZeroRuntime} from '../sdk/risc0-capacity-runtime-observer.mjs';
import {
  PINNED_RISC0_MAINNET_V3,validateRiscZeroMainnetReference,
} from '../sdk/risc0-verifier-reference.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {parseProverResourceMetrics} from '../sdk/prover-resource-metrics.mjs';
import {requireRisc0RecursionArtifact} from '../sdk/risc0-recursion-artifact.mjs';
import {
  parseRandomxProverSummary,reconcileRandomxProverSummary,
} from '../sdk/randomx-prover-summary.mjs';
import {validateReleaseSourceBoundary} from '../sdk/release-source-boundary.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurable,writePrivateJsonDurable} from '../sdk/durable-private-file.mjs';
import {assertExecutableUnchanged,snapshotExecutablePath} from '../sdk/stable-executable.mjs';

const CARGO='/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo';
const NPM='/usr/lib/chatgpt/resources/cua_node/bin/npm';
const GIT='/usr/bin/git';
const ANVIL='/home/leonardov/.foundry/bin/anvil';
const TIME='/usr/bin/time';

const labRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repositoryRoot=path.resolve(labRoot,'../..');
const projectRelative=path.relative(repositoryRoot,labRoot).split(path.sep).join('/');
const currentUid=process.getuid();
const artifactRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-capacity/checkpoint');
const runsRoot=path.join(artifactRoot,'runs');
const releaseRelative='config/proof-reserve.unconfigured.json';
const verifierRelative='config/checkpoint-verifier.unconfigured.json';
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
      || (privateMode && (metadata.mode&0o077)!==0)) fail(`unsafe checkpoint directory: ${target}`);
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
  return readDirectFile(target,{minimum,maximum,privateMode,label:'checkpoint file'});
}

async function strictJsonFile(target,label,{maximum=4*1024*1024}={}) {
  const bytes=await directFile(target,{maximum});
  return parseStrictJson(bytes.toString('utf8'),{label,maxBytes:maximum,maxDepth:64});
}

async function atomicJson(target,value) {
  await writePrivateJsonDurable(target,value);
}

async function runCommand(command,args,{cwd,env=process.env,log,timeout=12*60*60*1000}) {
  const executable=await snapshotExecutablePath(command);
  const output=await open(log,'w',0o600);
  let child,timer;
  try {
    child=spawn(executable.path,args,{cwd,env,detached:true,stdio:['ignore',output.fd,output.fd]});
    timer=setTimeout(()=>{ try { process.kill(-child.pid,'SIGKILL'); } catch {} },timeout);
    const result=await new Promise((resolve,reject)=>{
      child.once('error',reject);
      child.once('close',(code,signal)=>resolve({code,signal}));
    });
    if(result.code!==0) fail(`${path.basename(command)} failed (${result.signal??result.code}); see ${log}`);
  } finally {
    clearTimeout(timer);
    if(child?.exitCode===null) { try { process.kill(-child.pid,'SIGKILL'); } catch {} }
    await output.close();
    await assertExecutableUnchanged(executable);
  }
}

async function captureCommand(command,args,{cwd,maximum=1024*1024}={}) {
  const executable=await snapshotExecutablePath(command);
  const child=spawn(executable.path,args,{cwd,detached:true,stdio:['ignore','pipe','pipe']});
  const timer=setTimeout(()=>{ try { process.kill(-child.pid,'SIGKILL'); } catch {} },30_000);
  const chunks=[];
  let length=0,captured=0;
  const append=chunk=>{
    length+=chunk.length;
    if(length>maximum) child.kill('SIGKILL');
    else { chunks.push(Buffer.from(chunk)); captured+=chunk.length; }
  };
  child.stdout.on('data',append); child.stderr.on('data',append);
  const result=await new Promise((resolve,reject)=>{
    child.once('error',reject); child.once('close',(code,signal)=>resolve({code,signal}));
  });
  clearTimeout(timer);
  await assertExecutableUnchanged(executable);
  if(length>maximum || result.code!==0) {
    fail(`${path.basename(command)} inspection failed (${result.signal??result.code})`);
  }
  return Buffer.concat(chunks,captured).toString('utf8');
}

async function ensureArtifactHierarchy() {
  const local=path.join(os.homedir(),'.local'),share=path.join(local,'share');
  await requireDirectory(local,{privateMode:false});
  await requireDirectory(share,{privateMode:false});
  for(const directory of [path.join(share,'dom-usdom'),
    path.join(share,'dom-usdom/prover-capacity'),artifactRoot,runsRoot]) {
    await ensurePrivateDirectory(directory);
  }
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
    fail('checkpoint proving requires one CPU and 3 GiB of available RAM');
  }
}

async function copyPrivateTree(source,destination,state={files:0,bytes:0n}) {
  await requireDirectory(source);
  await ensurePrivateDirectory(destination);
  const entries=(await readdir(source,{withFileTypes:true}))
    .sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
  for(const entry of entries) {
    if(entry.name==='' || entry.name==='.' || entry.name==='..' || entry.name.includes('\0')) {
      fail('noncanonical checkpoint source filename');
    }
    const from=path.join(source,entry.name),to=path.join(destination,entry.name);
    const metadata=await lstat(from);
    if(metadata.isSymbolicLink()) fail(`checkpoint source contains a symlink: ${from}`);
    if(metadata.isDirectory()) await copyPrivateTree(from,to,state);
    else if(metadata.isFile()) {
      const bytes=await directFile(from,{privateMode:true});
      state.files+=1; state.bytes+=BigInt(bytes.length);
      if(state.files>16384 || state.bytes>4n*1024n*1024n*1024n) fail('checkpoint source tree exceeds its bound');
      await writePrivateFileDurable(to,bytes,{maximum:512*1024*1024});
    } else fail(`unsupported checkpoint source entry: ${from}`);
  }
  return state;
}

async function copyGuestArtifacts(workRoot) {
  const specifications=[
    ['dom-usdom-randomx-risc0-guest',['usdom-randomx.elf','usdom-randomx.bin','usdom-randomx.iid']],
    ['dom-usdom-randomx-aggregate-risc0-guest',
      ['usdom-randomx-aggregate.bin','usdom-randomx-aggregate.iid']],
    ['dom-usdom-economic-chunk-risc0-guest',
      ['usdom-economic-chunk.elf','usdom-economic-chunk.bin','usdom-economic-chunk.iid']],
    ['dom-usdom-economic-block-risc0-guest',
      ['usdom-economic-block.elf','usdom-economic-block.bin','usdom-economic-block.iid']],
    ['dom-usdom-checkpoint-segment-risc0-guest',
      ['usdom-checkpoint-segment.elf','usdom-checkpoint-segment.bin','usdom-checkpoint-segment.iid']],
    ['dom-usdom-checkpoint-outer-risc0-guest',
      ['usdom-checkpoint-outer.elf','usdom-checkpoint-outer.bin','usdom-checkpoint-outer.iid']],
  ];
  await ensurePrivateDirectory(path.join(workRoot,'crates'));
  for(const [crate,names] of specifications) {
    const destination=path.join(workRoot,'crates',crate,'elfs');
    await ensurePrivateDirectory(path.dirname(destination)); await ensurePrivateDirectory(destination);
    for(const name of names) {
      const source=path.join(repositoryRoot,'crates',crate,'elfs',name);
      const bytes=await directFile(source);
      await writePrivateFileDurable(path.join(destination,name),bytes,{maximum:512*1024*1024});
    }
  }
}

async function timedCargo(name,args,{cwd,runRoot,env}) {
  await requireCapacity();
  await runCommand(TIME,['-v','-o',path.join(runRoot,`${name}-time.log`),CARGO,...args],{
    cwd,env,log:path.join(runRoot,`${name}.log`),
  });
}

const cargoRun=(crate,binary,{release=false,features=null}={})=>[
  'run','--quiet',...(release?['--release']:[]),'--locked','--manifest-path',
  path.join(repositoryRoot,'Cargo.toml'),'-p',crate,...(features?['--features',features]:[]),
  '--bin',binary,
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
    fail(`capacity source ${source.sourceId} failed`);
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
  try { process.kill(-child.pid,'SIGTERM'); } catch {}
  await Promise.race([new Promise(resolve=>child.once('close',resolve)),
    new Promise(resolve=>setTimeout(resolve,5000))]);
  if(child.exitCode===null) { try { process.kill(-child.pid,'SIGKILL'); } catch {} }
}

async function verifyOnIsolatedEvm({observation,seal,statementHash,release,verifier,runRoot,
  adapterArtifact}) {
  if(seal.length!==260 || hexlify(seal.subarray(0,4)).toLowerCase()!=='0x73c457ba') {
    fail('checkpoint EVM seal is not the canonical selector-prefixed 260-byte proof');
  }
  const port=await freePort();
  const anvilLog=await open(path.join(runRoot,'anvil.log'),'w',0o600);
  if(Object.hasOwn(process.env,'USDOM_ANVIL')) fail('USDOM_ANVIL override is forbidden');
  const anvil=await snapshotExecutablePath(ANVIL);
  const child=spawn(anvil.path,[
    '--host','127.0.0.1','--port',String(port),'--chain-id','1','--silent',
  ],{detached:true,stdio:['ignore',anvilLog.fd,anvilLog.fd]});
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
      observation.riscZeroVerifier,verifier.checkpointGuestImageId,
    );
    await adapter.waitForDeployment();
    const adapterAddress=await adapter.getAddress();
    const [verifierGasLimit,journalDigest]=await Promise.all([
      adapter.RISC_ZERO_VERIFIER_GAS_LIMIT(),adapter.journalDigest(statementHash),
    ]);
    const expectedJournalDigest='0x'+createHash('sha256')
      .update(Buffer.from(statementHash.slice(2),'hex')).digest('hex');
    if(verifierGasLimit!==4_500_000n || journalDigest.toLowerCase()!==expectedJournalDigest) {
      fail('checkpoint adapter receipt boundary differs from the host journal/gas policy');
    }
    const runtimeCodeHash=keccak256(await provider.getCode(adapterAddress));
    const verifierConfigHash=await adapter.verifierConfigHash();
    if(runtimeCodeHash.toLowerCase()!==release.checkpointVerifierCodeHash.toLowerCase()
        || verifierConfigHash.toLowerCase()!==release.checkpointVerifierConfigHash.toLowerCase()) {
      fail('isolated checkpoint adapter differs from the exact release identity');
    }
    const proof=hexlify(seal);
    if(await adapter.verifyDOMCheckpoint.staticCall(statementHash,proof)
        !==id('DOM_CHECKPOINT_PROOF_V3')) fail('checkpoint adapter returned the wrong commitment');
    const data=adapter.interface.encodeFunctionData('verifyDOMCheckpoint',[statementHash,proof]);
    const transaction=await signer.sendTransaction({to:adapterAddress,data,gasLimit:5_000_000n});
    const receipt=await transaction.wait();
    if(!receipt || receipt.status!==1 || receipt.gasUsed===0n || receipt.gasUsed>5_000_000n) {
      fail('isolated checkpoint verification failed or exceeded the gas cap');
    }
    const receiptTranscript=checkpointIsolatedEvmReceiptCommitment({
      transactionHash:receipt.hash,blockHash:receipt.blockHash,
      blockNumber:String(receipt.blockNumber),adapter:adapterAddress,
      adapterRuntimeCodeHash:runtimeCodeHash,adapterVerifierConfigHash:verifierConfigHash,
      statementHash,evmSealSha256:rawSha(seal),
      adapterVerificationGas:receipt.gasUsed.toString(),
    });
    await writePrivateFileDurable(path.join(runRoot,'isolated-evm-receipt.json'),
      Buffer.from(receiptTranscript.canonicalTranscript));
    return {adapterRuntimeCodeHash:runtimeCodeHash,adapterVerifierConfigHash:verifierConfigHash,
      adapterVerificationGas:receipt.gasUsed.toString(),adapterCallAccepted:true,
      isolatedEvmTransactionHash:receiptTranscript.record.transactionHash,
      isolatedEvmBlockHash:receiptTranscript.record.blockHash,
      isolatedEvmBlockNumber:receiptTranscript.record.blockNumber,
      isolatedEvmReceiptSha256:receiptTranscript.sha256};
  } finally {
    provider.destroy(); await terminate(child); await anvilLog.close();
    await assertExecutableUnchanged(anvil);
  }
}

async function snapshotCheckpointAdapterArtifact(runRoot) {
  const source=path.join(labRoot,
    'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json');
  const bytes=await directFile(source,{maximum:16*1024*1024});
  const artifact=parseStrictJson(bytes.toString('utf8'),{
    label:'checkpoint adapter artifact',maxBytes:16*1024*1024,maxDepth:64,
  });
  const snapshotDirectory=path.join(runRoot,'input-snapshots');
  await createPrivateDirectory(snapshotDirectory);
  const snapshot=path.join(snapshotDirectory,'checkpoint-adapter-artifact.json');
  await writePrivateFileDurable(snapshot,bytes,{maximum:16*1024*1024});
  const installed=await directFile(snapshot,{maximum:16*1024*1024,privateMode:true});
  if(!installed.equals(bytes)) fail('checkpoint adapter artifact snapshot changed during installation');
  return artifact;
}

async function snapshotReportLogs(runRoot) {
  const specifications=[
    ['randomx.log',4096],['randomx-time.log',1024*1024],
    ['randomx-aggregate-time.log',1024*1024],['segment-time.log',1024*1024],
    ['outer-time.log',1024*1024],['compression-time.log',1024*1024],
  ];
  const snapshotDirectory=path.join(runRoot,'input-snapshots/report-logs');
  await ensurePrivateDirectory(snapshotDirectory);
  const snapshots=new Map();
  for(const [name,maximum] of specifications) {
    const source=path.join(runRoot,name);
    const bytes=await directFile(source,{maximum,privateMode:true});
    const sha256=rawSha(bytes),snapshot=path.join(snapshotDirectory,name);
    await writePrivateFileDurable(snapshot,bytes,{maximum});
    const installed=await directFile(snapshot,{maximum,privateMode:true});
    if(!installed.equals(bytes) || rawSha(installed)!==sha256) {
      fail(`checkpoint report log snapshot changed during installation: ${name}`);
    }
    snapshots.set(name,{source,bytes,sha256,maximum});
  }
  return snapshots;
}

async function assertReportLogOriginsUnchanged(snapshots) {
  for(const [name,record] of snapshots) {
    const current=await directFile(record.source,{maximum:record.maximum,privateMode:true});
    if(!current.equals(record.bytes) || rawSha(current)!==record.sha256) {
      fail(`checkpoint report log origin changed during E2E execution: ${name}`);
    }
  }
}

async function loadConfiguredInputs() {
  const [releaseBytes,verifierBytes,evidenceBytes]=await Promise.all([
    readDirectProjectFile(labRoot,releaseRelative),
    readDirectProjectFile(labRoot,verifierRelative),
    readDirectProjectFile(labRoot,evidenceRelative),
  ]);
  const release=parseStrictJson(releaseBytes.toString('utf8'),{label:'production release'});
  const verifier=parseStrictJson(verifierBytes.toString('utf8'),{label:'checkpoint verifier'});
  const evidence=parseStrictJson(evidenceBytes.toString('utf8'),{label:'release evidence'});
  if(release.productionReady!==true || release.ethereumChainId!=='1'
      || typeof evidence.releaseId!=='string' || evidence.releaseId.length<1
      || !/^[0-9a-f]{40}$/.test(evidence.sourceCommit??'')) {
    fail('the exact production release and evidence must be configured before checkpoint proving');
  }
  const finalized=checkpointVerifierConfigHash(verifier);
  if(Buffer.compare(verifierBytes,Buffer.from(finalized.canonicalManifest))!==0
      || finalized.verifierConfigHash.toLowerCase()!==release.checkpointVerifierConfigHash.toLowerCase()
      || verifier.ethereumChainId!=='1') {
    fail('checkpoint verifier manifest is not the exact canonical release configuration');
  }
  checkpointRegistryConfigurationFromRelease(release);
  validateRiscZeroMainnetReference(PINNED_RISC0_MAINNET_V3);
  await assertExactSourceBoundary(evidence.sourceCommit);
  return {release,verifier,evidence,releaseBytes,verifierBytes,
    evidenceSha256:rawSha(evidenceBytes)};
}

async function assertExactSourceBoundary(sourceCommit) {
  const head=(await captureCommand(GIT,['rev-parse','HEAD'],{cwd:repositoryRoot})).trim();
  const status=await captureCommand(GIT,['status','--porcelain=v1','-z','--untracked-files=all'],{
    cwd:repositoryRoot,maximum:16*1024*1024,
  });
  validateReleaseSourceBoundary({head,sourceCommit,status,projectRelative});
}

async function assertConfiguredInputsUnchanged(configured) {
  const [releaseBytes,verifierBytes,evidenceBytes]=await Promise.all([
    readDirectProjectFile(labRoot,releaseRelative),
    readDirectProjectFile(labRoot,verifierRelative),
    readDirectProjectFile(labRoot,evidenceRelative),
  ]);
  if(!releaseBytes.equals(configured.releaseBytes)
      || !verifierBytes.equals(configured.verifierBytes)
      || rawSha(evidenceBytes)!==configured.evidenceSha256) {
    fail('release configuration changed during checkpoint capacity execution');
  }
  await assertExactSourceBoundary(configured.evidence.sourceCommit);
}

function runId() {
  return new Date().toISOString().replace(/[-:]/g,'').replace(/\.[0-9]{3}Z$/,'Z')+`-${process.pid}`;
}

async function main() {
  if(process.argv.length!==2) fail('this fixed checkpoint capacity command accepts no arguments');
  if(!path.isAbsolute(os.homedir()) || os.homedir()==='/' || os.homedir()!==process.env.HOME
      || os.homedir()!==os.userInfo().homedir) {
    fail('HOME must be the current operating-system account home');
  }
  await requireDirectory(os.homedir(),{privateMode:false});
  const configured=await loadConfiguredInputs();
  const identifier=runId();
  await ensureArtifactHierarchy();
  const runRoot=path.join(runsRoot,identifier); await createPrivateDirectory(runRoot);
  const statusPath=path.join(runRoot,'run-status.json');
  const startedAt=BigInt(Math.floor(Date.now()/1000));
  await atomicJson(statusPath,{schema:'usdom-checkpoint-capacity-run-v1',status:'running',
    runId:identifier,sourceCommit:configured.evidence.sourceCommit,recordedAt:new Date().toISOString()});
  activeStatus={path:statusPath,runId:identifier,sourceCommit:configured.evidence.sourceCommit};

  const workRoot=path.join(runRoot,'work'),tempLab=path.join(workRoot,'labs/usdom-reserve');
  for(const directory of [workRoot,path.join(workRoot,'labs'),tempLab,path.join(tempLab,'evidence')]) {
    await ensurePrivateDirectory(directory);
  }
  await requireDirectory(path.join(labRoot,'evidence'));
  for(const name of ['checkpoint-source-set','randomx-statement-set']) {
    await copyPrivateTree(path.join(labRoot,'evidence',name),path.join(tempLab,'evidence',name));
  }
  for(const name of [
    'randomx-proof-jobs','randomx-receipt-set','randomx-aggregate-jobs',
    'randomx-aggregate-receipt-set','economic-proof-jobs','economic-receipt-set',
    'checkpoint-segment-proof-jobs','checkpoint-segment-receipt-set',
    'checkpoint-outer-proof-job','checkpoint-outer-receipt-set','checkpoint-outer-evm-proof',
  ]) await ensurePrivateDirectory(path.join(tempLab,'evidence',name));
  await copyGuestArtifacts(workRoot);

  const recursionArtifact=await requireRisc0RecursionArtifact({environment:proverEnvironment()});
  const environment=recursionArtifact.environment;
  await runCommand(NPM,['run','--silent','check:provenance'],{
    cwd:labRoot,env:environment,log:path.join(runRoot,'provenance.log'),
  });
  await runCommand(NPM,['run','--silent','pretest'],{
    cwd:labRoot,env:environment,log:path.join(runRoot,'pretest.log'),
  });
  for(const crate of [
    'dom-usdom-randomx-proof-host','dom-usdom-economic-proof-host',
    'dom-usdom-checkpoint-proof-host',
  ]) {
    await requireCapacity();
    await runCommand(CARGO,[
      'build','--quiet','--release','--locked','--manifest-path',
      path.join(repositoryRoot,'Cargo.toml'),'-p',crate,'--features','prove','--bins',
    ],{cwd:repositoryRoot,env:environment,log:path.join(runRoot,`${crate}-build.log`)});
  }
  const plan=async(name,args)=>runCommand(CARGO,args,{
    cwd:tempLab,env:environment,log:path.join(runRoot,`${name}.log`),
  });
  await plan('randomx-plan',cargoRun('dom-usdom-randomx-proof-host',
    'dom-usdom-plan-randomx-receipt-set'));
  await timedCargo('randomx',cargoRun('dom-usdom-randomx-proof-host',
    'dom-usdom-prove-randomx-receipt-set',{release:true,features:'prove'}),
  {cwd:tempLab,runRoot,env:environment});
  await plan('randomx-aggregate-plan',cargoRun('dom-usdom-randomx-proof-host',
    'dom-usdom-plan-randomx-aggregate-set',{release:true,features:'verify'}));
  await timedCargo('randomx-aggregate',cargoRun('dom-usdom-randomx-proof-host',
    'dom-usdom-prove-randomx-aggregate-set',{release:true,features:'prove'}),
  {cwd:tempLab,runRoot,env:environment});
  await plan('economic-plan',cargoRun('dom-usdom-economic-proof-host',
    'dom-usdom-plan-economic-receipt-set'));
  await timedCargo('economic',cargoRun('dom-usdom-economic-proof-host',
    'dom-usdom-prove-economic-receipt-set',{release:true,features:'prove'}),
  {cwd:tempLab,runRoot,env:environment});
  await plan('segment-plan',cargoRun('dom-usdom-checkpoint-proof-host',
    'dom-usdom-plan-checkpoint-segment-set',{release:true,features:'verify'}));
  await timedCargo('segment',cargoRun('dom-usdom-checkpoint-proof-host',
    'dom-usdom-prove-checkpoint-segment-set',{release:true,features:'prove'}),
  {cwd:tempLab,runRoot,env:environment});
  await plan('outer-plan',cargoRun('dom-usdom-checkpoint-proof-host',
    'dom-usdom-plan-checkpoint-outer',{release:true,features:'verify'}));
  await timedCargo('outer',cargoRun('dom-usdom-checkpoint-proof-host',
    'dom-usdom-prove-checkpoint-outer',{release:true,features:'prove'}),
  {cwd:tempLab,runRoot,env:environment});
  await timedCargo('compression',cargoRun('dom-usdom-checkpoint-proof-host',
    'dom-usdom-package-checkpoint-outer-evm-proof',{release:true,features:'prove'}),
  {cwd:tempLab,runRoot,env:environment});
  await assertConfiguredInputsUnchanged(configured);
  const adapterArtifact=await snapshotCheckpointAdapterArtifact(runRoot);
  const reportLogs=await snapshotReportLogs(runRoot);
  const reportLog=name=>reportLogs.get(name)?.bytes??fail(`missing report log snapshot: ${name}`);
  const randomxProverTranscript=reportLog('randomx.log');
  const randomxProofSummary=parseRandomxProverSummary(randomxProverTranscript.toString('utf8'));
  const readMetrics=name=>parseProverResourceMetrics(
    reportLog(`${name}-time.log`).toString('utf8'));
  const randomxResourceLog=reportLog('randomx-time.log');
  const metrics={randomx:parseProverResourceMetrics(randomxResourceLog.toString('utf8')),
    randomxAggregate:readMetrics('randomx-aggregate'),segment:readMetrics('segment'),
    outer:readMetrics('outer'),compression:readMetrics('compression')};
  const collected=await collectCheckpointCapacityArtifacts(tempLab,{
    metrics,checkpointVerifierConfig:configured.verifier,
  });
  reconcileRandomxProverSummary(randomxProofSummary,collected.randomxVerifiedGraph);
  const registryConfiguration=checkpointRegistryConfigurationFromRelease(configured.release);
  const submission=buildAuthenticatedCheckpointSubmission({
    registryConfiguration,verifierConfiguration:configured.verifier,
    statement:collected.evmArtifacts.statement,proofIndex:collected.evmArtifacts.proofIndex,
    evmSeal:collected.evmArtifacts.seal,
    releaseConfigSha256:rawSha(configured.releaseBytes),
    verifierManifestSha256:rawSha(configured.verifierBytes),
  });
  if(submission.statementHash!==collected.statementHash) {
    fail('collected statement differs from the canonical unsigned submission');
  }
  const observation=await observePinnedRiscZeroRuntime({
    reference:PINNED_RISC0_MAINNET_V3,sources:rpcSources,rpc,
  });
  const riscZeroRuntimeArtifact=Buffer.from(observation.runtimeCode+'\n');
  await writePrivateFileDurable(path.join(runRoot,'risc0-mainnet-verifier-runtime.hex'),
    riscZeroRuntimeArtifact);
  const evm=await verifyOnIsolatedEvm({observation,seal:collected.evmArtifacts.seal,
    statementHash:submission.statementHash,release:configured.release,
    verifier:configured.verifier,runRoot,adapterArtifact});
  const checkpoint=parseCheckpointStatementV6(collected.evmArtifacts.statement).checkpoint;
  const completedAt=BigInt(Math.floor(Date.now()/1000));
  const hostIdentity=JSON.stringify({platform:os.platform(),release:os.release(),arch:os.arch(),
    cpuModel:os.cpus()[0]?.model??'',logicalCpus:os.availableParallelism(),
    memoryTotalKiB:Math.floor(os.totalmem()/1024)});
  const artifactManifest=await buildCheckpointCapacityArtifactManifest(tempLab,identifier);
  const artifactManifestPath=path.join(runRoot,'artifact-manifest.json');
  await atomicJson(artifactManifestPath,artifactManifest.manifest);
  const base={
    runId:identifier,artifactManifestPath:'artifact-manifest.json',
    artifactManifestSha256:rawSha(artifactManifest.bytes),
    releaseId:configured.evidence.releaseId,sourceCommit:configured.evidence.sourceCommit,
    ethereumChainId:'1',checkpointRegistry:configured.release.checkpointRegistry,
    adapter:configured.release.checkpointVerifier,
    adapterRuntimeCodeHash:evm.adapterRuntimeCodeHash,
    adapterVerifierConfigHash:evm.adapterVerifierConfigHash,
    adapterCallAccepted:evm.adapterCallAccepted,adapterVerificationGas:evm.adapterVerificationGas,
    isolatedEvmTransactionHash:evm.isolatedEvmTransactionHash,
    isolatedEvmBlockHash:evm.isolatedEvmBlockHash,
    isolatedEvmBlockNumber:evm.isolatedEvmBlockNumber,
    isolatedEvmReceiptSha256:evm.isolatedEvmReceiptSha256,
    riscZeroVerifier:observation.riscZeroVerifier,
    riscZeroVerifierCodeHash:observation.runtimeCodeHash,risc0ZkvmVersion:'3.0.6',
    riscZeroFinalizedBlockNumber:observation.finalizedBlockNumber,
    riscZeroFinalizedBlockHash:observation.finalizedBlockHash,
    riscZeroObservationSourceIds:observation.sourceIds,
    riscZeroObservationEndpointHashes:observation.endpointSha256,
    riscZeroRuntimeArtifactSha256:rawSha(riscZeroRuntimeArtifact),
    sourcePackageSha256:collected.evmArtifacts.sourcePackageSha256,
    randomxProverTranscriptSha256:rawSha(randomxProverTranscript),
    randomxResourceLogSha256:rawSha(randomxResourceLog),
    hostFingerprintSha256:rawSha(hostIdentity),statementHash:submission.statementHash,checkpoint,
    checkpointStartHeight:checkpoint.previousHeight,checkpointEndHeight:checkpoint.height,
    confirmationHeight:checkpoint.confirmationHeight,
    checkpointSpan:(BigInt(checkpoint.height)-BigInt(checkpoint.previousHeight)).toString(),
    confirmationDepth:(BigInt(checkpoint.confirmationHeight)-BigInt(checkpoint.height)).toString(),
    startedAt:startedAt.toString(),completedAt:completedAt.toString(),
    compressionWallMilliseconds:collected.compressionMetrics.provingWallMilliseconds,
    compressionPeakResidentKiB:collected.compressionMetrics.peakResidentKiB,
    outerGroth16ReceiptSha256:collected.evmArtifacts.outerGroth16ReceiptSha256,
    outerGroth16ReceiptBytes:collected.evmArtifacts.outerGroth16ReceiptBytes,
    evmSealSha256:collected.evmArtifacts.evmSealSha256,
    evmSealBytes:collected.evmArtifacts.evmSealBytes,
    logicalCpus:os.availableParallelism(),memoryTotalKiB:String(Math.floor(os.totalmem()/1024)),
    prover:'local',rayonWorkers:1,devMode:false,mines:false,broadcastAuthorized:false,
    releaseSpecific:true,
  };
  await assertReportLogOriginsUnchanged(reportLogs);
  await assertConfiguredInputsUnchanged(configured);
  const report=buildCheckpointProofCapacityReport(base,collected.measuredLayers,{
    evidence:configured.evidence,releaseConfig:configured.release,
    checkpointVerifierConfig:configured.verifier,riscZeroReference:PINNED_RISC0_MAINNET_V3,
  });
  const reportPath=path.join(runRoot,'capacity-report.json');
  await atomicJson(reportPath,report);
  const reportSha256=await privateFileSha(reportPath,{minimum:1,maximum:16*1024*1024,
    privateMode:true,label:'checkpoint capacity report'});
  await assertConfiguredInputsUnchanged(configured);
  await atomicJson(statusPath,{schema:'usdom-checkpoint-capacity-run-v1',status:'succeeded',
    runId:identifier,sourceCommit:configured.evidence.sourceCommit,reportSha256,
    recordedAt:new Date().toISOString()});
  activeStatus=null;
  console.log(JSON.stringify({ok:true,status:'succeeded',runId:identifier,reportPath,
    reportSha256,adapterVerificationGas:evm.adapterVerificationGas,broadcastAuthorized:false},null,2));
}

if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  process.umask(0o077);
  try { await main(); }
  catch(error) {
    if(activeStatus) {
      try {
        await atomicJson(activeStatus.path,{schema:'usdom-checkpoint-capacity-run-v1',status:'failed',
          runId:activeStatus.runId,sourceCommit:activeStatus.sourceCommit,
          error:'RELEASE_OPERATION_REJECTED',recordedAt:new Date().toISOString()});
      } catch {}
    }
    writeReleaseFailure('run-checkpoint-capacity-e2e',error);
    process.exitCode=1;
  }
}
