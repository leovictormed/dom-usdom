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
import {
  ContractFactory,JsonRpcProvider,hexlify,id,keccak256,
} from 'ethers';
import {
  FINALIZED_BURN_CAPACITY_IMAGE_ID,FINALIZED_BURN_CAPACITY_INPUT_BYTES,
  FINALIZED_BURN_CAPACITY_INPUT_SHA256,FINALIZED_BURN_CAPACITY_PROGRAM_SHA256,
  FINALIZED_BURN_CAPACITY_REPORT_SCHEMA,FINALIZED_BURN_CAPACITY_STATEMENT_HASH,
  finalizedBurnIsolatedEvmReceiptCommitment,
  validateFinalizedBurnCapacityReport,
} from '../sdk/finalized-burn-capacity-report.mjs';
import {observePinnedRiscZeroRuntime} from '../sdk/risc0-capacity-runtime-observer.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../sdk/risc0-verifier-reference.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {parseProverResourceMetrics} from '../sdk/prover-resource-metrics.mjs';
import {requireRisc0RecursionArtifact} from '../sdk/risc0-recursion-artifact.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurable,writePrivateJsonDurable} from '../sdk/durable-private-file.mjs';
import {FINALIZED_BURN_EVM_SEAL_BYTES} from '../sdk/finalized-burn-submission.mjs';

process.umask(0o077);

const labRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repositoryRoot=path.resolve(labRoot,'../..');
const runIdPattern=/^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$/;
const currentUid=process.getuid();
const artifactRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-capacity/finalized-burn');
const proofRunsRoot=path.join(artifactRoot,'runs');
const capacityRunsRoot=path.join(artifactRoot,'evm-runs');
const sources=Object.freeze([
  Object.freeze({sourceId:'drpc',url:'https://eth.drpc.org/'}),
  Object.freeze({sourceId:'publicnode',url:'https://ethereum-rpc.publicnode.com/'}),
]);
let activeCapacityStatus=null;

function fail(message) { throw new Error(message); }
const rawSha=value=>createHash('sha256').update(value).digest('hex');
async function privateFileSha(target,options) {
  const bytes=await readDirectFile(target,options);
  try { return rawSha(bytes); }
  finally { bytes.fill(0); }
}

async function requireDirectory(target,{privateMode=true}={}) {
  const metadata=await lstat(target);
  if(!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid!==currentUid
      || (privateMode && (metadata.mode&0o077)!==0)) {
    fail(`unsafe capacity directory: ${target}`);
  }
}

async function ensurePrivateDirectory(target) {
  try { await mkdir(target,{mode:0o700}); }
  catch(error) { if(error?.code!=='EEXIST') throw error; }
  await requireDirectory(target);
}

async function directFile(target,{maximum=512*1024*1024,minimum=1,privateMode=false}={}) {
  return readDirectFile(target,{minimum,maximum,privateMode,label:'capacity file'});
}

async function strictJsonFile(target,label,{privateMode=false}={}) {
  const bytes=await directFile(target,{maximum:1024*1024,privateMode});
  return parseStrictJson(bytes.toString('utf8'),{label});
}

async function atomicJson(target,value) {
  await writePrivateJsonDurable(target,value);
}

export async function selectFinalizedBurnProofRun({runsRoot=proofRunsRoot,
  requestedRunId=process.env.USDOM_FINALIZED_BURN_PROOF_RUN_ID}={}) {
  await requireDirectory(runsRoot);
  if(requestedRunId!==undefined && !runIdPattern.test(requestedRunId)) {
    fail('explicit finalized-burn proof run ID is malformed');
  }
  const entries=(await readdir(runsRoot,{withFileTypes:true}))
    .filter(entry=>entry.isDirectory() && runIdPattern.test(entry.name))
    .map(entry=>entry.name).sort().reverse();
  if(entries.length===0) fail('no durable finalized-burn proof run is available');
  const runId=requestedRunId??entries[0];
  if(!entries.includes(runId)) fail('explicit finalized-burn proof run is unavailable');
  const root=path.join(runsRoot,runId);
  await requireDirectory(root);
  const status=await strictJsonFile(path.join(root,'run-status.json'),'proof run status',{
    privateMode:true,
  });
  exact(status,[
    'schema','status','runId','exitStatus','rayonWorkers','segmentLimitPo2','prover',
    'devMode','receiptKind','startedAt','recordedAt',
  ],'proof run status');
  const timestamp=/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
  if(status.schema!=='usdom-finalized-burn-prover-run-v1' || status.status!=='succeeded'
      || status.runId!==runId || status.exitStatus!==0 || ![1,2].includes(status.rayonWorkers)
      || status.segmentLimitPo2!==18 || status.prover!=='local' || status.devMode!==false
      || status.receiptKind!=='succinct' || !timestamp.test(status.startedAt)
      || !timestamp.test(status.recordedAt) || Date.parse(status.recordedAt)<Date.parse(status.startedAt)) {
    fail(`${requestedRunId?'explicitly selected':'latest'} durable finalized-burn proof run has not succeeded canonically`);
  }
  for(const name of [
    'finalized-burn-receipt.bin','finalized-burn-receipt-index.json','time.log','prover.log',
  ]) await directFile(path.join(root,name),{privateMode:true});
  return {runId,root,status};
}

async function latestSuccessfulProofRun() {
  return selectFinalizedBurnProofRun();
}

async function runCommand(command,args,{cwd,env=null,log}) {
  const output=await open(log,'w',0o600);
  try {
    const child=spawn(command,args,{cwd,env:env??process.env,stdio:['ignore',output.fd,output.fd]});
    const result=await new Promise((resolve,reject)=>{
      child.once('error',reject);
      child.once('close',(code,signal)=>resolve({code,signal}));
    });
    if(result.code!==0) fail(`${path.basename(command)} failed (${result.signal??result.code}); see ${log}`);
  } finally { await output.close(); }
}

function sanitizedProverEnvironment(extra={}) {
  const environment={...process.env,...extra,RAYON_NUM_THREADS:'1',MALLOC_ARENA_MAX:'2',
    RISC0_PROVER:'local',RISC0_DEV_MODE:'0'};
  for(const name of [
    'BONSAI_API_URL','BONSAI_API_KEY','BONSAI_POLL_INTERVAL_MS',
    'RISC0_SERVER_PATH','RISC0_SERVER_ADDR','RISC0_EXECUTOR','RISC0_PPROF_OUT',
    'RISC0_PPROF_ENABLE_INLINE_FUNCTIONS','RISC0_KECCAK_PO2',
    'RISC0_DEFAULT_PROVER_NUM_GPUS','RISC0_INFO','RISC0_REDIS_CHANNEL_SIZE',
  ]) {
    delete environment[name];
  }
  return environment;
}

async function requireLocalCompressionCapacity() {
  const memory=await readFile('/proc/meminfo','utf8');
  const available=memory.match(/^MemAvailable:\s+([0-9]+) kB$/m)?.[1];
  if(!available || BigInt(available)<3n*1024n*1024n || os.availableParallelism()<1) {
    fail('local Groth16 compression requires one CPU and 3 GiB of available RAM');
  }
}

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
    const reader=response.body.getReader();
    const chunks=[];
    let length=0;
    for(;;) {
      const {done,value}=await reader.read();
      if(done) break;
      length+=value.length;
      if(length>262144) {
        await reader.cancel();
        fail(`${method} response exceeds its byte bound`);
      }
      chunks.push(Buffer.from(value));
    }
    let text;
    try { text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,length)); }
    catch { fail(`${method} response is not valid UTF-8`); }
    const body=parseStrictJson(text,{label:`${method} response`});
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
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  const address=server.address();
  if(!address || typeof address==='string') fail('cannot allocate an isolated Anvil port');
  await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
  return address.port;
}

async function waitForAnvil(provider,child) {
  for(let attempt=0;attempt<300;attempt++) {
    if(child.exitCode!==null) fail(`Anvil exited before readiness: ${child.exitCode}`);
    try {
      if(await provider.send('eth_chainId',[])==='0x1') return;
    } catch {}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  fail('Anvil did not become ready');
}

async function terminate(child) {
  if(child.exitCode!==null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise(resolve=>child.once('close',resolve)),
    new Promise(resolve=>setTimeout(resolve,5000)),
  ]);
  if(child.exitCode===null) child.kill('SIGKILL');
}

async function verifyOnIsolatedEvm({observation,seal,runRoot,adapterArtifact}) {
  const port=await freePort();
  const anvilLog=await open(path.join(runRoot,'anvil.log'),'w',0o600);
  const child=spawn(process.env.USDOM_ANVIL??'anvil',[
    '--host','127.0.0.1','--port',String(port),'--chain-id','1','--silent',
  ],{stdio:['ignore',anvilLog.fd,anvilLog.fd]});
  const provider=new JsonRpcProvider(`http://127.0.0.1:${port}`,1,{
    staticNetwork:true,cacheTimeout:-1,
  });
  try {
    await waitForAnvil(provider,child);
    await provider.send('anvil_setCode',[observation.riscZeroVerifier,observation.runtimeCode]);
    const installed=await provider.getCode(observation.riscZeroVerifier);
    if(keccak256(installed)!==observation.runtimeCodeHash) fail('Anvil verifier runtime differs from observation');
    const signer=await provider.getSigner(0);
    const adapter=await new ContractFactory(adapterArtifact.abi,
      adapterArtifact.bytecode.object,signer).deploy(
      observation.riscZeroVerifier,'0x'+FINALIZED_BURN_CAPACITY_IMAGE_ID,
    );
    await adapter.waitForDeployment();
    const adapterAddress=await adapter.getAddress();
    const adapterCode=await provider.getCode(adapterAddress);
    const statement='0x'+FINALIZED_BURN_CAPACITY_STATEMENT_HASH;
    const proof=hexlify(seal);
    const accepted=await adapter.verifyFinalizedBurn.staticCall(statement,proof);
    if(accepted!==id('USDOM_FINALIZED_BURN_PROOF_V1')) fail('adapter returned the wrong acceptance commitment');
    const data=adapter.interface.encodeFunctionData('verifyFinalizedBurn',[statement,proof]);
    const transaction=await signer.sendTransaction({to:adapterAddress,data,gasLimit:5_000_000n});
    const receipt=await transaction.wait();
    if(!receipt || receipt.status!==1 || receipt.gasUsed===0n || receipt.gasUsed>5_000_000n) {
      fail('isolated adapter verification transaction failed or exceeded the gas cap');
    }
    const adapterRuntimeCodeHash=keccak256(adapterCode);
    const adapterVerifierConfigHash=await adapter.verifierConfigHash();
    const receiptTranscript=finalizedBurnIsolatedEvmReceiptCommitment({
      transactionHash:receipt.hash,blockHash:receipt.blockHash,
      blockNumber:String(receipt.blockNumber),adapter:adapterAddress,
      adapterRuntimeCodeHash,adapterVerifierConfigHash,
      statementHash:FINALIZED_BURN_CAPACITY_STATEMENT_HASH,evmSealSha256:rawSha(seal),
      adapterVerificationGas:receipt.gasUsed.toString(),
    });
    await writePrivateFileDurable(path.join(runRoot,'isolated-evm-receipt.json'),
      Buffer.from(receiptTranscript.canonicalTranscript));
    return {adapterRuntimeCodeHash,adapterVerifierConfigHash,
      adapterVerificationGas:receipt.gasUsed.toString(),adapterCallAccepted:true,
      isolatedEvmAdapter:receiptTranscript.record.adapter,
      isolatedEvmTransactionHash:receiptTranscript.record.transactionHash,
      isolatedEvmBlockHash:receiptTranscript.record.blockHash,
      isolatedEvmBlockNumber:receiptTranscript.record.blockNumber,
      isolatedEvmReceiptSha256:receiptTranscript.sha256};
  } finally {
    provider.destroy();
    await terminate(child);
    await anvilLog.close();
  }
}

async function snapshotFinalizedBurnAdapterArtifact(runRoot) {
  const source=path.join(labRoot,
    'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json');
  const bytes=await directFile(source,{maximum:16*1024*1024});
  const artifact=parseStrictJson(bytes.toString('utf8'),{
    label:'finalized-burn adapter artifact',maxBytes:16*1024*1024,maxDepth:64,
  });
  const snapshotDirectory=path.join(runRoot,'input-snapshots');
  await ensurePrivateDirectory(snapshotDirectory);
  const snapshot=path.join(snapshotDirectory,'finalized-burn-adapter-artifact.json');
  await writePrivateFileDurable(snapshot,bytes,{maximum:16*1024*1024});
  const installed=await directFile(snapshot,{maximum:16*1024*1024,privateMode:true});
  const expectedSha256=rawSha(bytes);
  if(!installed.equals(bytes) || rawSha(installed)!==expectedSha256) {
    fail('finalized-burn adapter artifact snapshot changed during installation');
  }
  return artifact;
}

export async function snapshotCapacitySourceMetrics(sourceRoot,runRoot) {
  const source=path.join(sourceRoot,'time.log');
  const bytes=await directFile(source,{maximum:1024*1024,privateMode:true});
  const sha256=rawSha(bytes);
  const snapshotDirectory=path.join(runRoot,'input-snapshots');
  await ensurePrivateDirectory(snapshotDirectory);
  const snapshot=path.join(snapshotDirectory,'source-prover-time.log');
  await writePrivateFileDurable(snapshot,bytes,{maximum:1024*1024});
  const installed=await directFile(snapshot,{maximum:1024*1024,privateMode:true});
  if(!installed.equals(bytes) || rawSha(installed)!==sha256) {
    fail('capacity source metrics snapshot changed during installation');
  }
  return {source,bytes,sha256};
}

export async function assertCapacitySourceMetricsUnchanged(record) {
  const current=await directFile(record.source,{maximum:1024*1024,privateMode:true});
  if(!current.equals(record.bytes) || rawSha(current)!==record.sha256) {
    fail('capacity source metrics changed during E2E execution');
  }
}

export async function snapshotCapacitySourceReceiptPair(sourceRoot,runRoot) {
  const names=['finalized-burn-receipt.bin','finalized-burn-receipt-index.json'];
  const snapshotDirectory=path.join(runRoot,'input-snapshots/source-receipt');
  await ensurePrivateDirectory(path.dirname(snapshotDirectory));
  await ensurePrivateDirectory(snapshotDirectory);
  const records=new Map();
  for(const name of names) {
    const source=path.join(sourceRoot,name);
    const maximum=name.endsWith('.json')?1024*1024:256*1024*1024;
    const bytes=await directFile(source,{maximum,privateMode:true});
    const sha256=rawSha(bytes),snapshot=path.join(snapshotDirectory,name);
    await writePrivateFileDurable(snapshot,bytes,{maximum});
    const installed=await directFile(snapshot,{maximum,privateMode:true});
    if(!installed.equals(bytes) || rawSha(installed)!==sha256) {
      fail(`capacity source receipt snapshot changed during installation: ${name}`);
    }
    records.set(name,{source,snapshot,sha256,size:installed.length,maximum});
  }
  return records;
}

export async function assertCapacitySourceReceiptOriginsUnchanged(records) {
  for(const [name,record] of records) {
    const current=await directFile(record.source,{maximum:record.maximum,privateMode:true});
    if(current.length!==record.size || rawSha(current)!==record.sha256) {
      fail(`capacity source receipt changed during E2E execution: ${name}`);
    }
  }
}

function exact(value,keys,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} must contain exact fields`);
  }
}

async function proofArtifacts(tempLab) {
  const receiptDirectory=path.join(tempLab,'evidence/finalized-burn-receipt');
  const proofDirectory=path.join(tempLab,'evidence/finalized-burn-evm-proof');
  const receiptPath=path.join(receiptDirectory,'finalized-burn-receipt.bin');
  const receiptIndexPath=path.join(receiptDirectory,'finalized-burn-receipt-index.json');
  const groth16Path=path.join(proofDirectory,'finalized-burn-groth16-receipt.bin');
  const sealPath=path.join(proofDirectory,'finalized-burn-evm-seal.bin');
  const proofIndexPath=path.join(proofDirectory,'finalized-burn-evm-proof-index.json');
  // Large receipts are intentionally read in sequence and reduced to their
  // authenticated identity before the next one is captured.
  let receipt=await directFile(receiptPath,{maximum:256*1024*1024,privateMode:true});
  const receiptIdentity={sha256:rawSha(receipt),bytes:receipt.length};
  receipt=null;
  const receiptIndexBytes=await directFile(receiptIndexPath,{maximum:1024*1024,privateMode:true});
  let groth16=await directFile(groth16Path,{maximum:256*1024*1024,privateMode:true});
  const groth16Identity={sha256:rawSha(groth16),bytes:groth16.length};
  groth16=null;
  const seal=await directFile(sealPath,{maximum:64*1024,privateMode:true});
  const proofIndexBytes=await directFile(proofIndexPath,{maximum:1024*1024,privateMode:true});
  const receiptIndex=parseStrictJson(receiptIndexBytes.toString('utf8'),{
    label:'succinct receipt index',
  });
  const proofIndex=parseStrictJson(proofIndexBytes.toString('utf8'),{label:'EVM proof index'});
  exact(receiptIndex,[
    'schema','proof_job_index_path','proof_job_index_sha256','input_path','input_sha256',
    'statement_hash','program_path','program_sha256','image_id','risc0_zkvm_version',
    'receipt_kind','segment_limit_po2','receipt_file','receipt_sha256','receipt_bytes',
    'relation_executed','receipt_verified','dev_mode','generates_proofs','mines',
  ],'succinct receipt index');
  exact(proofIndex,[
    'schema','receipt_index_path','receipt_index_sha256','image_id','statement_hash',
    'journal_digest','risc0_zkvm_version','receipt_kind','groth16_verifier_parameters',
    'evm_verifier_selector','groth16_receipt_file','groth16_receipt_sha256',
    'groth16_receipt_bytes','evm_seal_file','evm_seal_sha256','evm_seal_bytes',
    'receipt_verified','dev_mode','generates_proofs','mines',
  ],'EVM proof index');
  if(receiptIndex.schema!=='usdom-finalized-burn-receipt-v1'
      || receiptIndex.proof_job_index_path
        !=='evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json'
      || receiptIndex.input_path!=='evidence/finalized-burn-proof-job/finalized-burn-input.bin'
      || receiptIndex.receipt_file!=='finalized-burn-receipt.bin'
      || receiptIndex.input_sha256!==FINALIZED_BURN_CAPACITY_INPUT_SHA256
      || receiptIndex.statement_hash!==FINALIZED_BURN_CAPACITY_STATEMENT_HASH
      || receiptIndex.program_sha256!==FINALIZED_BURN_CAPACITY_PROGRAM_SHA256
      || receiptIndex.image_id!==FINALIZED_BURN_CAPACITY_IMAGE_ID
      || receiptIndex.risc0_zkvm_version!=='3.0.6' || receiptIndex.receipt_kind!=='succinct'
      || receiptIndex.segment_limit_po2!==18 || receiptIndex.receipt_sha256!==receiptIdentity.sha256
      || receiptIndex.receipt_bytes!==receiptIdentity.bytes || receiptIndex.relation_executed!==true
      || receiptIndex.receipt_verified!==true || receiptIndex.dev_mode!==false
      || receiptIndex.generates_proofs!==true || receiptIndex.mines!==false) {
    fail('succinct receipt index differs from the capacity proof artifacts');
  }
  if(proofIndex.schema!=='usdom-finalized-burn-evm-proof-v1'
      || proofIndex.receipt_index_path
        !=='evidence/finalized-burn-receipt/finalized-burn-receipt-index.json'
      || proofIndex.receipt_index_sha256!==rawSha(receiptIndexBytes)
      || proofIndex.image_id!==FINALIZED_BURN_CAPACITY_IMAGE_ID
      || proofIndex.statement_hash!==FINALIZED_BURN_CAPACITY_STATEMENT_HASH
      || proofIndex.risc0_zkvm_version!=='3.0.6' || proofIndex.receipt_kind!=='groth16'
      || proofIndex.journal_digest!==rawSha(Buffer.from(FINALIZED_BURN_CAPACITY_STATEMENT_HASH,'hex'))
      || proofIndex.groth16_verifier_parameters
        !=='73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc'
      || proofIndex.evm_verifier_selector!=='73c457ba'
      || proofIndex.groth16_receipt_file!=='finalized-burn-groth16-receipt.bin'
      || proofIndex.evm_seal_file!=='finalized-burn-evm-seal.bin'
      || proofIndex.groth16_receipt_sha256!==groth16Identity.sha256
      || proofIndex.groth16_receipt_bytes!==groth16Identity.bytes
      || proofIndex.evm_seal_sha256!==rawSha(seal) || proofIndex.evm_seal_bytes!==seal.length
      || seal.length!==FINALIZED_BURN_EVM_SEAL_BYTES
      || seal.subarray(0,4).toString('hex')!=='73c457ba'
      || proofIndex.receipt_verified!==true || proofIndex.dev_mode!==false
      || proofIndex.generates_proofs!==true || proofIndex.mines!==false) {
    fail('Groth16 proof index differs from the capacity artifacts');
  }
  return {receiptIdentity,receiptIndex,groth16Identity,seal,proofIndex};
}

async function main() {
  if(process.argv.length!==2) fail('this fixed capacity command accepts no arguments');
  if(!path.isAbsolute(os.homedir()) || os.homedir()==='/' || os.homedir()!==process.env.HOME
      || os.homedir()!==os.userInfo().homedir) {
    fail('HOME must be the current operating-system account home');
  }
  await requireDirectory(os.homedir(),{privateMode:false});
  const source=await latestSuccessfulProofRun();
  await ensurePrivateDirectory(capacityRunsRoot);
  const runRoot=path.join(capacityRunsRoot,source.runId);
  await ensurePrivateDirectory(runRoot);
  const existingReportPath=path.join(runRoot,'capacity-report.json');
  try {
    const existingBytes=await directFile(existingReportPath,{maximum:1024*1024,privateMode:true});
    const existing=parseStrictJson(existingBytes.toString('utf8'),{label:'existing capacity report'});
    validateFinalizedBurnCapacityReport(existing,{riscZeroReference:PINNED_RISC0_MAINNET_V3});
    console.log(JSON.stringify({ok:true,status:'already-succeeded',runId:source.runId,
      reportPath:existingReportPath,reportSha256:rawSha(existingBytes)},null,2));
    return;
  } catch(error) {
    if(error?.code!=='ENOENT' && !String(error?.message??error).includes('unsafe capacity file')) throw error;
  }
  await atomicJson(path.join(runRoot,'run-status.json'),{
    schema:'usdom-finalized-burn-capacity-run-v1',status:'running',runId:source.runId,
    recordedAt:new Date().toISOString(),
  });
  activeCapacityStatus={path:path.join(runRoot,'run-status.json'),runId:source.runId};
  const sourceMetrics=await snapshotCapacitySourceMetrics(source.root,runRoot);
  const sourceReceipts=await snapshotCapacitySourceReceiptPair(source.root,runRoot);
  const workRoot=path.join(runRoot,'work');
  const tempLab=path.join(workRoot,'labs/usdom-reserve');
  const guestDirectory=path.join(tempLab,'evidence/finalized-burn-guest');
  for(const directory of [workRoot,path.join(workRoot,'labs'),tempLab,
    path.join(workRoot,'crates'),path.dirname(guestDirectory),guestDirectory,
    path.join(tempLab,'evidence'),path.join(tempLab,'evidence/finalized-burn-source'),
    path.join(tempLab,'evidence/finalized-burn-proof-job'),
    path.join(tempLab,'evidence/finalized-burn-receipt'),
    path.join(tempLab,'evidence/finalized-burn-evm-proof')]) await ensurePrivateDirectory(directory);
  for(const name of ['usdom-finalized-burn.elf','usdom-finalized-burn.iid']) {
    const destination=path.join(guestDirectory,name);
    try { await directFile(destination,{privateMode:true}); }
    catch(error) {
      if(error?.code!=='ENOENT') throw error;
      const sourceBytes=await directFile(path.join(repositoryRoot,
        'crates/dom-usdom-finalized-burn-risc0-guest/elfs',name),{maximum:4*1024*1024});
      await writePrivateFileDurable(destination,sourceBytes,{maximum:4*1024*1024});
    }
  }
  const sourceInput=path.join(tempLab,'evidence/finalized-burn-source/finalized-burn-input.bin');
  const recursionArtifact=await requireRisc0RecursionArtifact({
    environment:sanitizedProverEnvironment(),
  });
  const proverEnvironment=recursionArtifact.environment;
  await runCommand('cargo',[
    'test','--quiet','--release','--locked','-p','dom-usdom-finalized-burn-program',
    '--test','raw_checkpoint_positive','raw_ethereum_checkpoint_executes_udfinl04_end_to_end',
    '--','--exact',
  ],{cwd:repositoryRoot,env:{...proverEnvironment,CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS:'true',
    USDOM_RAW_CHECKPOINT_VECTOR_OUT:sourceInput},log:path.join(runRoot,'vector.log')});
  const sourceBytes=await readDirectFile(sourceInput,{minimum:1,maximum:16*1024*1024,
    privateMode:true,label:'regenerated finalized-burn capacity input'});
  if(sourceBytes.length!==FINALIZED_BURN_CAPACITY_INPUT_BYTES
      || rawSha(sourceBytes)!==FINALIZED_BURN_CAPACITY_INPUT_SHA256) {
    fail('regenerated capacity input differs from the frozen vector');
  }
  await runCommand('cargo',[
    'run','--quiet','--release','--locked','--manifest-path',path.join(repositoryRoot,'Cargo.toml'),
    '-p','dom-usdom-finalized-burn-proof-host','--bin','dom-usdom-plan-finalized-burn-proof',
  ],{cwd:tempLab,env:proverEnvironment,log:path.join(runRoot,'planner.log')});
  for(const name of ['finalized-burn-receipt.bin','finalized-burn-receipt-index.json']) {
    const destination=path.join(tempLab,'evidence/finalized-burn-receipt',name);
    const record=sourceReceipts.get(name)??fail(`missing source receipt snapshot: ${name}`);
    const bytes=await directFile(record.snapshot,{minimum:record.size,maximum:record.size,
      privateMode:true});
    if(rawSha(bytes)!==record.sha256) fail(`source receipt snapshot changed: ${name}`);
    await writePrivateFileDurable(destination,bytes,{maximum:record.maximum});
  }
  await requireLocalCompressionCapacity();
  await runCommand('/usr/bin/time',[
    '-v','-o',path.join(runRoot,'packager-time.log'),'cargo','run','--quiet','--release','--locked',
    '--manifest-path',path.join(repositoryRoot,'Cargo.toml'),'-p',
    'dom-usdom-finalized-burn-proof-host','--features','prove','--bin',
    'dom-usdom-package-finalized-burn-evm-proof',
  ],{cwd:tempLab,env:proverEnvironment,log:path.join(runRoot,'packager.log')});
  const adapterArtifact=await snapshotFinalizedBurnAdapterArtifact(runRoot);
  const artifacts=await proofArtifacts(tempLab);
  const observation=await observePinnedRiscZeroRuntime({
    reference:PINNED_RISC0_MAINNET_V3,sources,rpc,
  });
  await writePrivateFileDurable(path.join(runRoot,'risc0-mainnet-verifier-runtime.hex'),
    observation.runtimeCode+'\n');
  const evm=await verifyOnIsolatedEvm({observation,seal:artifacts.seal,runRoot,adapterArtifact});
  const metrics=parseProverResourceMetrics(sourceMetrics.bytes.toString('utf8'));
  const startedAt=BigInt(Math.floor(Date.parse(source.status.startedAt)/1000));
  if(startedAt<=0n) fail('source proof start time is invalid');
  const completedAt=BigInt(Math.floor(Date.now()/1000));
  const report={
    schema:FINALIZED_BURN_CAPACITY_REPORT_SCHEMA,runId:source.runId,
    startedAt:startedAt.toString(),completedAt:completedAt.toString(),
    provingWallMilliseconds:metrics.provingWallMilliseconds,peakResidentKiB:metrics.peakResidentKiB,
    rayonWorkers:source.status.rayonWorkers,segmentLimitPo2:18,prover:'local',devMode:false,
    receiptKind:'groth16',receiptVerified:true,risc0ZkvmVersion:'3.0.6',mines:false,
    broadcastAuthorized:false,releaseSpecific:false,ethereumChainId:'1',
    inputSha256:FINALIZED_BURN_CAPACITY_INPUT_SHA256,inputBytes:FINALIZED_BURN_CAPACITY_INPUT_BYTES,
    statementHash:FINALIZED_BURN_CAPACITY_STATEMENT_HASH,
    guestProgramSha256:FINALIZED_BURN_CAPACITY_PROGRAM_SHA256,
    guestImageId:FINALIZED_BURN_CAPACITY_IMAGE_ID,
    succinctReceiptSha256:artifacts.receiptIdentity.sha256,
    succinctReceiptBytes:String(artifacts.receiptIdentity.bytes),
    groth16ReceiptSha256:artifacts.groth16Identity.sha256,
    groth16ReceiptBytes:String(artifacts.groth16Identity.bytes),
    evmSealSha256:rawSha(artifacts.seal),evmSealBytes:String(artifacts.seal.length),
    riscZeroVerifier:observation.riscZeroVerifier,
    riscZeroVerifierCodeHash:observation.runtimeCodeHash,
    finalizedObservationBlockNumber:observation.finalizedBlockNumber,
    finalizedObservationBlockHash:observation.finalizedBlockHash,
    observationSourceIds:[...observation.sourceIds],
    observationEndpointHashes:[...observation.endpointSha256],
    adapterRuntimeCodeHash:evm.adapterRuntimeCodeHash,
    adapterVerifierConfigHash:evm.adapterVerifierConfigHash,
    adapterCallAccepted:evm.adapterCallAccepted,
    adapterVerificationGas:evm.adapterVerificationGas,
    isolatedEvmAdapter:evm.isolatedEvmAdapter,
    isolatedEvmTransactionHash:evm.isolatedEvmTransactionHash,
    isolatedEvmBlockHash:evm.isolatedEvmBlockHash,
    isolatedEvmBlockNumber:evm.isolatedEvmBlockNumber,
    isolatedEvmReceiptSha256:evm.isolatedEvmReceiptSha256,
  };
  await assertCapacitySourceMetricsUnchanged(sourceMetrics);
  await assertCapacitySourceReceiptOriginsUnchanged(sourceReceipts);
  validateFinalizedBurnCapacityReport(report,{riscZeroReference:PINNED_RISC0_MAINNET_V3});
  await atomicJson(existingReportPath,report);
  const reportSha256=await privateFileSha(existingReportPath,{
    minimum:1,maximum:1024*1024,privateMode:true,label:'capacity report',
  });
  await atomicJson(path.join(runRoot,'run-status.json'),{
    schema:'usdom-finalized-burn-capacity-run-v1',status:'succeeded',runId:source.runId,
    reportSha256,recordedAt:new Date().toISOString(),
  });
  activeCapacityStatus=null;
  console.log(JSON.stringify({ok:true,status:'succeeded',runId:source.runId,
    reportPath:existingReportPath,reportSha256,adapterVerificationGas:evm.adapterVerificationGas,
    adapterVerifierConfigHash:evm.adapterVerifierConfigHash},null,2));
}

if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try { await main(); }
  catch(error) {
    if(activeCapacityStatus) {
      try {
        await atomicJson(activeCapacityStatus.path,{
          schema:'usdom-finalized-burn-capacity-run-v1',status:'failed',
          runId:activeCapacityStatus.runId,error:'RELEASE_OPERATION_REJECTED',
          recordedAt:new Date().toISOString(),
        });
      } catch {}
    }
    writeReleaseFailure('run-finalized-burn-capacity-e2e',error);
    process.exitCode=1;
  }
}
