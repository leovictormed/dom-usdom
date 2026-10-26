import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {validateReleaseSourceBoundary} from '../../sdk/release-source-boundary.mjs';

const scriptUrl=new URL('../../scripts/run-checkpoint-capacity-e2e.mjs',import.meta.url);
const source=await readFile(scriptUrl,'utf8');
const boundarySource=await readFile(new URL(
  '../../sdk/release-source-boundary.mjs',import.meta.url,
),'utf8');

test('checkpoint capacity executor fixes the complete local non-dev proof graph',()=>{
  for(const value of [
    "RAYON_NUM_THREADS:'1'","RISC0_PROVER:'local'","RISC0_DEV_MODE:'0'",
    'process.umask(0o077)',
    'os.userInfo().homedir',
    'dom-usdom-prove-randomx-receipt-set','dom-usdom-prove-randomx-aggregate-set',
    'dom-usdom-prove-economic-receipt-set','dom-usdom-prove-checkpoint-segment-set',
    'dom-usdom-prove-checkpoint-outer','dom-usdom-package-checkpoint-outer-evm-proof',
    "await timedCargo('randomx'","await timedCargo('randomx-aggregate'",
    "await timedCargo('economic'","await timedCargo('segment'",
    "await timedCargo('outer'","await timedCargo('compression'",
    'collectCheckpointCapacityArtifacts','buildCheckpointProofCapacityReport',
    'parseRandomxProverSummary','reconcileRandomxProverSummary',
    'collected.randomxVerifiedGraph',
    'randomxProverTranscriptSha256','randomxResourceLogSha256',
    'riscZeroFinalizedBlockNumber','riscZeroObservationEndpointHashes',
    'riscZeroRuntimeArtifactSha256',
    'checkpointIsolatedEvmReceiptCommitment','isolated-evm-receipt.json',
    'isolatedEvmReceiptSha256','isolatedEvmTransactionHash','isolatedEvmBlockHash',
    'buildAuthenticatedCheckpointSubmission','observePinnedRiscZeroRuntime',
    'assertConfiguredInputsUnchanged(configured)',
    'validateReleaseSourceBoundary',
    "'build','--quiet','--release','--locked'",
    "'anvil_setCode'",'adapterVerificationGas','broadcastAuthorized:false',
    'writePrivateJsonDurable','readDirectFile','readDirectProjectFile','writePrivateFileDurable',
    'readDirectProjectFile(labRoot,releaseRelative)',
    'readDirectProjectFile(labRoot,verifierRelative)',
    'readDirectProjectFile(labRoot,evidenceRelative)',
  ]) assert.match(source,new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  for(const value of [
    'config/mainnet-release-evidence.unconfigured.json','config/operator-intent.json',
    "relative.startsWith(`${root}/evidence/`)",
  ]) assert.match(boundarySource,new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  for(const variable of [
    'BONSAI_API_URL','BONSAI_API_KEY','BONSAI_POLL_INTERVAL_MS','RISC0_SERVER_PATH',
    'RISC0_SERVER_ADDR','RISC0_EXECUTOR','RISC0_PPROF_OUT','RISC0_KECCAK_PO2',
    'RISC0_DEFAULT_PROVER_NUM_GPUS','RISC0_REDIS_CHANNEL_SIZE',
  ]) assert.match(source,new RegExp(`'${variable}'`));
  assert.doesNotMatch(source,/eth_sendRawTransaction|wallet_sendTransaction|broadcastAuthorized:true/);
  assert.doesNotMatch(source,/readFile\((?:releasePath|verifierPath|evidencePath|reportPath)\)/);
  assert.doesNotMatch(source,/copyFile\(from,to\)|copyFile\(source,path\.join\(destination,name\)\)/);
});

test('checkpoint capacity executor rejects every argument before creating a run',async()=>{
  const child=spawn(process.execPath,[scriptUrl.pathname,'unexpected'],{
    cwd:new URL('../..',import.meta.url),stdio:['ignore','pipe','pipe'],
  });
  let output='';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data',value=>{output+=value;});
  child.stderr.on('data',value=>{output+=value;});
  const code=await new Promise((resolve,reject)=>{
    child.once('error',reject); child.once('close',resolve);
  });
  assert.equal(code,1);
  assert.equal(JSON.parse(output).code,'RELEASE_OPERATION_REJECTED');
});

test('checkpoint capacity snapshots the adapter before Anvil and publishes completion last',()=>{
  const snapshot=source.indexOf('snapshotCheckpointAdapterArtifact(runRoot)');
  const observation=source.indexOf('observePinnedRiscZeroRuntime({',snapshot);
  const isolatedEvm=source.indexOf('verifyOnIsolatedEvm({',observation);
  const report=source.indexOf('await atomicJson(reportPath,report)',isolatedEvm);
  const completion=source.indexOf("status:'succeeded'",report);
  assert.ok(snapshot>=0 && snapshot<observation && observation<isolatedEvm);
  assert.ok(isolatedEvm<report && report<completion);
  assert.match(source,/createPrivateDirectory\(snapshotDirectory\)/);
  assert.match(source,/writePrivateFileDurable\(snapshot,bytes/);
  assert.match(source,/installed\.equals\(bytes\)/);
  const verifierBody=source.slice(source.indexOf('async function verifyOnIsolatedEvm'),
    source.indexOf('async function snapshotCheckpointAdapterArtifact'));
  assert.doesNotMatch(verifierBody,/DOMCheckpointRiscZeroVerifier\.json/);
  assert.match(verifierBody,/adapterArtifact\.bytecode\.object/);
});

test('checkpoint capacity source boundary permits evidence-only changes',()=>{
  const commit='a'.repeat(40),root='labs/usdom-reserve';
  const valid=[
    ` M ${root}/config/mainnet-release-evidence.unconfigured.json`,
    `M  ${root}/config/operator-intent.json`,
    `?? ${root}/evidence/capacity/report.json`,
  ].join('\0')+'\0';
  assert.doesNotThrow(()=>validateReleaseSourceBoundary({
    head:commit,sourceCommit:commit,status:valid,projectRelative:root,
  }));
  for(const changed of [
    {head:'b'.repeat(40),status:valid},
    {head:commit,status:` M ${root}/sdk/reserve.mjs\0`},
    {head:commit,status:`D  ${root}/evidence/capacity/report.json\0`},
    {head:commit,status:`R  ${root}/evidence/a.json\0${root}/evidence/b.json\0`},
  ]) assert.throws(()=>validateReleaseSourceBoundary({
    head:changed.head,sourceCommit:commit,status:changed.status,projectRelative:root,
  }));
});

test('checkpoint capacity snapshots and rechecks every report transcript and resource log',()=>{
  const snapshot=source.indexOf('const reportLogs=await snapshotReportLogs(runRoot)');
  const observation=source.indexOf('observePinnedRiscZeroRuntime({',snapshot);
  const recheck=source.indexOf('assertReportLogOriginsUnchanged(reportLogs)',observation);
  const report=source.indexOf('await atomicJson(reportPath,report)',recheck);
  assert.ok(snapshot>=0 && snapshot<observation && observation<recheck && recheck<report);
  for(const name of [
    'randomx.log','randomx-time.log','randomx-aggregate-time.log','segment-time.log',
    'outer-time.log','compression-time.log',
  ]) assert.match(source,new RegExp(`\\['${name.replaceAll('.','\\.')}'`));
  assert.match(source,/input-snapshots\/report-logs/);
  assert.match(source,/installed\.equals\(bytes\)/);
  assert.match(source,/rawSha\(installed\)!==sha256/);
  assert.match(source,/current\.equals\(record\.bytes\)/);
  assert.match(source,/rawSha\(current\)!==record\.sha256/);
  assert.doesNotMatch(source.slice(snapshot,observation),
    /readDirectFile\(path\.join\(runRoot,`\$\{name\}-time\.log`/);
});
