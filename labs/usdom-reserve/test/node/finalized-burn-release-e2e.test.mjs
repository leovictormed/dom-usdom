import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  assertFinalizedBurnReleaseMetricOriginsUnchanged,
  snapshotFinalizedBurnReleaseMetricLogs,
} from '../../scripts/run-finalized-burn-release-e2e.mjs';
import {finalizedBurnReleaseEvmReceiptCommitment}
  from '../../sdk/finalized-burn-e2e-report.mjs';

const scriptUrl=new URL('../../scripts/run-finalized-burn-release-e2e.mjs',import.meta.url);
const source=await readFile(scriptUrl,'utf8');

test('release-specific finalized-burn executor fixes the local proof and EVM boundaries',()=>{
  for(const value of [
    'process.umask(0o077)','os.userInfo().homedir',"RAYON_NUM_THREADS:'1'","RISC0_PROVER:'local'","RISC0_DEV_MODE:'0'",
    'validateReleaseSourceBoundary','collectFinalizedBurnArtifacts','validateFinalizedBurnE2eReport',
    'dom-usdom-plan-finalized-burn-proof','dom-usdom-prove-finalized-burn',
    'dom-usdom-package-finalized-burn-evm-proof',"await timedCargo('prover'",
    "await timedCargo('compression'",'observePinnedRiscZeroRuntime',"'anvil_setCode'",
    'adapter.verifyFinalizedBurn.staticCall','gasLimit:5_000_000n','releaseSpecific:true',
    'finalizedBurnReleaseEvmReceiptCommitment','isolated-evm-receipt.json',
    'isolatedEvmReceiptSha256','isolatedEvmTransactionHash','isolatedEvmBlockHash',
    'writePrivateJsonDurable','readDirectFile','readDirectProjectFile','writePrivateFileDurable',
    'broadcastAuthorized:false','mines:false','assertConfiguredInputsUnchanged(configured)',
    'config/proof-reserve.unconfigured.json','config/finalized-burn-verifier.unconfigured.json',
    'config/mainnet-release-evidence.unconfigured.json',
  ]) assert.match(source,new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  for(const variable of [
    'BONSAI_API_URL','BONSAI_API_KEY','BONSAI_POLL_INTERVAL_MS','RISC0_SERVER_PATH',
    'RISC0_SERVER_ADDR','RISC0_EXECUTOR','RISC0_PPROF_OUT','RISC0_KECCAK_PO2',
    'RISC0_DEFAULT_PROVER_NUM_GPUS','RISC0_REDIS_CHANNEL_SIZE',
  ]) assert.match(source,new RegExp(`'${variable}'`));
  assert.doesNotMatch(source,/eth_sendRawTransaction|wallet_sendTransaction|broadcastAuthorized:true/);
  assert.doesNotMatch(source,/mnemonic|privateKey|private_key|--private-key/i);
  assert.doesNotMatch(source,/copyFile\(from,to\)|copyFile\(source,path\.join\(guestDirectory,name\)\)/);
  assert.doesNotMatch(source,/readFile\((?:reportPath|path\.join\(runRoot,'(?:prover|compression)-time\.log'\))/);
});

test('release-specific finalized-burn executor rejects every argument before creating a run',async()=>{
  const child=spawn(process.execPath,[scriptUrl.pathname,'unexpected'],{
    cwd:new URL('../..',import.meta.url),stdio:['ignore','pipe','pipe'],
  });
  let output='';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data',value=>{output+=value;}); child.stderr.on('data',value=>{output+=value;});
  const code=await new Promise((resolve,reject)=>{
    child.once('error',reject); child.once('close',resolve);
  });
  assert.equal(code,1);
  assert.equal(JSON.parse(output).code,'RELEASE_OPERATION_REJECTED');
});

test('release-specific finalized-burn executor snapshots its adapter before Anvil',()=>{
  const snapshot=source.indexOf('snapshotFinalizedBurnAdapterArtifact(runRoot)');
  const observation=source.indexOf('observePinnedRiscZeroRuntime({',snapshot);
  const isolatedEvm=source.indexOf('verifyOnIsolatedEvm({',observation);
  const report=source.indexOf('await atomicJson(reportPath,report)',isolatedEvm);
  const completion=source.indexOf("status:'succeeded'",report);
  assert.ok(snapshot>=0 && snapshot<observation && observation<isolatedEvm);
  assert.ok(isolatedEvm<report && report<completion);
  assert.match(source,/createPrivateDirectory\(snapshotDirectory\)/);
  assert.match(source,/writePrivateFileDurable\(snapshot,bytes/);
  assert.match(source,/installed\.equals\(bytes\)/);
  assert.match(source,/rawSha\(installed\)!==expectedSha256/);
  const verifierBody=source.slice(source.indexOf('async function verifyOnIsolatedEvm'),
    source.indexOf('async function snapshotFinalizedBurnAdapterArtifact'));
  assert.doesNotMatch(verifierBody,/DOMFinalizedBurnRiscZeroVerifier\.json/);
  assert.match(verifierBody,/adapterArtifact\.bytecode\.object/);
});

test('release EVM receipt rejects oversized decimal evidence before numeric conversion',()=>{
  const input={transactionHash:'0x'+'11'.repeat(32),blockHash:'0x'+'22'.repeat(32),
    blockNumber:'1',adapter:'0x'+'33'.repeat(20),adapterRuntimeCodeHash:'0x'+'44'.repeat(32),
    verifierConfigHash:'0x'+'55'.repeat(32),statementHash:'0x'+'66'.repeat(32),
    evmSealSha256:'77'.repeat(32),evmVerificationGas:'1'};
  for(const field of ['blockNumber','evmVerificationGas']) {
    assert.throws(()=>finalizedBurnReleaseEvmReceiptCommitment({
      ...input,[field]:'9'.repeat(100000),
    }),/canonical unsigned decimal/);
  }
});

test('release E2E rejects concurrent metric-log substitution after its private snapshot',async()=>{
  const runRoot=await mkdtemp(path.join(os.tmpdir(),'usdom-release-metrics-'));
  try {
    await writeFile(path.join(runRoot,'prover-time.log'),'Maximum resident set size (kbytes): 1\n',{
      mode:0o600,
    });
    await writeFile(path.join(runRoot,'compression-time.log'),
      'Maximum resident set size (kbytes): 2\n',{mode:0o600});
    const snapshots=await snapshotFinalizedBurnReleaseMetricLogs(runRoot);
    await writeFile(path.join(runRoot,'prover-time.log'),
      'Maximum resident set size (kbytes): 9\n',{mode:0o600});
    await assert.rejects(assertFinalizedBurnReleaseMetricOriginsUnchanged(snapshots),
      /metric-log origin changed during E2E execution: prover-time\.log/);
  } finally { await rm(runRoot,{recursive:true,force:true}); }
});
