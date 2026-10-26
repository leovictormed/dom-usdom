import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,rm,stat,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {keccak256} from 'ethers';
import {
  assertCapacitySourceMetricsUnchanged,assertCapacitySourceReceiptOriginsUnchanged,
  selectFinalizedBurnProofRun,snapshotCapacitySourceMetrics,snapshotCapacitySourceReceiptPair,
} from '../../scripts/run-finalized-burn-capacity-e2e.mjs';

const script=await readFile(new URL(
  '../../scripts/run-finalized-burn-capacity-e2e.mjs',import.meta.url,
),'utf8');
const observer=await readFile(new URL(
  '../../sdk/risc0-capacity-runtime-observer.mjs',import.meta.url,
),'utf8');
const runtimePath=new URL('../fixtures/risc0-mainnet-v3-runtime.hex',import.meta.url);

test('fixed capacity runner preserves the release and public-network boundaries',()=>{
  assert.match(script,/writePrivateJsonDurable/);
  assert.match(script,/writePrivateFileDurable/);
  assert.match(script,/readDirectFile/);
  assert.match(script,/process\.argv\.length!==2/);
  assert.match(script,/process\.umask\(0o077\)/);
  assert.match(script,/os\.userInfo\(\)\.homedir/);
  assert.match(script,/status\.status!==['"]succeeded['"]/);
  assert.match(script,/RISC0_PROVER:'local'/);
  assert.match(script,/RISC0_DEV_MODE:'0'/);
  assert.match(script,/'RISC0_EXECUTOR'/);
  assert.match(script,/delete environment\[name\]/);
  assert.match(script,/MemAvailable/);
  assert.match(script,/3n\*1024n\*1024n/);
  assert.match(script,/https:\/\/eth\.drpc\.org\//);
  assert.match(script,/https:\/\/ethereum-rpc\.publicnode\.com\//);
  assert.match(script,/length>262144/);
  assert.match(script,/new TextDecoder\(['"]utf-8['"],\{fatal:true\}\)/);
  assert.match(script,/parseStrictJson\(text/);
  assert.match(script,/maximum:256\*1024\*1024/);
  assert.match(script,/receipt=null/);
  assert.match(script,/groth16=null/);
  assert.match(observer,/eth_getBlockByNumber/);
  assert.match(observer,/eth_getCode/);
  assert.match(script,/anvil_setCode/);
  assert.match(script,/http:\/\/127\.0\.0\.1:/);
  assert.match(script,/adapter\.verifyFinalizedBurn\.staticCall/);
  assert.match(script,/receipt\.gasUsed/);
  assert.match(script,/finalizedBurnIsolatedEvmReceiptCommitment/);
  assert.match(script,/isolated-evm-receipt\.json/);
  assert.match(script,/isolatedEvmReceiptSha256/);
  assert.match(script,/gasLimit:5_000_000n/);
  assert.match(script,/releaseSpecific:false/);
  assert.match(script,/broadcastAuthorized:false/);
  assert.match(script,/validateFinalizedBurnCapacityReport/);
  assert.doesNotMatch(script,/\bgit\s+(?:push|fetch|pull)\b/);
  assert.doesNotMatch(script,/eth_sendRawTransaction/);
  assert.doesNotMatch(script,/mnemonic|privateKey|private_key|--private-key/i);
  assert.doesNotMatch(script,/copyFile\(|readFile\((?:receiptPath|groth16Path|sealPath|receiptIndexPath|existingReportPath|sourceInput)\)/);
});

test('capacity fixture is the exact pinned Ethereum mainnet verifier runtime',async()=>{
  const metadata=await stat(runtimePath);
  const runtime=(await readFile(runtimePath,'utf8')).trim();
  assert.equal(metadata.mode&0o777,0o644);
  assert.equal((runtime.length-2)/2,5313);
  assert.equal(keccak256(runtime),'0xfe03c66078969d097f867351171b4639d726c8376c35022675ed44cbbcbaa720');
});

test('capacity runner snapshots its adapter before observation and Anvil',()=>{
  const snapshot=script.indexOf('snapshotFinalizedBurnAdapterArtifact(runRoot)');
  const observation=script.indexOf('observePinnedRiscZeroRuntime({',snapshot);
  const isolatedEvm=script.indexOf('verifyOnIsolatedEvm({',observation);
  const report=script.indexOf('await atomicJson(existingReportPath,report)',isolatedEvm);
  const completion=script.indexOf("status:'succeeded'",report);
  assert.ok(snapshot>=0 && snapshot<observation && observation<isolatedEvm);
  assert.ok(isolatedEvm<report && report<completion);
  assert.match(script,/ensurePrivateDirectory\(snapshotDirectory\)/);
  assert.match(script,/writePrivateFileDurable\(snapshot,bytes/);
  assert.match(script,/installed\.equals\(bytes\)/);
  assert.match(script,/rawSha\(installed\)!==expectedSha256/);
  const verifierBody=script.slice(script.indexOf('async function verifyOnIsolatedEvm'),
    script.indexOf('async function snapshotFinalizedBurnAdapterArtifact'));
  assert.doesNotMatch(verifierBody,/DOMFinalizedBurnRiscZeroVerifier\.json/);
  assert.match(verifierBody,/adapterArtifact\.bytecode\.object/);
});

test('capacity runner rejects concurrent source-metric substitution',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-capacity-source-metrics-'));
  const sourceRoot=path.join(root,'source'),runRoot=path.join(root,'run');
  try {
    await Promise.all([mkdir(sourceRoot,{mode:0o700}),mkdir(runRoot,{mode:0o700})]);
    await writeFile(path.join(sourceRoot,'time.log'),
      'Maximum resident set size (kbytes): 1\n',{mode:0o600});
    const snapshot=await snapshotCapacitySourceMetrics(sourceRoot,runRoot);
    await writeFile(path.join(sourceRoot,'time.log'),
      'Maximum resident set size (kbytes): 9\n',{mode:0o600});
    await assert.rejects(assertCapacitySourceMetricsUnchanged(snapshot),
      /capacity source metrics changed during E2E execution/);
  } finally { await rm(root,{recursive:true,force:true}); }
});

test('capacity runner rejects concurrent source receipt-index substitution',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-capacity-source-receipt-'));
  const sourceRoot=path.join(root,'source'),runRoot=path.join(root,'run');
  try {
    await Promise.all([mkdir(sourceRoot,{mode:0o700}),mkdir(runRoot,{mode:0o700})]);
    await writeFile(path.join(sourceRoot,'finalized-burn-receipt.bin'),'receipt',{mode:0o600});
    await writeFile(path.join(sourceRoot,'finalized-burn-receipt-index.json'),
      '{"receipt":"original"}\n',{mode:0o600});
    const snapshot=await snapshotCapacitySourceReceiptPair(sourceRoot,runRoot);
    await writeFile(path.join(sourceRoot,'finalized-burn-receipt-index.json'),
      '{"receipt":"changed"}\n',{mode:0o600});
    await assert.rejects(assertCapacitySourceReceiptOriginsUnchanged(snapshot),
      /capacity source receipt changed during E2E execution: finalized-burn-receipt-index\.json/);
  } finally { await rm(root,{recursive:true,force:true}); }
});

test('proof-run selection rejects an orphan newest run but permits only explicit older success',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-capacity-proof-selection-'));
  const succeeded='20261022T010000Z-10',orphan='20261022T020000Z-11';
  const status=(runId,state)=>JSON.stringify({schema:'usdom-finalized-burn-prover-run-v1',
    status:state,runId,exitStatus:0,rayonWorkers:1,segmentLimitPo2:18,prover:'local',
    devMode:false,receiptKind:'succinct',startedAt:'2026-10-22T01:00:00Z',
    recordedAt:'2026-10-22T01:01:00Z'})+'\n';
  try {
    for(const [runId,state] of [[succeeded,'succeeded'],[orphan,'running']]) {
      const directory=path.join(root,runId); await mkdir(directory,{mode:0o700});
      await writeFile(path.join(directory,'run-status.json'),status(runId,state),{mode:0o600});
      if(state==='succeeded') for(const name of ['finalized-burn-receipt.bin',
        'finalized-burn-receipt-index.json','time.log','prover.log']) {
        await writeFile(path.join(directory,name),'x',{mode:0o600});
      }
    }
    await assert.rejects(selectFinalizedBurnProofRun({runsRoot:root}),
      /latest durable finalized-burn proof run has not succeeded canonically/);
    const selected=await selectFinalizedBurnProofRun({runsRoot:root,requestedRunId:succeeded});
    assert.equal(selected.runId,succeeded);
    await assert.rejects(selectFinalizedBurnProofRun({runsRoot:root,
      requestedRunId:'../../escape'}),/run ID is malformed/);
  } finally { await rm(root,{recursive:true,force:true}); }
});
