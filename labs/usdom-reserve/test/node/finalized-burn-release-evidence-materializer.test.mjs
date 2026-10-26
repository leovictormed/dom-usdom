import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {chmod,mkdir,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {captureFinalizedBurnReleaseRun} from '../../sdk/release-run-snapshot.mjs';

const scriptUrl=new URL(
  '../../scripts/materialize-finalized-burn-release-evidence.mjs',import.meta.url,
);
const source=await readFile(scriptUrl,'utf8');

test('finalized-burn evidence materializer selects only the latest fixed successful run',()=>{
  for(const value of [
    'process.umask(0o077)','os.userInfo().homedir','entries[0]','status.status!==\'succeeded\'',
    'status.sourceCommit!==sourceCommit','status.reportSha256!==rawSha(reportBytes)',
    'validateReleaseSourceBoundary','prepareFinalizedBurnReleaseEvidenceMaterialization',
    'assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes})',
    'assertRunUnchanged(latest)',
    'captureFinalizedBurnReleaseRun(runRoot)','await snapshot.assertOriginsUnchanged()',
    'FINALIZED_BURN_E2E_EVIDENCE_PATH','await immutableWrite(FINALIZED_BURN_E2E_EVIDENCE_PATH',
    'await atomicWrite(evidencePath','broadcastAuthorized:false',
    'readDirectFile(target,{minimum:1,maximum,privateMode:true',
    'writePrivateFileDurable(path.join(root,relative),content)',
    'writePrivateFileDurableNew(target,bytes)','immutable finalized-burn release evidence already differs',
  ]) assert.match(source,new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.doesNotMatch(source,/open\(target,'r'\)|rename\(temporary,target\)/);
  assert.doesNotMatch(source,/capacity-report\.json/);
  assert.doesNotMatch(source,/git\s+(?:add|commit|tag|push)|eth_sendRawTransaction|privateKey|mnemonic/i);
});

test('finalized-burn run snapshot rejects report mutation before materialization',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-release-run-snapshot-'));
  await chmod(root,0o700);
  const status=path.join(root,'run-status.json');
  const report=path.join(root,'finalized-burn-e2e-report.json');
  await writeFile(status,'{"status":"succeeded"}\n',{mode:0o600});
  await writeFile(report,'{"report":"original"}\n',{mode:0o600});
  await chmod(status,0o600); await chmod(report,0o600);
  let snapshot;
  try {
    snapshot=await captureFinalizedBurnReleaseRun(root,{
      beforeOriginRecheck:()=>writeFile(report,'{"report":"changed"}\n',{mode:0o600}),
    });
    assert.equal(snapshot.reportBytes.toString(),'{"report":"original"}\n');
    await assert.rejects(()=>snapshot.assertOriginsUnchanged(),
      /release run changed during materialization/);
  } finally {
    await snapshot?.cleanup();
    await rm(root,{recursive:true,force:true});
  }
});

test('finalized-burn evidence materializer rejects arguments before reading release state',async()=>{
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
  assert.equal(JSON.parse(output).code,'PILOT_OPERATION_REJECTED');
});
