import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {captureCheckpointCapacityRun} from '../../sdk/checkpoint-run-snapshot.mjs';

const scriptUrl=new URL(
  '../../scripts/materialize-checkpoint-capacity-release-evidence.mjs',import.meta.url,
);
const source=await readFile(scriptUrl,'utf8');

test('checkpoint evidence materializer selects only the latest fixed successful run',()=>{
  for(const value of [
    'process.umask(0o077)','os.userInfo().homedir','entries[0]','status.status!==\'succeeded\'',
    'status.sourceCommit!==sourceCommit','status.reportSha256!==rawSha(reportBytes)',
    'validateReleaseSourceBoundary','prepareCheckpointCapacityReleaseEvidenceMaterialization',
    'assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes})',
    'assertRunUnchanged(latest)',
    'captureCheckpointCapacityRun(runRoot)','await snapshot.assertOriginsUnchanged()',
    'await immutableWrite(CHECKPOINT_CAPACITY_EVIDENCE_PATH,prepared.reportContent)',
    'CHECKPOINT_CAPACITY_EVIDENCE_PATH','await immutableWrite(CHECKPOINT_CAPACITY_EVIDENCE_PATH',
    'await atomicWrite(evidencePath','broadcastAuthorized:false',
    'readDirectFile(target,{minimum:1,maximum,privateMode:true',
    'writePrivateFileDurable(path.join(root,relative),content)',
    'writePrivateFileDurableNew(target,bytes)','immutable checkpoint capacity evidence already differs',
  ]) assert.match(source,new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.doesNotMatch(source,/open\(target,'r'\)|rename\(temporary,target\)/);
  assert.doesNotMatch(source,/git\s+(?:add|commit|tag|push)|eth_sendRawTransaction|privateKey|mnemonic/i);
});

test('checkpoint run replica rejects concurrent report substitution',async()=>{
  const runRoot=await mkdtemp(path.join(os.tmpdir(),'usdom-checkpoint-run-snapshot-'));
  await chmod(runRoot,0o700);
  const status=path.join(runRoot,'run-status.json'),report=path.join(runRoot,'capacity-report.json');
  await writeFile(status,'{"status":"succeeded"}\n',{mode:0o600});
  await writeFile(report,'{"report":"original"}\n',{mode:0o600});
  let snapshot;
  try {
    snapshot=await captureCheckpointCapacityRun(runRoot,{
      beforeOriginRecheck:()=>writeFile(report,'{"report":"changed"}\n',{mode:0o600}),
    });
    assert.equal(snapshot.reportBytes.toString(),'{"report":"original"}\n');
    await assert.rejects(snapshot.assertOriginsUnchanged(),
      /checkpoint capacity run changed during materialization/);
  } finally { await snapshot?.cleanup(); await rm(runRoot,{recursive:true,force:true}); }
});

test('checkpoint evidence materializer rejects arguments before reading release state',async()=>{
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
