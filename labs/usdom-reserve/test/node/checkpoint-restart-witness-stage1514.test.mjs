import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
import {validateCheckpointRestartWitnessReport} from '../../sdk/checkpoint-restart-witness-report.mjs';
const digest=v=>createHash('sha256').update(v).digest('hex'),witnessBytes=Buffer.from('restart-a');
const manifestBytes=Buffer.from(JSON.stringify({restart_checkpoint:{witness_file:'restart.bin',witness_sha256:digest(witnessBytes)}}));
const valid={schema:'usdom-checkpoint-restart-witness-live-exercise/v1',manifestSha256:digest(manifestBytes),witnessSha256:digest(witnessBytes),
 firstProcessPid:101,secondProcessPid:202,firstStartupAccepted:true,secondStartupAccepted:true,sameDataDirectory:true,checkpointWitnessRequired:true};
test('restart report requires distinct successful processes over one persistent directory',()=>{
 const authority={manifestBytes,witnessBytes};
 assert.equal(validateCheckpointRestartWitnessReport(valid,authority),valid);
 for(const changed of [{...valid,secondProcessPid:101},{...valid,secondStartupAccepted:false},{...valid,sameDataDirectory:false},{...valid,checkpointWitnessRequired:false}]) assert.throws(()=>validateCheckpointRestartWitnessReport(changed));
 for(const field of ['manifestSha256','witnessSha256']) assert.throws(
  ()=>validateCheckpointRestartWitnessReport({...valid,[field]:'0'.repeat(64)}));
 assert.throws(()=>validateCheckpointRestartWitnessReport({...valid,witnessSha256:digest(Buffer.from('restart-b'))},authority));
 assert.throws(()=>validateCheckpointRestartWitnessReport(valid,{manifestBytes,witnessBytes:Buffer.from('restart-b')}));
});
test('checkpoint phase performs restart exercise after checkpoint observation',async()=>{
 const source=await readFile(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
 assert(source.indexOf('exercise:checkpoint-restart-witness')>source.indexOf('observe:authenticated-checkpoint'));
 assert(source.indexOf('check:checkpoint-restart-witness')>source.indexOf('exercise:checkpoint-restart-witness'));
 const harness=await readFile(new URL('../../scripts/exercise-checkpoint-restart-witness.mjs',import.meta.url),'utf8');
 assert.match(harness,/first=await one\('first startup'\)/);assert.match(harness,/second=await one\('second startup'\)/);
 assert.match(harness,/writePrivateFileDurableNewOrEqual/);assert.match(harness,/snapshotExecutablePath\('\/usr\/bin\/bash'\)/);
 assert.match(harness,/assertInputsUnchanged/);assert.match(harness,/manifest or witness changed during live exercise/);
 assert.match(harness,/open\(nodeLauncherPath,constants\.O_RDONLY\|constants\.O_NOFOLLOW\)/);
 assert.match(harness,/spawn\(launcher\.path,\['\/proc\/self\/fd\/3'\]/);
 assert.match(harness,/stdio:\['ignore','pipe','pipe',nodeLauncherHandle\.fd\]/);
 assert.match(harness,/node exited after accepting checkpoint restart witness/);
 assert.match(harness,/child\?\.exitCode!==null\|\|child\?\.signalCode!==null/);
 assert.doesNotMatch(harness,/while\(child\?\.exitCode===null/);
 assert.match(harness,/await waitForExit\(Date\.now\(\)\+10_000\)/);
 assert.match(harness,/node process group did not terminate/);
 assert.match(harness,/closed-mainnet node launcher changed during live exercise/);
 assert.match(harness,/USDOM_CHECKPOINT_RESTART_RUNTIME_ROOT:runtimeSnapshot/);
 assert.match(harness,/readDirectFile/);assert.match(harness,/mkdtemp/);
 const launcher=await readFile(new URL('../../scripts/run-closed-mainnet-node.sh',import.meta.url),'utf8');
 assert.match(launcher,/USDOM_CHECKPOINT_RESTART_RUNTIME_ROOT/);
 const checker=await readFile(new URL('../../scripts/check-checkpoint-restart-witness.mjs',import.meta.url),'utf8');
 assert.match(checker,/validateCheckpointRestartWitnessReport/);
 assert.match(checker,/privateMode:true/);
 assert.match(checker,/report\.manifestSha256!==sha\(manifestBytes\)/);
 assert.match(checker,/report\.witnessSha256!==sha\(witnessBytes\)/);
 assert.match(checker,/restart witness inputs changed during validation/);
});
