import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {Interface} from 'ethers';
import {buildReserveResumeCompletion,validateReserveResumeCompletion} from '../../sdk/reserve-resume-completion.mjs';
const h='0x'+'11'.repeat(32),d='22'.repeat(32),reserve='0x'+'12'.repeat(20),safe='0x'+'34'.repeat(20),iface=new Interface(['function scheduleResume()','function executeResume()']);
const state=(paused,ready)=>({paused,resumeReadyAt:String(ready),queueEpoch:'1',pilotAuthorizationGeneration:'2',pendingCount:'0',totalPendingAmount:'0',totalProvedDebtAmount:'1000000',depositsClosed:false,gracefullyShutdown:false,reserveConfigHash:h,controlPlaneHealthy:true});
const step=(name,before,after,block,time,transactionIndex=1)=>({schema:'usdom-reserve-resume-step/v2',step:name,chainId:'1',reserve,governanceSafe:safe,calldata:iface.encodeFunctionData(name==='schedule'?'scheduleResume':'executeResume').toLowerCase(),safeTransactionHash:h,ethereumTransactionHash:h,blockNumber:String(block),blockHash:h,transactionIndex:String(transactionIndex),eventLogIndex:String(transactionIndex+1),transactionTimestamp:String(time),finalizedBlockNumber:String(block+10),finalizedBlockHash:h,rawJournalSha256:d,receiptSha256:d,observationSha256:d,before,after});
test('completion requires schedule, real governance delay and finalized execute',()=>{const schedule=step('schedule',state(true,0),state(true,172900),100,100),execute=step('execute',state(true,172900),state(false,0),120,172900);const s=Buffer.from(JSON.stringify(schedule)),e=Buffer.from(JSON.stringify(execute));const out=buildReserveResumeCompletion({schedule,scheduleBytes:s,execute,executeBytes:e,governanceDelaySeconds:'172800'});assert.equal(validateReserveResumeCompletion(out),out);const early={...execute,transactionTimestamp:'172899'};assert.throws(()=>buildReserveResumeCompletion({schedule,scheduleBytes:s,execute:early,executeBytes:Buffer.from(JSON.stringify(early)),governanceDelaySeconds:'172800'}),/governance delay/);});
test('completion rejects queue, generation, debt, closure and shutdown substitution',()=>{for(const mutate of [v=>v.schedule.before.pendingCount='1',v=>v.schedule.after.totalPendingAmount='1',v=>v.execute.after.gracefullyShutdown=true,v=>v.execute.before.pilotAuthorizationGeneration='3',v=>v.execute.before.totalProvedDebtAmount='0',v=>v.execute.before.depositsClosed=true]){const schedule=step('schedule',state(true,0),state(true,172900),100,100),execute=step('execute',state(true,172900),state(false,0),120,172900),value={schedule,execute};mutate(value);assert.throws(()=>buildReserveResumeCompletion({schedule,scheduleBytes:Buffer.from(JSON.stringify(schedule)),execute,executeBytes:Buffer.from(JSON.stringify(execute)),governanceDelaySeconds:'172800'}));}});
test('completion rejects receipt/finality hash conflicts and finalized-head regression',()=>{
 for(const mutate of [
  value=>{value.schedule.finalizedBlockNumber=value.schedule.blockNumber;
    value.schedule.finalizedBlockHash='0x'+'22'.repeat(32);},
  value=>{value.schedule.finalizedBlockNumber='200';value.execute.finalizedBlockNumber='130';},
 ]) {
  const schedule=step('schedule',state(true,0),state(true,172900),100,100);
  const execute=step('execute',state(true,172900),state(false,0),120,172900);
  const value={schedule,execute}; mutate(value);
  assert.throws(()=>buildReserveResumeCompletion({schedule,scheduleBytes:Buffer.from(JSON.stringify(schedule)),
   execute,executeBytes:Buffer.from(JSON.stringify(execute)),governanceDelaySeconds:'172800'}),
  /identity|chronology/);
 }
});
test('completion preserves receipt positions and rejects same-block reordering',()=>{
 const schedule=step('schedule',state(true,0),state(true,172900),100,100,8);
 const execute=step('execute',state(true,172900),state(false,0),100,172900,9);
 const completion=buildReserveResumeCompletion({schedule,scheduleBytes:Buffer.from(JSON.stringify(schedule)),
  execute,executeBytes:Buffer.from(JSON.stringify(execute)),governanceDelaySeconds:'172800'});
 assert.equal(completion.scheduleTransactionIndex,'8');
 assert.equal(completion.executeTransactionIndex,'9');
 assert.equal(completion.scheduleEventLogIndex,'9');
 assert.equal(validateReserveResumeCompletion(completion),completion);
 for(const transactionIndex of ['8','7']) {
  const reordered={...execute,transactionIndex};
  assert.throws(()=>buildReserveResumeCompletion({schedule,
   scheduleBytes:Buffer.from(JSON.stringify(schedule)),execute:reordered,
   executeBytes:Buffer.from(JSON.stringify(reordered)),governanceDelaySeconds:'172800'}),
  /canonical transaction order/);
 }
 assert.throws(()=>validateReserveResumeCompletion({...completion,executeTransactionIndex:'8'}),
  /transaction order/);
});
test('resume evidence rejects zero addresses, transaction identities and document commitments',()=>{
 const schedule=step('schedule',state(true,0),state(true,172900),100,100);
 const execute=step('execute',state(true,172900),state(false,0),120,172900);
 for(const mutate of [
  v=>v.schedule.reserve='0x'+'00'.repeat(20),v=>v.schedule.safeTransactionHash='0x'+'00'.repeat(32),
  v=>v.schedule.before.reserveConfigHash='0x'+'00'.repeat(32),v=>v.execute.rawJournalSha256='0'.repeat(64),
 ]) {
  const value={schedule:structuredClone(schedule),execute:structuredClone(execute)}; mutate(value);
  assert.throws(()=>buildReserveResumeCompletion({schedule:value.schedule,
   scheduleBytes:Buffer.from(JSON.stringify(value.schedule)),execute:value.execute,
   executeBytes:Buffer.from(JSON.stringify(value.execute)),governanceDelaySeconds:'172800'}));
 }
 const completion=buildReserveResumeCompletion({schedule,scheduleBytes:Buffer.from(JSON.stringify(schedule)),
  execute,executeBytes:Buffer.from(JSON.stringify(execute)),governanceDelaySeconds:'172800'});
 for(const field of ['scheduleTransactionHash','executeTransactionHash']) assert.throws(
  ()=>validateReserveResumeCompletion({...completion,[field]:'0x'+'00'.repeat(32)}));
 for(const field of ['scheduleDocumentSha256','executeDocumentSha256']) assert.throws(
  ()=>validateReserveResumeCompletion({...completion,[field]:'0'.repeat(64)}));
});
test('DAG places explicit reserve resume between deployment and deposit',()=>{const r=spawnSync('bash',['scripts/generate-closed-mainnet-phase-command.sh','execute-reserve-resume-secret'],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/execute:reserve-resume/);assert.match(r.stdout,/reserve-resume-finalized-completion/);const p=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{encoding:'utf8'});assert.equal(p.status,0,p.stderr);const phases=JSON.parse(p.stdout).phaseOrder;assert.ok(phases.indexOf('execute-mainnet-deployment-secret')<phases.indexOf('execute-reserve-resume-secret'));assert.ok(phases.indexOf('execute-reserve-resume-secret')<phases.indexOf('execute-pilot-deposit-secret'));});
test('executor journals before publish and enforces two signers and finalized quorum',()=>{const s=readFileSync(new URL('../../scripts/execute-reserve-resume.sh',import.meta.url),'utf8');assert.ok(s.indexOf('install-private-file-new-stdin.mjs --json "$journal"')<s.indexOf('publish-private-raw-transaction.mjs'));assert.match(s,/signer1.*!=.*signer2/s);assert.match(s,/rpcs\[1\]/);assert.match(s,/while test .*canonical-uint256\.mjs ge.*date \+%s.*ready/);assert.match(s,/transactionIndex/);assert.match(s,/eventLogIndex/);});

test('reserve resume serializes the evidence directory before hardware and execution RPC',()=>{const s=readFileSync(new URL('../../scripts/execute-reserve-resume.sh',import.meta.url),'utf8'),lock=s.indexOf('flock -n 9'),hardware=s.indexOf('wallet address --ledger'),state=s.indexOf('before=$(state');assert.match(s,/test "\$\(stat -c '%u:%a' "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"\)" = "\$\(id -u\):700"/);assert.match(s,/exec 9<"\$USDOM_CONTROL_EVIDENCE_DIRECTORY"/);assert.ok(lock>=0&&lock<hardware&&lock<state);assert.match(s,/flock -n 9 \|\|[\s\S]*exit 75/);});

test('reserve resume preserves every post-signature failure as unresolved status 80',()=>{const s=readFileSync(new URL('../../scripts/execute-reserve-resume.sh',import.meta.url),'utf8');assert.match(s,/resume_broadcast_state=clean[\s\S]*finish\(\)[\s\S]*resume_broadcast_state != clean[\s\S]*status=80/);assert.match(s,/prepare-ledger-eip1559-transaction\.mjs[\s\S]*wallet sign --no-hash "\$signing_hash"[\s\S]*resume_broadcast_state=signed-unresolved[\s\S]*install-private-file-new-stdin\.mjs --json "\$journal"/);assert.match(s,/resume_broadcast_state=publishing\n  txhash=\$\(node scripts\/publish-private-raw-transaction\.mjs/);assert.doesNotMatch(s,/--arg raw "\$\(cat "\$raw"\)"|cast (?:tx-hash|publish) "\$\(cat "\$raw"\)"/);assert.ok(s.lastIndexOf('resume_broadcast_state=clean')>s.lastIndexOf('check-reserve-resume-step.mjs "$step"'));});

test('reserve resume consumes immutable private snapshots of every JSON authority',()=>{const s=readFileSync(new URL('../../scripts/execute-reserve-resume.sh',import.meta.url),'utf8');assert.match(s,/snapshot_authority\(\)[\s\S]*check-direct-strict-json-file\.mjs --stdout "\$source"[\s\S]*chmod 0600/);for(const name of ['deployment.json','rpc-sources.json','safe-package.json','reserve-config.json','rpc-catalog.json'])assert.ok(s.includes(`$authority_snapshot_dir/${name}`),name);assert.match(s,/publish-private-raw-transaction\.mjs "\$raw" "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "\$rpc_catalog"/);assert.match(s,/stat -c '%u:%d:%i:%a' -- "\$authority_snapshot_dir"[\s\S]*rm -rf -- "\$authority_snapshot_dir"/);});

test('reserve resume payer authorization binds the complete reviewed envelope',()=>{const s=readFileSync(new URL('../../scripts/execute-reserve-resume.sh',import.meta.url),'utf8');assert.match(s,/usdom-reserve-resume-payer-sign-v1\|step=\$\{step\}\|chainId=1\|signer=\$\{signer\.toLowerCase\(\)\}\|nonce=\$\{nonce\}\|target=\$\{target\.toLowerCase\(\)\}\|valueWei=0\|dataHash=\$\{dataHash\.toLowerCase\(\)\}\|reserve=\$\{reserve\.toLowerCase\(\)\}\|reserveConfigHash=\$\{configHash\.toLowerCase\(\)\}\|governanceSafe=\$\{governance\.toLowerCase\(\)\}\|governanceDelaySeconds=\$\{delay\}\|gasLimit=\$\{gas\}\|maxFeePerGas=\$\{fee\}\|maximumGasCostWei=\$\{cost\}/);assert.match(s,/authorizationHash=\$authorization_hash/);assert.match(s,/AUTORIZO ASSINAR RETOMADA \$step AUTH \$authorization_hash/);assert.doesNotMatch(s,/AUTORIZO ASSINAR RETOMADA \$step NONCE/);});
test('resume revalidates Safe nonce, state, payer nonce and Ledger identity after approval',()=>{const s=readFileSync(new URL('../../scripts/execute-reserve-resume.sh',import.meta.url),'utf8');assert.match(s,/AUTORIZO ASSINAR SAFE RESUME schedule OWNER 1 HASH[\s\S]*nonce\(\)\(uint256\).*rpcs\[1\][\s\S]*observed=.*wallet address --ledger[\s\S]*wallet sign --no-hash "\$safe_hash"/);assert.match(s,/AUTORIZO ASSINAR RETOMADA \$step AUTH \$authorization_hash[\s\S]*state "\$\{rpcs\[1\]\}"[\s\S]*cast nonce "\$signer2" --block pending[\s\S]*observed=.*wallet address --ledger[\s\S]*prepare-ledger-eip1559-transaction\.mjs[\s\S]*wallet sign --no-hash "\$signing_hash"/);});
