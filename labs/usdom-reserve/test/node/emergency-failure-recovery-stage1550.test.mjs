import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {classifyPilotNonce} from '../../sdk/pilot-nonce-recovery.mjs';
import {reconcileClosedMainnetPilotDag} from '../../sdk/closed-mainnet-pilot-dag.mjs';
import {pilotFailureRecord} from '../../sdk/pilot-safe-diagnostics.mjs';

const hash='0x'+'1'.repeat(64),other='0x'+'2'.repeat(64);
const receipt=nonce=>({nonce:String(nonce),finalizedRpcCount:2,canonical:true});
const partial=()=>({deposit:{packageSha256:'1'.repeat(64),amountBaseUnits:'1000000',broadcastAuthorized:false,
  baseNonce:'4',receipts:[receipt(4)],pendingNonce:'5',allowanceAfter:'0'}});

test('broadcast recovery distinguishes safe retry, known inclusion, disagreement and replacement',()=>{
  assert.equal(classifyPilotNonce('4','4','4','4','4'),'publish');
  assert.equal(classifyPilotNonce('4','4','5','4','5',hash,hash,hash),'recover-receipt');
  assert.equal(classifyPilotNonce('4','5','5','5','5',hash,hash,hash),'recover-receipt');
  assert.throws(()=>classifyPilotNonce('4','4','5','4','4',hash,hash,hash),/disagree/);
  assert.throws(()=>classifyPilotNonce('4','4','5','4','5',hash,other,hash),/exact known/);
  assert.throws(()=>classifyPilotNonce('4','6','6','6','6',hash,hash,hash),/ambiguous/);
});

test('crash, reorg and partial terminal facts remain resumable or fail closed',()=>{
  assert.equal(reconcileClosedMainnetPilotDag(partial()).phases[0].status,'resumable');
  const pending=partial(); pending.deposit.receipts[0]={nonce:'4',finalizedRpcCount:0,canonical:null};
  assert.equal(reconcileClosedMainnetPilotDag(pending).phases[0].status,'finality-recheck-required');
  for(const mutate of [
    value=>value.deposit.receipts[0].canonical=false,
    value=>value.deposit.receipts[0].finalizedRpcCount=1,
    value=>value.deposit.pendingNonce='6',
    value=>value.deposit.allowanceAfter='1',
  ]) { const value=partial(); mutate(value); assert.throws(()=>reconcileClosedMainnetPilotDag(value)); }
});

test('every pilot catch-site has a nonleaking failure operation',async()=>{
  const operations=['check-closed-mainnet-deposit-evidence','check-closed-mainnet-payout-evidence',
    'check-closed-mainnet-redemption','check-closed-mainnet-redemption-release','closed-mainnet-burn-block',
    'closed-mainnet-deposit-check','closed-mainnet-deposit-prepare','closed-mainnet-deposit-raw-check',
    'closed-mainnet-genesis-initialize','closed-mainnet-issuance-mine','closed-mainnet-issuance-submit',
    'closed-mainnet-phase-check','finalized-burn-evidence-materialize','finalized-burn-submission-prepare',
    'mainnet-preflight','mainnet-readiness'];
  for(const operation of operations) assert.equal(pilotFailureRecord(operation,new Error('SECRET')).operation,operation);
});

test('emergency pause cancels resume and invalidates the queue generation in O(1)',async()=>{
  const reserve=await readFile(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url),'utf8');
  assert.match(reserve,/function pauseQueueEpoch\(uint64 expectedQueueEpoch, uint64 expectedPilotAuthorizationGeneration\)[\s\S]*expectedQueueEpoch != queueEpoch[\s\S]*_pauseState\(\)/);
  assert.match(reserve,/function _pauseState\(\)[\s\S]*\+\+queueEpoch[\s\S]*pendingCount = 0[\s\S]*totalPendingAmount = 0[\s\S]*resumeReadyAt = 0[\s\S]*emit Paused/);
  assert.match(reserve,/function executeResume\(\)[\s\S]*block\.timestamp < resumeReadyAt[\s\S]*_requireControlPlaneUnchanged\(\)[\s\S]*_requireVerifierUnchanged\(\)[\s\S]*_requireTokenUsable/);
});

test('Safe owner loss, RPC outage and proof failure cannot silently advance lifecycle',async()=>{
  const recovery=await readFile(new URL('../../scripts/execute-recoverable-safe-recovery.sh',import.meta.url),'utf8');
  const deposit=await readFile(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  const redemption=await readFile(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.match(recovery,/flock[\s\S]*check-finalized-safe-recovery-execution\.mjs[\s\S]*safe-recovery-finalized-bundle\.json/);
  for(const source of [deposit,redemption]) {
    assert.match(source,/check-pilot-nonce-recovery\.mjs/);
    assert.match(source,/publish-private-raw-transaction\.mjs[\s\S]*check-transaction-hash-output\.mjs/);
    assert.match(source,/finalizedRpcCount/);
  }
});

test('closed pilot executors preserve signed and post-broadcast uncertainty as status 80',async()=>{
  const deposit=await readFile(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  const redemption=await readFile(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  for(const source of [deposit,redemption]) {
    assert.match(source,/pilot_broadcast_state=clean[\s\S]*cleanup\(\)[\s\S]*pilot_broadcast_state != clean[\s\S]*status=80/);
    assert.match(source,/expected_hash=.*validation[\s\S]*pilot_broadcast_state=signed-unresolved/);
    assert.match(source,/pilot_broadcast_state=publishing[\s\S]*publish-private-raw-transaction\.mjs/);
    assert.match(source,/nonce_action" = recover-receipt[\s\S]*pilot_broadcast_state=observed/);
    assert.ok(source.lastIndexOf('pilot_broadcast_state=clean')>source.indexOf('install-private-file-new-stdin.mjs --json "$finality_record"'));
    assert.match(source,/remove_private_tree "\$temporary"(?: "\$temporary_identity")? \|\| \{ \(\( status != 0 \)\) \|\| status=1; \}/);
  }
});

test('closed pilot receipts cross a final dual-RPC barrier immediately before persistence',async()=>{
  const deposit=await readFile(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  const redemption=await readFile(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  for(const [source,anchor,persist] of [[deposit,'refresh_consensus_block','install-private-file-new-stdin.mjs --json "$evidence/closed-deposit-$index-receipt.json"'],[redemption,'rpc_consensus_snapshot','cost=$(timeout']]) {
    const barrier=source.lastIndexOf(anchor,source.indexOf(persist));
    assert.ok(barrier>=0&&barrier<source.indexOf(persist,barrier));
    const slice=source.slice(barrier,source.indexOf(persist,barrier));
    assert.match(slice,/for rpc in "\$rpc1" "\$rpc2"/);
    assert.match(slice,/cast receipt "\$tx_hash"/);
    assert.match(slice,/receipt_projection/);
    assert.match(slice,/check_rpc_transaction_binding/);
    assert.match(slice,/cast block "\$(?:receipt_block|block)" --field hash/);
  }
});

test('closed pilot signing authorization binds the complete transaction authority tuple',async()=>{
  const deposit=await readFile(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  const redemption=await readFile(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  for(const [source,domain,action] of [[deposit,'usdom-closed-deposit-sign-v2','DEPOSITO'],[redemption,'usdom-closed-redemption-sign-v2','RESGATE']]) {
    assert.match(source,new RegExp(`${domain}\\|action=\\$name\\|stage=\\$index\\|chainId=1\\|signer=\\$`));
    assert.match(source,/target=\$to\|nonce=\$nonce\|tokenAmountBaseUnits=[^|]+\|valueWei=0\|dataHash=\$data_hash\|[^\n]+\|gasLimit=\$gas\|maxFeePerGas=\$fee\|maxPriorityFeePerGas=2000000000/);
    assert.match(source,/cast keccak "\$authorization_preimage" \| head -c 68/);
    assert.match(source,/\[\[ \$authorization_hash =~ \^0x\[0-9a-f\]\{64\}\$ \]\]/);
    assert.match(source,new RegExp(`AUTORIZO ASSINAR ${action} ETAPA \\$index AUTH \\$authorization_hash`));
  }
});

test('closed pilot revalidates private raw bytes immediately before recovery or publication',async()=>{
  const deposit=await readFile(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  const redemption=await readFile(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  for(const [source,checker] of [[deposit,'check-closed-mainnet-deposit-raw.mjs'],[redemption,'check-closed-mainnet-redemption.mjs']]) {
    const expected=source.indexOf('expected_hash=$(jq_run');
    const check=source.lastIndexOf(checker,expected);
    assert.ok(check>=0&&check<expected);
    const slice=source.slice(check-500,expected);
    assert.match(slice,/stat_run -c '%u:%a:%h' -- "\$validation"/);
    assert.match(slice,/cmp_exact - "\$validation"/);
    assert.match(slice,/USDOM_CLOSED_MAINNET_(?:DEPOSIT|REDEMPTION)_RAW_FILE=\$raw_file/);
  }
});
