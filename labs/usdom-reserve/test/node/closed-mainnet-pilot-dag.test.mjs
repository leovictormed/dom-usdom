import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {reconcileClosedMainnetPilotDag} from '../../sdk/closed-mainnet-pilot-dag.mjs';
const raw=n=>n.toString(16).padStart(2,'0').repeat(32),hex=n=>'0x'+raw(n);
const receipt=nonce=>({nonce:String(nonce),finalizedRpcCount:2,canonical:true});
const prepared=()=>({deposit:{packageSha256:raw(1),amountBaseUnits:'1000000',broadcastAuthorized:false,
  baseNonce:'4',receipts:[],pendingNonce:'4',allowanceAfter:'0'}});
const complete=()=>({deposit:{...prepared().deposit,receipts:[receipt(4),receipt(5),receipt(6)],pendingNonce:'7'},
  redemption:{packageSha256:raw(2),amountBaseUnits:'1000000',broadcastAuthorized:false,
    burnId:hex(3),requestId:hex(4),baseNonce:'7',receipts:[receipt(7),receipt(8)],pendingNonce:'9',
    paidBurn:true,paidRequest:true}});

test('offline pilot DAG recognizes phase progress and crash-resume boundaries',()=>{
  assert.deepEqual(reconcileClosedMainnetPilotDag({}).phases.map(x=>x.status),['missing','missing']);
  assert.equal(reconcileClosedMainnetPilotDag(prepared()).phases[0].status,'prepared');
  const crash=prepared(); crash.deposit.receipts=[receipt(4)]; crash.deposit.pendingNonce='5';
  assert.equal(reconcileClosedMainnetPilotDag(crash).phases[0].status,'resumable');
  crash.deposit.receipts[0].canonical=null; crash.deposit.receipts[0].finalizedRpcCount=0;
  assert.equal(reconcileClosedMainnetPilotDag(crash).phases[0].status,'finality-recheck-required');
  const waiting=complete(); waiting.redemption.receipts=[receipt(7)]; waiting.redemption.pendingNonce='8';
  waiting.redemption.paidBurn=false; waiting.redemption.paidRequest=false;
  assert.equal(reconcileClosedMainnetPilotDag(waiting).phases[1].status,'waiting-delay');
  assert.deepEqual(reconcileClosedMainnetPilotDag(complete()).phases.map(x=>x.status),['complete','complete']);
});

test('offline pilot DAG rejects every adversarial stale or terminal state',()=>{
  const cases=[
    s=>{s.deposit.broadcastAuthorized=true;},
    s=>{s.deposit.packageSha256='AA'.repeat(32);},
    s=>{s.deposit.baseNonce='9'.repeat(100000);},
    s=>{s.deposit.baseNonce=((1n<<64n)-3n).toString();},
    s=>{s.deposit.receipts[0].nonce=(1n<<64n).toString();},
    s=>{s.deposit.pendingNonce='8';},
    s=>{s.deposit.allowanceAfter='1';},
    s=>{s.deposit.receipts[1].canonical=false;},
    s=>{s.deposit.receipts[2].finalizedRpcCount=1;},
    s=>{s.redemption.broadcastAuthorized=true;},
    s=>{s.redemption.baseNonce=((1n<<64n)-2n).toString();},
    s=>{s.redemption.pendingNonce='10';},
    s=>{s.redemption.receipts[0].canonical=false;},
    s=>{s.redemption.paidBurn=false;},
    s=>{s.redemption.paidRequest=false;},
  ];
  for(const mutate of cases) { const state=complete(); mutate(state); assert.throws(()=>reconcileClosedMainnetPilotDag(state)); }
  const alreadyPaid=complete(); alreadyPaid.redemption.receipts=[receipt(7)]; alreadyPaid.redemption.pendingNonce='8';
  assert.throws(()=>reconcileClosedMainnetPilotDag(alreadyPaid),/already paid/);
});

test('partial pilot receipt prefixes are exact, sequential and finalized or explicitly pending',()=>{
  const mutations=[
    s=>{s.deposit.pendingNonce='5';},
    s=>{s.deposit.receipts=[receipt(5)];s.deposit.pendingNonce='5';},
    s=>{s.deposit.receipts=[receipt(4)];s.deposit.pendingNonce='6';},
    s=>{s.deposit.receipts=[{...receipt(4),canonical:false}];s.deposit.pendingNonce='5';},
    s=>{s.deposit.receipts=[{...receipt(4),finalizedRpcCount:1}];s.deposit.pendingNonce='5';},
    s=>{s.deposit.receipts=[{...receipt(4),unexpected:true}];s.deposit.pendingNonce='5';},
    s=>{s.deposit.receipts=[{...receipt(4),canonical:null}];s.deposit.pendingNonce='5';},
  ];
  for(const mutate of mutations) {
    const state=prepared(); mutate(state);
    assert.throws(()=>reconcileClosedMainnetPilotDag(state));
  }
  const pending=prepared();
  pending.deposit.receipts=[{...receipt(4),canonical:null,finalizedRpcCount:0}];
  pending.deposit.pendingNonce='5';
  assert.equal(reconcileClosedMainnetPilotDag(pending).phases[0].status,'finality-recheck-required');
});

test('pilot DAG root and phase schemas reject ambiguous or ill-typed state',()=>{
  const cases=[
    s=>{s.unexpected=true;},
    s=>{s.deposit=null;},
    s=>{s.deposit.unexpected=true;},
    s=>{delete s.deposit.allowanceAfter;},
    s=>{s.deposit.allowanceAfter='01';},
    s=>{s.deposit.allowanceAfter='9'.repeat(100000);},
    s=>{s.deposit.allowanceAfter=(1n<<256n).toString();},
    s=>{s.redemption.unexpected=true;},
    s=>{delete s.redemption.paidBurn;},
    s=>{s.redemption.paidBurn=0;},
    s=>{s.redemption.requestId='0x'+'A'.repeat(64);},
  ];
  for(const mutate of cases) {
    const state=complete(); mutate(state);
    assert.throws(()=>reconcileClosedMainnetPilotDag(state));
  }
});

test('pilot terminal facts cannot appear before terminal finalized receipts',()=>{
  const residual=prepared(); residual.deposit.allowanceAfter='1';
  assert.throws(()=>reconcileClosedMainnetPilotDag(residual),/residual allowance/);

  const paidPrepared=complete(); paidPrepared.redemption.receipts=[];
  paidPrepared.redemption.pendingNonce=paidPrepared.redemption.baseNonce;
  assert.throws(()=>reconcileClosedMainnetPilotDag(paidPrepared),/before terminal/);

  const paidPending=complete();
  paidPending.redemption.receipts[1].canonical=null;
  paidPending.redemption.receipts[1].finalizedRpcCount=0;
  assert.throws(()=>reconcileClosedMainnetPilotDag(paidPending),/before terminal/);

  const unpaidPending=structuredClone(paidPending);
  unpaidPending.redemption.paidBurn=false; unpaidPending.redemption.paidRequest=false;
  assert.equal(reconcileClosedMainnetPilotDag(unpaidPending).phases[1].status,
    'finality-recheck-required');
});

test('generated operator DAG includes both resumable secret execution phases',()=>{
  const source=readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  assert.match(source,/execute-pilot-deposit-secret/); assert.match(source,/execute:closed-mainnet-deposit/);
  assert.match(source,/execute-pilot-redemption-secret/); assert.match(source,/execute:closed-mainnet-redemption/);
  assert.match(source,/check-closed-mainnet-phase-artifacts\.mjs/);
  assert.doesNotMatch(source,/cast publish|broadcastAuthorized=true/);
});
