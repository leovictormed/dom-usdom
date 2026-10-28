import assert from 'node:assert/strict';
import test from 'node:test';
import {
  collectRecoverableSafeControlRecoveryConsensus,collectRecoverableSafeControlSnapshotConsensus,
  observeFinalizedSafeRecoveryExecutionConsensus,prepareRecoverableSafeRecoveryPlanConsensus,
  reconcileRecoverableSafeControlSnapshots,
} from '../../sdk/safe-control-rpc-consensus.mjs';
import {SafeRecoveryNotFinalizedError} from '../../sdk/safe-control-recovery-execution.mjs';
import {rpcConsensusEvidence,validateRpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';

const sources=[
 {sourceId:'operator-a',originKeccak256:'0x'+'11'.repeat(32),url:'https://rpc-a.example/secret'},
 {sourceId:'operator-b',originKeccak256:'0x'+'22'.repeat(32),url:'https://rpc-b.example/secret'},
];

test('RPC consensus evidence rejects omission, substitution and duplicate origins',()=>{
 const evidence=rpcConsensusEvidence(sources);
 assert.equal(validateRpcConsensusEvidence(evidence),true);
 for(const mutate of [
  value=>{delete value.sourceSetCommitment;},
  value=>{value.sources[0].originKeccak256='0x'+'33'.repeat(32);},
  value=>{value.sources[1].originKeccak256=value.sources[0].originKeccak256;},
  value=>{value.sources.reverse();},
 ]) {
  const changed=structuredClone(evidence); mutate(changed);
  assert.throws(()=>validateRpcConsensusEvidence(changed));
 }
});

test('RPC consensus evidence uses locale-independent ASCII source ordering',()=>{
 const punctuated=[
  {sourceId:'a0',originKeccak256:'0x'+'33'.repeat(32)},
  {sourceId:'a_',originKeccak256:'0x'+'44'.repeat(32)},
 ];
 assert.equal(validateRpcConsensusEvidence(rpcConsensusEvidence(punctuated)),true);
 assert.throws(()=>rpcConsensusEvidence([...punctuated].reverse()),/not ordered/);
 // ICU collation places these identifiers in the opposite order on Node 24;
 // the protocol order must remain the ASCII/UTF-8 byte order above.
 assert.ok(punctuated[0].sourceId.localeCompare(punctuated[1].sourceId)>0);
});

test('Safe snapshot consensus rechecks every cataloged source',async()=>{
  const calls=new Map(); const destroyed=[];
  const snapshot={schema:'fixture',finalizedBlockHash:'0x01'};
  const result=await collectRecoverableSafeControlSnapshotConsensus({packageDocument:{},sources,
    providerFactory:url=>({url,destroy:()=>destroyed.push(url)}),
    collectSnapshot:async({providerFactory,rpcUrl})=>{
      assert.equal(providerFactory().url,rpcUrl);
      calls.set(rpcUrl,(calls.get(rpcUrl)??0)+1); return structuredClone(snapshot);
    },
  });
  assert.equal(result.schema,snapshot.schema); assert.equal(result.rpcConsensus.sourceCount,'2');
  assert.deepEqual([...calls.values()],[2,2]); assert.equal(destroyed.length,2);
});

test('Safe snapshot consensus rejects source disagreement, mutation and redacts URL',async()=>{
  const changed=structuredClone({schema:'fixture',finalizedBlockHash:'0x02'});
  assert.throws(()=>reconcileRecoverableSafeControlSnapshots([
    {schema:'fixture',finalizedBlockHash:'0x01'},changed,
  ]),/disagree/);
  let count=0;
  await assert.rejects(collectRecoverableSafeControlSnapshotConsensus({packageDocument:{},sources,
    providerFactory:url=>({url,destroy(){}}),
    collectSnapshot:async()=>++count===2?changed:{schema:'fixture',finalizedBlockHash:'0x01'},
  }),error=>error.message.includes('changed during source recheck')
      &&!error.message.includes('rpc-a.example'));
});

test('Safe recovery consensus repeats the full transition on every source',async()=>{
  const calls=new Map(); const report={schema:'recovery-fixture',recoveryHash:'0x01'};
  const result=await collectRecoverableSafeControlRecoveryConsensus({packageDocument:{},
    baselineSnapshot:{},transitionsByRole:{governance:{lostOwner:'lost',replacementOwner:'replacement'}},transactions:{},sources,
    providerFactory:url=>({url,destroy(){}}),collectRecovery:async options=>{
      assert.equal(options.providerFactory().url,options.rpcUrl);
      calls.set(options.rpcUrl,(calls.get(options.rpcUrl)??0)+1); return structuredClone(report);
    },
  });
  assert.equal(result.schema,report.schema); assert.equal(result.rpcConsensus.sourceCount,'2'); assert.deepEqual([...calls.values()],[2,2]);
});

test('Safe recovery consensus rejects a changed recheck and redacts its endpoint',async()=>{
  let count=0;
  await assert.rejects(collectRecoverableSafeControlRecoveryConsensus({packageDocument:{},
    baselineSnapshot:{},transitionsByRole:{governance:{lostOwner:'lost',replacementOwner:'replacement'}},transactions:{},sources,
    providerFactory:url=>({url,destroy(){}}),collectRecovery:async()=>({
      schema:'recovery-fixture',recoveryHash:++count===2?'0x02':'0x01',
    }),
  }),error=>/changed during source recheck/.test(error.message)&&!error.message.includes('rpc-a.example'));
});

test('finalized execution consensus rechecks all sources',async()=>{
  const calls=new Map(); const observation={schema:'execution-fixture',blockHash:'0x01'};
  const result=await observeFinalizedSafeRecoveryExecutionConsensus({plan:{},transactionPackage:{},
    role:'governance',sources,providerFactory:url=>({url,destroy(){}}),observeExecution:async options=>{
      assert.equal(options.providerFactory().url,options.rpcUrl);
      calls.set(options.rpcUrl,(calls.get(options.rpcUrl)??0)+1); return structuredClone(observation);
    },
  });
  assert.equal(result.schema,observation.schema); assert.equal(result.rpcConsensus.sourceCount,'2'); assert.deepEqual([...calls.values()],[2,2]);
});

test('finalized execution consensus preserves not-finalized result and redacts endpoint',async()=>{
  await assert.rejects(observeFinalizedSafeRecoveryExecutionConsensus({plan:{},transactionPackage:{},
    role:'governance',sources,providerFactory:url=>({url,destroy(){}}),observeExecution:async({rpcUrl})=>{
      throw new SafeRecoveryNotFinalizedError(`pending at ${rpcUrl}`);
    },
  }),error=>error instanceof SafeRecoveryNotFinalizedError
      &&error.code==='SAFE_RECOVERY_NOT_FINALIZED'&&!error.message.includes('rpc-a.example'));
});

test('Safe recovery plan consensus rechecks every source',async()=>{
  const calls=new Map(); const plan={schema:'plan-fixture',planHash:'0x01'};
  const result=await prepareRecoverableSafeRecoveryPlanConsensus({packageDocument:{},
    baselineSnapshot:{},transitionsByRole:{governance:{lostOwner:'lost',replacementOwner:'replacement'}},sources,
    providerFactory:url=>({url,destroy(){}}),preparePlan:async options=>{
      assert.equal(options.providerFactory().url,options.rpcUrl);
      calls.set(options.rpcUrl,(calls.get(options.rpcUrl)??0)+1); return structuredClone(plan);
    },
  });
  assert.equal(result.schema,plan.schema); assert.equal(result.rpcConsensus.sourceCount,'2'); assert.deepEqual([...calls.values()],[2,2]);
});

test('Safe recovery plan consensus rejects source divergence',async()=>{
  let calls=0;
  await assert.rejects(prepareRecoverableSafeRecoveryPlanConsensus({packageDocument:{},
    baselineSnapshot:{},transitionsByRole:{governance:{lostOwner:'lost',replacementOwner:'replacement'}},sources,
    providerFactory:url=>({url,destroy(){}}),preparePlan:async()=>({
      schema:'plan-fixture',planHash:++calls>2?'0x02':'0x01',
    }),
  }),/cataloged RPCs disagree/);
});
