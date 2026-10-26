import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Interface,TypedDataEncoder,Wallet,concat,keccak256,zeroPadValue} from 'ethers';
import {
  SAFE_FALLBACK_HANDLER_STORAGE_SLOT,
  SAFE_GUARD_STORAGE_SLOT,
  SAFE_CONTROL_RECOVERY_SCHEMA,
  SAFE_CONTROL_SNAPSHOT_SCHEMA,
  _safeControlObservationInternals,
  collectRecoverableSafeControlRecovery,
  collectRecoverableSafeControlSnapshot,
  validateRecoverableSafeControlRecoveryReport,
} from '../../sdk/safe-control-observation.mjs';
import {prepareRecoverableSafeControlDeployments} from '../../sdk/safe-control-deployment.mjs';
import {
  SAFE_RECOVERY_PLAN_SCHEMA,
  SAFE_RECOVERY_TRANSACTION_PACKAGE_SCHEMA,
  assembleRecoverableSafeRecoveryTransactions,
  prepareRecoverableSafeRecoveryPlan,
  validateRecoverableSafeRecoveryTransactionPackage,
} from '../../sdk/safe-control-recovery-plan.mjs';
import {
  SafeRecoveryNotFinalizedError,
  observeFinalizedSafeRecoveryExecution,
  validateFinalizedSafeRecoveryExecution,
  validateRecoverableSafeRecoveryRawTransaction,
} from '../../sdk/safe-control-recovery-execution.mjs';
import {
  SAFE_RECOVERY_ENVELOPE_SCHEMA,
  prepareRecoverableSafeRecoveryEnvelope,
} from '../../sdk/safe-control-recovery-envelope.mjs';
import {bindRpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';
import {
  SAFE_CONTROL_RELEASE_EVIDENCE_SCHEMA,
  buildRecoverableSafeControlReleaseEvidence,
  validateRecoverableSafeControlReleaseEvidence,
} from '../../sdk/safe-control-release-evidence.mjs';

import {
  SAFE_CONTROL_EVIDENCE_PATHS,
  SAFE_CONTROL_RELEASE_FRAGMENT_SCHEMA,
  materializeSafeControlReleaseConfig,
  materializeSafeControlReleaseMetadata,
  validateSafeControlReleaseFragment,
} from '../../sdk/safe-control-materialization.mjs';

const durableRpcSources=[
  {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32)},
  {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32)},
];
const durableSnapshot=value=>bindRpcConsensusEvidence(value,durableRpcSources,'snapshotHash');
const durableRecovery=value=>bindRpcConsensusEvidence(value,durableRpcSources,'recoveryHash');
const durablePlan=value=>bindRpcConsensusEvidence(value,durableRpcSources,'planHash');

const owners=[
  '0x0000000000000000000000000000000000000011',
  '0x0000000000000000000000000000000000000022',
  '0x0000000000000000000000000000000000000033',
];
const ownersByRole={
  governance:owners,
  reserveGuardian:['0x0000000000000000000000000000000000000044','0x0000000000000000000000000000000000000055','0x0000000000000000000000000000000000000066'],
  checkpointGuardian:['0x0000000000000000000000000000000000000077','0x0000000000000000000000000000000000000088','0x0000000000000000000000000000000000000099'],
};
const factory='0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67';
const singleton='0x41675C099F32341bf84BFc5382aF534df5C7461a';
const fallbackHandler='0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99';
const sentinel='0x0000000000000000000000000000000000000001';
const blockHash='0x'+'ab'.repeat(32);
const safeCode=JSON.parse(readFileSync(
  new URL('../fixtures/safe-1.4.1-mainnet.json',import.meta.url),'utf8',
));
const factoryInterface=new Interface([
  'function proxyCreationCode() view returns (bytes)',
]);
const safeInterface=new Interface([
  'function masterCopy() view returns (address)',
  'function VERSION() view returns (string)',
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function nonce() view returns (uint256)',
  'function getModulesPaginated(address,uint256) view returns (address[] array,address next)',
  'function getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256) view returns (bytes32)',
  'function execTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address payable refundReceiver,bytes signatures) returns (bool success)',
  'function swapOwner(address prevOwner,address oldOwner,address newOwner)',
  'event RemovedOwner(address indexed owner)',
  'event AddedOwner(address indexed owner)',
  'event ExecutionSuccess(bytes32 indexed txHash,uint256 payment)',
]);

function providerFixture({guard='0x0000000000000000000000000000000000000000',
  modules=[],nonce=0n,reorg=false}={}) {
  let numberedReads=0;
  const calls=[];
  const storage=[];
  const ownersForSafe=new Map();
  const provider={
    getNetwork:async()=>({chainId:1n}),
    getBlock:async tag=>{
      if(tag!=='finalized') numberedReads++;
      return {number:21000000,hash:reorg&&numberedReads>1?'0x'+'cd'.repeat(32):blockHash};
    },
    getCode:async(address,blockTag)=>{
      if(Object.values(ownersByRole).flat().some(owner=>owner.toLowerCase()===address.toLowerCase())) return '0x';
      if(address.toLowerCase()===factory.toLowerCase()) return safeCode.factoryRuntimeCode;
      if(address.toLowerCase()===singleton.toLowerCase()) return safeCode.singletonRuntimeCode;
      if(address.toLowerCase()===fallbackHandler.toLowerCase()) return safeCode.fallbackHandlerRuntimeCode;
      assert.equal(blockTag,21000000);
      return '0x6080604052600080fd';
    },
    call:async transaction=>{
      calls.push(transaction);
      if(transaction.to.toLowerCase()===factory.toLowerCase()) {
        return factoryInterface.encodeFunctionResult('proxyCreationCode',[safeCode.proxyCreationCode]);
      }
      const selector=transaction.data.slice(0,10);
      const functions=['masterCopy','VERSION','getOwners','getThreshold','nonce','getModulesPaginated'];
      const name=functions.find(candidate=>safeInterface.getFunction(candidate).selector===selector);
      assert.ok(name,selector);
      const values={
        masterCopy:[singleton],VERSION:['1.4.1'],getOwners:[ownersForSafe.get(transaction.to.toLowerCase())??owners],getThreshold:[2n],nonce:[nonce],
        getModulesPaginated:[modules,modules.length===0?sentinel:modules.at(-1)],
      };
      return safeInterface.encodeFunctionResult(name,values[name]);
    },
    getStorage:async(address,position,blockTag)=>{
      storage.push({address,position,blockTag});
      if(position===0) return zeroPadValue(singleton,32);
      if(position===SAFE_FALLBACK_HANDLER_STORAGE_SLOT) return zeroPadValue(fallbackHandler,32);
      if(position===SAFE_GUARD_STORAGE_SLOT) return zeroPadValue(guard,32);
      assert.fail(`unexpected storage position ${position}`);
    },
  };
  return {provider,providerFactory:()=>provider,calls,storage,ownersForSafe};
}

async function packageFixture(fixture=providerFixture()) {
  const packageDocument=await prepareRecoverableSafeControlDeployments({
      ownersByRole,rpcUrl:'https://rpc.invalid',blockTag:21000000,
      providerFactory:fixture.providerFactory,
    });
  for(const control of packageDocument.controls) fixture.ownersForSafe.set(
    control.safe.toLowerCase(),packageDocument.ownersByRole[control.role]);
  return {fixture,packageDocument};
}

test('collects three recoverable Safe roles from one immutable finalized snapshot',async()=>{
  const {fixture,packageDocument}=await packageFixture();
  fixture.calls.length=0;
  const report=await collectRecoverableSafeControlSnapshot({
    packageDocument,rpcUrl:'https://rpc.invalid',providerFactory:fixture.providerFactory,
  });
  assert.equal(report.schema,SAFE_CONTROL_SNAPSHOT_SCHEMA);
  assert.equal(report.finalizedBlockNumber,'21000000');
  assert.equal(report.finalizedBlockHash,blockHash);
  assert.match(report.packageHash,/^0x[0-9a-f]{64}$/);
  assert.match(report.snapshotHash,/^0x[0-9a-f]{64}$/);
  assert.deepEqual(report.roles.map(role=>[role.role,role.threshold,role.nonce]),[
    ['governance','2','0'],['reserveGuardian','2','0'],['checkpointGuardian','2','0'],
  ]);
  assert.equal(new Set(report.roles.map(role=>role.configurationHash)).size,3);
  assert.ok(report.roles.every(role=>role.guard==='0x0000000000000000000000000000000000000000'));
  assert.ok(fixture.calls.every(call=>call.blockTag===21000000));
  assert.ok(fixture.storage.every(read=>read.blockTag===21000000));
});

test('rejects a guard, module, nonce or changed finalized block',async()=>{
  for(const [options,pattern] of [
    [{guard:'0x0000000000000000000000000000000000000044'},/guard must be empty/],
    [{modules:['0x0000000000000000000000000000000000000044']},/modules must be empty/],
    [{nonce:1n},/nonce mismatch/],
    [{reorg:true},/snapshot changed/],
  ]) {
    const {fixture,packageDocument}=await packageFixture(providerFixture(options));
    await assert.rejects(collectRecoverableSafeControlSnapshot({
      packageDocument,rpcUrl:'https://rpc.invalid',providerFactory:fixture.providerFactory,
    }),pattern);
  }
});

test('rejects any Safe package substitution before accepting on-chain state',async()=>{
  const {fixture,packageDocument}=await packageFixture();
  for(const mutate of [
    value=>{value.extra=true;},
    value=>{value.controls[0].safe=value.controls[1].safe;},
    value=>{value.controls[0].data=value.controls[0].data+'00';},
    value=>{value.ownersByRole.governance.reverse();},
    value=>{value.ownersByRole.reserveGuardian[0]=value.ownersByRole.governance[0];},
  ]) {
    const changed=structuredClone(packageDocument);
    mutate(changed);
    await assert.rejects(collectRecoverableSafeControlSnapshot({
      packageDocument:changed,rpcUrl:'https://rpc.invalid',providerFactory:fixture.providerFactory,
    }),/source-derived finalized reconstruction|globally distinct/);
  }
});

function recoveryProvider({sourceOwners,observedOwners,nonce,finalizedNumber,finalizedHash,
  observedOwnersBySafe=new Map(),transactions=new Map(),receipts=new Map(),safeTxHashes=new Map(),additionalEoas=[]}) {
  const canonicalReceiptBlocks=new Map(
    [...receipts.values()].map(receipt=>[receipt.blockNumber,receipt.blockHash]),
  );
  const provider={
    getNetwork:async()=>({chainId:1n}),
    getBlock:async tag=>{
      const number=tag==='finalized'?finalizedNumber:Number(tag);
      if(number===21000000) return {number,hash:blockHash};
      if(number===finalizedNumber) return {number,hash:finalizedHash};
      const canonicalHash=canonicalReceiptBlocks.get(number);
      return canonicalHash?{number,hash:canonicalHash}:null;
    },
    getCode:async address=>{
      if([...sourceOwners,...observedOwners,...additionalEoas]
        .some(owner=>owner.toLowerCase()===address.toLowerCase())) {
        return '0x';
      }
      if(address.toLowerCase()===factory.toLowerCase()) return safeCode.factoryRuntimeCode;
      if(address.toLowerCase()===singleton.toLowerCase()) return safeCode.singletonRuntimeCode;
      if(address.toLowerCase()===fallbackHandler.toLowerCase()) return safeCode.fallbackHandlerRuntimeCode;
      return '0x6080604052600080fd';
    },
    call:async transaction=>{
      if(transaction.to.toLowerCase()===factory.toLowerCase()) {
        return factoryInterface.encodeFunctionResult('proxyCreationCode',[safeCode.proxyCreationCode]);
      }
      const selector=transaction.data.slice(0,10);
      const functions=['masterCopy','VERSION','getOwners','getThreshold','nonce',
        'getModulesPaginated','getTransactionHash'];
      const name=functions.find(candidate=>safeInterface.getFunction(candidate).selector===selector);
      assert.ok(name,selector);
      let transactionHashResult;
      if(name==='getTransactionHash') {
        transactionHashResult=safeTxHashes.get(transaction.to.toLowerCase());
        if(transactionHashResult===undefined) {
          const decoded=safeInterface.decodeFunctionData('getTransactionHash',transaction.data);
          transactionHashResult=TypedDataEncoder.hash(
            {chainId:1,verifyingContract:transaction.to},
            {SafeTx:[
              {name:'to',type:'address'},{name:'value',type:'uint256'},
              {name:'data',type:'bytes'},{name:'operation',type:'uint8'},
              {name:'safeTxGas',type:'uint256'},{name:'baseGas',type:'uint256'},
              {name:'gasPrice',type:'uint256'},{name:'gasToken',type:'address'},
              {name:'refundReceiver',type:'address'},{name:'nonce',type:'uint256'},
            ]},
            {to:decoded[0],value:decoded[1],data:decoded[2],operation:decoded[3],
              safeTxGas:decoded[4],baseGas:decoded[5],gasPrice:decoded[6],
              gasToken:decoded[7],refundReceiver:decoded[8],nonce:decoded[9]},
          );
        }
      }
      const values={
        masterCopy:[singleton],VERSION:['1.4.1'],
        getOwners:[observedOwnersBySafe.get(transaction.to.toLowerCase())??observedOwners],
        getThreshold:[2n],nonce:[nonce],getModulesPaginated:[[],sentinel],
        getTransactionHash:[transactionHashResult],
      };
      return safeInterface.encodeFunctionResult(name,values[name]);
    },
    getStorage:async(_address,position)=>{
      if(position===0) return zeroPadValue(singleton,32);
      if(position===SAFE_FALLBACK_HANDLER_STORAGE_SLOT) return zeroPadValue(fallbackHandler,32);
      if(position===SAFE_GUARD_STORAGE_SLOT) return zeroPadValue('0x0000000000000000000000000000000000000000',32);
      assert.fail(`unexpected storage position ${position}`);
    },
    getTransaction:async hash=>transactions.get(hash),
    getTransactionReceipt:async hash=>receipts.get(hash),
  };
  return {provider,providerFactory:()=>provider};
}

function encodedLog(address,event,args) {
  const encoded=safeInterface.encodeEventLog(safeInterface.getEvent(event),args);
  return {address,data:encoded.data,topics:encoded.topics};
}

async function buildRecoveryCase() {
  const wallets=Array.from({length:12},(_,index)=>new Wallet(`0x${(index+1).toString(16).padStart(64,'0')}`));
  const roleNames=['governance','reserveGuardian','checkpointGuardian'];
  const sourceOwnersByRole=Object.fromEntries(roleNames.map((role,index)=>[role,
    wallets.slice(index*3,index*3+3).map(wallet=>wallet.address)
      .sort((left,right)=>BigInt(left)<BigInt(right)?-1:1)]));
  const sourceOwners=Object.values(sourceOwnersByRole).flat();
  const walletByAddress=new Map(wallets.map(wallet=>[wallet.address.toLowerCase(),wallet]));
  const baselineOwnersBySafe=new Map();
  const baselineFixture=recoveryProvider({sourceOwners,observedOwners:sourceOwnersByRole.governance,
    observedOwnersBySafe:baselineOwnersBySafe,nonce:0n,
    finalizedNumber:21000000,finalizedHash:blockHash});
  const packageDocument=await prepareRecoverableSafeControlDeployments({
    ownersByRole:sourceOwnersByRole,rpcUrl:'https://rpc.invalid',blockTag:21000000,
    providerFactory:baselineFixture.providerFactory,
  });
  for(const control of packageDocument.controls) baselineOwnersBySafe.set(
    control.safe.toLowerCase(),sourceOwnersByRole[control.role]);
  const baselineSnapshot=durableSnapshot(await collectRecoverableSafeControlSnapshot({
    packageDocument,rpcUrl:'https://rpc.invalid',providerFactory:baselineFixture.providerFactory,
  }));
  const transitionsByRole=Object.fromEntries(roleNames.map((role,index)=>[role,{
    lostOwner:sourceOwnersByRole[role][0],replacementOwner:wallets[9+index].address}]));
  const transactions=new Map();
  const receipts=new Map();
  const safeTxHashes=new Map();
  const transactionHashes={};
  for(const [index,control] of packageDocument.controls.entries()) {
    const {lostOwner,replacementOwner}=transitionsByRole[control.role];
    const survivorWallets=sourceOwnersByRole[control.role].slice(1)
      .map(address=>walletByAddress.get(address.toLowerCase()));
    const transactionHash=`0x${(0xa1+index).toString(16).repeat(32)}`;
    const safeTxHash=`0x${(0xb1+index).toString(16).repeat(32)}`;
    const blockNumber=21000001+index;
    const receiptBlockHash=`0x${(0xc1+index).toString(16).repeat(32)}`;
    const signatures=concat(survivorWallets.map(wallet=>({
      address:wallet.address,signature:wallet.signingKey.sign(safeTxHash).serialized,
    })).sort((left,right)=>BigInt(left.address)<BigInt(right.address)?-1:1)
      .map(({signature})=>signature));
    const inner=safeInterface.encodeFunctionData('swapOwner',[sentinel,lostOwner,replacementOwner]);
    const data=safeInterface.encodeFunctionData('execTransaction',[
      control.safe,0n,inner,0,0n,0n,0n,'0x0000000000000000000000000000000000000000',
      '0x0000000000000000000000000000000000000000',signatures,
    ]);
    transactions.set(transactionHash,{hash:transactionHash,to:control.safe,value:0n,data,
      blockNumber,blockHash:receiptBlockHash});
    receipts.set(transactionHash,{hash:transactionHash,status:1,to:control.safe,blockNumber,
      blockHash:receiptBlockHash,logs:[
        encodedLog(control.safe,'RemovedOwner',[lostOwner]),
        encodedLog(control.safe,'AddedOwner',[replacementOwner]),
        encodedLog(control.safe,'ExecutionSuccess',[safeTxHash,0n]),
      ]});
    safeTxHashes.set(control.safe.toLowerCase(),safeTxHash);
    transactionHashes[control.role]=transactionHash;
  }
  const finalizedHash='0x'+'ef'.repeat(32);
  const recoveredOwnersBySafe=new Map(packageDocument.controls.map(control=>{
    const transition=transitionsByRole[control.role];
    return [control.safe.toLowerCase(),sourceOwnersByRole[control.role].map(owner=>
      owner===transition.lostOwner?transition.replacementOwner:owner)];
  }));
  const recoveryFixture=recoveryProvider({sourceOwners,
    observedOwners:recoveredOwnersBySafe.values().next().value,observedOwnersBySafe:recoveredOwnersBySafe,nonce:1n,
    finalizedNumber:21000010,finalizedHash,transactions,receipts,safeTxHashes,
    additionalEoas:Object.values(transitionsByRole).map(value=>value.replacementOwner)});
  const input={
    packageDocument,baselineSnapshot,transitionsByRole,transactions:transactionHashes,
    rpcUrl:'https://rpc.invalid',providerFactory:recoveryFixture.providerFactory,
  };
  return {input,transactions,receipts,safeTxHashes,sourceOwners,sourceOwnersByRole,walletByAddress,
    transitionsByRole,lostOwner:transitionsByRole.governance.lostOwner,
    replacementOwner:transitionsByRole.governance.replacementOwner,
    survivorWallets:sourceOwnersByRole.governance.slice(1).map(address=>walletByAddress.get(address.toLowerCase())),
    finalizedHash};
}

test('verifies an exact finalized three-role loss-of-one-key recovery drill',async()=>{
  const fixture=await buildRecoveryCase();
  const report=durableRecovery(await collectRecoverableSafeControlRecovery(fixture.input));
  assert.equal(report.schema,SAFE_CONTROL_RECOVERY_SCHEMA);
  assert.equal(report.afterSnapshot.finalizedBlockHash,fixture.finalizedHash);
  assert.deepEqual(report.afterSnapshot.roles.map(role=>role.nonce),['1','1','1']);
  assert.deepEqual(report.recoveries.map(role=>role.signers),[
    fixture.sourceOwnersByRole.governance.slice(1),fixture.sourceOwnersByRole.reserveGuardian.slice(1),
    fixture.sourceOwnersByRole.checkpointGuardian.slice(1),
  ]);
  assert.match(report.recoveryHash,/^0x[0-9a-f]{64}$/);
  assert.equal(validateRecoverableSafeControlRecoveryReport(
    report,fixture.input.baselineSnapshot,fixture.input.packageDocument),report);
});

test('persisted Safe recovery report rejects after-state and transaction substitutions',async()=>{
  const fixture=await buildRecoveryCase();
  const source=durableRecovery(await collectRecoverableSafeControlRecovery(fixture.input));
  for(const [mutate,pattern] of [
    [value=>{value.afterSnapshot.roles[0].owners.reverse();},/after-state mismatch/],
    [value=>{value.afterSnapshot.roles[1].configurationHash=value.afterSnapshot.roles[0]
      .configurationHash;},/configuration hash mismatch/],
    [value=>{value.recoveries[0].signers.reverse();},/transaction evidence mismatch/],
    [value=>{value.recoveries[2].transactionHash=value.recoveries[1].transactionHash;},
      /transaction hashes are not distinct/],
  ]) {
    const changed=structuredClone(source);
    mutate(changed);
    const unsignedAfter={...changed.afterSnapshot}; delete unsignedAfter.snapshotHash;
    changed.afterSnapshot.snapshotHash=_safeControlObservationInternals.documentHash(unsignedAfter);
    const unsigned={...changed}; delete unsigned.recoveryHash;
    changed.recoveryHash=_safeControlObservationInternals.documentHash(unsigned);
    assert.throws(()=>validateRecoverableSafeControlRecoveryReport(
      changed,fixture.input.baselineSnapshot,fixture.input.packageDocument),pattern);
  }
});

test('builds one cross-bound canonical Safe release-evidence set',async()=>{
  const fixture=await buildRecoveryCase();
  const recoveryReport=durableRecovery(await collectRecoverableSafeControlRecovery(fixture.input));
  const bundle=buildRecoverableSafeControlReleaseEvidence({
    packageDocument:fixture.input.packageDocument,
    baselineSnapshot:fixture.input.baselineSnapshot,
    recoveryReport,
  });
  assert.equal(bundle.schema,SAFE_CONTROL_RELEASE_EVIDENCE_SCHEMA);
  assert.deepEqual(Object.keys(bundle.roleReports),[
    'governance','guardian','checkpointGuardian',
  ]);
  assert.equal(bundle.roleReports.guardian.safeRole,'reserveGuardian');
  assert.equal(bundle.recoveryDrillReport.roles.length,3);
  assert.equal(bundle.baselineRpcConsensus.sourceCount,'2');
  assert.deepEqual(bundle.recoveryRpcConsensus,bundle.baselineRpcConsensus);
  assert.equal(validateRecoverableSafeControlReleaseEvidence(bundle),bundle);
});

test('Safe release evidence rejects internally rehashed semantic substitutions',async()=>{
  const fixture=await buildRecoveryCase();
  const source=buildRecoverableSafeControlReleaseEvidence({
    packageDocument:fixture.input.packageDocument,
    baselineSnapshot:fixture.input.baselineSnapshot,
    recoveryReport:durableRecovery(await collectRecoverableSafeControlRecovery(fixture.input)),
  });
  const rehash=(document,key)=>{
    const unsigned={...document}; delete unsigned[key];
    document[key]=_safeControlObservationInternals.documentHash(unsigned);
  };
  {
    const changed=structuredClone(source);
    changed.baselineRpcConsensus.sources[0].originKeccak256='0x'+'91'.repeat(32);
    rehash(changed,'bundleHash');
    assert.throws(()=>validateRecoverableSafeControlReleaseEvidence(changed),/commitment mismatch/);
  }
  {
    const changed=structuredClone(source);
    changed.recoveryRpcConsensus.sources.pop();
    rehash(changed,'bundleHash');
    assert.throws(()=>validateRecoverableSafeControlReleaseEvidence(changed),/RPC sources/);
  }
  {
    const changed=structuredClone(source);
    changed.roleReports.governance.ownersAfter.reverse();
    rehash(changed.roleReports.governance,'reportHash');
    rehash(changed,'bundleHash');
    assert.throws(()=>validateRecoverableSafeControlReleaseEvidence(changed),
      /recovery policy|configuration commitment/);
  }
  {
    const changed=structuredClone(source);
    changed.roleReports.governance.recoveryBlockNumber='9'.repeat(100000);
    rehash(changed.roleReports.governance,'reportHash');
    rehash(changed,'bundleHash');
    assert.throws(()=>validateRecoverableSafeControlReleaseEvidence(changed),/recovery policy/);
  }
  {
    const changed=structuredClone(source);
    changed.separationReport.roles[1].configurationHash=
      changed.separationReport.roles[0].configurationHash;
    rehash(changed.separationReport,'reportHash');
    rehash(changed,'bundleHash');
    assert.throws(()=>validateRecoverableSafeControlReleaseEvidence(changed),
      /separation report mismatch/);
  }
  {
    const changed=structuredClone(source);
    changed.recoveryDrillReport.roles[0].signers.reverse();
    rehash(changed.recoveryDrillReport,'reportHash');
    rehash(changed,'bundleHash');
    assert.throws(()=>validateRecoverableSafeControlReleaseEvidence(changed),
      /recovery drill report mismatch/);
  }
});

function artifactSetForBundle(bundle) {
  return {bundle,roleReports:structuredClone(bundle.roleReports),
    separationReport:structuredClone(bundle.separationReport),
    recoveryDrillReport:structuredClone(bundle.recoveryDrillReport)};
}

function fragmentForBundle(bundle) {
  const pointer=path=>({path,sha256:'ab'.repeat(32)});
  return {
    schema:SAFE_CONTROL_RELEASE_FRAGMENT_SCHEMA,
    bundleHash:bundle.bundleHash,
    controlPlaneEvidenceBundle:pointer(SAFE_CONTROL_EVIDENCE_PATHS.bundle),
    controlPlane:Object.fromEntries(['governance','guardian','checkpointGuardian'].map(role=>[
      role,{address:bundle.roleReports[role].address,
        runtimeCodeHash:bundle.roleReports[role].runtimeCodeHash,
        configurationHash:bundle.roleReports[role].configurationHash,
        configurationReport:pointer(SAFE_CONTROL_EVIDENCE_PATHS[role])},
    ])),
    controlPlaneSeparationReport:pointer(SAFE_CONTROL_EVIDENCE_PATHS.separation),
    controlPlaneRecoveryDrillReport:pointer(SAFE_CONTROL_EVIDENCE_PATHS.recovery),
  };
}

test('materializes Safe source identities and evidence metadata in separate phases',async()=>{
  const fixture=await buildRecoveryCase();
  const bundle=buildRecoverableSafeControlReleaseEvidence({
    packageDocument:fixture.input.packageDocument,
    baselineSnapshot:fixture.input.baselineSnapshot,
    recoveryReport:durableRecovery(await collectRecoverableSafeControlRecovery(fixture.input)),
  });
  const artifactSet=artifactSetForBundle(bundle);
  const fragment=fragmentForBundle(bundle);
  assert.equal(validateSafeControlReleaseFragment(fragment,bundle),fragment);

  const releaseConfig=JSON.parse(readFileSync(
    new URL('../../config/proof-reserve.unconfigured.json',import.meta.url),'utf8'));
  const configured=materializeSafeControlReleaseConfig({releaseConfig,artifactSet});
  assert.equal(configured.productionReady,false);
  assert.equal(configured.realFundsAuthorized,false);
  assert.equal(configured.governance,bundle.roleReports.governance.address);
  assert.equal(configured.guardian,bundle.roleReports.guardian.address);
  assert.equal(configured.checkpointGuardian,bundle.roleReports.checkpointGuardian.address);
  assert.deepEqual(configured.governanceOwners,bundle.roleReports.governance.ownersAfter);
  assert.deepEqual(configured.guardianOwners,bundle.roleReports.guardian.ownersAfter);
  assert.deepEqual(configured.checkpointGuardianOwners,
    bundle.roleReports.checkpointGuardian.ownersAfter);
  assert.equal(configured.token,releaseConfig.token);
  assert.deepEqual(materializeSafeControlReleaseConfig({releaseConfig:configured,artifactSet}),configured);

  const releaseEvidence=JSON.parse(readFileSync(
    new URL('../../config/mainnet-release-evidence.unconfigured.json',import.meta.url),'utf8'));
  const metadata=materializeSafeControlReleaseMetadata({releaseEvidence,fragment,artifactSet});
  assert.deepEqual(metadata.controlPlane,fragment.controlPlane);
  assert.deepEqual(metadata.controlPlaneEvidenceBundle,fragment.controlPlaneEvidenceBundle);
  assert.equal(metadata.releaseId,null);
  assert.deepEqual(materializeSafeControlReleaseMetadata({
    releaseEvidence:metadata,fragment,artifactSet,
  }),metadata);

  const conflicting=structuredClone(configured);
  conflicting.governance='0x0000000000000000000000000000000000000005';
  assert.throws(()=>materializeSafeControlReleaseConfig({releaseConfig:conflicting,artifactSet}),
    /different value/);
  const conflictingOwners=structuredClone(configured);
  conflictingOwners.guardianOwners.reverse();
  assert.throws(()=>materializeSafeControlReleaseConfig({
    releaseConfig:conflictingOwners,artifactSet,
  }),/guardianOwners already contains a different value/);
  const substituted=structuredClone(fragment);
  substituted.controlPlane.guardian.configurationHash='0x'+'99'.repeat(32);
  assert.throws(()=>materializeSafeControlReleaseMetadata({
    releaseEvidence,fragment:substituted,artifactSet,
  }),/disagrees/);
});

test('rejects unsafe payment fields and any Safe recovery event substitution',async()=>{
  {
    const fixture=await buildRecoveryCase();
    const hash=fixture.input.transactions.governance;
    const transaction=fixture.transactions.get(hash);
    const outer=safeInterface.decodeFunctionData('execTransaction',transaction.data);
    transaction.data=safeInterface.encodeFunctionData('execTransaction',[
      outer.to,outer.value,outer.data,outer.operation,outer.safeTxGas,outer.baseGas,1n,
      outer.gasToken,outer.refundReceiver,outer.signatures,
    ]);
    await assert.rejects(collectRecoverableSafeControlRecovery(fixture.input),/unsafe execution or payment/);
  }
  {
    const fixture=await buildRecoveryCase();
    const hash=fixture.input.transactions.reserveGuardian;
    const receipt=fixture.receipts.get(hash);
    const safe=fixture.input.packageDocument.controls[1].safe;
    receipt.logs[2]=encodedLog(safe,'ExecutionSuccess',[
      fixture.safeTxHashes.get(safe.toLowerCase()),1n,
    ]);
    await assert.rejects(collectRecoverableSafeControlRecovery(fixture.input),/Safe events mismatch/);
  }
  {
    const fixture=await buildRecoveryCase();
    const hash=fixture.input.transactions.checkpointGuardian;
    fixture.receipts.get(hash).logs.push(fixture.receipts.get(hash).logs[2]);
    await assert.rejects(collectRecoverableSafeControlRecovery(fixture.input),/unexpected Safe log set/);
  }
});

test('rejects a lost-key signature, preapproved signature and noncanonical receipt',async()=>{
  {
    const fixture=await buildRecoveryCase();
    const hash=fixture.input.transactions.governance;
    const transaction=fixture.transactions.get(hash);
    const outer=safeInterface.decodeFunctionData('execTransaction',transaction.data);
    const safeTxHash=fixture.safeTxHashes.get(transaction.to.toLowerCase());
    const lostWallet=fixture.walletByAddress.get(
      fixture.input.transitionsByRole.governance.lostOwner.toLowerCase());
    const wrong=[lostWallet,fixture.survivorWallets[0]].map(wallet=>({
      address:wallet.address,signature:wallet.signingKey.sign(safeTxHash).serialized,
    })).sort((left,right)=>BigInt(left.address)<BigInt(right.address)?-1:1);
    transaction.data=safeInterface.encodeFunctionData('execTransaction',[
      outer.to,outer.value,outer.data,outer.operation,outer.safeTxGas,outer.baseGas,outer.gasPrice,
      outer.gasToken,outer.refundReceiver,concat(wrong.map(value=>value.signature)),
    ]);
    await assert.rejects(collectRecoverableSafeControlRecovery(fixture.input),/two surviving owners/);
  }
  {
    const fixture=await buildRecoveryCase();
    const hash=fixture.input.transactions.governance;
    const transaction=fixture.transactions.get(hash);
    const outer=safeInterface.decodeFunctionData('execTransaction',transaction.data);
    const bytes=Buffer.from(outer.signatures.slice(2),'hex');
    bytes[64]=1;
    transaction.data=safeInterface.encodeFunctionData('execTransaction',[
      outer.to,outer.value,outer.data,outer.operation,outer.safeTxGas,outer.baseGas,outer.gasPrice,
      outer.gasToken,outer.refundReceiver,`0x${bytes.toString('hex')}`,
    ]);
    await assert.rejects(collectRecoverableSafeControlRecovery(fixture.input),/preapproved Safe signatures/);
  }
  {
    const fixture=await buildRecoveryCase();
    const hash=fixture.input.transactions.reserveGuardian;
    const changed='0x'+'99'.repeat(32);
    fixture.transactions.get(hash).blockHash=changed;
    fixture.receipts.get(hash).blockHash=changed;
    await assert.rejects(collectRecoverableSafeControlRecovery(fixture.input),/no longer canonical/);
  }
});

async function buildPlanCase() {
  const wallets=Array.from({length:12},(_,index)=>
    new Wallet(`0x${(index+1).toString(16).padStart(64,'0')}`));
  const roleNames=['governance','reserveGuardian','checkpointGuardian'];
  const sourceOwnersByRole=Object.fromEntries(roleNames.map((role,index)=>[role,
    wallets.slice(index*3,index*3+3).map(wallet=>wallet.address)
      .sort((left,right)=>BigInt(left)<BigInt(right)?-1:1)]));
  const sourceOwners=Object.values(sourceOwnersByRole).flat();
  const walletByAddress=new Map(wallets.map(wallet=>[wallet.address.toLowerCase(),wallet]));
  const transitionsByRole=Object.fromEntries(roleNames.map((role,index)=>[role,{
    lostOwner:sourceOwnersByRole[role][0],replacementOwner:wallets[9+index].address,
  }]));
  const ownersBySafe=new Map();
  const fixture=recoveryProvider({sourceOwners,observedOwners:sourceOwnersByRole.governance,
    observedOwnersBySafe:ownersBySafe,nonce:0n,finalizedNumber:21000000,
    finalizedHash:blockHash,
    additionalEoas:Object.values(transitionsByRole).map(value=>value.replacementOwner)});
  const packageDocument=await prepareRecoverableSafeControlDeployments({
    ownersByRole:sourceOwnersByRole,rpcUrl:'https://rpc.invalid',blockTag:21000000,
    providerFactory:fixture.providerFactory,
  });
  for(const control of packageDocument.controls) ownersBySafe.set(
    control.safe.toLowerCase(),sourceOwnersByRole[control.role]);
  const rawBaselineSnapshot=await collectRecoverableSafeControlSnapshot({
    packageDocument,rpcUrl:'https://rpc.invalid',providerFactory:fixture.providerFactory,
  });
  const baselineSnapshot=durableSnapshot(rawBaselineSnapshot);
  const rawPlan=await prepareRecoverableSafeRecoveryPlan({
    packageDocument,baselineSnapshot,transitionsByRole,
    rpcUrl:'https://rpc.invalid',providerFactory:fixture.providerFactory,
  });
  const plan=durablePlan(rawPlan);
  const signatures=Object.fromEntries(plan.roles.map(role=>[
    role.role,role.requiredSigners.map(signer=>({
      signer,signature:walletByAddress.get(signer.toLowerCase()).signingKey
        .sign(role.safeTxHash).serialized,
    })),
  ]));
  return {plan,signatures,sourceOwners,sourceOwnersByRole,walletByAddress,transitionsByRole};
}

test('prepares typed Safe recovery payloads and assembles exact unsigned executions',async()=>{
  const fixture=await buildPlanCase();
  assert.equal(fixture.plan.schema,SAFE_RECOVERY_PLAN_SCHEMA);
  assert.deepEqual(fixture.plan.roles.map(role=>role.safeTransaction.nonce),['0','0','0']);
  assert.ok(fixture.plan.roles.every(role=>
    TypedDataEncoder.hash(role.typedData.domain,{SafeTx:role.typedData.types.SafeTx},
      role.typedData.message)===role.safeTxHash));
  const assembled=assembleRecoverableSafeRecoveryTransactions(fixture);
  assert.equal(assembled.schema,SAFE_RECOVERY_TRANSACTION_PACKAGE_SCHEMA);
  assert.equal(assembled.planHash,fixture.plan.planHash);
  assert.equal(assembled.transactions.length,3);
  assert.ok(assembled.transactions.every(transaction=>
    transaction.signers.length===2&&transaction.value==='0'));
});

test('recovery assembly rejects lost-key, preapproved and typed-data substitutions',async()=>{
  {
    const fixture=await buildPlanCase();
    const [governance,reserveGuardian]=fixture.plan.roles;
    governance.requiredSigners=[...reserveGuardian.requiredSigners];
    const unsigned={...fixture.plan}; delete unsigned.planHash;
    fixture.plan.planHash=_safeControlObservationInternals.documentHash(unsigned);
    await assert.throws(()=>assembleRecoverableSafeRecoveryTransactions(fixture),
      /globally separated by role/);
  }
  {
    const fixture=await buildPlanCase();
    const governance=fixture.signatures.governance;
    fixture.signatures.governance=fixture.signatures.reserveGuardian;
    fixture.signatures.reserveGuardian=governance;
    await assert.throws(()=>assembleRecoverableSafeRecoveryTransactions(fixture),
      /signature signer mismatch|two surviving owners/);
  }
  {
    const fixture=await buildPlanCase();
    const role=fixture.plan.roles[0];
    const lostWallet=fixture.walletByAddress.get(fixture.plan.transitionsByRole.governance.lostOwner.toLowerCase());
    fixture.signatures[role.role][0]={signer:lostWallet.address,
      signature:lostWallet.signingKey.sign(role.safeTxHash).serialized};
    await assert.throws(()=>assembleRecoverableSafeRecoveryTransactions(fixture),
      /two surviving owners/);
  }
  {
    const fixture=await buildPlanCase();
    const role=fixture.plan.roles[0];
    fixture.signatures[role.role][0].signature=
      `${fixture.signatures[role.role][0].signature.slice(0,-2)}01`;
    await assert.throws(()=>assembleRecoverableSafeRecoveryTransactions(fixture),
      /direct EIP-712 hardware signature/);
  }
  {
    const fixture=await buildPlanCase();
    fixture.plan.roles[0].typedData.message.gasPrice='1';
    const unsigned={...fixture.plan}; delete unsigned.planHash;
    fixture.plan.planHash=_safeControlObservationInternals.documentHash(unsigned);
    await assert.throws(()=>assembleRecoverableSafeRecoveryTransactions(fixture),
      /typed-data handoff mismatch/);
  }
});

test('recovers one exact execution from finalized logs and rejects absence or receipt drift',async()=>{
  const fixture=await buildPlanCase();
  const transactionPackage=assembleRecoverableSafeRecoveryTransactions(fixture);
  const role=fixture.plan.roles[0];
  const expected=transactionPackage.transactions[0];
  const transactionHash='0x'+'d1'.repeat(32);
  const executionBlockHash='0x'+'d2'.repeat(32);
  const finalizedHash='0x'+'d3'.repeat(32);
  const log={...encodedLog(role.safe,'ExecutionSuccess',[role.safeTxHash,0n]),
    transactionHash,blockNumber:21000001,blockHash:executionBlockHash};
  const transaction={hash:transactionHash,to:role.safe,value:0n,data:expected.data,
    blockNumber:21000001,blockHash:executionBlockHash};
  const receipt={hash:transactionHash,status:1,to:role.safe,blockNumber:21000001,
    blockHash:executionBlockHash,logs:[log]};
  const provider={
    getNetwork:async()=>({chainId:1n}),
    getBlock:async tag=>tag==='finalized'
      ?{number:21000005,hash:finalizedHash}:{number:Number(tag),hash:executionBlockHash},
    getLogs:async()=>[log],
    getTransaction:async()=>transaction,
    getTransactionReceipt:async()=>receipt,
  };
  const input={plan:fixture.plan,transactionPackage,role:'governance',
    rpcUrl:'https://rpc.invalid',providerFactory:()=>provider};
  const observed=await observeFinalizedSafeRecoveryExecution(input);
  assert.equal(observed.transactionHash,transactionHash);
  assert.equal(observed.safeTxHash,role.safeTxHash);
  const consensus=bindRpcConsensusEvidence(observed,[
    {sourceId:'operator-a',originKeccak256:'0x'+'01'.repeat(32)},
    {sourceId:'operator-b',originKeccak256:'0x'+'02'.repeat(32)},
  ]);
  assert.equal(validateFinalizedSafeRecoveryExecution({plan:fixture.plan,transactionPackage,
    execution:consensus}),consensus);
  for(const mutate of [
    value=>{value.extra=true;},value=>{delete value.blockHash;},
    value=>{value.transactionHash=value.transactionHash.toUpperCase();},
    value=>{value.blockNumber='021000001';},
    value=>{value.finalizedObservationBlockNumber=(2n**64n).toString();},
    value=>{value.blockNumber='21000006';},
    value=>{value.safe=fixture.plan.roles[1].safe;},
    value=>{value.safeTxHash=fixture.plan.roles[1].safeTxHash;},
    value=>{value.rpcConsensus.sourceCount='3';},
  ]) {
    const changed=structuredClone(consensus); mutate(changed);
    assert.throws(()=>validateFinalizedSafeRecoveryExecution({
      plan:fixture.plan,transactionPackage,execution:changed,
    }));
  }
  const noLog={...provider,getLogs:async()=>[]};
  await assert.rejects(observeFinalizedSafeRecoveryExecution({...input,providerFactory:()=>noLog}),
    error=>error instanceof SafeRecoveryNotFinalizedError);
  const drifted={...provider,getBlock:async tag=>tag==='finalized'
    ?{number:21000005,hash:finalizedHash}:{number:Number(tag),hash:'0x'+'ff'.repeat(32)}};
  await assert.rejects(observeFinalizedSafeRecoveryExecution({...input,providerFactory:()=>drifted}),
    /transaction or receipt mismatch/);
});

test('persisted recovery transaction package rejects recomputed calldata substitution',async()=>{
  const fixture=await buildPlanCase();
  const transactionPackage=assembleRecoverableSafeRecoveryTransactions(fixture);
  transactionPackage.transactions[0].data=transactionPackage.transactions[1].data;
  transactionPackage.transactions[0].dataHash=keccak256(transactionPackage.transactions[0].data);
  const unsigned={...transactionPackage}; delete unsigned.transactionPackageHash;
  transactionPackage.transactionPackageHash=
    _safeControlObservationInternals.documentHash(unsigned);
  assert.throws(()=>validateRecoverableSafeRecoveryTransactionPackage(
    fixture.plan,transactionPackage),/fields mismatch/);
});

test('raw recovery journal is bound to chain, surviving relayer and exact Safe calldata',async()=>{
  const fixture=await buildPlanCase();
  const transactionPackage=assembleRecoverableSafeRecoveryTransactions(fixture);
  const expected=transactionPackage.transactions[0];
  const relayer=fixture.plan.roles[0].requiredSigners[0];
  const wallet=fixture.walletByAddress.get(relayer.toLowerCase());
  const envelopeProvider=(url,pendingNonce=7,finalizedNumber=22000000)=>({
    getNetwork:async()=>({chainId:1n}),
    getTransactionCount:async(_address,tag)=>tag==='pending'?pendingNonce:7,
    send:async(method)=>{
      assert.equal(method,'eth_estimateGas');
      return url.endsWith('one')?'0x30d40':'0x320c8';
    },
    getBlock:async tag=>{
      if(tag==='finalized') return {number:finalizedNumber,
        hash:`0x${finalizedNumber.toString(16).padStart(64,'0')}`,
        baseFeePerGas:url.endsWith('one')?20_000_000_000n:21_000_000_000n};
      assert.equal(tag,'latest');
      return {number:url.endsWith('one')?22000001:22000002,
        hash:url.endsWith('one')?'0x'+'81'.repeat(32):'0x'+'82'.repeat(32),
        baseFeePerGas:url.endsWith('one')?20_000_000_000n:21_000_000_000n};
    },
    getBalance:async()=>1_000_000_000_000_000_000n,
    getCode:async()=> '0x',
  });
  const envelopePlan=await prepareRecoverableSafeRecoveryEnvelope({
    plan:fixture.plan,transactionPackage,role:'governance',relayerOwner:relayer,
    sources:[
      {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32),url:'https://rpc.one'},
      {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32),url:'https://rpc.two'},
      {sourceId:'operator-c',originKeccak256:'0x'+'83'.repeat(32),url:'https://rpc.three'},
    ],
    providerFactory:url=>envelopeProvider(url),
  });
  assert.equal(envelopePlan.schema,SAFE_RECOVERY_ENVELOPE_SCHEMA);
  assert.equal(envelopePlan.rpcObservations.length,3);
  assert.equal(envelopePlan.rpcConsensus.sourceCount,'3');
  assert.equal(envelopePlan.nonce,'7');
  assert.equal(envelopePlan.maxPriorityFeePerGas,'2000000000');
  let inclusionFee=21_000_000_000n;
  for(let index=0;index<12;index++) inclusionFee=(inclusionFee*9n+7n)/8n;
  assert.equal(envelopePlan.maxFeePerGas,String(inclusionFee+2_000_000_000n));
  assert.ok(envelopePlan.rpcObservations.every(value=>!('latestBlockNumber' in value)));
  const envelope={type:2,chainId:1,nonce:Number(envelopePlan.nonce),to:expected.to,
    value:0,data:expected.data,gasLimit:BigInt(envelopePlan.gasLimit),
    maxFeePerGas:BigInt(envelopePlan.maxFeePerGas),
    maxPriorityFeePerGas:BigInt(envelopePlan.maxPriorityFeePerGas),
    accessList:[]};
  const rawTransaction=await wallet.signTransaction(envelope);
  const input={plan:fixture.plan,transactionPackage,envelopePlan,role:'governance',
    rawTransaction,relayerOwner:relayer};
  const result=validateRecoverableSafeRecoveryRawTransaction(input);
  assert.equal(result.from,relayer);
  assert.equal(result.to,expected.to);
  assert.match(result.transactionHash,/^0x[0-9a-f]{64}$/);

  for(const [changes,pattern] of [
    [{chainId:5},/envelope mismatch/],
    [{data:'0x1234'},/envelope mismatch/],
    [{type:0,gasPrice:40_000_000_000n,maxFeePerGas:undefined,
      maxPriorityFeePerGas:undefined,accessList:undefined},/envelope mismatch/],
  ]) {
    const changed={...envelope,...changes};
    const raw=await wallet.signTransaction(changed);
    assert.throws(()=>validateRecoverableSafeRecoveryRawTransaction({...input,rawTransaction:raw}),
      pattern);
  }
  const outsider=Wallet.createRandom();
  const outsiderRaw=await outsider.signTransaction(envelope);
  assert.throws(()=>validateRecoverableSafeRecoveryRawTransaction(
    {...input,rawTransaction:outsiderRaw}),/envelope mismatch/);
  assert.throws(()=>validateRecoverableSafeRecoveryRawTransaction(
    {...input,relayerOwner:outsider.address}),/must be one of the two surviving owners/);
  const changedEnvelope=structuredClone(envelopePlan);
  changedEnvelope.gasLimit=String(BigInt(changedEnvelope.gasLimit)+1n);
  assert.throws(()=>validateRecoverableSafeRecoveryRawTransaction(
    {...input,envelopePlan:changedEnvelope}),/envelope hash mismatch/);
  const substitutedSources=structuredClone(envelopePlan);
  substitutedSources.rpcConsensus.sources[0].originKeccak256='0x'+'91'.repeat(32);
  const unsignedSubstitution={...substitutedSources}; delete unsignedSubstitution.envelopeHash;
  substitutedSources.envelopeHash=_safeControlObservationInternals.documentHash(unsignedSubstitution);
  assert.throws(()=>validateRecoverableSafeRecoveryRawTransaction(
    {...input,envelopePlan:substitutedSources}),/commitment mismatch/);
  const omittedSource=structuredClone(envelopePlan);
  omittedSource.rpcConsensus.sources.pop();
  const unsignedOmission={...omittedSource}; delete unsignedOmission.envelopeHash;
  omittedSource.envelopeHash=_safeControlObservationInternals.documentHash(unsignedOmission);
  assert.throws(()=>validateRecoverableSafeRecoveryRawTransaction(
    {...input,envelopePlan:omittedSource}),/RPC consensus/);
  await assert.rejects(prepareRecoverableSafeRecoveryEnvelope({
    plan:fixture.plan,transactionPackage,role:'governance',relayerOwner:relayer,
    sources:[
      {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32),url:'https://rpc.one'},
      {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32),url:'https://rpc.two'},
    ],
    providerFactory:url=>envelopeProvider(url,url.endsWith('two')?8:7),
  }),/nonce disagrees/);
  await assert.rejects(prepareRecoverableSafeRecoveryEnvelope({
    plan:fixture.plan,transactionPackage,role:'governance',relayerOwner:relayer,
    sources:[
      {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32),url:'https://rpc.one'},
      {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32),url:'https://rpc.two'},
    ],
    providerFactory:url=>envelopeProvider(url,7,url.endsWith('two')?22000001:22000000),
  }),/finalized snapshot disagrees/);
  await assert.rejects(prepareRecoverableSafeRecoveryEnvelope({
    plan:fixture.plan,transactionPackage,role:'governance',relayerOwner:relayer,
    sources:[
      {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32),url:'https://rpc.one'},
      {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32),url:'https://rpc.two'},
    ],providerFactory:url=>{
      const provider=envelopeProvider(url);
      provider.send=async method=>{assert.equal(method,'eth_estimateGas'); return '0x7a121';};
      return provider;
    },
  }),/gas estimate exceeds recovery policy/);
  await assert.rejects(prepareRecoverableSafeRecoveryEnvelope({
    plan:fixture.plan,transactionPackage,role:'governance',relayerOwner:relayer,
    sources:[
      {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32),url:'https://rpc.one'},
      {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32),url:'https://rpc.two'},
    ],providerFactory:url=>{
      const provider=envelopeProvider(url),getBlock=provider.getBlock;
      provider.getBlock=async tag=>tag==='finalized'
        ?{...(await getBlock(tag)),baseFeePerGas:120_000_000_001n}:getBlock(tag);
      return provider;
    },
  }),/base fee exceeds recovery policy/);
  await assert.rejects(prepareRecoverableSafeRecoveryEnvelope({
    plan:fixture.plan,transactionPackage,role:'governance',relayerOwner:relayer,
    sources:[
      {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32),url:'https://rpc.one'},
      {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32),url:'https://rpc.two'},
    ],providerFactory:url=>{
      const provider=envelopeProvider(url),getBlock=provider.getBlock;
      provider.getBlock=async tag=>tag==='finalized'
        ?{...(await getBlock(tag)),baseFeePerGas:0n}:getBlock(tag);
      return provider;
    },
  }),/base fee exceeds recovery policy/);
  await assert.rejects(prepareRecoverableSafeRecoveryEnvelope({
    plan:fixture.plan,transactionPackage,role:'governance',relayerOwner:relayer,
    sources:[
      {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32),url:'https://rpc.one'},
      {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32),url:'https://rpc.two'},
    ],providerFactory:url=>{
      const provider=envelopeProvider(url);
      provider.getBalance=async()=>1n;
      return provider;
    },
  }),/balance cannot cover/);
  let blockReads=0;
  await assert.rejects(prepareRecoverableSafeRecoveryEnvelope({
    plan:fixture.plan,transactionPackage,role:'governance',relayerOwner:relayer,
    sources:[
      {sourceId:'operator-a',originKeccak256:'0x'+'81'.repeat(32),url:'https://rpc.one'},
      {sourceId:'operator-b',originKeccak256:'0x'+'82'.repeat(32),url:'https://rpc.two'},
    ],providerFactory:url=>{
      const provider=envelopeProvider(url),getBlock=provider.getBlock;
      provider.getBlock=async tag=>{const block=await getBlock(tag); blockReads++;
        return {...block,hash:'0x'+String(blockReads).padStart(64,'0')};};
      return provider;
    },
  }),/changed during envelope recheck/);
});

test('Safe publication requires the exact signed finalized envelope after Ledger delay',()=>{
  const script=readFileSync(new URL('../../scripts/execute-recoverable-safe-recovery.sh',
    import.meta.url),'utf8');
  assert.match(script,/zero-finalized-[\s\S]*block validity window/);
  assert.ok(script.includes('"$cmp_bin" -s "$envelope_snapshot" "$temporary/$role-recovery-envelope.prepublish.json"'));
  assert.ok(!script.includes("jq -er '.nonce' \"$temporary/$role-recovery-envelope.prepublish.json\""));
});
