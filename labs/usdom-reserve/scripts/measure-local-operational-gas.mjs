#!/usr/bin/env node
// Deterministic, local-only operational gas measurement. No external RPC,
// production identity, signing device or deployment is accepted.
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {AbiCoder,Contract,ContractFactory,Interface,concat,keccak256,toUtf8Bytes,zeroPadValue} from 'ethers';
import {localEvm} from '../test/node/helpers/evm.mjs';
import {ANVIL_PATH,ANVIL_SHA256} from '../test/node/helpers/pinned-anvil.mjs';
import {solidityArtifactExecutableFingerprint}
  from '../sdk/solidity-artifact-executable-fingerprint.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const artifactPaths={
  reserve:'out/USDOMProofReserve.sol/USDOMProofReserve.json',
  verifier:'out/USDOMProofReserve.t.sol/MockFinalizedBurnVerifier.json',
  token:'out/Mocks.sol/HostileToken.json',governance:'out/Mocks.sol/MockGovernance.json',
  registry:'out/Mocks.sol/MockGracefulShutdownRegistry.json',
};
const safeFixturePath='test/fixtures/safe-1.4.1-mainnet.json';
async function load(relative){const bytes=await readFile(path.join(root,relative));const value=JSON.parse(bytes);return {relative,bytes,sha256:sha(bytes),executableSha256:relative.startsWith('out/')?solidityArtifactExecutableFingerprint(value):null,value}}
const artifacts=Object.fromEntries(await Promise.all(Object.entries(artifactPaths).map(async([k,p])=>[k,await load(p)])));
const safeFixture=await load(safeFixturePath);
const proof='0x73c457ba'+'00'.repeat(256);
const genesis=1606824023n;

async function oneRun(){
 const cleanups=[]; const rpc=await localEvm({after:fn=>cleanups.push(fn)});
 try {
  const signers=await Promise.all([0,1,2,3,4].map(i=>rpc.provider.getSigner(i)));
  const deploy=async(build,args=[])=>{const c=await new ContractFactory(build.value.abi,build.value.bytecode.object,signers[0]).deploy(...args);await c.waitForDeployment();return c};
  async function reserveFixture(){
   const token=await deploy(artifacts.token),verifier=await deploy(artifacts.verifier);
   const governance=await deploy(artifacts.governance),guardian=await deploy(artifacts.governance);
   const domain=keccak256(toUtf8Bytes('LOCAL OPERATIONAL GAS DOMAIN'));
   const activation=keccak256(toUtf8Bytes('LOCAL OPERATIONAL GAS ACTIVATION'));
   const registry=await deploy(artifacts.registry,[domain,activation]);
   const reserve=await deploy(artifacts.reserve,[[await token.getAddress(),await verifier.getAddress(),
    await registry.getAddress(),domain,activation,await governance.getAddress(),await guardian.getAddress(),
    86400,172800,100_000_000_000n,2_000_000_000n,false]]);
   await (await token.mint(await signers[0].getAddress(),100_000_000_000n)).wait();
   await (await token.approve(await reserve.getAddress(),100_000_000_000n)).wait();
   await (await reserve.deposit(100_000_000_000n,keccak256(toUtf8Bytes('LOCAL GAS DEPOSIT')),
    '0x'+'00'.repeat(31)+'01')).wait();
   const block=await rpc.provider.getBlock('latest');
   const finalityBeaconSlot=(BigInt(block.timestamp)-genesis)/12n;
   return {token,verifier,governance,guardian,registry,reserve,domain,finalityBeaconSlot,now:BigInt(block.timestamp)};
  }
  async function pilotFixture(){
   const token=await deploy(artifacts.token),verifier=await deploy(artifacts.verifier);
   const governance=await deploy(artifacts.governance),guardian=await deploy(artifacts.governance);
   const domain=keccak256(toUtf8Bytes('LOCAL PILOT GAS DOMAIN'));
   const activation=keccak256(toUtf8Bytes('LOCAL PILOT GAS ACTIVATION'));
   const registry=await deploy(artifacts.registry,[domain,activation]);
   const reserve=await deploy(artifacts.reserve,[[await token.getAddress(),await verifier.getAddress(),
    await registry.getAddress(),domain,activation,await governance.getAddress(),await guardian.getAddress(),
    86400,172800,100_000_000_000n,2_000_000_000n,true]]);
   const funder=await signers[0].getAddress(),amount=1_000_000n;
   const salt=keccak256(toUtf8Bytes('LOCAL PILOT GAS SALT'));
   const commitment='0x'+'00'.repeat(31)+'02';
   await (await token.mint(funder,amount)).wait();
   await (await token.approve(await reserve.getAddress(),amount)).wait();
   const block=await rpc.provider.getBlock('latest'),validUntil=BigInt(block.timestamp)+86400n;
   const snapshot=keccak256(toUtf8Bytes('LOCAL PILOT GAS SNAPSHOT'));
   const authorizeData=reserve.interface.encodeFunctionData('authorizePilotDeposit',
    [snapshot,funder,amount,salt,commitment,validUntil,0]);
   return {token,verifier,governance,guardian,registry,reserve,domain,funder,amount,salt,
    commitment,validUntil,snapshot,authorizeData,now:BigInt(block.timestamp)};
  }
  const makeBurn=async(fixture,index)=>({burnId:keccak256(toUtf8Bytes(`LOCAL GAS BURN ${index}`)),
   requestId:keccak256(toUtf8Bytes(`LOCAL GAS REQUEST ${index}`)),recipient:await signers[4].getAddress(),amount:1n,
   domDomain:fixture.domain,height:BigInt(index+1),blockHash:keccak256(toUtf8Bytes(`LOCAL GAS BLOCK ${index}`)),
   stateRoot:keccak256(toUtf8Bytes(`LOCAL GAS STATE ${index}`)),finalityBeaconSlot:fixture.finalityBeaconSlot,
   validUntil:fixture.now+604800n});
  async function queue(fixture,index){
   const burn=await makeBurn(fixture,index); const statement=await fixture.reserve.burnStatementHash(burn);
   await (await fixture.verifier.approve(statement,proof)).wait();
   const receipt=await (await fixture.reserve.queueWithdrawal(burn,proof)).wait();
   return {burn,receipt};
  }
  const queueFixture=await reserveFixture(); await queue(queueFixture,0);
  const queueMeasured=await queue(queueFixture,1);
  const expiredFixture=await reserveFixture();
  for(let i=0;i<256;i++) await queue(expiredFixture,10_000+i);
  await rpc.provider.send('evm_increaseTime',[604801]); await rpc.provider.send('evm_mine',[]);
  const expiredReceipt=await (await expiredFixture.reserve.pruneExpired(256)).wait();
  if(await expiredFixture.reserve.pendingCount()!==0n) throw new Error('pruneExpired did not remove 256');
  const discardFixture=await reserveFixture(); const discardIds=[];
  for(let i=0;i<256;i++) discardIds.push((await queue(discardFixture,20_000+i)).burn.burnId);
  await (await discardFixture.guardian.execute(await discardFixture.reserve.getAddress(),
   discardFixture.reserve.interface.encodeFunctionData('pause'))).wait();
  const discardReceipt=await (await discardFixture.reserve.pruneDiscardable(discardIds)).wait();
  for(const id of discardIds){const pending=await discardFixture.reserve.pendingWithdrawals(id);if(pending[0]!==('0x'+'00'.repeat(32)))throw new Error('discardable entry remained')}

  const authorizeFixture=await pilotFixture();
  const authorizeReceipt=await (await authorizeFixture.governance.execute(
   await authorizeFixture.reserve.getAddress(),authorizeFixture.authorizeData)).wait();
  const cancelData=authorizeFixture.reserve.interface.encodeFunctionData(
   'cancelPilotDepositAuthorization',[authorizeFixture.snapshot,0]);
  const cancelReceipt=await (await authorizeFixture.governance.execute(
   await authorizeFixture.reserve.getAddress(),cancelData)).wait();

  const clearFixture=await pilotFixture();
  await (await clearFixture.governance.execute(await clearFixture.reserve.getAddress(),clearFixture.authorizeData)).wait();
  await rpc.provider.send('evm_setNextBlockTimestamp',[Number(clearFixture.validUntil+1n)]);
  const clearReceipt=await (await clearFixture.reserve.clearExpiredPilotDepositAuthorization(
   clearFixture.snapshot,0)).wait();

  const depositFixture=await pilotFixture();
  await (await depositFixture.governance.execute(await depositFixture.reserve.getAddress(),depositFixture.authorizeData)).wait();
  const depositTransaction=await depositFixture.reserve.deposit(depositFixture.amount,depositFixture.salt,
   depositFixture.commitment);
  const depositReceipt=await depositTransaction.wait();

  // The opening route is reachable only after the pilot collateral is fully
  // redeemed, so prepare that exact settled state instead of mutating storage.
  const openBlock=await rpc.provider.getBlock('latest');
  const openBurn={burnId:keccak256(toUtf8Bytes('LOCAL PILOT OPEN BURN')),
   requestId:keccak256(toUtf8Bytes('LOCAL PILOT OPEN REQUEST')),recipient:await signers[4].getAddress(),
   amount:depositFixture.amount,domDomain:depositFixture.domain,height:1n,
   blockHash:keccak256(toUtf8Bytes('LOCAL PILOT OPEN BLOCK')),
   stateRoot:keccak256(toUtf8Bytes('LOCAL PILOT OPEN STATE')),
   finalityBeaconSlot:(BigInt(openBlock.timestamp)-genesis)/12n,validUntil:BigInt(openBlock.timestamp)+604800n};
  const openStatement=await depositFixture.reserve.burnStatementHash(openBurn);
  await (await depositFixture.verifier.approve(openStatement,proof)).wait();
  await (await depositFixture.reserve.queueWithdrawal(openBurn,proof)).wait();
  await rpc.provider.send('evm_increaseTime',[86400]);await rpc.provider.send('evm_mine',[]);
  await (await depositFixture.reserve.executeWithdrawal(openBurn)).wait();
  const scheduleData=depositFixture.reserve.interface.encodeFunctionData('schedulePermissionlessDeposits');
  const scheduleReceipt=await (await depositFixture.governance.execute(
   await depositFixture.reserve.getAddress(),scheduleData)).wait();
  await rpc.provider.send('evm_increaseTime',[172800]);await rpc.provider.send('evm_mine',[]);
  const openReceipt=await (await depositFixture.reserve.executePermissionlessDeposits()).wait();

  const singleton='0x1000000000000000000000000000000000000001';
  await rpc.provider.send('anvil_setCode',[singleton,safeFixture.value.singletonRuntimeCode]);
  const init=concat([safeFixture.value.proxyCreationCode,AbiCoder.defaultAbiCoder().encode(['address'],[singleton])]);
  const deployment=await (await signers[0].sendTransaction({data:init})).wait();
  if(!deployment.contractAddress) throw new Error('Safe proxy deployment failed');
  const safeAbi=[
   'function setup(address[] owners,uint256 threshold,address to,bytes data,address fallbackHandler,address paymentToken,uint256 payment,address payable paymentReceiver)',
   'function getOwners() view returns(address[])','function nonce() view returns(uint256)','function approveHash(bytes32)',
   'function getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256) view returns(bytes32)',
   'function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address payable,bytes) returns(bool)',
   'function swapOwner(address,address,address)'];
  const safe=new Contract(deployment.contractAddress,safeAbi,signers[0]);
  const ownerAddresses=await Promise.all(signers.slice(0,3).map(s=>s.getAddress()));
  await (await safe.setup(ownerAddresses,2,'0x0000000000000000000000000000000000000000','0x',
   '0x0000000000000000000000000000000000000000','0x0000000000000000000000000000000000000000',0,
   '0x0000000000000000000000000000000000000000')).wait();
  const ordered=await safe.getOwners(),oldOwner=ordered[2],previousOwner=ordered[1],newOwner=await signers[3].getAddress();
  const inner=new Interface(safeAbi).encodeFunctionData('swapOwner',[previousOwner,oldOwner,newOwner]);
  const zero='0x0000000000000000000000000000000000000000';
  const safeTxHash=await safe.getTransactionHash(deployment.contractAddress,0,inner,0,0,0,0,zero,zero,0);
  const approving=ownerAddresses.slice(0,2);
  for(let i=0;i<2;i++) await (await safe.connect(signers[i]).approveHash(safeTxHash)).wait();
  const signatures=concat(approving.sort((a,b)=>BigInt(a)<BigInt(b)?-1:1).map(owner=>
   concat([zeroPadValue(owner,32),'0x'+'00'.repeat(32),'0x01'])));
  const safeTransaction=await safe.execTransaction(deployment.contractAddress,0,inner,0,0,0,0,zero,zero,signatures);
  const safeReceipt=await safeTransaction.wait();
  if(!(await safe.getOwners()).some(owner=>owner.toLowerCase()===newOwner.toLowerCase()))throw new Error('Safe admin action failed');
  const safeOverhead=BigInt(safeReceipt.gasUsed);
  const modeled=receipt=>({directOrGovernanceGasUsed:receipt.gasUsed.toString(),
   modeledSafeUpperBoundGas:(receipt.gasUsed+safeOverhead).toString(),safeOverheadBasisGas:safeOverhead.toString()});
  return {
   queueWithdrawal:{gasUsed:queueMeasured.receipt.gasUsed.toString(),proofBytes:260,queueDepthBefore:1,events:queueMeasured.receipt.logs.length},
   pruneExpired256:{gasUsed:expiredReceipt.gasUsed.toString(),inputCount:256,removed:256,queueDepthBefore:256},
   pruneDiscardable256:{gasUsed:discardReceipt.gasUsed.toString(),inputCount:256,removed:256,invalidatedByEmergency:true},
   safeAdminOverhead:{gasUsed:safeReceipt.gasUsed.toString(),safeVersion:'1.4.1',owners:3,threshold:2,
    approvals:2,action:'swapOwner',innerCalldataBytes:(inner.length-2)/2,outerCalldataBytes:(safeTransaction.data.length-2)/2},
   authorizePilotDeposit:{...modeled(authorizeReceipt),generation:0,calldataBytes:(authorizeFixture.authorizeData.length-2)/2},
   cancelPilotDepositAuthorization:{...modeled(cancelReceipt),generation:0,calldataBytes:(cancelData.length-2)/2},
   clearExpiredPilotDepositAuthorization:{gasUsed:clearReceipt.gasUsed.toString(),generation:0,
    calldataBytes:(clearFixture.reserve.interface.encodeFunctionData('clearExpiredPilotDepositAuthorization',
     [clearFixture.snapshot,0]).length-2)/2},
   authorizedPilotDeposit:{gasUsed:depositReceipt.gasUsed.toString(),amountBaseUnits:depositFixture.amount.toString(),
    calldataBytes:(depositTransaction.data.length-2)/2,generationAfter:1},
   schedulePermissionlessDeposits:{...modeled(scheduleReceipt),calldataBytes:(scheduleData.length-2)/2},
   executePermissionlessDeposits:{gasUsed:openReceipt.gasUsed.toString(),calldataBytes:4,opened:true},
  };
 } finally {for(const cleanup of cleanups.reverse())await cleanup()}
}
const first=await oneRun(),second=await oneRun();
if(JSON.stringify(first)!==JSON.stringify(second)) {
 const differing=[];
 const visit=(left,right,prefix)=>{
  if(left&&right&&typeof left==='object'&&typeof right==='object'
      &&!Array.isArray(left)&&!Array.isArray(right)) {
   for(const key of new Set([...Object.keys(left),...Object.keys(right)])) visit(left[key],right[key],prefix?`${prefix}.${key}`:key);
  } else if(JSON.stringify(left)!==JSON.stringify(right)) differing.push(prefix);
 };
 visit(first,second,'');
 throw new Error(`operational gas measurements are not reproducible: ${differing.join(', ')}`);
}
const report={schema:'usdom-local-operational-gas-measurement/v3',network:'anvil-local-chain-31337',runs:2,
 node:{path:'node',sha256:sha(await readFile(process.execPath)),version:process.version},
 anvil:{path:ANVIL_PATH,sha256:ANVIL_SHA256},
 artifacts:Object.fromEntries(Object.entries(artifacts).map(([name,value])=>[name,{artifactPath:value.relative,artifactExecutableSha256:value.executableSha256}])),
 safeFixture:{path:safeFixture.relative,sha256:safeFixture.sha256,singletonRuntimeCodeHash:keccak256(safeFixture.value.singletonRuntimeCode)},
 scenarios:first,productionRequirementsRemainFalse:true,
 limitations:['local chain 31337 and deterministic test doubles are not production release evidence',
  'production measurements must be repeated after exact release pins and mainnet Safe identities are materialized']};
process.stdout.write(JSON.stringify(report,null,2)+'\n');
