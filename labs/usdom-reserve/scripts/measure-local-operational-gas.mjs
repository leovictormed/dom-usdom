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

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const artifactPaths={
  reserve:'out/USDOMProofReserve.sol/USDOMProofReserve.json',
  verifier:'out/USDOMProofReserve.t.sol/MockFinalizedBurnVerifier.json',
  token:'out/Mocks.sol/HostileToken.json',governance:'out/Mocks.sol/MockGovernance.json',
  registry:'out/Mocks.sol/MockGracefulShutdownRegistry.json',
};
const safeFixturePath='test/fixtures/safe-1.4.1-mainnet.json';
async function load(relative){const bytes=await readFile(path.join(root,relative));return {relative,bytes,sha256:sha(bytes),value:JSON.parse(bytes)}}
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
    86400,172800,100_000_000_000n,2_000_000_000n]]);
   await (await token.mint(await signers[0].getAddress(),100_000_000_000n)).wait();
   await (await token.approve(await reserve.getAddress(),100_000_000_000n)).wait();
   await (await reserve.deposit(100_000_000_000n,keccak256(toUtf8Bytes('LOCAL GAS DEPOSIT')),
    '0x'+'00'.repeat(31)+'01')).wait();
   const block=await rpc.provider.getBlock('latest');
   const finalityBeaconSlot=(BigInt(block.timestamp)-genesis)/12n;
   return {token,verifier,governance,guardian,registry,reserve,domain,finalityBeaconSlot,now:BigInt(block.timestamp)};
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
  return {
   queueWithdrawal:{gasUsed:queueMeasured.receipt.gasUsed.toString(),proofBytes:260,queueDepthBefore:1,events:queueMeasured.receipt.logs.length},
   pruneExpired256:{gasUsed:expiredReceipt.gasUsed.toString(),inputCount:256,removed:256,queueDepthBefore:256},
   pruneDiscardable256:{gasUsed:discardReceipt.gasUsed.toString(),inputCount:256,removed:256,invalidatedByEmergency:true},
   safeAdminOverhead:{gasUsed:safeReceipt.gasUsed.toString(),safeVersion:'1.4.1',owners:3,threshold:2,
    approvals:2,action:'swapOwner',innerCalldataBytes:(inner.length-2)/2,outerCalldataBytes:(safeTransaction.data.length-2)/2},
  };
 } finally {for(const cleanup of cleanups.reverse())await cleanup()}
}
const first=await oneRun(),second=await oneRun();
if(JSON.stringify(first)!==JSON.stringify(second))throw new Error('operational gas measurements are not reproducible');
const report={schema:'usdom-local-operational-gas-measurement/v1',network:'anvil-local-chain-31337',runs:2,
 node:{path:process.execPath,sha256:sha(await readFile(process.execPath)),version:process.version},
 anvil:{path:ANVIL_PATH,sha256:ANVIL_SHA256},
 artifacts:Object.fromEntries(Object.entries(artifacts).map(([name,value])=>[name,{artifactPath:value.relative,artifactSha256:value.sha256}])),
 safeFixture:{path:safeFixture.relative,sha256:safeFixture.sha256,singletonRuntimeCodeHash:keccak256(safeFixture.value.singletonRuntimeCode)},
 scenarios:first,productionRequirementsRemainFalse:true,
 limitations:['local chain 31337 and deterministic test doubles are not production release evidence',
  'production measurements must be repeated after exact release pins and mainnet Safe identities are materialized']};
process.stdout.write(JSON.stringify(report,null,2)+'\n');
