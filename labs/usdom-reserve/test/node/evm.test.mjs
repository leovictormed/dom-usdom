import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {ContractFactory, JsonRpcProvider, Wallet, keccak256, toUtf8Bytes} from 'ethers';
import {domain, burnTypes, digest, quorumSignatures} from '../../sdk/reserve.mjs';
import {finalizedBurnStatementHash} from '../../sdk/proof-reserve.mjs';
import {finalizedBurnVerifierConfigHash} from '../../sdk/verifier-config.mjs';
import {
 deriveCheckpointVerifierInitcodeHash,deriveCheckpointVerifierRuntimeCodeHash,
 deriveFinalizedBurnVerifierInitcodeHash,deriveFinalizedBurnVerifierRuntimeCodeHash,
 deriveReserveInitcodeHash,deriveReserveRuntimeCodeHash,
} from '../../sdk/compiled-runtime.mjs';
import {
 CHECKPOINT_EVENT_TOPIC0,checkpointRegistryConfigHash,checkpointStatementHash,
} from '../../sdk/checkpoint-registry.mjs';
import {checkpointVerifierConfigHash} from '../../sdk/checkpoint-verifier-config.mjs';
const artifact = async name => JSON.parse(await readFile(new URL(`../../out/${name}.json`,import.meta.url)));
const bn254ScalarField = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const canonicalCommitment = entropy =>
 '0x'+(BigInt(entropy)%(bn254ScalarField-1n)+1n).toString(16).padStart(64,'0');

test('SDK, source-derived runtimes and deployed EVM behavior agree exactly', {timeout:90000}, async t => {
 const child=spawn(process.env.USDOM_ANVIL ?? 'anvil',['--host','127.0.0.1','--port','18545','--chain-id','31337','--silent'],{stdio:'ignore'});
 let spawnError; child.on('error',e=>{spawnError=e;});
 const provider=new JsonRpcProvider('http://127.0.0.1:18545',31337,{staticNetwork:true,cacheTimeout:-1});
 t.after(async()=>{provider.destroy();child.kill('SIGTERM');});
 for(let i=0;;i++){try{await provider.send('eth_chainId',[]);break;}catch(e){if(spawnError)throw spawnError;if(child.exitCode !== null) throw new Error(`Anvil exited before readiness: ${child.exitCode}`);if(i===300)throw e;await delay(100);}}
 const funder=await provider.getSigner(0), recipient=await provider.getSigner(2);
 const deploy=async(name,args=[])=>{const a=await artifact(name);const c=await new ContractFactory(a.abi,a.bytecode.object,funder).deploy(...args);await c.waitForDeployment();return c;};
 const token=await deploy('Mocks.sol/HostileToken'), governor=await deploy('Mocks.sol/MockGovernance');
 const guardian=await deploy('Mocks.sol/MockGovernance');
 const wallets=[101,102,103,104].map(n=>new Wallet('0x'+n.toString(16).padStart(64,'0')));
 const notaries=wallets.map(w=>w.address).sort((a,b)=>BigInt(a)<BigInt(b)?-1:1);
 const domDomain=keccak256(toUtf8Bytes('LOCAL TEST ONLY'));
 const reserve=await deploy('USDOMReserve.sol/USDOMReserve', [
  [await token.getAddress(),domDomain,await governor.getAddress(),await guardian.getAddress(),86400,172800,100000000000n,2000000000n],notaries,3]);
 const address=await reserve.getAddress(), receiver=await recipient.getAddress();
 await (await token.mint(await funder.getAddress(),10000000000n)).wait();
 await (await token.approve(address,10000000000n)).wait();
 await (await reserve.deposit(10000000000n,keccak256(toUtf8Bytes('salt')),canonicalCommitment(keccak256(toUtf8Bytes('commitment'))))).wait();
 const now=BigInt((await provider.getBlock('latest')).timestamp);
 const burn={burnId:keccak256(toUtf8Bytes('burn')),requestId:keccak256(toUtf8Bytes('request')),recipient:receiver,amount:1000000n,domDomain,height:1n,blockHash:keccak256(toUtf8Bytes('block')),epoch:1n,validUntil:now+6n*86400n};
 assert.equal(await reserve.burnDigest(burn),digest('31337',address,burn));
 const signatures=await Promise.all(wallets.slice(0,3).map(w=>w.signTypedData(domain('31337',address),burnTypes,burn)));
 const ordered=quorumSignatures({chainId:'31337',reserve:address,burn,signatures,notaries,threshold:3});
 const receipt=await (await reserve.queueWithdrawal(burn,ordered)).wait();
 assert(receipt.logs.some(log=>{try{return reserve.interface.parseLog(log)?.name==='WithdrawalCertificate';}catch{return false;}}));
 assert.equal(await reserve.totalPendingAmount(),burn.amount);
 await assert.rejects(reserve.executeWithdrawal.staticCall(burn));
 await provider.send('evm_increaseTime',[86400]);await provider.send('evm_mine',[]);
 await (await reserve.executeWithdrawal(burn)).wait();
 assert.equal(await token.balanceOf(receiver),burn.amount);
 assert.equal(await reserve.totalPendingAmount(),0n);
 await assert.rejects(reserve.executeWithdrawal.staticCall(burn));
 await assert.rejects(reserve.queueWithdrawal.staticCall(burn,ordered));

 const verifier=await deploy('USDOMProofReserve.t.sol/MockFinalizedBurnVerifier');
 const activationScheduleCommitment=keccak256(toUtf8Bytes('LOCAL DOM ACTIVATION SCHEDULE'));
 const proofReserve=await deploy('USDOMProofReserve.sol/USDOMProofReserve', [[
  await token.getAddress(),await verifier.getAddress(),domDomain,activationScheduleCommitment,
  await governor.getAddress(),await guardian.getAddress(),
  86400,172800,100000000000n,2000000000n,
 ]]);
 const proofReserveAddress=await proofReserve.getAddress();
 const proofReserveArtifact=await artifact('USDOMProofReserve.sol/USDOMProofReserve');
 const deployedConfig={
  token:await proofReserve.token(),tokenCodeHash:await proofReserve.tokenCodeHash(),
  verifier:await proofReserve.verifier(),verifierCodeHash:await proofReserve.verifierCodeHash(),
  verifierConfigHash:await proofReserve.verifierConfigHash(),reserveConfigHash:await proofReserve.reserveConfigHash(),
  domDomain:await proofReserve.domDomain(),
  activationScheduleCommitment:await proofReserve.activationScheduleCommitment(),
  governance:await proofReserve.governance(),
  governanceCodeHash:await proofReserve.governanceCodeHash(),guardian:await proofReserve.guardian(),
  guardianCodeHash:await proofReserve.guardianCodeHash(),withdrawalDelaySeconds:await proofReserve.withdrawalDelay(),
  governanceDelaySeconds:await proofReserve.governanceDelay(),maxOutstandingBaseUnits:await proofReserve.maxOutstanding(),
  outflowCapacityBaseUnitsPerDay:await proofReserve.outflowCapacity(),
 };
 const derivedRuntime=deriveReserveRuntimeCodeHash({artifact:proofReserveArtifact,releaseConfig:deployedConfig});
 assert.equal(derivedRuntime.runtimeCodeHash,keccak256(await provider.getCode(proofReserveAddress)));
 const derivedInitcode=deriveReserveInitcodeHash({artifact:proofReserveArtifact,releaseConfig:deployedConfig});
 const deploymentTransaction=proofReserve.deploymentTransaction();
 assert.equal(derivedInitcode.initcodeHash,keccak256(deploymentTransaction.data));
 assert.equal(deploymentTransaction.to,null);
 assert.equal(deploymentTransaction.value,0n);

 const riscZero=await deploy('DOMFinalizedBurnRiscZeroVerifier.t.sol/MockRiscZeroVerifierV3',['0x73c457ba']);
 const riscZeroAddress=await riscZero.getAddress();
 const riscZeroCodeHash=keccak256(await provider.getCode(riscZeroAddress));
 const finalizedImageId=keccak256(toUtf8Bytes('LOCAL FINALIZED BURN IMAGE ID'));
 const checkpointImageId=keccak256(toUtf8Bytes('LOCAL CHECKPOINT IMAGE ID'));
 const finalizedAdapter=await deploy(
  'DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier',
  [riscZeroAddress,finalizedImageId],
 );
 const checkpointAdapter=await deploy(
  'DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier',
  [riscZeroAddress,checkpointImageId],
 );
 const zeroHash='0x'+'00'.repeat(32);
 const fillManifest=async(name,overrides)=>{
  const value=JSON.parse(await readFile(new URL(`../../config/${name}`,import.meta.url),'utf8'));
  for(const key of Object.keys(value)) if(value[key]===null) value[key]=keccak256(toUtf8Bytes(`LOCAL ${name} ${key}`));
  return Object.assign(value,overrides);
 };
 const finalizedVerifierConfig=await fillManifest('finalized-burn-verifier.unconfigured.json',{
  domNetworkMagic:'2712847316',firstV4Height:'100000',minimumFinalityBeaconSlot:'1',
  proofSystem:'risc0-groth16-v3',trustedSetupRequired:false,trustedSetupTranscriptSha256:zeroHash,
  ethereumChainId:'31337',riscZeroVerifier:riscZeroAddress,riscZeroVerifierCodeHash:riscZeroCodeHash,
  finalizedBurnGuestImageId:finalizedImageId,
 });
 const checkpointVerifierConfig=await fillManifest('checkpoint-verifier.unconfigured.json',{
  domNetworkMagic:'2712847316',firstV4Height:'100000',trustedSetupRequired:false,
  trustedSetupTranscriptSha256:zeroHash,ethereumChainId:'31337',riscZeroVerifier:riscZeroAddress,
  riscZeroVerifierCodeHash:riscZeroCodeHash,checkpointGuestImageId:checkpointImageId,
 });
 const finalizedAdapterArtifact=await artifact(
  'DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier',
 );
 const checkpointAdapterArtifact=await artifact(
  'DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier',
 );
 const derivedFinalizedAdapter=deriveFinalizedBurnVerifierRuntimeCodeHash({
  artifact:finalizedAdapterArtifact,verifierConfig:finalizedVerifierConfig,
 });
 const derivedFinalizedAdapterInitcode=deriveFinalizedBurnVerifierInitcodeHash({
  artifact:finalizedAdapterArtifact,verifierConfig:finalizedVerifierConfig,
 });
 const derivedCheckpointAdapter=deriveCheckpointVerifierRuntimeCodeHash({
  artifact:checkpointAdapterArtifact,verifierConfig:checkpointVerifierConfig,
 });
 const derivedCheckpointAdapterInitcode=deriveCheckpointVerifierInitcodeHash({
  artifact:checkpointAdapterArtifact,verifierConfig:checkpointVerifierConfig,
 });
 assert.equal(derivedFinalizedAdapter.runtimeCodeHash,
  keccak256(await provider.getCode(await finalizedAdapter.getAddress())));
 assert.equal(derivedCheckpointAdapter.runtimeCodeHash,
  keccak256(await provider.getCode(await checkpointAdapter.getAddress())));
 assert.equal(derivedFinalizedAdapterInitcode.initcodeHash,
  keccak256(finalizedAdapter.deploymentTransaction().data));
 assert.equal(derivedCheckpointAdapterInitcode.initcodeHash,
  keccak256(checkpointAdapter.deploymentTransaction().data));
 assert.equal(derivedFinalizedAdapter.runtimeSize,1921);
 assert.equal(derivedCheckpointAdapter.runtimeSize,1922);
 assert.equal(await finalizedAdapter.verifierConfigHash(),
  finalizedBurnVerifierConfigHash(finalizedVerifierConfig).verifierConfigHash);
 assert.equal(await checkpointAdapter.verifierConfigHash(),
  checkpointVerifierConfigHash(checkpointVerifierConfig).verifierConfigHash);
 const proofBurn={burnId:keccak256(toUtf8Bytes('proof burn')),requestId:keccak256(toUtf8Bytes('proof request')),
  recipient:receiver,amount:1000000n,domDomain,height:2n,blockHash:keccak256(toUtf8Bytes('DOM block')),
  stateRoot:keccak256(toUtf8Bytes('private USDOM state')),finalityBeaconSlot:1n,validUntil:now+6n*86400n};
 assert.equal(await proofReserve.burnStatementHash(proofBurn),finalizedBurnStatementHash({
  chainId:'31337',reserve:proofReserveAddress,activationScheduleCommitment,burn:proofBurn,
 }));

 const checkpointVerifier=await deploy('DOMCheckpointRegistry.t.sol/MockDOMCheckpointVerifier');
 const checkpointDomain=keccak256(toUtf8Bytes('LOCAL CHECKPOINT DOMAIN'));
 const checkpointDomChainId=keccak256(toUtf8Bytes('LOCAL DOM CHAIN ID'));
 const initialBlock=keccak256(toUtf8Bytes('LOCAL INITIAL DOM BLOCK'));
 const initialStateRoot=keccak256(toUtf8Bytes('LOCAL INITIAL USDOM STATE'));
 const initialContextHash=keccak256(toUtf8Bytes('LOCAL INITIAL DOM CONSENSUS CONTEXT'));
 const checkpointRegistry=await deploy('DOMCheckpointRegistry.sol/DOMCheckpointRegistry', [[
  checkpointDomain,0xA1B2C3D4,checkpointDomChainId,101n,initialStateRoot,
  activationScheduleCommitment,360,30,86400,await checkpointVerifier.getAddress(),
  await guardian.getAddress(),100n,initialBlock,initialStateRoot,initialContextHash,1000000n,
 ]]);
 const checkpointRegistryAddress=await checkpointRegistry.getAddress();
 const checkpointConfiguration={
  ethereumChainId:'31337',registry:checkpointRegistryAddress,bridgeDomain:checkpointDomain,
  domNetworkMagic:'2712847316',activationScheduleCommitment,
  domChainId:checkpointDomChainId,firstV4Height:'101',activationEmptyStateRoot:initialStateRoot,
  checkpointInterval:'360',confirmationDepth:'30',challengePeriod:'86400',
  verifier:await checkpointRegistry.verifier(),verifierCodeHash:await checkpointRegistry.verifierCodeHash(),
  verifierConfigHash:await checkpointRegistry.verifierConfigHash(),guardian:await checkpointRegistry.guardian(),
  guardianCodeHash:await checkpointRegistry.guardianCodeHash(),initialHeight:'100',initialBlock,initialStateRoot,
  initialContextHash,
  initialTotalDifficulty:'1000000',
 };
 assert.equal(await checkpointRegistry.checkpointConfigHash(),
  checkpointRegistryConfigHash(checkpointConfiguration).checkpointConfigHash);
 const checkpoint={previousHeight:'100',previousBlock:initialBlock,previousStateRoot:initialStateRoot,
  previousContextHash:initialContextHash,
  previousTotalDifficulty:'1000000',
  height:'460',blockHash:keccak256(toUtf8Bytes('LOCAL NEXT DOM BLOCK')),
  stateRoot:keccak256(toUtf8Bytes('LOCAL NEXT USDOM STATE')),
  contextHash:keccak256(toUtf8Bytes('LOCAL NEXT DOM CONSENSUS CONTEXT')),totalDifficulty:'1000360',
  confirmationHeight:'490',confirmationBlock:keccak256(toUtf8Bytes('LOCAL CONFIRMATION DOM BLOCK')),
  confirmationTotalDifficulty:'1000390',confirmationTimestamp:now.toString()};
 const checkpointProof='0x01020304';
 const checkpointHash=checkpointStatementHash(checkpointConfiguration,checkpoint);
 assert.equal(await checkpointRegistry.checkpointStatementHash(checkpoint),checkpointHash);
 await (await checkpointVerifier.approve(checkpointHash,checkpointProof)).wait();
 const candidateReceipt=await (await checkpointRegistry.submitCheckpointCandidate(checkpoint,checkpointProof)).wait();
 assert(!candidateReceipt.logs.some(log=>log.topics[0]===CHECKPOINT_EVENT_TOPIC0),
  'unfinalized candidate must not emit the authenticated checkpoint event ABI');
 assert.equal(await checkpointRegistry.latestHeight(),100n);
 await provider.send('evm_increaseTime',[86400]);await provider.send('evm_mine',[]);
 const checkpointReceipt=await (await checkpointRegistry.finalizeCheckpoint()).wait();
 const checkpointLog=checkpointReceipt.logs.find(log=>log.topics[0]===CHECKPOINT_EVENT_TOPIC0);
 assert(checkpointLog,'checkpoint registry must emit the authenticated event ABI');
 assert.equal(await checkpointRegistry.latestHeight(),460n);
 assert.equal(await checkpointRegistry.latestBlock(),checkpoint.blockHash);
 assert.equal(await checkpointRegistry.latestStateRoot(),checkpoint.stateRoot);
 assert.equal(await checkpointRegistry.latestContextHash(),checkpoint.contextHash);
});
