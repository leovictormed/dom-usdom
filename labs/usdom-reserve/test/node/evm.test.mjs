import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {ContractFactory, JsonRpcProvider, Wallet, keccak256, sha256, toUtf8Bytes} from 'ethers';
import {domain, burnTypes, digest, quorumSignatures} from '../../sdk/reserve.mjs';
import {finalizedBurnStatementHash} from '../../sdk/proof-reserve.mjs';
import {finalizedBurnVerifierConfigHash} from '../../sdk/verifier-config.mjs';
import {
 deriveCheckpointVerifierInitcodeHash,deriveCheckpointVerifierRuntimeCodeHash,
 deriveFinalizedBurnVerifierInitcodeHash,deriveFinalizedBurnVerifierRuntimeCodeHash,
 deriveReserveInitcodeHash,deriveReserveRuntimeCodeHash,
} from '../../sdk/compiled-runtime.mjs';
import {
 CHECKPOINT_EVENT_TOPIC0,CHECKPOINT_STATEMENT_TYPEHASH,checkpointRegistryConfigHash,checkpointStatementHash,
} from '../../sdk/checkpoint-registry.mjs';
import {
 CHECKPOINT_PROOF_ACCEPTED_HASH,CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
 CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
 checkpointVerifierConfigHash,
} from '../../sdk/checkpoint-verifier-config.mjs';
import {pinnedAnvil} from './helpers/pinned-anvil.mjs';
import {
 CHECKPOINT_GROTH16_VERIFIER_PARAMETERS,CHECKPOINT_OUTER_IMAGE_ID,
 buildAuthenticatedCheckpointSubmission,encodeCheckpointStatementV6,
 verifyAuthenticatedCheckpointSubmissionOnEvm,
} from '../../sdk/checkpoint-submission.mjs';
const artifact = async name => JSON.parse(await readFile(new URL(`../../out/${name}.json`,import.meta.url)));
const bn254ScalarField = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const canonicalCommitment = entropy =>
 '0x'+(BigInt(entropy)%(bn254ScalarField-1n)+1n).toString(16).padStart(64,'0');

test('SDK, source-derived runtimes and deployed EVM behavior agree exactly', {timeout:90000}, async t => {
 const child=spawn(await pinnedAnvil(),['--host','127.0.0.1','--port','18545','--chain-id','31337','--silent'],{stdio:'ignore'});
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
 const safeSingleton=await deploy('Mocks.sol/MockGovernance');
 const proofGovernance=await deploy('Mocks.sol/MockMutableSingletonControl',[await safeSingleton.getAddress()]);
 const proofGuardian=await deploy('Mocks.sol/MockMutableSingletonControl',[await safeSingleton.getAddress()]);
 await (await proofGovernance.setOwners(
  '0x0000000000000000000000000000000000000101',
  '0x0000000000000000000000000000000000000102',
  '0x0000000000000000000000000000000000000103')).wait();
 await (await proofGuardian.setOwners(
  '0x0000000000000000000000000000000000000201',
  '0x0000000000000000000000000000000000000202',
  '0x0000000000000000000000000000000000000203')).wait();
 const shutdownRegistry=await deploy('Mocks.sol/MockGracefulShutdownRegistry',[
  domDomain,activationScheduleCommitment,
 ]);
 const proofReserve=await deploy('USDOMProofReserve.sol/USDOMProofReserve', [[
  await token.getAddress(),await verifier.getAddress(),await shutdownRegistry.getAddress(),
  domDomain,activationScheduleCommitment,
  await proofGovernance.getAddress(),await proofGuardian.getAddress(),
  86400,172800,100000000000n,2000000000n,true,
 ]]);
 const proofReserveAddress=await proofReserve.getAddress();
 const proofReserveArtifact=await artifact('USDOMProofReserve.sol/USDOMProofReserve');
 const deployedConfig={
  ethereumChainId:'31337',reserve:proofReserveAddress,
  token:await proofReserve.token(),tokenCodeHash:await proofReserve.tokenCodeHash(),
  verifier:await proofReserve.verifier(),verifierCodeHash:await proofReserve.verifierCodeHash(),
  verifierConfigHash:await proofReserve.verifierConfigHash(),
  checkpointRegistry:await proofReserve.checkpointRegistry(),
  checkpointRegistryRuntimeCodeHash:await proofReserve.checkpointRegistryCodeHash(),
  checkpointRegistryConfigHash:await proofReserve.checkpointRegistryConfigHash(),
  domDomain:await proofReserve.domDomain(),
  activationScheduleCommitment:await proofReserve.activationScheduleCommitment(),
  governance:await proofReserve.governance(),
  governanceCodeHash:await proofReserve.governanceCodeHash(),
  governanceImplementation:await proofReserve.governanceImplementation(),
  governanceImplementationCodeHash:await proofReserve.governanceImplementationCodeHash(),
  governanceOwnersCommitment:await proofReserve.governanceOwnersCommitment(),
  guardian:await proofReserve.guardian(),guardianCodeHash:await proofReserve.guardianCodeHash(),
  guardianImplementation:await proofReserve.guardianImplementation(),
  guardianImplementationCodeHash:await proofReserve.guardianImplementationCodeHash(),
  guardianOwnersCommitment:await proofReserve.guardianOwnersCommitment(),
  withdrawalDelaySeconds:await proofReserve.withdrawalDelay(),
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
  proofSystem:'risc0-groth16-v3',trustedSetupRequired:true,
  trustedSetupTranscriptSha256:keccak256(toUtf8Bytes('RISC Zero Groth16 ceremony evidence')),
  ethereumChainId:'31337',riscZeroVerifier:riscZeroAddress,riscZeroVerifierCodeHash:riscZeroCodeHash,
  finalizedBurnGuestImageId:finalizedImageId,
 });
 const checkpointVerifierConfig=await fillManifest('checkpoint-verifier.unconfigured.json',{
  domNetworkMagic:'2712847316',firstV4Height:'100000',trustedSetupRequired:true,
  checkpointStatementTypeHash:CHECKPOINT_STATEMENT_TYPEHASH,
  proofAcceptedHash:CHECKPOINT_PROOF_ACCEPTED_HASH,
  segmentStateDomainHash:CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,
  segmentTransitionDomainHash:CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
  randomxStatementDomainHash:CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
  trustedSetupTranscriptSha256:keccak256(toUtf8Bytes('RISC Zero Groth16 ceremony evidence')),
  ethereumChainId:'31337',riscZeroVerifier:riscZeroAddress,
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
 assert.equal(derivedFinalizedAdapter.runtimeSize,
  (await provider.getCode(await finalizedAdapter.getAddress())).slice(2).length/2);
 assert.equal(derivedCheckpointAdapter.runtimeSize,
  (await provider.getCode(await checkpointAdapter.getAddress())).slice(2).length/2);
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
 const submissionVerifierConfig={...checkpointVerifierConfig,
  activationScheduleCommitment,domNetworkMagic:'2712847316',domChainId:checkpointDomChainId,
  firstV4Height:'101',activationEmptyStateRoot:initialStateRoot,checkpointInterval:'360',
  confirmationDepth:'30',challengePeriod:'86400',maxCheckpointSpan:'390',
  checkpointGuestImageId:CHECKPOINT_OUTER_IMAGE_ID,
 };
 await (await checkpointVerifier.setConfigHash(
  checkpointVerifierConfigHash(submissionVerifierConfig).verifierConfigHash,
 )).wait();
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
  guardianCodeHash:await checkpointRegistry.guardianCodeHash(),
  guardianImplementation:await checkpointRegistry.guardianImplementation(),
  guardianImplementationCodeHash:await checkpointRegistry.guardianImplementationCodeHash(),
  guardianOwnersCommitment:await checkpointRegistry.guardianOwnersCommitment(),
  initialHeight:'100',initialBlock,initialStateRoot,
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
  totalIssued:'1000000',totalBurned:'1000',issuanceClosed:false,
  confirmationHeight:'490',confirmationBlock:keccak256(toUtf8Bytes('LOCAL CONFIRMATION DOM BLOCK')),
  confirmationTotalDifficulty:'1000390',confirmationTimestamp:now.toString()};
 const checkpointProof='0x73c457ba'+'01'.repeat(256);
 const checkpointHash=checkpointStatementHash(checkpointConfiguration,checkpoint);
 assert.equal(await checkpointRegistry.checkpointStatementHash(checkpoint),checkpointHash);
 await (await checkpointVerifier.approve(checkpointHash,checkpointProof)).wait();
 const checkpointStatement=encodeCheckpointStatementV6(checkpointConfiguration,checkpoint);
 const checkpointProofBytes=Buffer.from(checkpointProof.slice(2),'hex');
 const rawSha=value=>createHash('sha256').update(value).digest('hex');
 const checkpointProofIndex=Buffer.from(JSON.stringify({
  schema:'usdom-checkpoint-outer-evm-proof-v1',
  outer_receipt_index_path:
   'evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json',
  outer_receipt_index_sha256:'41'.repeat(32),outer_image_id:CHECKPOINT_OUTER_IMAGE_ID.slice(2),
  statement_hash:checkpointHash.slice(2),journal_digest:sha256(checkpointHash).slice(2),
  risc0_zkvm_version:'3.0.6',receipt_kind:'groth16',
  groth16_verifier_parameters:CHECKPOINT_GROTH16_VERIFIER_PARAMETERS.slice(2),
  evm_verifier_selector:'73c457ba',groth16_receipt_file:'checkpoint-outer-groth16-receipt.bin',
  groth16_receipt_sha256:'42'.repeat(32),groth16_receipt_bytes:1024,
  evm_seal_file:'checkpoint-outer-evm-seal.bin',evm_seal_sha256:rawSha(checkpointProofBytes),
  evm_seal_bytes:checkpointProofBytes.length,receipt_verified:true,dev_mode:false,
  generates_proofs:true,mines:false,
 },null,2)+'\n');
 const submission=buildAuthenticatedCheckpointSubmission({
  registryConfiguration:checkpointConfiguration,verifierConfiguration:submissionVerifierConfig,
  statement:checkpointStatement,proofIndex:checkpointProofIndex,evmSeal:checkpointProofBytes,
  releaseConfigSha256:'43'.repeat(32),
 });
 const localVerification=await verifyAuthenticatedCheckpointSubmissionOnEvm(provider,submission);
 assert.equal(localVerification.callAccepted,true);
 assert.equal(localVerification.statementHash,checkpointHash);
 await assert.rejects(verifyAuthenticatedCheckpointSubmissionOnEvm(provider,{
  ...submission,proof:{...submission.proof,selector:'0x01020304'},
 }));
 await assert.rejects(verifyAuthenticatedCheckpointSubmissionOnEvm(provider,{
  ...submission,data:submission.data.slice(0,-2)+(submission.data.endsWith('00')?'01':'00'),
 }));
 const candidateReceipt=await (await funder.sendTransaction({
  to:submission.to,data:submission.data,value:0n,
 })).wait();
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
