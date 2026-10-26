import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {
  ContractFactory,JsonRpcProvider,keccak256,sha256,toUtf8Bytes,
} from 'ethers';
import {
  FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS,FINALIZED_BURN_IMAGE_ID,
  buildAuthenticatedFinalizedBurnSubmission,verifyAuthenticatedFinalizedBurnSubmissionOnEvm,
} from '../../sdk/finalized-burn-submission.mjs';
import {finalizedBurnStatementHash} from '../../sdk/proof-reserve.mjs';
import {
  FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,finalizedBurnVerifierConfigHash,
} from '../../sdk/verifier-config.mjs';
import {pinnedAnvil} from './helpers/pinned-anvil.mjs';

const artifact=async name=>JSON.parse(await readFile(new URL(`../../out/${name}.json`,import.meta.url)));
const rawSha=value=>createHash('sha256').update(value).digest('hex');
const canonicalCommitment=entropy=>{
  const field=0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
  return '0x'+(BigInt(entropy)%(field-1n)+1n).toString(16).padStart(64,'0');
};

test('authenticated DOM burn package completes local deposit, queue and redemption',
  {timeout:90000},async t=>{
    const child=spawn(await pinnedAnvil(),[
      '--host','127.0.0.1','--port','18546','--chain-id','31337','--silent',
    ],{stdio:'ignore'});
    let spawnError; child.on('error',error=>{spawnError=error;});
    const provider=new JsonRpcProvider('http://127.0.0.1:18546',31337,{
      staticNetwork:true,cacheTimeout:-1,
    });
    t.after(async()=>{provider.destroy();child.kill('SIGTERM');});
    for(let index=0;;index++) {
      try { await provider.send('eth_chainId',[]); break; }
      catch(error) {
        if(spawnError) throw spawnError;
        if(child.exitCode!==null) throw new Error(`Anvil exited before readiness: ${child.exitCode}`);
        if(index===300) throw error;
        await delay(100);
      }
    }
    const funder=await provider.getSigner(0);
    const recipient=await provider.getSigner(2);
    const deploy=async(name,args=[])=>{
      const compiled=await artifact(name);
      const contract=await new ContractFactory(compiled.abi,compiled.bytecode.object,funder).deploy(...args);
      await contract.waitForDeployment();
      return contract;
    };
    const token=await deploy('Mocks.sol/HostileToken');
    const safeSingleton=await deploy('Mocks.sol/MockGovernance');
    const governance=await deploy('Mocks.sol/MockMutableSingletonControl',[await safeSingleton.getAddress()]);
    const guardian=await deploy('Mocks.sol/MockMutableSingletonControl',[await safeSingleton.getAddress()]);
    const riscZero=await deploy('DOMFinalizedBurnRiscZeroVerifier.t.sol/MockRiscZeroVerifierV3',[
      FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
    ]);
    const activationScheduleCommitment=keccak256(toUtf8Bytes('LOCAL AUTHENTICATED ACTIVATION'));
    const verifierTemplate=JSON.parse(await readFile(new URL(
      '../../config/finalized-burn-verifier.unconfigured.json',import.meta.url,
    ),'utf8'));
    for(const key of Object.keys(verifierTemplate)) {
      if(verifierTemplate[key]===null) verifierTemplate[key]=keccak256(toUtf8Bytes(`LOCAL ${key}`));
    }
    const verifierConfiguration=Object.assign(verifierTemplate,{
      activationScheduleCommitment,domNetworkMagic:'3669344250',firstV4Height:'1',
      minimumFinalityBeaconSlot:'1',proofSystem:'risc0-groth16-v3',trustedSetupRequired:true,
      trustedSetupTranscriptSha256:keccak256(toUtf8Bytes('RISC Zero Groth16 ceremony evidence')),
      ethereumChainId:'31337',
      riscZeroVerifier:await riscZero.getAddress(),
      riscZeroVerifierCodeHash:keccak256(await provider.getCode(await riscZero.getAddress())),
      riscZeroVerifierSelector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
      finalizedBurnGuestImageId:FINALIZED_BURN_IMAGE_ID,
      provingProgramSha256:
        '0x883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21',
    });
    const adapter=await deploy('DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier',[
      await riscZero.getAddress(),FINALIZED_BURN_IMAGE_ID,
    ]);
    const domDomain=keccak256(toUtf8Bytes('LOCAL AUTHENTICATED DOM DOMAIN'));
    const checkpointRegistry=await deploy('Mocks.sol/MockGracefulShutdownRegistry',[
      domDomain,activationScheduleCommitment,
    ]);
    const reserve=await deploy('USDOMProofReserve.sol/USDOMProofReserve',[{
      token:await token.getAddress(),verifier:await adapter.getAddress(),
      checkpointRegistry:await checkpointRegistry.getAddress(),domDomain,
      activationScheduleCommitment,governance:await governance.getAddress(),guardian:await guardian.getAddress(),
      withdrawalDelay:86400,governanceDelay:172800,maxOutstanding:100_000_000_000n,
      outflowCapacity:2_000_000_000n,
    }]);
    const reserveConfiguration={
      ethereumChainId:'31337',reserve:await reserve.getAddress(),token:await token.getAddress(),
      tokenCodeHash:await reserve.tokenCodeHash(),verifier:await adapter.getAddress(),
      verifierCodeHash:await reserve.verifierCodeHash(),verifierConfigHash:await reserve.verifierConfigHash(),
      checkpointRegistry:await reserve.checkpointRegistry(),
      checkpointRegistryRuntimeCodeHash:await reserve.checkpointRegistryCodeHash(),
      checkpointRegistryConfigHash:await reserve.checkpointRegistryConfigHash(),domDomain,activationScheduleCommitment,governance:await governance.getAddress(),
      governanceCodeHash:await reserve.governanceCodeHash(),
      governanceImplementation:await reserve.governanceImplementation(),
      governanceImplementationCodeHash:await reserve.governanceImplementationCodeHash(),
      governanceOwnersCommitment:await reserve.governanceOwnersCommitment(),
      guardian:await guardian.getAddress(),guardianCodeHash:await reserve.guardianCodeHash(),
      guardianImplementation:await reserve.guardianImplementation(),
      guardianImplementationCodeHash:await reserve.guardianImplementationCodeHash(),
      guardianOwnersCommitment:await reserve.guardianOwnersCommitment(),
      withdrawalDelaySeconds:'86400',
      governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'100000000000',
      outflowCapacityBaseUnitsPerDay:'2000000000',
    };
    assert.equal(
      finalizedBurnVerifierConfigHash(verifierConfiguration).verifierConfigHash,
      reserveConfiguration.verifierConfigHash,
    );
    await (await token.mint(await funder.getAddress(),10_000_000_000n)).wait();
    await (await token.approve(await reserve.getAddress(),10_000_000_000n)).wait();
    await (await reserve.deposit(
      10_000_000_000n,keccak256(toUtf8Bytes('authenticated deposit')),
      canonicalCommitment(keccak256(toUtf8Bytes('private note commitment'))),
    )).wait();
    const now=BigInt((await provider.getBlock('latest')).timestamp);
    const finalityBeaconSlot=(now-1_606_824_023n)/12n;
    const burn={
      burnId:keccak256(toUtf8Bytes('authenticated native burn')),
      requestId:keccak256(toUtf8Bytes('authenticated reserve request')),
      recipient:await recipient.getAddress(),amount:'1000000',domDomain,height:'100360',
      blockHash:keccak256(toUtf8Bytes('authenticated DOM block')),
      stateRoot:keccak256(toUtf8Bytes('authenticated private USDOM state')),
      finalityBeaconSlot:finalityBeaconSlot.toString(),validUntil:(now+6n*86400n).toString(),
    };
    const statementHash=finalizedBurnStatementHash({
      chainId:'31337',reserve:await reserve.getAddress(),activationScheduleCommitment,burn,
    });
    const sourceInput=Buffer.from('local canonical UDFINL04 integration fixture');
    const sourceIndex=Buffer.from(JSON.stringify({
      schema:'usdom-finalized-burn-source-v3',network:'regtest',manifest_sha256:'31'.repeat(32),
      candidate_v2_first_height:1,burn_id:burn.burnId.slice(2),checkpoint_dom_height:100360,
      checkpoint_dom_block:burn.blockHash.slice(2),checkpoint_dom_state_root:burn.stateRoot.slice(2),
      checkpoint_ethereum_block_number:20000010,checkpoint_ethereum_block:'34'.repeat(32),
      checkpoint_beacon_slot:Number(finalityBeaconSlot),checkpoint_witness_sha256:'35'.repeat(32),
      statement_hash:statementHash.slice(2),burn,ethereum_chain_id:'31337',
      reserve:await reserve.getAddress(),activation_schedule_commitment:activationScheduleCommitment,
      input_file:'finalized-burn-input.bin',input_sha256:rawSha(sourceInput),input_length:sourceInput.length,
    },null,2)+'\n');
    const receiptIndex=Buffer.from(JSON.stringify({
      schema:'usdom-finalized-burn-receipt-v1',
      proof_job_index_path:'evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json',
      proof_job_index_sha256:'36'.repeat(32),
      input_path:'evidence/finalized-burn-proof-job/finalized-burn-input.bin',
      input_sha256:rawSha(sourceInput),statement_hash:statementHash.slice(2),
      program_path:'evidence/finalized-burn-guest/usdom-finalized-burn.elf',
      program_sha256:'883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21',
      image_id:FINALIZED_BURN_IMAGE_ID.slice(2),risc0_zkvm_version:'3.0.6',receipt_kind:'succinct',
      segment_limit_po2:18,receipt_file:'finalized-burn-receipt.bin',receipt_sha256:'37'.repeat(32),
      receipt_bytes:4096,relation_executed:true,receipt_verified:true,dev_mode:false,
      generates_proofs:true,mines:false,
    },null,2)+'\n');
    const evmSeal=Buffer.concat([
      Buffer.from(FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2),'hex'),Buffer.alloc(256,1),
    ]);
    const proofIndex=Buffer.from(JSON.stringify({
      schema:'usdom-finalized-burn-evm-proof-v1',
      receipt_index_path:'evidence/finalized-burn-receipt/finalized-burn-receipt-index.json',
      receipt_index_sha256:rawSha(receiptIndex),image_id:FINALIZED_BURN_IMAGE_ID.slice(2),
      statement_hash:statementHash.slice(2),journal_digest:sha256(statementHash).slice(2),
      risc0_zkvm_version:'3.0.6',receipt_kind:'groth16',
      groth16_verifier_parameters:FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS.slice(2),
      evm_verifier_selector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2),
      groth16_receipt_file:'finalized-burn-groth16-receipt.bin',
      groth16_receipt_sha256:'38'.repeat(32),groth16_receipt_bytes:1024,
      evm_seal_file:'finalized-burn-evm-seal.bin',evm_seal_sha256:rawSha(evmSeal),
      evm_seal_bytes:evmSeal.length,receipt_verified:true,dev_mode:false,generates_proofs:true,mines:false,
    },null,2)+'\n');
    const submission=buildAuthenticatedFinalizedBurnSubmission({
      reserveConfiguration,verifierConfiguration,sourceIndex,sourceInput,receiptIndex,proofIndex,evmSeal,
    });
    await (await riscZero.expect(
      evmSeal,FINALIZED_BURN_IMAGE_ID,sha256(statementHash),
    )).wait();
    const checked=await verifyAuthenticatedFinalizedBurnSubmissionOnEvm(provider,submission);
    assert.equal(checked.callAccepted,true);
    await (await funder.sendTransaction({to:submission.to,data:submission.data,value:0n})).wait();
    assert.equal(await reserve.totalPendingAmount(),1_000_000n);
    await provider.send('evm_increaseTime',[86400]);
    await provider.send('evm_mine',[]);
    await (await reserve.executeWithdrawal(burn)).wait();
    assert.equal(await token.balanceOf(await recipient.getAddress()),1_000_000n);
    assert.equal(await reserve.totalPendingAmount(),0n);
  });
