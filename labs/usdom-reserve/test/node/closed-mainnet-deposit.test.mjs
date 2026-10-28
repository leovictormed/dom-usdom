import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Interface,Wallet,getAddress} from 'ethers';
import {
  CLOSED_MAINNET_DEPOSIT_AMOUNT,buildClosedMainnetDepositPackage,
  validateClosedMainnetDepositPackage,validateNativeReceivingWalletPublic,
} from '../../sdk/closed-mainnet-deposit.mjs';
import {proofReserveDeploymentConfigHash} from '../../sdk/configuration.mjs';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {CLOSED_DEPOSIT_MAX_FEE_PER_GAS,CLOSED_DEPOSIT_PRIORITY_FEE_PER_GAS,
  validateClosedMainnetDepositRawTransaction} from '../../sdk/closed-mainnet-deposit-execution.mjs';
import {buildPilotFundsSnapshot,pilotFundsSnapshotCommitment,pilotFundsAuthorizationDigest,pilotFundsReleaseId}
  from '../../sdk/pilot-funds-authorization.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';

const hash=byte=>'0x'+byte.toString(16).padStart(2,'0').repeat(32);
const raw=byte=>byte.toString(16).padStart(2,'0').repeat(32);
const tokenInterface=new Interface(['function approve(address spender,uint256 amount) returns (bool)']);
const reserveInterface=new Interface([
  'function deposit(uint64 amount,bytes32 salt,bytes32 receivingCommitment) returns (bytes32)',
]);
const testFunderWallet=new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123');

const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
function fixture(reserve='0x0000000000000000000000000000000000000020') {
  const configuration={
    ethereumChainId:'1',reserve,
    token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',tokenCodeHash:hash(21),
    verifier:'0x0000000000000000000000000000000000000021',verifierCodeHash:hash(22),
    verifierConfigHash:hash(23),
    checkpointRegistry:'0x0000000000000000000000000000000000000024',
    checkpointRegistryRuntimeCodeHash:hash(28),checkpointRegistryConfigHash:hash(29),
    domDomain:hash(24),activationScheduleCommitment:hash(25),
    governance:'0x0000000000000000000000000000000000000022',governanceCodeHash:hash(26),
    governanceImplementation:'0x0000000000000000000000000000000000000022',
    governanceImplementationCodeHash:hash(26),
    governanceOwnersCommitment:hash(36),
    guardian:'0x0000000000000000000000000000000000000023',guardianCodeHash:hash(27),
    guardianImplementation:'0x0000000000000000000000000000000000000023',
    guardianImplementationCodeHash:hash(27),
    guardianOwnersCommitment:hash(37),
    withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',
    maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'1000000',
  };
  const release={...configuration,
    reserveConfigHash:proofReserveDeploymentConfigHash(configuration).reserveConfigHash,
    productionReady:true,realFundsAuthorized:false,
    governanceOwners:['0x0000000000000000000000000000000000000101','0x0000000000000000000000000000000000000102','0x0000000000000000000000000000000000000103'],
    guardianOwners:['0x0000000000000000000000000000000000000111','0x0000000000000000000000000000000000000112','0x0000000000000000000000000000000000000113'],
    checkpointGuardianOwners:['0x0000000000000000000000000000000000000121','0x0000000000000000000000000000000000000122','0x0000000000000000000000000000000000000123'],
  };
  const chain=raw(2),owner=raw(3),scan=raw(4);
  const wallet={
    schema:'usdom-native-receiving-wallet-public-v1',domDomain:configuration.domDomain,
    privacyPolicyHash:hash(5),chainScalar:'0x'+chain,receivingCommitment:'0x'+owner,
    recipientAddress:Buffer.concat([
      Buffer.from('USDADR01','ascii'),Buffer.from(chain,'hex'),Buffer.from(owner,'hex'),
      Buffer.from(scan,'hex'),
    ]).toString('hex'),
  };
  const releaseBytes=Buffer.from(JSON.stringify(release));
  const walletBytes=Buffer.from(JSON.stringify(wallet));
  const releaseConfigSha256=sha256(releaseBytes),walletIdentitySha256=sha256(walletBytes);
  const pilotFundsSnapshot=buildPilotFundsSnapshot({releaseConfig:release,releaseConfigSha256,deploymentPackageSha256:raw(44),safeControlBundleSha256:raw(45),nativePrivacyInstallationSha256:raw(46),checkpointCapacityEvidenceSha256:raw(47),finalizedBurnCapacityEvidenceSha256:raw(48),operationalGasEvidenceSha256:raw(49),residualRiskDraftSha256:raw(50),pilotDepositBaseUnits:'1000000',funder:testFunderWallet.address,salt:hash(41),receivingCommitment:wallet.receivingCommitment,planSha256:raw(60),phaseCatalogSha256:raw(61),releaseValidationReportSha256:raw(62)});
  const snapshotCommitment=pilotFundsSnapshotCommitment(pilotFundsSnapshot);
  const authorization={schema:'usdom-pilot-funds-authorization/v1',snapshotCommitment,releaseId:pilotFundsReleaseId(snapshotCommitment),validAfter:'1000',validUntil:'2000',governance:release.governance,pilotDepositBaseUnits:'1000000',funder:pilotFundsSnapshot.funder,salt:pilotFundsSnapshot.salt,receivingCommitment:pilotFundsSnapshot.receivingCommitment,nonce:hash(52),signature:'0x1234'};
  const digest=pilotFundsAuthorizationDigest(authorization,release),rpcConsensus=rpcConsensusEvidence([{sourceId:'a',originKeccak256:hash(53)},{sourceId:'b',originKeccak256:hash(54)}]);
  const pilotFundsAuthorizationState={schema:'usdom-pilot-funds-authorization-state/v1',authorization,digest,consumed:false,finalizedObservation:{chainId:'1',governance:release.governance,governanceCodeHash:release.governanceCodeHash,finalizedBlockHash:hash(55),finalizedBlockNumber:'99',snapshotBlockHashAfter:hash(55),finalizedBlockTimestamp:'1500',rpcConsensus,approvals:{pilotFundsAuthorization:{digest,valid:true}}}};
  const pilotFundsSnapshotBytes=Buffer.from(JSON.stringify(pilotFundsSnapshot));
  const pilotFundsAuthorizationStateBytes=Buffer.from(JSON.stringify(pilotFundsAuthorizationState));
  return {release,wallet,funder:testFunderWallet.address,salt:hash(41),pilotFundsSnapshot,pilotFundsAuthorizationState,
    releaseConfigSha256,walletIdentitySha256,expectedPrivacyPolicyHash:hash(5),releaseBytes,
    releaseSha256:releaseConfigSha256,walletBytes,walletSha256:walletIdentitySha256,
    pilotFundsSnapshotBytes,pilotFundsSnapshotSha256:sha256(pilotFundsSnapshotBytes),
    pilotFundsAuthorizationStateBytes,
    pilotFundsAuthorizationStateSha256:sha256(pilotFundsAuthorizationStateBytes)};
}

test('closed mainnet deposit package fixes one USDT and exact three-step calldata',()=>{
  const f=fixture();
  const value=buildClosedMainnetDepositPackage(f);
  assert.equal(validateClosedMainnetDepositPackage(value),value);
  assert.equal(value.amountBaseUnits,CLOSED_MAINNET_DEPOSIT_AMOUNT.toString());
  assert.equal(value.broadcastAuthorized,false);
  assert.equal(value.transactions.length,3);
  assert.deepEqual([...tokenInterface.decodeFunctionData('approve',value.transactions[0].data)],
    [getAddress(value.reserve),0n]);
  assert.deepEqual([...tokenInterface.decodeFunctionData('approve',value.transactions[1].data)],
    [getAddress(value.reserve),CLOSED_MAINNET_DEPOSIT_AMOUNT]);
  assert.deepEqual([...reserveInterface.decodeFunctionData('deposit',value.transactions[2].data)],
    [CLOSED_MAINNET_DEPOSIT_AMOUNT,f.salt,f.wallet.receivingCommitment]);
});

test('wallet identity rejects substitutions in every encoded public component',()=>{
  for(const mutate of [
    wallet=>{wallet.recipientAddress='00'+wallet.recipientAddress.slice(2);},
    wallet=>{wallet.recipientAddress=wallet.recipientAddress.slice(0,80)+raw(6)
      +wallet.recipientAddress.slice(144);},
    wallet=>{wallet.recipientAddress=wallet.recipientAddress.slice(0,144)+'00'.repeat(32);},
    wallet=>{wallet.receivingCommitment=hash(7);},
    wallet=>{wallet.extra=true;},
  ]) {
    const {wallet}=fixture(); mutate(wallet);
    assert.throws(()=>validateNativeReceivingWalletPublic(wallet));
  }
});

test('closed mainnet package rejects metadata, authorization and calldata substitutions',()=>{
  const original=buildClosedMainnetDepositPackage(fixture());
  for(const mutate of [
    value=>{value.amountBaseUnits='2000000';},
    value=>{value.broadcastAuthorized=true;},
    value=>{value.releaseConfigSha256='AA'.repeat(32);},
    value=>{value.reserveConfigHash=hash(0);},
    value=>{value.salt=hash(44);},
    value=>{value.depositId=hash(45);},
    value=>{value.receivingCommitment=hash(46);},
    value=>{value.recipientAddress='00'+value.recipientAddress.slice(2);},
    value=>{value.transactions.reverse();},
    value=>{value.transactions[0].data+='00';},
    value=>{value.transactions[1].data=tokenInterface.encodeFunctionData('approve',[
      value.reserve,2_000_000n,
    ]);},
    value=>{value.transactions[2].data=reserveInterface.encodeFunctionData('deposit',[
      CLOSED_MAINNET_DEPOSIT_AMOUNT,value.salt,hash(47),
    ]);},
    value=>{value.transactions[0].extra=true;},
    value=>{value.extra=true;},
    value=>{value.transactions={length:3};},
  ]) {
    const value=structuredClone(original); mutate(value);
    assert.throws(()=>validateClosedMainnetDepositPackage(value));
  }
});

test('construction is gated by exact production release and wallet domain',()=>{
  for(const mutate of [
    f=>{f.releaseConfigSha256=raw(99);},
    f=>{f.release.productionReady=false;},
    f=>{f.release.realFundsAuthorized=true;},
    f=>{f.release.ethereumChainId='31337';},
    f=>{f.wallet.domDomain=hash(48);},
    f=>{f.wallet.privacyPolicyHash=hash(48);},
    f=>{f.expectedPrivacyPolicyHash=hash(48);},
    f=>{f.release.maxOutstandingBaseUnits='999999';},
    f=>{f.release.outflowCapacityBaseUnitsPerDay='999999';},
    f=>{f.releaseConfigSha256='0x'+raw(49);},
  ]) {
    const f=fixture(); mutate(f);
    assert.throws(()=>buildClosedMainnetDepositPackage(f));
  }
});

test('deposit preparation snapshots and binds the native privacy policy manifest',()=>{
  const source=readFileSync(new URL('../../scripts/prepare-closed-mainnet-deposit.mjs',import.meta.url),'utf8');
  assert.match(source,/requirementsPath='config\/production-requirements\.json'/);
  assert.match(source,/expectedPrivacyPolicyHash:`0x\$\{requirements\.native_privacy_policy_hash\}`/);
  assert.match(source,/currentRequirementsBytes\.equals\(requirementsBytes\)/);
});

test('closed deposit raw validator binds each zero-value hardware transaction',async()=>{
  const wallet=testFunderWallet;
  const input=fixture();
  const packageValue=buildClosedMainnetDepositPackage(input),expected=packageValue.transactions[1];
  const tx={type:2,chainId:1,nonce:9,to:expected.to,value:0,data:expected.data,gasLimit:100000n,
    maxFeePerGas:10_000_000_000n,maxPriorityFeePerGas:CLOSED_DEPOSIT_PRIORITY_FEE_PER_GAS,accessList:[]};
  const raw=await wallet.signTransaction(tx);
  assert.equal(validateClosedMainnetDepositRawTransaction({raw,packageValue,index:1,nonce:'9',...input}).value,'0');
  assert.throws(()=>validateClosedMainnetDepositRawTransaction({raw,packageValue,index:1,...input,
    nonce:'9'.repeat(100000)}),/nonce is invalid/);
  assert.throws(()=>validateClosedMainnetDepositRawTransaction({raw,packageValue,index:1,...input,
    nonce:(1n<<64n).toString()}),/exceeds uint64/);
  for(const changed of [{...tx,value:1},{...tx,chainId:31337},{...tx,nonce:10},{...tx,to:wallet.address},
    {...tx,data:'0x'}, {...tx,maxFeePerGas:CLOSED_DEPOSIT_MAX_FEE_PER_GAS+1n}]) {
    const changedRaw=await wallet.signTransaction(changed);
    assert.throws(()=>validateClosedMainnetDepositRawTransaction({raw:changedRaw,packageValue,index:1,
      nonce:'9',...input}));
  }
});

test('deposit raw validator rejects coordinated package and raw B under upstream authority A',async()=>{
  const authorityA=fixture(),inputB=fixture('0x0000000000000000000000000000000000000030');
  const packageB=buildClosedMainnetDepositPackage(inputB),expected=packageB.transactions[2];
  const rawB=await testFunderWallet.signTransaction({type:2,chainId:1,nonce:9,to:expected.to,
    value:0,data:expected.data,gasLimit:100000n,maxFeePerGas:10_000_000_000n,
    maxPriorityFeePerGas:CLOSED_DEPOSIT_PRIORITY_FEE_PER_GAS,accessList:[]});
  assert.throws(()=>validateClosedMainnetDepositRawTransaction({raw:rawB,packageValue:packageB,
    index:2,nonce:'9',...authorityA}),/differs from authenticated upstream authority/);
});

test('closed deposit executor separates sign, validate, publish and output-last evidence',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s node scripts\/install-private-file-new-stdin\.mjs/g)??[]).length,8);
  assert.equal((source.match(/node scripts\/install-private-file-new-stdin\.mjs/g)??[]).length,9);
  assert.match(source,/check-pilot-funds-consumption\.mjs/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s node scripts\/check-private-strict-json-file\.mjs/g)??[]).length,11);
  assert.equal((source.match(/node scripts\/check-private-strict-json-file\.mjs/g)??[]).length,11);
  assert.match(source,/check_rpc_transaction_binding/);
  assert.match(source,/\.input\|ascii_downcase\)==\(\$input\[0\]\.data\|ascii_downcase\) and \.value=="0x0"/);
  assert.match(source,/\{transactionHash,status,from,to,blockNumber,blockHash,transactionIndex,logs\}/);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-mainnet-toolchain\.mjs >\/dev\/null/);
  assert.match(source,/check-mainnet-readiness\.mjs real-funds/);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-closed-mainnet-deposit-package\.mjs "\$package" >\/dev\/null/);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 300s \\\n\s+node scripts\/check-mainnet-readiness\.mjs real-funds \| head -c 1048577 >"\$gate"/);
  assert.match(source,/test "\$\(stat_run -c '%s' "\$gate"\)" -le 1048576/);
  assert.match(source,/check-private-strict-json-file\.mjs "\$gate"/);
  assert.match(source,/AUTORIZO ASSINAR DEPOSITO ETAPA \$index AUTH \$authorization_hash/);
  assert.match(source,/check-closed-mainnet-deposit-raw\.mjs/);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-closed-mainnet-deposit-raw\.mjs "\$@" \| head -c 1048577 >"\$destination"/);
  assert.match(source,/test "\$\(stat_run -c '%s' "\$destination"\)" -le 1048576/);
  assert.match(source,/check-private-strict-json-file\.mjs "\$destination"/);
  assert.equal((source.match(/write_deposit_validation "\$(?:recovered_validation|candidate)"/g)??[]).length,2);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-closed-mainnet-deposit-raw\.mjs/g)??[]).length,3);
  assert.match(source,/AUTORIZO TRANSMITIR DEPOSITO ETAPA \$index TX \$expected_hash/);
  assert.ok(source.indexOf('check-closed-mainnet-deposit-raw.mjs')<source.indexOf('publish-private-raw-transaction.mjs'));
  assert.match(source,/allowance\(address,address\)\(uint256\)/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast call/g)??[]).length,0);
  assert.equal((source.match(/cast call/g)??[]).length,3);
  assert.equal((source.match(/rpc_uint_call /g)??[]).length,22);
  assert.equal((source.match(/rpc_bool_call /g)??[]).length,2);
  assert.match(source,/cast call "\$@" \| head -c 80/);
  assert.match(source,/cast call "\$@" \| head -c 8/);
  assert.match(source,/case \$value in true\|false\) ;; \*\) return 1 ;; esac/);
  assert.equal((source.match(/rpc_tuple_call /g)??[]).length,2);
  assert.match(source,/cast call "\$@" \| head -c 1025/);
  assert.match(source,/\(\(\$\{#record_fields\[@\]\} == 3\)\)/);
  assert.equal(source.includes('cast gas-price'),false);
  const castLines=source.split('\n');
  assert.deepEqual(castLines.flatMap((line,index)=>line.includes('cast ')&&!line.includes('cast rpc eth_estimateGas')&&!line.includes('cast wallet sign --no-hash')&&!line.trimStart().startsWith('#')&&!castLines.slice(index,index+3).join(' ').includes('head -c ')?[index+1]:[]),[]);
  assert.equal((source.match(/sha256sum/g)??[]).length,1);
  assert.equal((source.match(/sha256_file /g)??[]).length,5);
  assert.match(source,/sha256sum -- "\$path" \| head -c 66/);
  assert.match(source,/test "\$before" = "\$after"/);
  assert.equal((source.match(/node -e/g)??[]).length,1);
  assert.equal((source.match(/node_eval /g)??[]).length,22);
  assert.match(source,/node -e "\$@" \| head -c 161/);
  assert.equal((source.match(/cmp -s/g)??[]).length,1);
  assert.equal((source.match(/cmp_exact /g)??[]).length,3);
  assert.match(source,/120s cmp -s -- "\$@"/);
  assert.equal((source.match(/\bjq\b/g)??[]).length,1);
  assert.equal((source.match(/jq_run /g)??[]).length,84);
  assert.match(source,/value=\$\(timeout --foreground --signal=TERM --kill-after=5s 120s jq "\$@" \| head -c 1048577\)/);
  assert.match(source,/\(\( \$\{#value\} <= 1048576 \)\)/);
  assert.equal((source.match(/\bstat\b/g)??[]).length,1);
  assert.equal((source.match(/stat_run /g)??[]).length,37);
  assert.match(source,/\[\[ -d \$evidence && ! -L \$evidence \]\]/);
  assert.match(source,/realpath -e \/proc\/\$\$\/fd\/9/);
  assert.match(source,/stat_run -Lc '%u:%a' -- \/proc\/\$\$\/fd\/9\)" = "\$UID:700"/);
  assert.match(source,/stat_run -c '%d:%i' -- "\$evidence"[\s\S]*stat_run -Lc '%d:%i' -- \/proc\/\$\$\/fd\/9/);
  assert.equal((source.match(/read_deployment_hash "\$evidence\/contract-deployment-[01]-submission-hash\.txt"/g)??[]).length,2);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s tr -d '\\n' <"\$path" \| head -c 67/g)??[]).length,1);
  assert.doesNotMatch(source,/=\$\(tr -d '\\n' < "\$evidence\/contract-deployment-/);
  assert.equal((source.match(/mktemp/g)??[]).length,1);
  assert.equal((source.match(/private_tmpdir /g)??[]).length,1);
  assert.match(source,/120s stat "\$@" \| head -c 257/);
  assert.match(source,/isBlackListed\(address\)\(bool\)/);
  assert.match(source,/refresh_consensus_block/);
  assert.match(source,/hash1=.*cast block "\$consensus_block"/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast block/g)??[]).length,16);
  assert.equal((source.match(/cast block/g)??[]).length,17);
  assert.equal((source.match(/cast block[^\n]+--field hash[^\n]+\| tr '\[:upper:\]' '\[:lower:\]' \| head -c 68/g)??[]).length,5);
  assert.equal((source.match(/--field baseFeePerGas/g)??[]).length,6);
  assert.equal(source.split('--field baseFeePerGas').slice(1).filter(part=>part.slice(0,160).includes('| head -c 80')).length,6);
  assert.equal((source.match(/is_canonical_rpc_uint "\$(?:base|live_base)[12]"/g)??[]).length,6);
  assert.match(source,/\^\(0\|\[1-9\]\[0-9\]\*\|0x0\|0x\[1-9a-f\]\[0-9a-f\]\*\)\$/);
  assert.match(source,/\[\[ \$hash1 =~ \^0x\[0-9a-f\]\{64\}\$ && \$hash2 =~ \^0x\[0-9a-f\]\{64\}\$ \]\]/);
  assert.match(source,/test "\$hash1" = "\$hash2"/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast chain-id --rpc-url "\$1" \| head -c 80/g)??[]).length,1);
  assert.equal((source.match(/require_mainnet_chain_id "\$rpc"/g)??[]).length,4);
  assert.match(source,/expected_next_nonce=\$\(node_eval/);
  assert.match(source,/read_nonce "\$funder" pending "\$rpc"\)" = "\$expected_next_nonce"/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast block finalized --field number/g)??[]).length,4);
  assert.equal((source.match(/cast block finalized --field number/g)??[]).length,5);
  assert.equal((source.match(/cast block finalized --field number[^\n]+\| head -c 80/g)??[]).length,5);
  assert.equal((source.match(/is_canonical_rpc_uint "\$(?:finalized1|finalized2|finalized_number)"/g)??[]).length,5);
  assert.match(source,/prepare-private-eth-estimate-gas\.mjs "\$private_input" "\$funder"/);
  assert.equal((source.match(/cast rpc eth_estimateGas --raw --rpc-url "\$rpc[12]"/g)??[]).length,2);
  assert.doesNotMatch(source,/cast estimate "\$to" "\$data"|cast mktx[^\n]*--data "\$data"/);
  assert.equal((source.match(/is_canonical_rpc_uint "\$estimate[12]"/g)??[]).length,2);
  assert.match(source,/closed-mainnet-deposit-execution\.json/);
  assert.match(source,/Earlier receipts authenticate history/);
  assert.match(source,/test ! -L "\$receipt_record"/);
  assert.doesNotMatch(source,/cast send|cast publish|--private-key|--mnemonic|USDOM_CLOSED_MAINNET_DEPOSIT_RAW=/);
});

test('deposit package and raw gates use strict direct input and fail with nonzero status',()=>{
  const directory=mkdtempSync(join(tmpdir(),'usdom-deposit-check-'));
  try {
    const packagePath=join(directory,'package.json');
    const value=buildClosedMainnetDepositPackage(fixture());
    writeFileSync(packagePath,JSON.stringify(value),{mode:0o600});
    const packageChecker=new URL('../../scripts/check-closed-mainnet-deposit-package.mjs',import.meta.url).pathname;
    const valid=spawnSync(process.execPath,[packageChecker,packagePath],{encoding:'utf8'});
    assert.equal(valid.status,0,valid.stderr);
    assert.deepEqual(JSON.parse(valid.stdout),value);
    writeFileSync(packagePath,JSON.stringify(value).replace('{','{"schema":"ambiguous",'),{mode:0o600});
    const duplicate=spawnSync(process.execPath,[packageChecker,packagePath],{encoding:'utf8'});
    assert.notEqual(duplicate.status,0); assert.equal(duplicate.stdout,'');
    assert.doesNotMatch(duplicate.stderr,/ambiguous/);

    const rawChecker=new URL('../../scripts/check-closed-mainnet-deposit-raw.mjs',import.meta.url).pathname;
    const rawRejected=spawnSync(process.execPath,[rawChecker,packagePath,'1','9'],{encoding:'utf8'});
    assert.notEqual(rawRejected.status,0); assert.equal(rawRejected.stdout,'');
    const source=readFileSync(rawChecker,'utf8');
    assert.match(source,/readDirectFile/); assert.match(source,/parseStrictJsonBytes/);
    assert.match(source,/process\.exitCode=1/); assert.doesNotMatch(source,/readFileSync|JSON\.parse/);
  } finally { rmSync(directory,{recursive:true,force:true}); }
});
