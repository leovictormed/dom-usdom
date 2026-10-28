import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Interface,Wallet,keccak256,sha256} from 'ethers';
import {buildClosedMainnetRedemptionPackage,validateClosedMainnetRedemptionPackage,
  validateClosedMainnetRedemptionRawTransaction,CLOSED_REDEMPTION_PRIORITY_FEE_PER_GAS}
  from '../../sdk/closed-mainnet-redemption-execution.mjs';
import {FINALIZED_BURN_IMAGE_ID,FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS}
  from '../../sdk/finalized-burn-submission.mjs';
import {finalizedBurnStatementHash} from '../../sdk/proof-reserve.mjs';

const h=n=>'0x'+n.toString(16).padStart(2,'0').repeat(32);
const tuple='(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil)';
const iface=new Interface([`function queueWithdrawal(${tuple},bytes)`,`function executeWithdrawal(${tuple})`]);
function fixture(recipient='0x0000000000000000000000000000000000000040') {
  const burn={burnId:h(1),requestId:h(2),recipient,amount:'1000000',domDomain:h(3),height:'4',
    blockHash:h(5),stateRoot:h(6),finalityBeaconSlot:'7',validUntil:'9999999999'};
  const proof='0x73c457ba'+'11'.repeat(256),data=iface.encodeFunctionData('queueWithdrawal',[burn,proof]);
  const activationScheduleCommitment=h(19);
  const statementHash=finalizedBurnStatementHash({chainId:'1',
    reserve:'0x0000000000000000000000000000000000000020',activationScheduleCommitment,burn});
  return {schema:'usdom-authenticated-finalized-burn-submission-v2',ethereumChainId:'1',
    to:'0x0000000000000000000000000000000000000020',value:'0',method:'queueWithdrawal',burn,
    proof:{selector:'0x73c457ba',bytes:260,sha256:(awaitHash(proof))},statementHash,
    journalDigest:sha256(statementHash),data,dataKeccak256:keccak256(data),source:{
      releaseConfigSha256:'11'.repeat(32),verifierManifestSha256:'12'.repeat(32),
      sourceIndexPath:'evidence/finalized-burn-source/finalized-burn-source-index.json',sourceIndexSha256:'13'.repeat(32),
      inputPath:'evidence/finalized-burn-source/finalized-burn-input.bin',inputSha256:'14'.repeat(32),
      receiptIndexPath:'evidence/finalized-burn-receipt/finalized-burn-receipt-index.json',receiptIndexSha256:'15'.repeat(32),
      proofIndexPath:'evidence/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json',proofIndexSha256:'16'.repeat(32),
      sealPath:'evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin',
      imageId:FINALIZED_BURN_IMAGE_ID,groth16VerifierParameters:FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS,
      activationScheduleCommitment,
    },broadcastAuthorized:false};
}
function awaitHash(hex) { return (awaitHash.crypto??=requireHash)(Buffer.from(hex.slice(2),'hex')); }
import {createHash} from 'node:crypto';
const requireHash=b=>createHash('sha256').update(b).digest('hex');

test('redemption fixes queue then execute for one USDOM with broadcast disabled',()=>{
  const submission=fixture(),value=buildClosedMainnetRedemptionPackage(submission);
  assert.equal(value.amountBaseUnits,'1000000'); assert.equal(value.broadcastAuthorized,false);
  assert.equal(value.token,'0xdAC17F958D2ee523a2206206994597C13D831ec7');
  assert.deepEqual(value.transactions.map(x=>x.name),['queue-withdrawal','execute-withdrawal']);
  assert.equal(validateClosedMainnetRedemptionPackage(value,submission),value);
  for(const mutate of [v=>v.transactions.reverse(),v=>v.broadcastAuthorized=true,
    v=>v.amountBaseUnits='2',v=>v.transactions[1].data='0x']) {
    const changed=structuredClone(value); mutate(changed);
    assert.throws(()=>validateClosedMainnetRedemptionPackage(changed,submission));
  }
});

test('raw validation binds nonce, chain, zero value, calldata and fee bounds',async()=>{
  const wallet=new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123');
  const submission=fixture(wallet.address);
  const value=buildClosedMainnetRedemptionPackage(submission),expected=value.transactions[0];
  const tx={type:2,chainId:1,nonce:9,to:expected.to,value:0,data:expected.data,gasLimit:500000n,
    maxFeePerGas:10_000_000_000n,maxPriorityFeePerGas:CLOSED_REDEMPTION_PRIORITY_FEE_PER_GAS,accessList:[]};
  const raw=await wallet.signTransaction(tx);
  assert.equal(validateClosedMainnetRedemptionRawTransaction({raw,packageValue:value,submission,index:0,nonce:'9'}).value,'0');
  assert.throws(()=>validateClosedMainnetRedemptionRawTransaction({raw,packageValue:value,index:0,
    submission,nonce:'9'.repeat(100000)}),/nonce is invalid/);
  assert.throws(()=>validateClosedMainnetRedemptionRawTransaction({raw,packageValue:value,index:0,
    submission,nonce:(1n<<64n).toString()}),/nonce is invalid/);
  for(const changed of [{...tx,value:1},{...tx,chainId:31337},{...tx,nonce:10},{...tx,data:'0x'}]) {
    const changedRaw=await wallet.signTransaction(changed);
    assert.throws(()=>validateClosedMainnetRedemptionRawTransaction({
      raw:changedRaw,packageValue:value,submission,index:0,nonce:'9',
    }));
  }
  const wrongSigner=new Wallet('0x1123456789012345678901234567890123456789012345678901234567890123');
  const wrongRaw=await wrongSigner.signTransaction(tx);
  assert.throws(()=>validateClosedMainnetRedemptionRawTransaction({
    raw:wrongRaw,packageValue:value,submission,index:0,nonce:'9',
  }));

  // A detached package and raw transaction that agree with each other must
  // still be rejected when recipient, destination, calldata and digest do not
  // reproduce the authenticated finalized-burn submission.
  const detached=structuredClone(value);
  detached.recipient=wrongSigner.address;
  detached.transactions[0].to=wrongSigner.address;
  detached.transactions[0].data='0x12345678';
  detached.transactions[0].dataKeccak256=keccak256(detached.transactions[0].data);
  const detachedRaw=await wrongSigner.signTransaction({...tx,to:wrongSigner.address,
    data:detached.transactions[0].data});
  assert.throws(()=>validateClosedMainnetRedemptionRawTransaction({
    raw:detachedRaw,packageValue:detached,submission,index:0,nonce:'9',
  }),/closed redemption package is not canonical/);
});

test('executor separates every signature/publication and finalizes across two RPCs',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s node scripts\/install-private-file-new-stdin\.mjs/g)??[]).length,6);
  assert.equal((source.match(/node scripts\/install-private-file-new-stdin\.mjs/g)??[]).length,12);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s node scripts\/check-private-strict-json-file\.mjs/g)??[]).length,8);
  assert.equal((source.match(/node scripts\/check-private-strict-json-file\.mjs/g)??[]).length,8);
  assert.match(source,/check_rpc_transaction_binding/);
  assert.match(source,/\.input\|ascii_downcase\)==\(\$input\[0\]\.data\|ascii_downcase\) and \.value=="0x0"/);
  assert.match(source,/\{transactionHash,status,from,to,blockNumber,blockHash,transactionIndex,logs\}/);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-mainnet-toolchain\.mjs >\/dev\/null/);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-closed-mainnet-redemption\.mjs "\$@" \| head -c 1048577 >"\$destination"/);
  assert.match(source,/test "\$\(stat_run -c '%s' "\$destination"\)" -le 1048576/);
  assert.match(source,/check-private-strict-json-file\.mjs "\$destination"/);
  assert.equal((source.match(/write_redemption_candidate "\$candidate"/g)??[]).length,1);
  assert.equal((source.match(/check-safe-redemption-relayer-raw\.mjs/g)??[]).length,4);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 300s \\\n\s+node scripts\/check-mainnet-readiness\.mjs real-funds \| head -c 1048577 >"\$readiness"/);
  assert.match(source,/test "\$\(stat_run -c '%s' "\$readiness"\)" -le 1048576/);
  assert.match(source,/check-private-strict-json-file\.mjs "\$readiness"/);
  assert.match(source,/AUTORIZO ASSINAR RESGATE ETAPA \$index AUTH \$authorization_hash/);
  assert.match(source,/AUTORIZO TRANSMITIR RESGATE ETAPA \$index TX \$expected_hash/);
  assert.match(source,/pendingWithdrawals\(bytes32\)/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast block finalized --field number/g)??[]).length,2);
  assert.equal((source.match(/cast block finalized --field number/g)??[]).length,2);
  assert.equal((source.match(/cast block finalized --field number[^\n]+\| head -c 80/g)??[]).length,2);
  assert.equal((source.match(/is_canonical_rpc_uint "\$number[12]"/g)??[]).length,2);
  assert.match(source,/paidBurns\(bytes32\)/); assert.match(source,/outputLast:true/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast call/g)??[]).length,0);
  assert.equal((source.match(/cast call/g)??[]).length,5);
  assert.equal((source.match(/rpc_uint_call /g)??[]).length,26);
  assert.match(source,/closed-redemption-\$index-broadcast-journal\.json/);
  assert.match(source,/usdom-closed-mainnet-redemption-broadcast-journal-v1/);
  assert.ok(source.indexOf('broadcast_journal="$evidence/closed-redemption-$index-broadcast-journal.json"') < source.indexOf('publish-private-raw-transaction.mjs'));
  assert.match(source,/live_safe_nonce1=.*nonce\(\)\(uint256\)/);
  assert.match(source,/cmp_exact "\$live_safe_plan" "\$safe_plan"/);
  assert.equal((source.match(/rpc_bool_call /g)??[]).length,10);
  assert.match(source,/cast call "\$@" \| head -c 80/);
  assert.match(source,/cast call "\$@" \| head -c 8/);
  assert.match(source,/case \$value in true\|false\) ;; \*\) return 1 ;; esac/);
  assert.equal((source.match(/rpc_address_call /g)??[]).length,3);
  assert.match(source,/cast call "\$@" \| head -c 44/);
  assert.match(source,/\[\[ \$value =~ \^0x\[0-9a-fA-F\]\{40\}\$ \]\]/);
  assert.equal((source.match(/rpc_bytes32_call /g)??[]).length,6);
  assert.match(source,/cast call "\$@" \| head -c 68/);
  assert.match(source,/\[\[ \$value =~ \^0x\[0-9a-fA-F\]\{64\}\$ \]\]/);
  assert.equal((source.match(/rpc_tuple_call /g)??[]).length,2);
  assert.match(source,/cast call "\$@" \| head -c 1025/);
  assert.match(source,/\(\(\$\{#pending_fields\[@\]\} == 8\)\)/);
  assert.match(source,/mainnet_genesis=0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3/);
  assert.match(source,/test "\$number1" = "\$number2"/); assert.match(source,/test "\$hash1" = "\$hash2"/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast block/g)??[]).length,15);
  assert.equal((source.match(/cast block/g)??[]).length,15);
  assert.equal((source.match(/cast block[^\n]+--field hash[^\n]+\| tr '\[:upper:\]' '\[:lower:\]' \| head -c 68/g)??[]).length,9);
  assert.equal((source.match(/--field (?:timestamp|baseFeePerGas)/g)??[]).length,4);
  assert.equal(source.split(/--field (?:timestamp|baseFeePerGas)/).slice(1).filter(part=>part.slice(0,160).includes('| head -c 80')).length,4);
  assert.equal((source.match(/is_canonical_rpc_uint "\$(?:time|base)[12]"/g)??[]).length,4);
  assert.match(source,/\^\(0\|\[1-9\]\[0-9\]\*\|0x0\|0x\[1-9a-f\]\[0-9a-f\]\*\)\$/);
  assert.match(source,/\[\[ \$genesis1 =~ \^0x\[0-9a-f\]\{64\}\$ && \$genesis2 =~ \^0x\[0-9a-f\]\{64\}\$ \]\]/);
  assert.match(source,/\[\[ \$hash1 =~ \^0x\[0-9a-f\]\{64\}\$ && \$hash2 =~ \^0x\[0-9a-f\]\{64\}\$ \]\]/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast chain-id --rpc-url "\$1" \| head -c 80/g)??[]).length,1);
  assert.equal((source.match(/require_mainnet_chain_id "\$rpc[12]"/g)??[]).length,2);
  assert.equal((source.match(/require_mainnet_chain_id "\$rpc"/g)??[]).length,3);
  assert.match(source,/reserveRuntimeCodeHash/); assert.match(source,/reserveConfigHash\(\)\(bytes32\)/);
  for(const predicate of ['paused\\(\\)\\(bool\\)','deprecated\\(\\)\\(bool\\)',
    'upgradedAddress\\(\\)\\(address\\)','basisPointsRate\\(\\)\\(uint256\\)',
    'maximumFee\\(\\)\\(uint256\\)','isBlackListed\\(address\\)\\(bool\\)']) {
    assert.match(source,new RegExp(predicate));
  }
  assert.match(source,/isBlackListed\(address\)\(bool\)' "\$reserve"/);
  assert.match(source,/isBlackListed\(address\)\(bool\)' "\$recipient"/);
  assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s cast codehash/g)??[]).length,0);
  assert.equal((source.match(/cast codehash/g)??[]).length,1);
  assert.equal((source.match(/rpc_codehash /g)??[]).length,2);
  assert.match(source,/cast codehash "\$@" \| head -c 68/);
  assert.equal(source.includes('cast gas-price'),false);
  const castLines=source.split('\n');
  assert.deepEqual(castLines.flatMap((line,index)=>line.includes('cast ')&&!line.includes('cast rpc eth_estimateGas')&&!line.includes('cast wallet sign --no-hash')&&!line.trimStart().startsWith('#')&&!castLines.slice(index,index+3).join(' ').includes('head -c ')?[index+1]:[]),[]);
  assert.equal((source.match(/sha256sum/g)??[]).length,1);
  assert.equal((source.match(/sha256_file /g)??[]).length,8);
  assert.match(source,/sha256sum -- "\$path" \| head -c 66/);
  assert.match(source,/test "\$before" = "\$after"/);
  assert.equal((source.match(/node -e/g)??[]).length,1);
  assert.equal((source.match(/node_eval /g)??[]).length,19);
  assert.match(source,/node -e "\$@" \| head -c 161/);
  assert.equal((source.match(/cmp -s/g)??[]).length,1);
  assert.equal((source.match(/cmp_exact /g)??[]).length,6);
  assert.match(source,/120s cmp -s -- "\$@"/);
  assert.equal((source.match(/\bjq\b/g)??[]).length,1);
  assert.equal((source.match(/jq_run /g)??[]).length,77);
  assert.match(source,/value=\$\(timeout --foreground --signal=TERM --kill-after=5s 120s jq "\$@" \| head -c 1048577\)/);
  assert.match(source,/\(\( \$\{#value\} <= 1048576 \)\)/);
  assert.equal((source.match(/\bstat\b/g)??[]).length,1);
  assert.equal((source.match(/stat_run /g)??[]).length,24);
  assert.match(source,/\[\[ -d \$evidence && ! -L \$evidence \]\]/);
  assert.match(source,/realpath -e \/proc\/\$\$\/fd\/9/);
  assert.match(source,/stat_run -Lc '%u:%a' -- \/proc\/\$\$\/fd\/9\)" = "\$UID:700"/);
  assert.match(source,/stat_run -c '%d:%i' -- "\$evidence"[\s\S]*stat_run -Lc '%d:%i' -- \/proc\/\$\$\/fd\/9/);
  assert.equal((source.match(/mktemp/g)??[]).length,1);
  assert.equal((source.match(/private_tmpdir /g)??[]).length,1);
  assert.match(source,/120s stat "\$@" \| head -c 257/);
  assert.match(source,/prepare-private-eth-estimate-gas\.mjs "\$private_input" "\$signer"/);
  assert.equal((source.match(/cast rpc eth_estimateGas --raw --rpc-url "\$rpc[12]"/g)??[]).length,2);
  assert.doesNotMatch(source,/cast estimate "\$to" "\$data"|cast mktx[^\n]*--data "\$data"/);
  assert.equal((source.match(/is_canonical_rpc_uint "\$estimate[12]"/g)??[]).length,2);
  assert.doesNotMatch(source,/cast send|--private-key|--mnemonic|sleep /);
});

test('redemption package CLI uses strict bounded direct input and exact arity',()=>{
  const directory=mkdtempSync(join(tmpdir(),'usdom-redemption-check-'));
  try {
    const submission=join(directory,'submission.json'),value=fixture();
    writeFileSync(submission,JSON.stringify(value),{mode:0o600});
    const checker=new URL('../../scripts/check-closed-mainnet-redemption.mjs',import.meta.url).pathname;
    const valid=spawnSync(process.execPath,[checker,submission],{encoding:'utf8'});
    assert.equal(valid.status,0,valid.stderr);
    assert.deepEqual(JSON.parse(valid.stdout),buildClosedMainnetRedemptionPackage(value));
    const extra=spawnSync(process.execPath,[checker,submission,'extra','0'],{encoding:'utf8'});
    assert.notEqual(extra.status,0); assert.equal(extra.stdout,'');
    writeFileSync(submission,JSON.stringify(value).replace('{','{"schema":"ambiguous",'),{mode:0o600});
    const duplicate=spawnSync(process.execPath,[checker,submission],{encoding:'utf8'});
    assert.notEqual(duplicate.status,0); assert.equal(duplicate.stdout,'');
    assert.doesNotMatch(duplicate.stderr,/ambiguous/);
  } finally { rmSync(directory,{recursive:true,force:true}); }
});

test('redemption revalidates consensus, Safe nonce and expiry before mobile authorization and relayer handoff',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  const approval=source.indexOf('sign-onekey-ios-walletconnect-typed-data.mjs');
  const signing=source.indexOf('sign-operational-gas-relayer.sh redemption:',approval);
  assert.ok(approval>=0&&signing>approval);
  const window=source.slice(approval,signing);
  assert.match(window,/rpc_consensus_snapshot/);
  assert.match(window,/read_nonce "\$signer" pending/);
  assert.match(window,/consensus_timestamp/);
  assert.match(source,/prepare-safe-redemption-operation\.mjs/);
  assert.match(source,/check-safe-redemption-relayer-raw\.mjs/);
  assert.doesNotMatch(source,/--ledger|wallet sign|wallet address|prepare-ledger|assemble-ledger|sign-onekey-mainnet-transaction|prepare-onekey-eip1559/i);
});
