import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {classifyPilotNonce} from '../../sdk/pilot-nonce-recovery.mjs';

test('nonce recovery publishes only at exact nonce and recovers only exact successor',()=>{
  const known='0x'+'12'.repeat(32);
  assert.equal(classifyPilotNonce('9','9','9','9','9'),'publish');
  assert.equal(classifyPilotNonce('9','9','10','9','10',known,known,known),'recover-receipt');
  assert.equal(classifyPilotNonce('9','10','10','10','10',known,known,known),'recover-receipt');
  for(const values of [['9','9','9','9','10'],['9','9','11','9','11'],['9','8','8','8','8'],
    ['9'.repeat(100000),'9','9','9','9'],
    ['9','9','010','9','010'],['9','9','10','9','10',known,known,'0x'+'13'.repeat(32)],
    ['18446744073709551615','18446744073709551616','18446744073709551616','18446744073709551616','18446744073709551616']]) {
    assert.throws(()=>classifyPilotNonce(...values));
  }
});

test('both executors recover known hash without a second publish prompt',()=>{
  for(const file of ['execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh']) {
    const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    const expectedNonceReads=file==='execute-closed-mainnet-deposit.sh'?15:13;
    assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+cast nonce "\$1" --block "\$2" --rpc-url "\$3" \| head -c 80/g)??[]).length,1);
    assert.equal((source.match(/read_nonce "\$(?:funder|signer)"/g)??[]).length,expectedNonceReads);
    assert.match(source,/is_canonical_rpc_uint "\$value"/);
    assert.match(source,/check-pilot-nonce-recovery\.mjs/);
    assert.match(source,/(?:refresh_consensus_block|rpc_consensus_snapshot)/);
    assert.match(source,/--block "\$consensus_block"/);
    assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+cast rpc eth_getTransactionByHash "\$expected" --rpc-url "\$rpc" \| head -c 65537/);
    assert.match(source,/test "\$\(stat_run -c '%s' "\$response"\)" -le 65536/);
    assert.match(source,/check-private-strict-json-file\.mjs "\$response"/);
    assert.equal((source.match(/lookup_known_transaction "\$rpc[12]" "\$expected_hash"/g)??[]).length,2);
    assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-pilot-nonce-recovery\.mjs/g)??[]).length,1);
    assert.match(source,/check-pilot-nonce-recovery\.mjs[^\n]+\| head -c 33\)/);
    assert.match(source,/test "\$\{#nonce_action\}" -le 32/);
    assert.match(source,/case \$nonce_action in publish\|recover-receipt\)/);
    assert.doesNotMatch(source,/eth_getTransactionByHash[^\n]*\|\| true/);
    assert.match(source,/cast tx .*--json --rpc-url/);
    assert.equal((source.match(/(?:finalized[12]|current[12])=\$\(read_nonce "\$(?:funder|signer)" (?:"\$consensus_block"|pending) "\$rpc[12]"\)/g)??[]).length,4);
    assert.equal((source.match(/n[12]=\$\(read_nonce "\$(?:funder|signer)" pending "\$rpc[12]"\)/g)??[]).length,2);
    assert.match(source,/LEDGER CLEAR REVIEW/);
    assert.match(source,/blind signing é proibido/);
    assert.match(source,/dataHash=%s/);
    assert.doesNotMatch(source,/eth_sign|personal_sign/);
    assert.match(source,/for\(let i=0;i<12;i\+\+\)f=\(f\*9n\+7n\)\/8n/);
    assert.match(source,/nonce_action" = recover-receipt/);
    assert.match(source,/tx_hash=\$expected_hash/);
    assert.match(source,/\[\[ -e \$raw_file && ! -e \$validation \]\]/);
    assert.match(source,/install-private-file-new-stdin\.mjs --json "\$validation"/);
    assert.doesNotMatch(source,/cast publish/);
    assert.ok(source.indexOf('nonce_action=$(timeout --foreground --signal=TERM --kill-after=5s 120s')
      <source.indexOf('cast receipt "$tx_hash" --confirmations 2'));
  }
  const redemption=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.match(redemption,/live_time1/);
  assert.match(redemption,/\+204n>BigInt/);
});
