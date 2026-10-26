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
    ['9','9','010','9','010'],['9','9','10','9','10',known,known,'0x'+'13'.repeat(32)],
    ['18446744073709551615','18446744073709551616','18446744073709551616','18446744073709551616','18446744073709551616']]) {
    assert.throws(()=>classifyPilotNonce(...values));
  }
});

test('both executors recover known hash without a second publish prompt',()=>{
  for(const file of ['execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh']) {
    const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    assert.match(source,/check-pilot-nonce-recovery\.mjs/);
    assert.match(source,/(?:refresh_consensus_block|rpc_consensus_snapshot)/);
    assert.match(source,/--block "\$consensus_block"/);
    assert.match(source,/cast tx "\$expected_hash" --field hash/);
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
    assert.ok(source.indexOf('nonce_action=$(node scripts/check-pilot-nonce-recovery.mjs')
      <source.indexOf('cast receipt "$tx_hash" --confirmations 2'));
  }
  const redemption=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.match(redemption,/live_time1/);
  assert.match(redemption,/\+204n>BigInt/);
});
