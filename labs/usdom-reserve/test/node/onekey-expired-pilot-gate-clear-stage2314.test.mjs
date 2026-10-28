import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';

test('expired pilot gate clear uses only the common untrusted relayer boundary',async()=>{
 const source=await readFile(new URL('../../scripts/execute-expired-pilot-gate-clear.sh',import.meta.url),'utf8');
 assert.doesNotMatch(source,/wallet (?:address|sign)[^\n]*--ledger|prepare-ledger|assemble-ledger|sign-onekey-mainnet-transaction|prepare-onekey-eip1559|payer_identity/);
 for(const marker of ['pilot-gate-relayer-policy.json','pilot-deposit-gate-clear-transaction.json','pilot-deposit-gate-clear-relayer-envelope.json','prepare-pilot-gate-relayer-envelope.mjs','check-pilot-gate-relayer-raw.mjs','raw privada do relayer ausente']) assert.ok(source.includes(marker),marker);
 for(const field of ['.token','.reserve','.governance','.guardian','.governanceOwners[]','.guardianOwners[]','.checkpointGuardianOwners[]']) assert.ok(source.includes(field),field);
});

test('expired clear binds direct action and revalidates relayer around broadcast',async()=>{
 const source=await readFile(new URL('../../scripts/execute-expired-pilot-gate-clear.sh',import.meta.url),'utf8');
 assert.match(source,/usdom-pilot-gate-clear-relayer-package\/v1/);
 assert.match(source,/assert_relayer_live[\s\S]*cast nonce "\$relayer" --block pending --rpc-url "\$rpc1"[\s\S]*cast code "\$relayer" --block finalized[\s\S]*check-pilot-gate-relayer-raw\.mjs/);
 assert.match(source,/assert_relayer_live[\s\S]*AUTORIZO TRANSMITIR LIMPEZA EXPIRADA[\s\S]*assert_relayer_live[\s\S]*observe "\$rpc1" "\$tmp\/pre-send-a\.json"/);
 assert.match(source,/pilot_clear_broadcast_state=signed-unresolved[\s\S]*pilot_clear_broadcast_state=publishing/);
 assert.match(source,/pilot_clear_broadcast_state != clean[\s\S]*status=80/);
 const rotation=await readFile(new URL('../../scripts/rotate-expired-pilot-funds-authorization.mjs',import.meta.url),'utf8');
 for(const artifact of ['pilot-deposit-gate-clear-transaction.json','pilot-deposit-gate-clear-relayer-envelope.json']) assert.ok(rotation.includes(artifact),artifact);
});
