import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';

test('cancel delegates gas only to the common bounded relayer boundary',async()=>{
 const source=await readFile(new URL('../../scripts/execute-pilot-deposit-gate-cancel.sh',import.meta.url),'utf8');
 assert.doesNotMatch(source,/payer_identity|onekey-classic-1s-identity|sign-onekey-mainnet-transaction|prepare-onekey-eip1559|AUTORIZO ASSINAR CANCELAMENTO GATE/);
 assert.match(source,/pilot-gate-relayer-policy\.json/);assert.match(source,/pilot-deposit-gate-cancel-relayer-envelope\.json/);
 assert.match(source,/prepare-pilot-gate-relayer-envelope\.mjs/);assert.match(source,/check-pilot-gate-relayer-raw\.mjs/);
 assert.match(source,/raw privada do relayer ausente/);assert.match(source,/exit 78/);
 for(const field of ['.token','.reserve','.governance','.guardian','.governanceOwners[]','.guardianOwners[]','.checkpointGuardianOwners[]']) assert.ok(source.includes(field),field);
});

test('cancel revalidates dual-RPC relayer nonce, EOA and exact raw on both sides of broadcast approval',async()=>{
 const source=await readFile(new URL('../../scripts/execute-pilot-deposit-gate-cancel.sh',import.meta.url),'utf8');
 const helper=source.slice(source.indexOf('assert_relayer_live'),source.indexOf('if test ! -e "$receipt"'));
 for(const marker of ['cast nonce "$relayer" --block pending --rpc-url "$rpc1"','cast nonce "$relayer" --block pending --rpc-url "$rpc2"','cast code "$relayer" --block finalized --rpc-url "$rpc1"','cast code "$relayer" --block finalized --rpc-url "$rpc2"','check-pilot-gate-relayer-raw.mjs']) assert.ok(helper.includes(marker),marker);
 assert.match(source,/assert_relayer_live; read -r -p "Digite AUTORIZO TRANSMITIR CANCELAMENTO GATE[\s\S]*assert_live; assert_relayer_live; assert_evidence_parent; pilot_cancel_broadcast_state=publishing/);
 assert.ok(source.indexOf('pilot_cancel_broadcast_state=signed-unresolved')<source.indexOf('publish-private-raw-transaction.mjs'));
});
