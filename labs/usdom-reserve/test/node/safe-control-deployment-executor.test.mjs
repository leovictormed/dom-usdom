import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../../scripts/execute-safe-control-deployment.sh',import.meta.url),'utf8');
test('Safe deployment preserves RPC quorum, finality and status-80 barriers',()=>{
 assert.match(source,/safe_broadcast_state=clean[\s\S]*cleanup\(\)[\s\S]*safe_broadcast_state != clean[\s\S]*status=80/);
 assert.match(source,/Safe transaction outcome requires exact-hash and finalized-nonce revalidation; do not sign or publish a replacement\./);
 for(const name of ['serve-private-rpc-catalog-proxy.mjs','check-private-rpc-proxy-ready.mjs','check-safe-control-deployment-target.mjs','check-safe-control-deployment-receipt.mjs','check-safe-control-deployment-finality.mjs']) assert.ok(source.includes(name),name);
 assert.match(source,/canonical_hash=\$\(rpc block "\$receipt_block" --field hash/); assert.match(source,/finalized_number=\$\(rpc block finalized --field number/);
 assert.doesNotMatch(source,/\(\( finalized_number >= receipt_block \)\)/); assert.doesNotMatch(source,/https:\/\//); assert.doesNotMatch(source,/cast send|"\$cast_bin" publish/);
});
test('Safe deployment consumes an externally installed gas-only relayer transaction',()=>{
 for(const name of ['safe-control-deployment-relayer-policy.json','safe-control-deployment-relayer-keystore.json','safe-deployment-$role-relayer-envelope.json','prepare-safe-control-deployment-relayer-envelope.mjs','check-safe-control-deployment-relayer-raw.mjs']) assert.ok(source.includes(name),name);
 assert.match(source,/install_private_create_once "\$current_validation" "\$validation" json/); assert.match(source,/install_private_create_once "\$journal_candidate" "\$journal" json/);
 assert.match(source,/Envelope gas-only do relayer instalado em/); assert.match(source,/exit 78/);
 assert.doesNotMatch(source,/wallet (?:address|sign)|--ledger|Ledger|OneKey|onekey|prepare-ledger|assemble-ledger/);
});
test('Safe deployment journals validation before publication and revalidates completion',()=>{
 const validate=source.indexOf('scripts/check-safe-control-deployment-relayer-raw.mjs "$role" "$temporary/$role-raw.txt"');
 const install=source.indexOf('install_private_create_once "$current_validation" "$validation" json',validate);
 const journal=source.indexOf('install_private_create_once "$journal_candidate" "$journal" json',install);
 const publish=source.indexOf('publish-private-raw-transaction.mjs "$temporary/$role-raw.txt"',journal);
 assert.ok(validate>=0&&install>validate&&journal>install&&publish>journal); assert.match(source,/usdom-safe-deployment-journal\/v1/);
 const message=source.indexOf('All four recoverable Safes are finalized'),loop=source.lastIndexOf('for role in governance reserveGuardian checkpointGuardian usdtCustody; do',message),final=source.slice(loop,message);
 assert.ok(loop>0&&message>loop); assert.match(final,/snapshot "\$envelope"/); assert.match(final,/check-safe-control-deployment-relayer-raw\.mjs/); assert.match(final,/check-safe-control-deployment-receipt\.mjs/); assert.match(final,/assert_inputs[\s\S]*assert_package_rebuild/);
});
test('Safe deployment keeps locked control parent and explicit transmit consent',()=>{
 assert.match(source,/exec 9<"\$control_dir"[\s\S]*"\$flock_bin" -n 9/); assert.match(source,/realpath -e \/proc\/\$\$\/fd\/9/);
 assert.ok(source.indexOf('assert_control_parent; safe_broadcast_state=publishing')<source.indexOf('publish-private-raw-transaction.mjs "$temporary/$role-raw.txt"'));
 assert.match(source,/Digite AUTORIZO TRANSMITIR SAFE \$role NONCE \$nonce TX \$tx_hash:/); assert.doesNotMatch(source,/AUTORIZO ASSINAR SAFE/);
});
