import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const source=name=>readFile(path.join(root,name),'utf8');

test('Safe deposit publisher uses authenticated RPC sources and exact pre-broadcast journal',async()=>{
 const script=await source('scripts/publish-safe-deposit-relayer.sh');
 assert.match(script,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:\?required/);
 assert.match(script,/materialize-private-foundry-rpc-aliases\.mjs/);
 assert.match(script,/publish-private-raw-transaction\.mjs "\$raw" "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "\$rpc_catalog" 0/);
 assert.doesNotMatch(script,/rpc1=https?:|rpc2=https?:/);
 assert.match(script,/\.schema=="usdom-safe-deposit-broadcast-journal\/v1"[\s\S]*\.state=="signed-unresolved"[\s\S]*\.validation==\$validation\[0\]/);
 assert.ok(script.indexOf('broadcast-journal/v1')<script.indexOf('state=publishing'));
});

test('restart revalidates exact finalized transaction on both authenticated origins',async()=>{
 const script=await source('scripts/publish-safe-deposit-relayer.sh');
 const restart=script.slice(script.indexOf('if test -e "$completion"'),script.indexOf('observe "$rpc1"'));
 for(const marker of ['transactionHash','blockNumber','blockHash','finalizedRpcCount==2','for rpc in "$rpc1" "$rpc2"','cast_bin block "$block" --field hash','cast_bin block finalized','cast_bin receipt "$txhash"']) assert.ok(restart.includes(marker),marker);
 assert.match(restart,/\.status=="0x1"[\s\S]*\.blockNumber==\$block[\s\S]*\.blockHash\|ascii_downcase/);
});

test('pilot phase routes every relayer signature request through a bounded status78 cycle',async()=>{
 const generator=await source('scripts/generate-closed-mainnet-phase-command.sh');
 for(const profile of ['pilot-gate','pilot-gate-cancel','pilot-gate-clear','deposit','redemption']) assert.match(generator,new RegExp(`run-operational-status78-cycle\\.mjs ${profile}`));
 assert.doesNotMatch(generator,/npm run --silent execute:pilot-deposit-gate-cancel/);
 assert.doesNotMatch(generator,/npm run --silent execute:expired-pilot-gate-clear/);
 const dag=await source('scripts/write-open-claims-execution-plan.mjs');
 for(const profile of ['pilot-gate','pilot-gate-cancel','pilot-gate-clear','deposit']) assert.match(dag,new RegExp(`run-operational-status78-cycle\\.mjs ${profile}`));
});
