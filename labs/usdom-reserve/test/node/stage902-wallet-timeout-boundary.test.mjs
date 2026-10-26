import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const cases=new Map([
 ['register-finalized-deposit-wallet.sh',3],
 ['collect-finalized-deposit-source.sh',1],
 ['prepare-native-receiving-wallet.sh',2],
 ['bootstrap-closed-mainnet-tpm-authority.sh',3],
 ['drill-closed-mainnet-wallet-recovery.sh',3],
 ['observe-finalized-deposit-wallet.sh',3],
 ['provision-closed-mainnet-tpm-keystore.sh',2],
 ['submit-closed-mainnet-private-burn.sh',3],
]);

for(const [script,expectedCalls] of cases) test(`${script} authenticates every timeout`,async()=>{
 const source=await readFile(new URL(script,directory),'utf8');
 assert.match(source,/source "\$(?:LAB_ROOT|RESERVE_DIRECTORY)\/scripts\/pinned-shell-tool-functions\.sh"/);
 assert.match(source,/pin_runtime_tool timeout/);
 assert.match(source,/run_pinned_timeout\(\) \{ assert_runtime_tool timeout; "\$timeout_bin" "\$@"; \}/);
 assert.equal([...source.matchAll(/run_pinned_timeout --signal=/g)].length,expectedCalls);
 assert.doesNotMatch(source,/(?:^|[|;]\s*)timeout --signal=/m);
});
