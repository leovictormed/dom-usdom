import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const script=new URL('../../scripts/probe-ledger-clear-signing.sh',import.meta.url).pathname;
const source=readFileSync(script,'utf8');
test('capability probe prints one exact command without touching a device',()=>{
 const result=spawnSync('bash',[script,'--print-command'],{encoding:'utf8'});
 assert.equal(result.status,0);
 assert.equal(result.stdout,'cd /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve && bash scripts/probe-ledger-clear-signing.sh --run\n');
 assert.equal(result.stderr,'');
});
test('probe is local, disposable, clear-review only and cryptographically verifies output',()=>{
 for(const expected of ['chainId":"31337"','SafeTx','wallet sign --data --from-file',
  'wallet verify --address','blind signing reprova','check-ledger-clear-signing-capability.mjs',
  '--chain 31337','--value 0','rm -rf -- "$temporary"']) assert.match(source,new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 assert.doesNotMatch(source,/eth_sign|personal_sign|cast send|cast publish|eth_sendRawTransaction|--rpc-url|chain 1\b/);
 assert.match(source,/unset ETH_RPC_URL/);
});
