import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../..',import.meta.url));
test('capability probe is EIP-712 only and cannot create or broadcast a transaction',async()=>{
 const [shell,prepare,pkg,inventory]=await Promise.all([
  readFile(`${root}/scripts/probe-onekey-ios-walletconnect-signing.sh`,'utf8'),
  readFile(`${root}/scripts/prepare-onekey-ios-capability-probe.mjs`,'utf8'),
  readFile(`${root}/package.json`,'utf8'),readFile(`${root}/config/onekey-production-script-inventory.json`,'utf8')]);
 for(const forbidden of ['--ledger','eth_sendTransaction','eth_sendRawTransaction','eth_signTransaction','cast send','cast mktx']) {
  assert.doesNotMatch(shell,new RegExp(forbidden));assert.doesNotMatch(prepare,new RegExp(forbidden));
 }
 assert.match(shell,/sign-onekey-ios-walletconnect-typed-data\.mjs/u);
 assert.match(shell,/nenhuma transação foi criada ou transmitida/u);
 assert.match(prepare,/chainId:1/u);assert.match(prepare,/Capability/u);
 assert.match(pkg,/probe:onekey-ios-walletconnect-signing/u);
 assert.doesNotMatch(pkg,/probe:ledger-clear-signing/u);
 assert.match(inventory,/probe-onekey-ios-walletconnect-signing\.sh/u);
 assert.doesNotMatch(inventory,/probe-ledger-clear-signing/u);
});
