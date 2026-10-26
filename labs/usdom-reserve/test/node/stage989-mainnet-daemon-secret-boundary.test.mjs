import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const root=new URL('../../',import.meta.url);
const read=name=>readFile(new URL(name,root),'utf8');

test('credential-bearing RPC proxy requires hardened launcher and byte-strict catalog',async()=>{
  const source=await read('scripts/serve-private-rpc-catalog-proxy.mjs');
  assert.match(source,/USDOM_PRIVATE_RPC_PROXY_LAUNCHER!=='1'/);
  assert.match(source,/delete process\.env\.USDOM_PRIVATE_RPC_PROXY_LAUNCHER/);
  assert.match(source,/readRuntimeSecretJsonFile\('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES'/);
  assert.match(source,/parseStrictJsonBytes\(catalogBytes/);
  assert.doesNotMatch(source,/catalogBytes\.toString\(['"]utf8['"]\)/);
  assert.match(source,/catch \{[\s\S]*bounded upstream RPC failure/);
  assert.doesNotMatch(source,/console\.(?:log|error)|stderr\.write\(`[^`]*\$\{error/);
});

test('mainnet executors launch the long-lived proxy with a minimal environment',async()=>{
  for(const name of ['execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh']) {
    const source=await read(`scripts/${name}`);
    const launch=/\/usr\/bin\/env -i HOME="\$HOME" PATH=\/usr\/bin:\/bin[\s\S]*?USDOM_PRIVATE_RPC_PROXY_LAUNCHER=1[\s\S]*?USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"[\s\S]*?serve-private-rpc-catalog-proxy\.mjs/;
    assert.match(source,launch,name);
    assert.doesNotMatch(source,/serve-private-rpc-catalog-proxy\.mjs[^\n]*\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
    assert.match(source,/ulimit -c 0/);
    assert.match(source,/set \+x/);
  }
});
