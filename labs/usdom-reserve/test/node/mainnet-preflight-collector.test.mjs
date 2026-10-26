import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const source=await readFile(new URL('../../scripts/check-mainnet-preflight.mjs',import.meta.url),'utf8');

test('mainnet preflight requires two complete identical finalized RPC observations',()=>{
  for(const expected of [
    'new BoundedMainnetPreflightProvider(rpcSource.url)',
    'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES','matchMainnetPreflightRpcSources',
    'rpcConsensusEvidence','rpcConsensus:',
    "config/mainnet-preflight-rpc-catalog.json",
    'rpcSources.map(source=>observe(releaseConfig,riscZeroReference,source))',
    'const collected=await Promise.all(',
    'validateMainnetPreflightTimeConsensus(collected.map(value=>value.timeSample))',
    'const canonical=observations.map(value=>JSON.stringify(value))',
    "throw new Error('independent finalized RPC observations disagree')",
    "provider.send('eth_getBlockByNumber',['finalized',false])",
    "provider.send('eth_getBlockByNumber',[finalizedTag,false])",
    'governanceControl.getThreshold(callOptions)','governanceControl.getOwners(callOptions)',
    'governanceControl.getModulesPaginated(safeSentinel,1,callOptions)',
    "provider.send('eth_getStorageAt',[safe,safeGuardStorageSlot,finalizedTag])",
    "'eth_getStorageAt',[safe,safeFallbackHandlerStorageSlot,finalizedTag]",
    "'config/proof-reserve.unconfigured.json','config/risc0-ethereum-mainnet-v3.json'",
    'readDirectProjectFile(root,relative',
    'finally {\n    await provider.destroy();',
  ]) assert.match(source,new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.doesNotMatch(source,/eth\.drpc\.org|ethereum-rpc\.publicnode\.com/);
  assert.doesNotMatch(source,/Promise\.(?:any|race)/);
  assert.doesNotMatch(source,/from 'node:fs\/promises'/);
  assert.doesNotMatch(source,/eth_sendRawTransaction|wallet_sendTransaction|privateKey|mnemonic/i);
});

test('mainnet preflight parses snapshotted authority directly from strict bytes',()=>{
  assert.match(source,/parseStrictJsonBytes\(validationBytes,/);
  assert.match(source,/parseStrictJsonBytes\(value,/);
  assert.doesNotMatch(source,/parseStrictJson\(|\.toString\(['"]utf8['"]\)/);
  for(const bytes of [
    Buffer.from('{"transactionHash":"a","\\u0074ransactionHash":"b"}'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'preflight authority'}),
    /duplicate (?:object )?key|invalid UTF-8/);
});
