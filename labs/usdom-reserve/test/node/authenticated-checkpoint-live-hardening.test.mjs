import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const collector=await readFile(
 new URL('../../scripts/observe-authenticated-checkpoint.mjs',import.meta.url),'utf8');
const launcher=await readFile(
 new URL('../../scripts/observe-authenticated-checkpoint.sh',import.meta.url),'utf8');
const providerSource=await readFile(
 new URL('../../sdk/mainnet-preflight-rpc.mjs',import.meta.url),'utf8');

test('authenticated checkpoint observer uses cataloged bounded multi-RPC snapshots',()=>{
 for(const expected of [
  'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES','config/mainnet-preflight-rpc-catalog.json',
  'mainnetPreflightRpcSourceSet','rpcSourceSetCommitment','rpcSourceCount','rpcSources',
  'matchMainnetPreflightRpcSources','new BoundedMainnetPreflightProvider(source.url)',
  "provider.send('eth_getBlockByNumber',['finalized',false])",
  "provider.send('eth_getBlockByNumber',[blockTag,false])",
  'Promise.all(providers.map(provider=>collect(provider,submission)))',
  "throw new Error('cataloged finalized RPC observations disagree')",
  'const currentInputs=await readAuthenticatedInputs()',
  "throw new Error('authenticated checkpoint inputs changed during observation')",
 ]) assert.match(collector,new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 assert.doesNotMatch(collector,/new JsonRpcProvider|ETHEREUM_RPC_URL/);
 assert.doesNotMatch(launcher,/read -r|ETHEREUM_RPC_URL/);
 assert.match(launcher,/exec "\$ENV_BIN" -i[\s\S]*"\$NODE_BIN" scripts\/observe-authenticated-checkpoint\.mjs/);
 for(const expected of [
  'node_size=$(stat', 'node_directory_identity=$(stat',
  'env_size=$(stat', 'env_directory_identity=$(stat',
  `test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"`,
  `test "$(stat -Lc '%d:%i:%u:%a' "$env_directory")" = "$env_directory_identity"`,
 ]) assert.ok(launcher.includes(expected),`missing launcher boundary: ${expected}`);
 assert.doesNotMatch(launcher,/(?:^|\s)&\s*(?:#.*)?$|\bcoproc\b|\bwait\b|\bkill\b/m);
 assert.match(collector,/finally \{[\s\S]*for\(const provider of providers\) provider\.destroy\(\)/);
 assert.match(providerSource,/timeoutMs<1\|\|timeoutMs>120_000/);
 assert.match(providerSource,/setTimeout\(\(\)=>controller\.abort\(\),this\.timeoutMs\)/);
 assert.match(providerSource,/limitedJson\(response,this\.maxBytes\)/);
});

test('authenticated checkpoint evidence is private create-once and errors redact runtime URLs',()=>{
 assert.match(collector,/writePrivateFileDurableNew\(outputPath/);
 assert.match(collector,/removePrivateFileDurableIfExists\(outputPath\)/);
 assert.match(collector,/mode:0o700/);
 assert.match(collector,/checkpoint observation directory mode is unsafe/);
 assert.match(collector,/writeReleaseFailure\('observe-authenticated-checkpoint'/);
 assert.match(collector,/canonicalEthereumQuantity\(chainIdRaw,\{maximum:MAX_UINT256\}\)/);
 assert.match(collector,/canonicalEthereumQuantity\(finalized\?\.number\)/);
 assert.match(collector,/canonicalEthereumQuantity\(finalized\?\.timestamp\)/);
 assert.doesNotMatch(collector,/BigInt\(finalized\.(?:number|timestamp)\)/);
 assert.doesNotMatch(`${collector}\n${launcher}`,/curl|wget|git push|cast send|eth_sendRawTransaction/);
});

test('checkpoint observer invalidates stale output before authentication or RPC',()=>{
 const prepareCall=collector.indexOf('await prepareOutput();');
 const firstRead=collector.indexOf('const initialConfiguration=',prepareCall);
 const firstProvider=collector.indexOf('new BoundedMainnetPreflightProvider',prepareCall);
 const firstRpc=collector.indexOf('Promise.all(providers.map(provider=>collect(provider,submission)))',prepareCall);
 assert.ok(prepareCall>=0 && firstRead>prepareCall && firstProvider>firstRead && firstRpc>firstProvider);
 const prepareStart=collector.indexOf('async function prepareOutput()');
 const prepareEnd=collector.indexOf('async function atomicWrite',prepareStart);
 const prepare=collector.slice(prepareStart,prepareEnd);
 assert.match(prepare,/removePrivateFileDurableIfExists\(outputPath\)/);
 assert.throws(()=>{
  const unsafe=collector.replace('await prepareOutput();','// stale output retained');
  assert.match(unsafe,/await prepareOutput\(\);/);
 });
});
