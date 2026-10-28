import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {LIMITED_MAINNET_POLICY,materializeLimitedMainnetPolicy}
  from '../../sdk/limited-mainnet-policy.mjs';

const installed=JSON.parse(readFileSync(fileURLToPath(new URL(
  '../../config/proof-reserve.unconfigured.json',import.meta.url)),'utf8'));
const template={...installed,...Object.fromEntries(Object.keys(LIMITED_MAINNET_POLICY).map(
  field=>[field,null]))};

test('limited mainnet pilot policy is exact, conservative and authorization-free',()=>{
  const result=materializeLimitedMainnetPolicy(template);
  assert.deepEqual(Object.fromEntries(Object.keys(LIMITED_MAINNET_POLICY).map(
    key=>[key,result[key]])),LIMITED_MAINNET_POLICY);
  assert.equal(result.maxOutstandingBaseUnits,'1000000');
  assert.equal(result.outflowCapacityBaseUnitsPerDay,'1000000');
  assert.equal(result.productionReady,false);
  assert.equal(result.realFundsAuthorized,false);
  assert.equal(template.withdrawalDelaySeconds,null);
  assert.deepEqual(materializeLimitedMainnetPolicy(installed),installed);
});

test('limited policy refuses drift, other networks, tokens and prior authorization',()=>{
  for(const changed of [
    {...template,withdrawalDelaySeconds:'86399'},
    {...template,ethereumChainId:'31337'},
    {...template,token:'0x0000000000000000000000000000000000000001'},
    {...template,productionReady:true},
    {...template,realFundsAuthorized:true},
  ]) assert.throws(()=>materializeLimitedMainnetPolicy(changed));
  const once=materializeLimitedMainnetPolicy(template);
  assert.deepEqual(materializeLimitedMainnetPolicy(once),once);
});

test('limited policy writer confirms exact durable bytes and metadata',()=>{
  const source=readFileSync(fileURLToPath(new URL(
    '../../scripts/materialize-limited-mainnet-policy.sh',import.meta.url)),'utf8');
  assert.match(source,/stat -Lc '%u:%a:%h' "\$target"/);
  assert.equal((source.match(/cmp -s "\$temporary" "\$target"/g)??[]).length,3);
  assert.match(source,/sync -f "\$config_directory"\ncmp -s "\$temporary" "\$target"/);
  assert.match(source,/replace-locked-source-stdin\.mjs/);
  assert.match(source,/"\$target_sha256" "\$parent_device" "\$parent_inode"/);
  assert.match(source,/pin_tool python3/);
});
