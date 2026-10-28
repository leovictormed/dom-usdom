import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {canonicalEthereumQuantity,canonicalUnsignedDecimal,MAX_ETHEREUM_QUANTITY_UINT64}
  from '../../sdk/ethereum-quantity.mjs';

test('finalized-deposit collector uses bounded canonical readers for external integers',async()=>{
  const source=await readFile(new URL('../../scripts/collect-finalized-deposit-source.mjs',import.meta.url),'utf8');
  assert.match(source,/BigInt\(canonicalEthereumQuantity\(value\)\)/);
  assert.match(source,/canonicalUnsignedDecimal\(value,\{maximum:MAX_ETHEREUM_QUANTITY_UINT64\}\)/);
  for(const forbidden of [
    'BigInt(finality.finalized_header.execution.block_number)',
    'BigInt(bootstrap.header.beacon.slot)',
    'BigInt(finality.finalized_header.beacon.slot)',
    'BigInt(source.depositBlockNumber)',
  ]) assert.equal(source.includes(forbidden),false);
  assert.match(source,/evidenceMetadata\.uid!==process\.getuid\(\)/);
  assert.match(source,/metadata\.uid!==process\.getuid\(\)/);
  assert.match(source,/evidenceMetadata\.isSymbolicLink\(\)/);
});

test('collector integer authorities reject oversized and out-of-range inputs before conversion',()=>{
  for(const value of [`0x${'f'.repeat(100_000)}`,`0x${(1n<<64n).toString(16)}`,'0x01','0xA']) {
    assert.throws(()=>canonicalEthereumQuantity(value));
  }
  for(const value of ['9'.repeat(100_000),(1n<<64n).toString(),'01','-1']) {
    assert.throws(()=>canonicalUnsignedDecimal(value,{maximum:MAX_ETHEREUM_QUANTITY_UINT64}));
  }
});
