import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {canonicalEthereumQuantity,canonicalUnsignedDecimal,MAX_ETHEREUM_QUANTITY_UINT64,MAX_UINT256}
  from '../../sdk/ethereum-quantity.mjs';

test('canonical Ethereum quantity preserves uint64 precision as decimal text',()=>{
  assert.equal(canonicalEthereumQuantity('0x0'),'0');
  assert.equal(canonicalEthereumQuantity('0x1'),'1');
  assert.equal(canonicalEthereumQuantity('0xffffffffffffffff'),MAX_ETHEREUM_QUANTITY_UINT64.toString());
});

test('canonical unsigned decimal retains uint256 precision and rejects coercion forms',()=>{
  assert.equal(canonicalUnsignedDecimal(MAX_UINT256.toString()),MAX_UINT256.toString());
  for(const value of ['', '-1','+1','01','1.0','1e3',(MAX_UINT256+1n).toString(),1,null]) {
    assert.throws(()=>canonicalUnsignedDecimal(value));
  }
  assert.throws(()=>canonicalEthereumQuantity(`0x${'f'.repeat(100000)}`));
  assert.throws(()=>canonicalUnsignedDecimal('9'.repeat(100000)));
});

test('quantity CLI compares uint64 values with BigInt and fails closed',()=>{
  const script=fileURLToPath(new URL('../../scripts/check-ethereum-quantity.mjs',import.meta.url));
  const run=(...args)=>spawnSync(process.execPath,[script,...args],{encoding:'utf8'});
  assert.equal(run('0xffffffffffffffff','0xffffffffffffffff').stdout,
    '18446744073709551615\n');
  assert.notEqual(run('0x2','0x1').status,0);
  assert.notEqual(run('0x01','0x2').status,0);
  assert.notEqual(run('0x10000000000000000','0xffffffffffffffff').status,0);
});

test('canonical Ethereum quantity rejects overflow, leading zero and malformed values',()=>{
  for(const value of ['0x10000000000000000','0x00','0x01','0X1','0x','1','0xg','-0x1',1,null]) {
    assert.throws(()=>canonicalEthereumQuantity(value));
  }
});
