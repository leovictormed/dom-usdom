import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {Transaction, TypedDataEncoder, Wallet} from 'ethers';
import {createOneKeyEthereumMainnetBoundary} from '../../sdk/onekey-ethereum-mainnet.mjs';

const wallet = new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a841b1f6ea2b34be6d0');
const path = "m/44'/60'/0'/0/0";
const connectId = 'usb-connect-1', deviceId = 'classic-1s-device-1';

function fixture() {
  const calls = [];
  const device = {
    async evmGetAddress(connection, identity, request) {
      calls.push(['evmGetAddress', connection, identity, request]);
      return {success: true, payload: {address: wallet.address}};
    },
    async evmSignTransaction(connection, identity, request) {
      calls.push(['evmSignTransaction', connection, identity, request]);
      if(request.transaction.chainId!==1)throw new Error('chainId must be a number');
      const tx = Transaction.from(request.transaction);
      const signature = wallet.signingKey.sign(tx.unsignedHash);
      return {success: true, payload: {v: `0x${signature.yParity}`, r: signature.r, s: signature.s}};
    },
    async evmSignTypedData(connection, identity, request) {
      calls.push(['evmSignTypedData', connection, identity, request]);
      const signingTypes=Object.fromEntries(Object.entries(request.data.types).filter(([name])=>name!=='EIP712Domain'));
      const signature = wallet.signingKey.sign(TypedDataEncoder.hash(request.data.domain, signingTypes, request.data.message));
      return {success: true, payload: {address:wallet.address,signature:signature.serialized.slice(2)}};
    },
  };
  return {calls, device, boundary: createOneKeyEthereumMainnetBoundary({device, connectId, deviceId, derivationPath: path, expectedAddress: wallet.address})};
}

function unsigned() {
  const tx = Transaction.from({type: 2, chainId: 1, nonce: 4, gasLimit: 90000,
    maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n,
    to: '0x1111111111111111111111111111111111111111', value: 7n, data: '0x1234', accessList: []});
  return {unsignedSerialized: tx.unsignedSerialized, unsignedHash: tx.unsignedHash};
}

test('OneKey boundary displays the bound address and signs the exact mainnet envelope', async () => {
  const {boundary, calls} = fixture();
  const expected = unsigned();
  const result = await boundary.signTransaction(expected);
  assert.equal(Transaction.from(result.rawTransaction).unsignedHash, expected.unsignedHash);
  assert.deepEqual(calls.map(call => call[0]), ['evmGetAddress', 'evmSignTransaction']);
  assert.equal(calls[0][1], connectId); assert.equal(calls[0][2], deviceId);
  assert.deepEqual(calls[0][3], {path, chainId: 1, useEmptyPassphrase: true, showOnOneKey: true});
  assert.equal(calls[1][3].path, path);
  assert.deepEqual(Object.keys(calls[1][3]).sort(),['path','transaction','useEmptyPassphrase']);
  assert.deepEqual(Object.keys(calls[1][3].transaction).sort(),['chainId','data','gasLimit','maxFeePerGas','maxPriorityFeePerGas','nonce','to','value']);
  assert.equal(calls[1][3].transaction.chainId, 1);
  assert.equal(typeof calls[1][3].transaction.chainId, 'number');
  assert.equal(calls[1][3].transaction.nonce, '0x4');
  assert.equal(calls[1][3].transaction.value, '0x7');
  assert.equal(calls[1][3].transaction.gasLimit, '0x15f90');
  assert.equal(calls[1][3].transaction.data, '0x1234');
});

test('OneKey boundary signs exact EIP-712 bytes after address confirmation', async () => {
  const {boundary, calls} = fixture();
  const domain = {name: 'USDOM', version: '1', chainId: 1, verifyingContract: '0x1111111111111111111111111111111111111111'};
  const types = {EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},{name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],Approval: [{name: 'action', type: 'bytes32'}, {name: 'nonce', type: 'uint256'}]};
  const value = {action: `0x${'22'.repeat(32)}`, nonce: 9};
  const digest = TypedDataEncoder.hash(domain, {Approval:types.Approval}, value);
  const result = await boundary.signTypedData({domain, types, value, digest});
  assert.equal(result.digest, digest);
  assert.deepEqual(calls.map(call => call[0]), ['evmGetAddress', 'evmSignTypedData']);
  assert.deepEqual(Object.keys(calls[1][3]).sort(),['chainId','data','metamaskV4Compat','path','useEmptyPassphrase']);
  assert.equal(calls[1][3].data.primaryType,'Approval');
  assert.equal(calls[1][3].metamaskV4Compat, true);
  await assert.rejects(() => boundary.signTypedData({domain, types, value: {...value, nonce: 10}, digest}), /binding mismatch/);
});

test('OneKey boundary rejects changed identity, path, network and envelope hash', async () => {
  const {device, boundary} = fixture();
  assert.throws(() => createOneKeyEthereumMainnetBoundary({device, connectId, deviceId, derivationPath: "m/44'/60'/00'/0/0", expectedAddress: wallet.address}), /path/);
  assert.throws(() => createOneKeyEthereumMainnetBoundary({device, connectId, deviceId, derivationPath: path, expectedAddress: wallet.address.toLowerCase()}), /noncanonical/);
  await assert.rejects(() => boundary.signTransaction({...unsigned(), unsignedHash: `0x${'00'.repeat(32)}`}), /binding mismatch/);
  const foreign = fixture(); foreign.device.evmGetAddress = async () => ({success: true, payload: {address: Wallet.createRandom().address}});
  await assert.rejects(() => foreign.boundary.confirmAddress(), /address binding mismatch/);
});

test('OneKey boundary rejects ambiguous or non-SDK signature payloads', async () => {
  const fixtureWithExtra = fixture();
  fixtureWithExtra.device.evmSignTransaction = async (_connection, _identity, request) => {
    const signature = wallet.signingKey.sign(Transaction.from(request.transaction).unsignedHash);
    return {success: true, payload: {v: `0x${signature.yParity}`, r: signature.r, s: signature.s, signature: signature.serialized}};
  };
  await assert.rejects(() => fixtureWithExtra.boundary.signTransaction(unsigned()), /response is ambiguous/);
  const fixtureWithLegacyV = fixture();
  fixtureWithLegacyV.device.evmSignTransaction = async (_connection, _identity, request) => {
    const signature = wallet.signingKey.sign(Transaction.from(request.transaction).unsignedHash);
    return {success: true, payload: {v: signature.v, r: signature.r, s: signature.s}};
  };
  await assert.rejects(() => fixtureWithLegacyV.boundary.signTransaction(unsigned()), /signature is noncanonical/);
});

test('OneKey production boundary has no legacy signer or secret fallback', async () => {
  const source = await readFile(new URL('../../sdk/onekey-ethereum-mainnet.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /ledger|--ledger|mnemonic|process\.env|Wallet|SigningKey/i);
  assert.match(source, /evmGetAddress/);
  assert.match(source, /evmSignTransaction/);
  assert.match(source, /evmSignTypedData/);
  assert.throws(() => createOneKeyEthereumMainnetBoundary({device: {}, connectId, deviceId, derivationPath: path, expectedAddress: wallet.address}), /unavailable/);
});
