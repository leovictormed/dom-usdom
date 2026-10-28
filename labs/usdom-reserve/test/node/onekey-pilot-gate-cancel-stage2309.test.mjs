import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {TypedDataEncoder} from 'ethers';
import {pilotDepositGateSafeTypedData} from '../../sdk/pilot-deposit-gate.mjs';

const fields=[{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'data',type:'bytes'},
 {name:'operation',type:'uint8'},{name:'safeTxGas',type:'uint256'},{name:'baseGas',type:'uint256'},
 {name:'gasPrice',type:'uint256'},{name:'gasToken',type:'address'},{name:'refundReceiver',type:'address'},{name:'nonce',type:'uint256'}];
const controlSafe='0x1111111111111111111111111111111111111111';
const safeTransaction={to:'0x2222222222222222222222222222222222222222',value:'0',data:'0x12345678',operation:'0',safeTxGas:'0',baseGas:'0',gasPrice:'0',gasToken:'0x0000000000000000000000000000000000000000',refundReceiver:'0x0000000000000000000000000000000000000000',nonce:'11'};
const safeTxHash=TypedDataEncoder.hash({chainId:'1',verifyingContract:controlSafe},{SafeTx:fields},safeTransaction);
const plan={schema:'usdom-pilot-deposit-gate-cancel-plan/v1',chainId:'1',controlSafe,safeTransaction,safeTxHash};

test('cancel Safe typed data binds guardian Safe, cancel calldata and nonce exactly',()=>{
 const typed=pilotDepositGateSafeTypedData(plan),types={...typed.types};delete types.EIP712Domain;
 assert.equal(typed.domain.verifyingContract,controlSafe);assert.equal(typed.message.data,safeTransaction.data);
 assert.equal(TypedDataEncoder.hash(typed.domain,types,typed.message),safeTxHash);
 assert.throws(()=>pilotDepositGateSafeTypedData({...plan,safeTxHash:`0x${'00'.repeat(32)}`}));
 assert.throws(()=>pilotDepositGateSafeTypedData({...plan,schema:'usdom-pilot-deposit-gate-clear-plan/v1'}));
});

test('cancel executor uses guardian OneKey quorum and an untrusted external relayer',async()=>{
 const source=await readFile(new URL('../../scripts/execute-pilot-deposit-gate-cancel.sh',import.meta.url),'utf8');
 assert.doesNotMatch(source,/wallet (?:address|sign)[^\n]*--ledger|prepare-ledger|assemble-ledger|ledger_signature|observed_payer/);
 assert.match(source,/onekey-guardian-owner-\$index-identity\.json/);
 assert.match(source,/sign-onekey-ios-walletconnect-typed-data\.mjs/);assert.doesNotMatch(source,/sign-onekey-mainnet-(?:transaction|typed-data)\.mjs/);
 assert.match(source,/pilot-deposit-gate-cancel-onekey-signature-1\.hex/);
 assert.match(source,/\.authorizedOwners\[\$\(\(index-1\)\)\]/);
 const ownerSign=source.indexOf('sign-onekey-ios-walletconnect-typed-data.mjs'),ownerInstall=source.indexOf('materialize-pilot-gate-onekey-signature.mjs');
 assert.ok(source.indexOf('pilot_cancel_broadcast_state=signed-unresolved',ownerSign)<ownerInstall);
 assert.match(source,/prepare-pilot-gate-relayer-envelope\.mjs/);assert.match(source,/check-pilot-gate-relayer-raw\.mjs/);
 assert.ok(source.lastIndexOf('assert_live',ownerSign)>source.lastIndexOf('AUTORIZO CANCELAR GATE PILOTO OWNER',ownerSign));
 assert.match(source,/assert_relayer_live[\s\S]*AUTORIZO TRANSMITIR CANCELAMENTO GATE[\s\S]*assert_relayer_live/);
});

test('rotation consumes all OneKey partial-signature recovery artifacts',async()=>{
 const source=await readFile(new URL('../../scripts/rotate-expired-pilot-funds-authorization.mjs',import.meta.url),'utf8');
 for(const name of ['pilot-deposit-gate-cancel-onekey-signature-1.hex','pilot-deposit-gate-cancel-onekey-signature-2.hex','pilot-deposit-gate-cancel-relayer-envelope.json']) assert.ok(source.includes(name));
});
