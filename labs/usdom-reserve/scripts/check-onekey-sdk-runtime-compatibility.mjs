#!/usr/bin/env node
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname,resolve} from 'node:path';

const require=createRequire(resolve(process.cwd(),'package.json'));
const imported=require('@onekeyfe/hd-common-connect-sdk');
const sdk=imported.default?.default??imported.default;
for(const method of ['init','searchDevices','getDeviceState','evmGetAddress',
 'evmSignTransaction','evmSignTypedData','cancel','dispose']) {
 assert.equal(typeof sdk?.[method],'function',`missing OneKey SDK method ${method}`);
}
const transport=require('@onekeyfe/hd-transport').default;
const webDevice=require('@onekeyfe/hd-transport-web-device');
assert.equal(typeof webDevice.ElectronBleTransport,'function','Electron BLE transport import failed');
assert.equal(webDevice.WebUsbTransport instanceof Function,true,'stable package export changed');
const coreRoot=dirname(require.resolve('@onekeyfe/hd-core/package.json'));
const schema=JSON.parse(readFileSync(resolve(coreRoot,'src/data/messages/messages.json'),'utf8'));
const messages=transport.parseConfigure(schema);
const path=[2147483692,2147483708,2147483648,0,0];
const vectors={
 Features:{vendor:'onekey.so',major_version:4,minor_version:10,patch_version:0,
  device_id:'offline-compatibility-vector',model:'classic1s',initialized:true},
 EthereumGetAddress:{address_n:path,show_display:true},
 EthereumAddress:{address:'0x1111111111111111111111111111111111111111'},
 EthereumSignTxEIP1559:{address_n:path,nonce:'00',max_gas_fee:'01',
  max_priority_fee:'01',gas_limit:'5208',to:'1111111111111111111111111111111111111111',
  value:'01',data_initial_chunk:'',data_length:0,chain_id:1},
 EthereumTxRequest:{data_length:0,signature_v:1,signature_r:'11'.repeat(32),
  signature_s:'22'.repeat(32)},
 EthereumSignTypedData:{address_n:path,primary_type:'SafeTx',metamask_v4_compat:true},
};
for(const [name,input] of Object.entries(vectors)) {
 const {Message,messageTypeId}=transport.createMessageFromName(messages,name);
 assert.ok(Number.isInteger(messageTypeId),`${name} has no Protocol V1 message id`);
 assert.equal(Message.verify(input),null,`${name} input rejected`);
 const encoded=transport.encodeProtobuf(Message,input);
 const decoded=transport.decodeProtobuf(Message,encoded.clone());
 assert.equal(Message.verify(decoded),null,`${name} round trip rejected`);
}
assert.equal(require('protobufjs/package.json').version,'8.8.1');
assert.equal(require('axios/package.json').version,'1.21.0');
assert.equal(require('lodash/package.json').version,'4.18.1');
process.stdout.write('PASS: OneKey SDK, Electron BLE renderer transport and Protocol V1 descriptors are compatible offline; native BLE host remains unapproved\n');
