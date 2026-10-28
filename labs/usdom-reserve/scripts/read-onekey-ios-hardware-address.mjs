#!/usr/bin/env node
import {getAddress} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

if(process.argv.length!==3) {
  process.stderr.write('usage: read-onekey-ios-hardware-address.mjs PHYSICAL_EVIDENCE\n');
  process.exit(64);
}

const bytes=await readDirectFile(process.argv[2],{maximum:16*1024,exactMode:0o600,
  label:'OneKey iOS physical account evidence'});
const value=parseStrictJsonBytes(bytes,{label:'OneKey iOS physical account evidence'});
const keys=value&&typeof value==='object'&&!Array.isArray(value)?Object.keys(value).sort():[];
const expected=['address','appReleaseSha256','deviceId','firmware','hardwareAccountSelected',
  'hardwareAddressConfirmed','hardwareSigningApproved','ratified','schema','source'].sort();
if(keys.length!==expected.length||keys.some((key,index)=>key!==expected[index])
  ||value.schema!=='usdom-onekey-ios-hardware-account-evidence/v1'
  ||value.source!=='onekey-ios-app'||typeof value.deviceId!=='string'||value.deviceId.length<1
  ||typeof value.firmware!=='string'||value.firmware.length<1
  ||getAddress(value.address)!==value.address
  ||! /^[0-9a-f]{64}$/u.test(value.appReleaseSha256)
  ||value.hardwareAddressConfirmed!==true||value.hardwareAccountSelected!==true
  ||value.ratified!==true||value.hardwareSigningApproved!==false) {
  throw new Error('OneKey iOS physical account evidence rejected');
}
process.stdout.write(`${value.address}\n`);
