#!/usr/bin/env node
import {getAddress} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

if(process.argv.length<3||process.argv.length>4){process.stderr.write('usage: read-mainnet-gas-relayer-identity.mjs IDENTITY [ROLE]\n');process.exit(64);}
const value=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:8192,
 privateMode:true,exactMode:0o600,label:'mainnet gas relayer public identity'}),
 {label:'mainnet gas relayer public identity'});
const expected=['address','chainId','custodyAuthority','encryptedKeystoreSha256','role','schema','tokenCustody'].sort();
const keys=value&&typeof value==='object'&&!Array.isArray(value)?Object.keys(value).sort():[];
const expectedRole=process.argv[3]??'deployment';
const legacy=value.schema==='usdom-mainnet-gas-relayer-public-identity/v1'&&expectedRole==='deployment'&&value.role==='mainnet-deployment-gas-only';
const current=value.schema==='usdom-mainnet-gas-relayer-public-identity/v2'&&value.role===`${expectedRole}-gas-only`;
if(keys.length!==expected.length||keys.some((key,index)=>key!==expected[index])
 ||(!legacy&&!current)||value.chainId!=='1'||getAddress(value.address)!==value.address
 ||!/^[0-9a-f]{64}$/u.test(value.encryptedKeystoreSha256??'')
 ||value.custodyAuthority!==false||value.tokenCustody!==false)throw new Error('mainnet gas relayer identity rejected');
process.stdout.write(`${value.address}\n`);
