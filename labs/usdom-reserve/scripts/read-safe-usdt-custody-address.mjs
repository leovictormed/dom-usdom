#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateSafeUsdtCustodyAuthority} from '../sdk/onekey-ios-safe-usdt-custody.mjs';
if(process.argv.length!==3){process.stderr.write('usage: read-safe-usdt-custody-address.mjs AUTHORITY\n');process.exit(64);}
const authority=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:65536,
 exactMode:0o600,label:'configured Safe USDT custody authority'}),{label:'configured Safe USDT custody authority'});
validateSafeUsdtCustodyAuthority(authority,{configured:true});
process.stdout.write(`${authority.safe}\n`);
