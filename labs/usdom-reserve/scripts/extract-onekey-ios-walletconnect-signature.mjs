#!/usr/bin/env node
import {readOneKeyIosTypedDataResponse} from '../sdk/onekey-ios-walletconnect-typed-data.mjs';
if(process.argv.length!==4){console.error('usage: extract-onekey-ios-walletconnect-signature.mjs REQUEST RESPONSE');process.exit(64);}
try {const response=await readOneKeyIosTypedDataResponse(process.argv[3],process.argv[2]);process.stdout.write(`${response.signature}\n`);}
catch(error){console.error(error?.message??'WalletConnect response rejected');process.exit(1);}
