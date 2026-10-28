#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {prepareOneKeyEip1559Transaction} from '../sdk/onekey-eip1559-transaction.mjs';
try{if(![8,9].includes(process.argv.length))throw new Error('usage: private transaction input, payer, nonce, gas and fees');const input=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:8*1024*1024,exactMode:0o600}),{label:'private transaction input'});process.stdout.write(JSON.stringify(prepareOneKeyEip1559Transaction({from:process.argv[3],to:input.to,data:input.data,nonce:process.argv[4],gasLimit:process.argv[5],maxFeePerGas:process.argv[6],maxPriorityFeePerGas:process.argv[7],maxGasLimit:process.argv[8]??'500000'}))+'\n');}catch(error){writeReleaseFailure('prepare-onekey-eip1559-transaction',error);process.exitCode=1;}
