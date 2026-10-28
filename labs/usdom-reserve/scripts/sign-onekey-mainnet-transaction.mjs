#!/usr/bin/env node
import {runOneKeyMainnetTransaction} from '../sdk/onekey-mainnet-transaction-cli.mjs';
import {openApprovedOneKeyBluetooth} from '../sdk/onekey-bluetooth-factory.mjs';
try {
  if(process.argv.length!==5) throw new Error('usage: private identity, private prepared transaction, private output');
  await runOneKeyMainnetTransaction({identityPath:process.argv[2],preparedPath:process.argv[3],
    outputPath:process.argv[4],factory:openApprovedOneKeyBluetooth});
} catch(error) {
  process.stderr.write(`OneKey signing failed: ${error instanceof Error?error.message:'unknown failure'}\n`);
  process.exitCode=error?.exitCode===80?80:1;
}
