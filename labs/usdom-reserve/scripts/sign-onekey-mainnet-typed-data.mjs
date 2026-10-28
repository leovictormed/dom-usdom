#!/usr/bin/env node
import {runOneKeyMainnetTypedData} from '../sdk/onekey-mainnet-typed-data-cli.mjs';
import {openApprovedOneKeyBluetooth} from '../sdk/onekey-bluetooth-factory.mjs';

if(process.argv.length!==5) {
  console.error('usage: sign-onekey-mainnet-typed-data.mjs IDENTITY ENVELOPE OUTPUT');
  process.exit(64);
}
try {
  await runOneKeyMainnetTypedData({identityPath:process.argv[2],envelopePath:process.argv[3],
    outputPath:process.argv[4],factory:openApprovedOneKeyBluetooth});
} catch(error) {
  console.error(error?.message??'OneKey typed-data signing failed');
  process.exit(error?.exitCode===80?80:1);
}
