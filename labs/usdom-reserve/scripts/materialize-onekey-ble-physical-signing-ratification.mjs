#!/usr/bin/env node
import {materializePhysicalSigningRatification} from '../sdk/onekey-ble-physical-signing-exercises.mjs';
if(process.argv.length!==7)throw new Error('usage: materialize-onekey-ble-physical-signing-ratification AUTHORITY EIP1559 EIP712 RATIFICATION OUTPUT');
await materializePhysicalSigningRatification({authorityPath:process.argv[2],eip1559Path:process.argv[3],eip712Path:process.argv[4],ratificationPath:process.argv[5],outputPath:process.argv[6]});
process.stdout.write('PASS: EIP-1559 and EIP-712 physical exercise gate ratified; general hardware approval remains false\n');
