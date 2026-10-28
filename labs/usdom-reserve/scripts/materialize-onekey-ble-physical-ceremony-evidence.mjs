#!/usr/bin/env node
import {materializeOneKeyBlePhysicalCeremonyEvidence} from '../sdk/onekey-ble-physical-ceremony-evidence.mjs';
if(process.argv.length!==5) throw new Error('usage: materialize-onekey-ble-physical-ceremony-evidence AUTHORITY OBSERVATION OUTPUT');
await materializeOneKeyBlePhysicalCeremonyEvidence({authorityPath:process.argv[2],observationPath:process.argv[3],outputPath:process.argv[4]});
process.stdout.write('PASS: physical OneKey BLE observation materialized; explicit operator ratification remains required\n');
