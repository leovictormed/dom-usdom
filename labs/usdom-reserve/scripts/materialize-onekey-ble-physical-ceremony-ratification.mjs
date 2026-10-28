#!/usr/bin/env node
import {materializeOneKeyBlePhysicalCeremonyRatification} from '../sdk/onekey-ble-physical-ceremony-ratification.mjs';
if(process.argv.length!==7) throw new Error('usage: materialize-onekey-ble-physical-ceremony-ratification AUTHORITY OBSERVATION EVIDENCE RATIFICATION OUTPUT');
await materializeOneKeyBlePhysicalCeremonyRatification({authorityPath:process.argv[2],observationPath:process.argv[3],evidencePath:process.argv[4],ratificationPath:process.argv[5],outputPath:process.argv[6]});
process.stdout.write('PASS: single-operator physical ratification installed; residual risk remains explicit\n');
