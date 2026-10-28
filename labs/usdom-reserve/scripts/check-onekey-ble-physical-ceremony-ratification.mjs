#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateOneKeyBlePhysicalReadinessRatification} from '../sdk/onekey-ble-physical-ceremony-ratification.mjs';
if(process.argv.length!==3) throw new Error('usage: check-onekey-ble-physical-ceremony-ratification RATIFICATION');
const value=validateOneKeyBlePhysicalReadinessRatification(parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:32768,exactMode:0o600,label:'physical readiness ratification'}),{label:'physical readiness ratification'}));
process.stdout.write(`${JSON.stringify(value.readinessGates)}\n`);
