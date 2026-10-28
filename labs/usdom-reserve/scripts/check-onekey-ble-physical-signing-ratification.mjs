#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';import {validatePhysicalSigningReadiness} from '../sdk/onekey-ble-physical-signing-exercises.mjs';
if(process.argv.length!==3)throw new Error('usage: check-onekey-ble-physical-signing-ratification FILE');
const value=validatePhysicalSigningReadiness(parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:32768,exactMode:0o600,label:'physical signing readiness'}),{label:'physical signing readiness'}));
process.stdout.write(`${JSON.stringify(value.readinessGates)}\n`);
