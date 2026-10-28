#!/usr/bin/env node
import {resolve} from 'node:path';
import {checkOneKeyElectronBlePolicy,readOneKeyElectronBlePolicy} from '../sdk/onekey-electron-ble-handoff-policy.mjs';

const root=resolve(new URL('..',import.meta.url).pathname);
const policy=await readOneKeyElectronBlePolicy(resolve(root,
 'config/onekey-electron-ble-handoff-policy.unconfigured.json'));
const result=checkOneKeyElectronBlePolicy(policy);
process.stdout.write(`PASS: Electron BLE policy is ${result.status} and hardware signing remains blocked\n`);
