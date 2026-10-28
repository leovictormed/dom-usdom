#!/usr/bin/env node
import {resolve} from 'node:path';
import {loadUnconfiguredOneKeyElectronBlePackageAuthority} from '../sdk/onekey-electron-ble-package-authority.mjs';

const root=resolve(import.meta.dirname,'..');
await loadUnconfiguredOneKeyElectronBlePackageAuthority(
 resolve(root,'config/onekey-electron-ble-package-authority.unconfigured.json'));
process.stdout.write('PASS: packaged Electron BLE artifact and every physical ceremony gate remain fail-closed\n');
