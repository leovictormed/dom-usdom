#!/usr/bin/env node
import {resolve} from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateOneKeyBlePhysicalCeremonyAuthority} from '../sdk/onekey-ble-physical-ceremony-evidence.mjs';

const file=resolve(import.meta.dirname,'../config/onekey-ble-physical-ceremony-authority.unconfigured.json');
const value=parseStrictJsonBytes(await readDirectFile(file,{minimum:2,maximum:32768,exactMode:0o644,label:'unconfigured physical ceremony authority'}),{label:'unconfigured physical ceremony authority'});
validateOneKeyBlePhysicalCeremonyAuthority(value);
process.stdout.write(`${JSON.stringify({schema:'usdom-onekey-ble-physical-readiness-v1',
 production_onekey_ble_pairing_and_permissions_verified:false,
 production_onekey_ble_device_identity_and_reconnection_verified:false,
 production_onekey_address_verified_on_device:false,
 production_onekey_eip1559_and_eip712_signing_verified:false,
 production_onekey_reject_cancel_disconnect_reconnect_verified:false})}\n`);
