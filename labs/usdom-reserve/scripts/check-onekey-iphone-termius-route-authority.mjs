#!/usr/bin/env node
import {resolve} from 'node:path';import {readDirectFile} from '../sdk/direct-project-file.mjs';import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
const exact=(v,k,l)=>{if(v===null||typeof v!=='object'||Array.isArray(v)||JSON.stringify(Object.keys(v).sort())!==JSON.stringify([...k].sort()))throw new Error(`${l} schema invalid`);};
const file=process.argv[2]??resolve(import.meta.dirname,'../config/onekey-iphone-termius-route-authority.unconfigured.json');
const a=parseStrictJsonBytes(await readDirectFile(file,{minimum:2,maximum:32768,exactMode:0o644,label:'iPhone route authority'}),{label:'iPhone route authority'});
exact(a,['schema','status','termiusCoreBluetoothForwardingSupported','rawEip1559SignatureRequired','ethSendTransactionAccepted','exactEip712Required','recommendedRoute','routes','gates','officialSources'],'authority');
exact(a.routes,['linuxHostBle','oneKeyIosWalletConnect','nativeIosBleCompanion'],'routes');exact(a.gates,['iphoneRemoteSigningApproved','walletConnectRawEip1559Verified','walletConnectExactEip712Verified','nativeIosBleCompanionApproved'],'gates');
exact(a.officialSources,['appleCoreBluetooth','termiusIos','oneKeyMobileDeeplinks','oneKeyEthereumRpc','walletConnectPairing'],'sources');
if(a.schema!=='usdom-onekey-iphone-termius-route-authority-v1'||a.status!=='evaluated-fail-closed'||a.termiusCoreBluetoothForwardingSupported!==false
 ||a.rawEip1559SignatureRequired!==true||a.ethSendTransactionAccepted!==false||a.exactEip712Required!==true
 ||a.recommendedRoute!=='native-ios-ble-companion'||a.routes.linuxHostBle!=='non-production-not-applicable-wallet-near-iphone'
 ||a.routes.oneKeyIosWalletConnect!=='rejected-missing-documented-raw-eip1559-signing'||a.routes.nativeIosBleCompanion!=='blocked-not-implemented-or-reviewed'
 ||Object.values(a.gates).some(x=>x!==false)||Object.values(a.officialSources).some(x=>typeof x!=='string'||!x.startsWith('https://')))throw new Error('iPhone/Termius authority is not fail-closed');
process.stdout.write('PASS: iPhone/Termius route remains fail-closed; native iOS BLE companion is required but remains blocked\n');
