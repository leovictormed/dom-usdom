#!/usr/bin/env node
import {resolve} from 'node:path';import {readDirectFile} from '../sdk/direct-project-file.mjs';import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
const a=parseStrictJsonBytes(await readDirectFile(resolve(import.meta.dirname,'../config/onekey-ios-relayer-authority.unconfigured.json'),{minimum:2,maximum:32768,exactMode:0o644,label:'iOS relayer authority'}),{label:'iOS relayer authority'});
const keys=['schema','status','chainId','relayer','safe','token','governance','guardian','owners','notaries','threshold','allowedTargets','allowedSelectors','maxRelayerBalanceWei','maxOuterGasLimit','maxFeePerGasWei','emergencyReplacementRelayer','gates'];
const gateKeys=['relayerRoleSeparationVerified','relayerNoTokenCustodyVerified','signedSafeTxExactCalldataVerified','relayerEconomicCapsVerified','relayerNonceAndNoBlindRetryVerified','emergencyRelayerRotationVerified'];
if(JSON.stringify(Object.keys(a).sort())!==JSON.stringify(keys.sort())||JSON.stringify(Object.keys(a.gates).sort())!==JSON.stringify(gateKeys.sort())||a.schema!=='usdom-onekey-ios-relayer-authority-v1'||a.status!=='unconfigured'||a.chainId!=='1'
 ||['relayer','safe','token','governance','guardian','threshold','maxRelayerBalanceWei','maxOuterGasLimit','maxFeePerGasWei','emergencyReplacementRelayer'].some(k=>a[k]!==null)
 ||a.owners.length||a.notaries.length||a.allowedTargets.length||a.allowedSelectors.length||Object.values(a.gates).some(Boolean))throw new Error('iOS relayer authority is not fail-closed');
process.stdout.write('PASS: iOS EIP-712 relayer is unconfigured and every custody/execution gate is closed\n');
