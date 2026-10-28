#!/usr/bin/env node
import {resolve} from 'node:path';import {readDirectFile} from '../sdk/direct-project-file.mjs';import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';import {evaluateOneKeyProductionReadinessDag} from '../sdk/onekey-production-readiness-dag.mjs';
const file=process.argv[2]??resolve(import.meta.dirname,'../config/onekey-production-readiness-dag.unconfigured.json');
const ios=parseStrictJsonBytes(await readDirectFile(resolve(import.meta.dirname,'../config/onekey-ios-walletconnect-authority.json'),{minimum:2,maximum:65536,exactMode:0o600,label:'iOS WalletConnect authority'}),{label:'iOS WalletConnect authority'});
const authority=parseStrictJsonBytes(await readDirectFile(file,{minimum:2,maximum:32768,exactMode:0o644,label:'OneKey readiness DAG'}),{label:'OneKey readiness DAG'});
if(authority.facts.iosWalletConnectAuthorityPinned!==(ios.productionTransport==='walletconnect-v2-deeplink'&&JSON.stringify(ios.allowedMethods)===JSON.stringify(['eth_signTypedData_v4']))
 ||authority.facts.iosWalletConnectClientPinned!==(typeof ios.walletConnectClientVersion==='string'&&typeof ios.walletConnectClientIntegrity==='string')
 ||authority.facts.iosWalletConnectSessionRuntimeApproved!==ios.sessionRuntimeApproved
 ||authority.facts.iosWalletConnectNetworkApproved!==ios.networkExecutionApproved)throw new Error('iOS WalletConnect DAG facts drifted');
const result=evaluateOneKeyProductionReadinessDag(authority);
if(result.hardwareSigningApproved!==false||Object.values(result.readinessGates).some(Boolean))throw new Error('unconfigured OneKey DAG unexpectedly opened a production gate');
process.stdout.write(`${JSON.stringify(result)}\n`);
