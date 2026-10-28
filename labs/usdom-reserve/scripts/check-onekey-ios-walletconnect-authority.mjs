#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {ONEKEY_IOS_WC_FORBIDDEN_METHODS,ONEKEY_IOS_WC_METHOD,
 buildOneKeyIosWalletConnectProposal} from '../sdk/onekey-ios-walletconnect-typed-data.mjs';

const root=resolve(import.meta.dirname,'..');
const authority=parseStrictJson(readFileSync(resolve(root,'config/onekey-ios-walletconnect-authority.json'),'utf8'),
 {label:'OneKey iOS WalletConnect authority'});
if(authority.schema!=='usdom-onekey-ios-walletconnect-authority/v1'
 ||authority.status!=='implementation-complete-session-and-hardware-evidence-unconfigured'
 ||authority.productionTransport!=='walletconnect-v2-deeplink'||authority.chainId!=='eip155:1'
 ||JSON.stringify(authority.allowedMethods)!==JSON.stringify([ONEKEY_IOS_WC_METHOD])
 ||authority.allowedEvents.length!==0||JSON.stringify(authority.forbiddenMethods)!==JSON.stringify(ONEKEY_IOS_WC_FORBIDDEN_METHODS)
 ||authority.oneKeyCustomScheme!=='onekey-wallet://wc?uri='||authority.rawTransactionSigningDocumented!==false
 ||authority.hardwareAccountEvidenceRequired!==true||authority.relayEndToEndEncryptionAssumed!==true
 ||authority.releaseAuthorizationCallerIntegrated!==true
 ||authority.safeRecoveryCallerIntegrated!==true
 ||authority.pairingUriPersistence!==false||authority.pairingUriLogging!==false
 ||authority.deepLinkDisplay!=='explicit-one-time-operator-action'
 ||authority.walletConnectClientVersion!=='2.26.0'
 ||authority.walletConnectClientIntegrity!=='sha512-zu15NhOmGp1o0LsV9t6V1w+DFYx0UdljNLspqXu2L0GDJlU0Nv5Z70gadrbQGHn8tN70aQrrbOxfMCB48GTe8Q=='
 ||authority.walletConnectProjectId!==null||authority.networkExecutionApproved!==false
 ||authority.sessionRuntimeApproved!==false||authority.hardwareAccountApproved!==false
 ||authority.hardwareSigningApproved!==false)throw new Error('OneKey iOS WalletConnect authority is not fail-closed');
const sample=buildOneKeyIosWalletConnectProposal('0x1111111111111111111111111111111111111111');
if(JSON.stringify(sample.requiredNamespaces)!==JSON.stringify({eip155:{chains:['eip155:1'],methods:['eth_signTypedData_v4'],events:[]}})) {
 throw new Error('OneKey iOS WalletConnect proposal drift');
}
const source=readFileSync(resolve(root,'sdk/onekey-ios-walletconnect-typed-data.mjs'),'utf8');
for(const forbidden of ['fetch(','http.request','https.request','eth_sendRawTransaction\',params','eth_sendTransaction\',params']) {
 if(source.includes(forbidden))throw new Error(`forbidden OneKey iOS network/send implementation: ${forbidden}`);
}
process.stdout.write('PASS: OneKey iOS WalletConnect boundary is EIP-712-only and remains offline/unapproved\n');
