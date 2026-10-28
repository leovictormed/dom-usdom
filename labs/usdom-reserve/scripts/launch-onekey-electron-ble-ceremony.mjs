#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {evaluateOneKeyProductionReadinessDag} from '../sdk/onekey-production-readiness-dag.mjs';

const authority=parseStrictJson(readFileSync(new URL('../config/onekey-production-readiness-dag.unconfigured.json',import.meta.url),'utf8'),{label:'OneKey production DAG'});
const readiness=evaluateOneKeyProductionReadinessDag(authority);
if(readiness.productionRoute!=='onekey-ios-walletconnect-eip712-only'||readiness.hardwareSigningApproved!==true) {
 process.stderr.write('BLOCKED: production OneKey route is iOS WalletConnect EIP-712-only and its complete DAG is not approved\n');
 process.exit(78);
}
throw new Error('approved pinned iOS WalletConnect launcher is not installed');
