#!/usr/bin/env node
import {materializeSafeUsdtCustodyEvidence} from '../sdk/onekey-ios-safe-usdt-custody.mjs';
if(process.argv.length!==5)throw new Error('usage: materialize-onekey-ios-safe-usdt-custody AUTHORITY EVIDENCE OUTPUT');
await materializeSafeUsdtCustodyEvidence({authorityPath:process.argv[2],evidencePath:process.argv[3],outputPath:process.argv[4]});
process.stdout.write('PASS: Safe USDT custody observation materialized; single-operator ratification and real funds remain blocked\n');
