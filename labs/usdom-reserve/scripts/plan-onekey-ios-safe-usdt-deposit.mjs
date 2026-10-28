#!/usr/bin/env node
import {materializeSafeUsdtDepositPlan} from '../sdk/onekey-ios-safe-usdt-deposit-workflow.mjs';
if(process.argv.length!==5)throw new Error('usage: plan-onekey-ios-safe-usdt-deposit AUTHORITY PRE_STATE OUTPUT');
await materializeSafeUsdtDepositPlan({authorityPath:process.argv[2],preStatePath:process.argv[3],outputPath:process.argv[4]});process.stdout.write('PASS: exact sequential SafeTx plan created; signatures, execution and funds remain blocked\n');
