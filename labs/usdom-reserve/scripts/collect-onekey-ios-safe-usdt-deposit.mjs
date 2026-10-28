#!/usr/bin/env node
import {materializeCollectedSafeUsdtDepositEvidence} from '../sdk/onekey-ios-safe-usdt-deposit-workflow.mjs';
if(process.argv.length!==7)throw new Error('usage: collect-onekey-ios-safe-usdt-deposit AUTHORITY PLAN OBSERVER_A OBSERVER_B OUTPUT');
try{await materializeCollectedSafeUsdtDepositEvidence({authorityPath:process.argv[2],planPath:process.argv[3],observerAPath:process.argv[4],observerBPath:process.argv[5],outputPath:process.argv[6]});process.stdout.write('PASS: two pinned RPC observations agree and evidence was installed create-once\n');}catch(error){process.stderr.write(`SAFE_DEPOSIT_COLLECTION_UNRESOLVED: ${error.message}\n`);process.exitCode=80;}
