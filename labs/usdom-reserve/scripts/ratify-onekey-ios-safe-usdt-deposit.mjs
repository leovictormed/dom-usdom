#!/usr/bin/env node
import {materializeSafeUsdtDepositRatification} from '../sdk/onekey-ios-safe-usdt-deposit-workflow.mjs';
if(process.argv.length!==8)throw new Error('usage: ratify-onekey-ios-safe-usdt-deposit AUTHORITY PLAN EVIDENCE OBSERVATION APPROVAL OUTPUT');
try{await materializeSafeUsdtDepositRatification({authorityPath:process.argv[2],planPath:process.argv[3],evidencePath:process.argv[4],observationPath:process.argv[5],approvalPath:process.argv[6],outputPath:process.argv[7]});process.stdout.write('PASS: exact observed Safe deposit ratified; broad hardware/funds approval remains closed\n');}catch(error){process.stderr.write(`SAFE_DEPOSIT_RATIFICATION_UNRESOLVED: ${error.message}\n`);process.exitCode=80;}
