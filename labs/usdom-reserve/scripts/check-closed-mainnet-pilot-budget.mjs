#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {validateClosedMainnetPilotBudget} from '../sdk/closed-mainnet-pilot-budget.mjs';
if(process.argv.length!==4) process.exit(64);
const list=value=>value===''?[]:value.split(',');
try {
  process.stdout.write(`${JSON.stringify(validateClosedMainnetPilotBudget({
    depositMaximumCosts:list(process.argv[2]),redemptionMaximumCosts:list(process.argv[3]),
  }))}\n`);
} catch(error) { writeReleaseFailure('check-closed-mainnet-pilot-budget',error); process.exitCode=1; }
