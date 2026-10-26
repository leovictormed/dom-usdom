#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {planMainnetDeploymentGas} from '../sdk/mainnet-deployment-execution.mjs';

try {
  if(process.argv.length!==5) throw new Error('usage: plan-mainnet-deployment-gas.mjs NAME INITCODE MAXIMUM_ESTIMATE');
  const gasLimit=planMainnetDeploymentGas({name:process.argv[2],data:process.argv[3],maximumEstimate:process.argv[4]});
  process.stdout.write(`${gasLimit}\n`);
} catch(error) {
  writeReleaseFailure('plan-mainnet-deployment-gas',error);
  process.exitCode=1;
}
