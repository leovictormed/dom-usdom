#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
const UINT=/^(?:0|[1-9][0-9]{0,77})$/,MAX_UINT256=(1n<<256n)-1n;
try {
  if(process.argv.length!==6) throw new Error('estimate, base fee, gas cap and cost cap required');
  const values=process.argv.slice(2);
  if(!values.every(value=>UINT.test(value))) throw new Error('fee input is not canonical uint256');
  const [estimate,baseFee,gasCap,costCap]=values.map(BigInt);
  if([estimate,baseFee,gasCap,costCap].some(value=>value>MAX_UINT256)
    ||estimate===0n||baseFee===0n||gasCap===0n||costCap===0n) throw new Error('fee input outside policy');
  const gas=(estimate*125n+99n)/100n,maxFee=baseFee*2n+2000000000n;
  if(gas>gasCap||maxFee>100000000000n) throw new Error('fee component exceeds policy');
  const maximumCost=gas*maxFee;
  if(maximumCost>costCap) throw new Error('maximum gas cost exceeds policy');
  process.stdout.write(`${JSON.stringify({gas:gas.toString(),maxFee:maxFee.toString(),maximumCost:maximumCost.toString()})}\n`);
} catch(error) { writeReleaseFailure('calculate-pilot-transaction-fees',error);process.exitCode=1; }
